# SPDX-License-Identifier: Apache-2.0
"""Boot-time wiring for the durable run-state store.

``OrchestratorConfig.run_state_backend`` selects *which* :class:`RunStateStore`
the orchestrator persists run lifecycle + audit ribbon to. Historically this
field was defined but never read: :class:`RunOrchestrator` silently defaulted to
an in-memory store, so even a production boot lost every in-progress run (and its
human-approval gate) on restart.

:func:`resolve_run_state_store` is the single deterministic entry point that maps
a config to a concrete store, and — following a deny-by-default /
fail-closed posture — **refuses to hand back an in-memory store outside dev**.
The fail-closed enforcement lives here (and at the boot call sites that mount the
returned store), NOT in :meth:`RunOrchestrator.__init__`, whose optional
``state_store`` parameter stays unchanged so the existing unit/integration tests
keep instantiating it without a store.

Backend matrix:

==========  ========  ===========================================
backend     is_dev    result
==========  ========  ===========================================
memory      True      :class:`InMemoryRunStateStore`
memory      False     :class:`RunStateConfigError` (no silent prod memory)
sqlite      any       :class:`SQLiteRunStateStore` (durable)
pg          any       :class:`NotImplementedError` (Stage 1 has no store)
<other>     any       :class:`RunStateConfigError`
==========  ========  ===========================================

PG run-state is deferred: Stage 1 built only ``PgEventStore`` (the audit event
log), never a ``PgRunStateStore``. The ``"pg"`` branch is defensive — the config
``Literal`` is ``"memory" | "sqlite"`` so ``"pg"`` is unreachable by type, but a
dataclass field can be assigned any string at runtime, so we fail loudly rather
than silently mis-route.
"""

from __future__ import annotations

from secugent.config import OrchestratorConfig
from secugent.orchestrator.lease import (
    InMemoryLeaseManager,
    LeaseManager,
    PgLeaseManager,
    PgLeasePrimitives,
    SQLiteLeaseManager,
)
from secugent.orchestrator.recovery import PublishFn, RecoveryReport, run_recovery
from secugent.orchestrator.runner import RunOrchestrator
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunRecord,
    RunStateStore,
    SQLiteRunStateStore,
)

__all__ = [
    "LeaseConfigError",
    "RunStateConfigError",
    "recover_open_runs",
    "resolve_lease_manager",
    "resolve_run_state_store",
]


class RunStateConfigError(RuntimeError):
    """Run-state backend configuration violates a fail-closed invariant.

    Raised when the requested backend cannot be honoured safely — most notably a
    request for the in-memory backend outside dev (which would silently lose
    in-progress runs on restart), an empty sqlite path, or an unknown backend
    name. The error deliberately names the *backend/mode* but never echoes the
    configured filesystem path, so a boot failure cannot leak on-disk layout.
    """


def resolve_run_state_store(
    cfg: OrchestratorConfig,
    *,
    is_dev: bool,
) -> RunStateStore:
    """Resolve the configured durable run-state store, fail-closed.

    :param cfg: orchestrator config carrying ``run_state_backend`` and (for the
        sqlite backend) ``run_state_db_path``.
    :param is_dev: whether the process is running in dev mode. The caller (the
        boot path) computes this — e.g.
        ``os.environ.get("SECUGENT_ENV", "dev").lower() == "dev"`` — so this
        module never reads the environment itself (keeps it pure/testable).
    :returns: a :class:`RunStateStore` for the selected backend.
    :raises RunStateConfigError: memory backend outside dev, empty sqlite path,
        or an unknown backend name.
    :raises NotImplementedError: the ``"pg"`` backend (deferred; Stage 1 has no
        ``PgRunStateStore``).

    ``None`` (UNCONFIGURED, F8/F13) is treated exactly like the documented dev
    default — in dev it yields an in-memory store; in prod it is still refused
    (deny-by-default). The boot path (:func:`_resolve_run_state_config`) upgrades
    an unconfigured prod default to ``"sqlite"`` BEFORE calling this resolver, so
    prod boot works out of the box while an EXPLICIT ``"memory"`` still fails fast.
    """
    backend = cfg.run_state_backend
    if backend is None or backend == "memory":
        if not is_dev:
            raise RunStateConfigError(
                "in-memory / unconfigured run-state backend is dev-only; production "
                "(SECUGENT_ENV!=dev) requires a durable backend "
                "(run_state_backend='sqlite'). Refusing to silently lose "
                "in-progress runs on restart."
            )
        return InMemoryRunStateStore()
    if backend == "sqlite":
        path = cfg.run_state_db_path
        if not path:
            raise RunStateConfigError("run_state_backend='sqlite' requires a non-empty run_state_db_path.")
        return SQLiteRunStateStore(path)
    if backend == "pg":
        raise NotImplementedError("PG run-state deferred; Stage 1 has no PgRunStateStore")
    raise RunStateConfigError(f"unknown run_state_backend {backend!r}; expected 'memory' or 'sqlite'.")


# ---------------------------------------------------------------------------
# HA lease manager resolution
# ---------------------------------------------------------------------------


class LeaseConfigError(RuntimeError):
    """HA-lease backend configuration violates a fail-closed invariant.

    Raised when HA is enabled but the requested backend cannot be honoured —
    most notably the in-memory lease manager outside dev (single-process only;
    it would give a *false* single-leader guarantee across nodes), the PG
    backend without a usable store, or an unknown HA backend name. Like
    :class:`RunStateConfigError`, the message names the backend/mode but never
    echoes connection strings or filesystem paths.
    """


def resolve_lease_manager(
    cfg: OrchestratorConfig,
    store: object | None,
    *,
    is_dev: bool,
) -> LeaseManager | None:
    """Resolve the configured HA lease manager, fail-closed. ``None`` = no HA.

    HA is **off by default**: when the config carries no ``ha_enabled`` flag (or
    it is falsy) this returns ``None`` and the orchestrator runs single-node,
    exactly as before. This keeps existing boots unchanged until the config lane
    introduces the flag.

    When HA is on, the backend is chosen by ``ha_backend`` (falling back to the
    run-state backend so a single config knob usually suffices):

    ==========  ========  =================================================
    ha_backend  is_dev    result
    ==========  ========  =================================================
    memory      True      :class:`InMemoryLeaseManager`
    memory      False     :class:`LeaseConfigError` (no cross-node guarantee)
    sqlite      any       :class:`SQLiteLeaseManager` (single-host)
    pg          any       :class:`PgLeaseManager` over ``store`` (production)
    <other>     any       :class:`LeaseConfigError`
    ==========  ========  =================================================

    :param cfg: orchestrator config; read defensively via ``getattr`` for the
        optional HA fields so this module does not hard-depend on config fields a
        sibling lane may still be adding.
    :param store: the live event store (a PG event store for the ``pg`` backend);
        wrapped by :class:`PgLeaseManager`. Ignored by memory/sqlite backends.
    :param is_dev: whether the process runs in dev mode (caller-computed, mirrors
        :func:`resolve_run_state_store`).
    :raises LeaseConfigError: in-memory outside dev, missing/invalid PG store, or
        an unknown HA backend name.
    """
    if not bool(getattr(cfg, "ha_enabled", False)):
        return None

    # ha_backend falls back to run_state_backend; an unconfigured (None) run-state
    # backend means "in-memory" (the dev default), so normalise None → "memory".
    backend = str(getattr(cfg, "ha_backend", "") or cfg.run_state_backend or "memory")
    if backend == "memory":
        if not is_dev:
            raise LeaseConfigError(
                "in-memory lease manager is dev-only; it tracks leases in a "
                "single process and cannot guarantee a single leader across HA "
                "nodes. Use ha_backend='pg' (or 'sqlite' for single-host)."
            )
        return InMemoryLeaseManager()
    if backend == "sqlite":
        path = cfg.run_state_db_path
        if not path:
            raise LeaseConfigError("ha_backend='sqlite' requires a non-empty run_state_db_path.")
        return SQLiteLeaseManager(path)
    if backend == "pg":
        if not isinstance(store, PgLeasePrimitives):
            raise LeaseConfigError(
                "ha_backend='pg' requires a PG event store exposing the lease "
                "primitives (try_acquire_leader/acquire_run_lease/…); got an "
                "incompatible store."
            )
        return PgLeaseManager(store)
    raise LeaseConfigError(f"unknown ha_backend {backend!r}; expected 'memory', 'sqlite', or 'pg'.")


# ---------------------------------------------------------------------------
# Boot-time crash recovery hook
# ---------------------------------------------------------------------------


async def recover_open_runs(
    orchestrator: RunOrchestrator,
    state_store: RunStateStore,
    publish_event: PublishFn,
    *,
    lease_manager: LeaseManager | None = None,
    worker_id: str = "node-local",
) -> RecoveryReport:
    """Boot hook the lifespan calls once after the orchestrator starts.

    Enumerates open runs from ``state_store`` (``list_open_runs`` is a MANDATORY
    member of the :class:`RunStateStore` Protocol) and feeds them to
    :func:`secugent.orchestrator.recovery.run_recovery`, wiring its callbacks to
    :meth:`RunOrchestrator.resume` (re-schedule existing run) and the supplied
    event publisher. Idempotent: re-invoking yields the same result because the
    driver guards on each run's current persisted state.

    F9 (LEADER-SINGLETON): when ``lease_manager`` is provided (HA multi-node),
    ``run_recovery`` skips any run whose lease is held by another live worker, so
    a booting node never fails-out / resumes a run another node is actively
    holding. Single-node (``lease_manager is None``) keeps prior behaviour.

    :param publish_event: ``async (run_id, topic, payload) -> None``; typically
        the orchestrator's own publisher so ``run.handover`` lands on the run's
        audit ribbon.
    :returns: a :class:`RecoveryReport`.
    """
    open_runs = await state_store.list_open_runs()

    async def _enqueue(record: RunRecord) -> None:
        await orchestrator.resume(record)

    return await run_recovery(
        open_runs,
        state_store=state_store,
        enqueue=_enqueue,
        publish_event=publish_event,
        lease_manager=lease_manager,
        worker_id=worker_id,
    )
