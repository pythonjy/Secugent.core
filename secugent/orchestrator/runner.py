# SPDX-License-Identifier: Apache-2.0
"""Background pipeline driver.

Per master prompt §2.3:

* ``start()`` initialises an :class:`asyncio.Semaphore` worker pool.
* ``enqueue()`` schedules an :func:`asyncio.create_task` wrapping
  :meth:`_run_pipeline`.
* The pipeline transitions PENDING → PLANNING → AWAITING_APPROVAL (or
  APPROVED if ``auto_approve``) → EXECUTING → REPORTING → COMPLETED.
* Any exception in HEAD / Dispatcher / SUB is converted into FAILED +
  ``run.failed`` event so the orchestrator itself stays alive.
* ``stop()`` cancels in-flight tasks, marks the affected runs CANCELLED, and
  causes new ``enqueue()`` calls to raise :class:`OrchestratorStoppedError`.

The orchestrator deliberately depends on *protocols* (planner / dispatcher /
event publisher) rather than concrete classes so unit tests can inject
deterministic stubs without spinning up FastAPI.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from secugent.config import OrchestratorConfig
from secugent.observability.metrics import HITL_BACKLOG, RUN_LATENCY
from secugent.orchestrator.errors import (
    DispatcherResultMalformed,
    PlannerFailedError,
)
from secugent.orchestrator.events import OrchestratorEventType as ET
from secugent.orchestrator.lease import LeaseLostError, LeaseManager
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunEvent,
    RunRecord,
    RunState,
    RunStateStore,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only imports, no runtime dependency.
    # ``secugent.cost`` is the BSL-1.1 Enterprise quota-enforcement tier and is
    # NOT shipped in the public OSS Core wheel. The orchestrator only holds an
    # OPTIONAL, injected ``CostLedger`` (defaults to ``None`` = no enforcement),
    # so the annotation is type-only and ``QuotaExceededError`` is needed only on
    # the enforcement path. Importing the tier at module load would break
    # standalone import of Core (``ModuleNotFoundError: secugent.cost``) and leak
    # the tier (open-core boundary I2/I8). The runtime ledger is supplied by the
    # Enterprise wiring; the ``except`` path resolves QuotaExceededError lazily
    # (so it is imported there, not here — only CostLedger is needed for typing).
    from secugent.cost.accounting import CostLedger

__all__ = [
    "ApprovalDecision",
    "OrchestratorStoppedError",
    "PlanLike",
    "PlannerProtocol",
    "DispatcherProtocol",
    "EventPublisher",
    "RunOrchestrator",
    "SubFactory",
]


_logger = logging.getLogger("secugent.orchestrator")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OrchestratorStoppedError(RuntimeError):
    """Raised when :meth:`RunOrchestrator.enqueue` is called after stop()."""


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@dataclass
class PlanLike:
    """Minimal plan shape the orchestrator needs.

    Real HEAD planners return Pydantic :class:`secugent.core.contracts.Plan`
    objects; the orchestrator only reads ``id``, ``steps`` (length), and the
    free-form ``summary``.
    """

    id: str
    summary: str
    steps: list[Any]
    raw: Any = None  # the underlying Plan or compatible object


class PlannerProtocol(Protocol):
    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike: ...


class DispatcherProtocol(Protocol):
    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]: ...


EventPublisher = Callable[[str, str, dict[str, Any]], Awaitable[None]]
"""``async (run_id, topic, payload) -> None``."""

SubFactory = Callable[[str, str, "str | None", Any, str], Any]
"""``(actor, plan_approval_id, envelope_hash, oversight, regulations_version)
-> SubAgent`` — kept here so the FastAPI layer can wire concrete SUB agents
without the orchestrator caring. ``oversight`` is the per-run
:class:`~secugent.core.mechanical_oversight.OversightEngine` (G-H4) threaded
explicitly (never via contextvar, mirroring ``envelope_hash``) so each run's
SUBs read that run's effective tenant policy; ``regulations_version`` is the
effective policy version stamped onto audit events."""


# ---------------------------------------------------------------------------
# Approval signal
# ---------------------------------------------------------------------------


@dataclass
class ApprovalDecision:
    action: str  # "approve" | "reject" | "amend"
    approver: str | None = None
    reason: str | None = None
    instruction: str | None = None  # amend only


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class RunOrchestrator:
    """Asyncio-based pipeline driver. Single-process, in-memory queue."""

    def __init__(
        self,
        *,
        planner: PlannerProtocol,
        dispatcher: DispatcherProtocol,
        state_store: RunStateStore | None = None,
        config: OrchestratorConfig | None = None,
        publish_event: EventPublisher | None = None,
        lease_manager: LeaseManager | None = None,
        worker_id: str = "node-local",
        lease_ttl_seconds: int = 60,
        cost_ledger: CostLedger | None = None,
    ) -> None:
        self._planner = planner
        self._dispatcher = dispatcher
        self._store: RunStateStore = state_store or InMemoryRunStateStore()
        self._config = config or OrchestratorConfig()
        self._publish = publish_event or _noop_publish
        # Optional HA single-leader lease (G-C8). ``None`` = single-node mode:
        # the dispatch path runs exactly as before (no acquire/release). When set,
        # a run is only dispatched while this node holds that run's lease.
        self._lease_manager = lease_manager
        self._worker_id = worker_id
        self._lease_ttl_seconds = lease_ttl_seconds
        # Optional cost ledger (S8B). None = skip quota enforcement (backward compat).
        self._cost_ledger = cost_ledger
        self._semaphore: asyncio.Semaphore | None = None
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._approval_queues: dict[str, asyncio.Queue[ApprovalDecision]] = {}
        self._stopped = False
        self._lifecycle_lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._semaphore is None:
                self._semaphore = asyncio.Semaphore(self._config.max_concurrent_runs)
                self._stopped = False
                _logger.info(
                    "orchestrator started max_concurrent=%d auto_approve=%s",
                    self._config.max_concurrent_runs,
                    self._config.auto_approve,
                )

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            self._stopped = True
            tasks = list(self._tasks.items())
        for _run_id, task in tasks:  # noqa: B007 - run_id used in second loop only
            task.cancel()
        for run_id, task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: S110 - intentional swallow; see docstring
                pass
            # Best-effort: ensure cancelled runs land in CANCELLED.
            record = await self._store.get(run_id)
            if record and record.state not in _TERMINAL:
                await self._store.update_state(
                    run_id, RunState.CANCELLED, failure_reason="orchestrator_stopped"
                )
                await self._record_and_publish(
                    run_id,
                    ET.RUN_CANCELLED,
                    {"reason": "orchestrator_stopped"},
                )
        self._tasks.clear()
        _logger.info("orchestrator stopped")

    @property
    def is_running(self) -> bool:
        return self._semaphore is not None and not self._stopped

    @property
    def lease_manager(self) -> LeaseManager | None:
        """The HA lease manager (``None`` = single-node). Read-only accessor used
        by boot recovery so it can probe per-run lease ownership (F9)."""
        return self._lease_manager

    def set_lease_manager(self, lease_manager: LeaseManager | None) -> None:
        """Mount/replace the HA lease manager AFTER construction (F3).

        The PG lease backend needs the PG event store, which is only set in the
        lifespan AFTER :class:`AppState` is built (``pg_store`` is ``None`` during
        ``__init__``). The boot path therefore re-resolves the lease manager once
        the PG store is live and installs it here. Must be called before any run
        is dispatched (i.e. in the lifespan, before recovery/enqueue) so the
        single-leader guarantee holds from the first dispatch."""
        self._lease_manager = lease_manager

    # ------------------------------------------------------------------ #
    # Enqueue + approval signals
    # ------------------------------------------------------------------ #

    async def enqueue(
        self,
        run_id: str,
        command: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Register the run and schedule the pipeline. Non-blocking.

        TOCTOU closed (SG-FIX-05): the initial stopped-check is a fast-path
        guard only. After the two awaits (store.create + record_and_publish)
        we re-acquire _lifecycle_lock and re-check _stopped before claiming
        the task slot. create_task + _tasks insert are both synchronous, so
        "stopped re-check → task claim" is atomic w.r.t. stop() — identical
        to the pattern in resume() (F10, "TOCTOU closed"). The store row
        created above is left as-is when the re-check fires: it is an
        already-persisted row in a non-PENDING state that boot recovery will
        handle if needed; no live pipeline task is ever spawned.
        """
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
        await self._store.create(run_id, command, context or {})
        await self._record_and_publish(run_id, ET.COMMAND_RECEIVED, {"command": command})
        # Re-acquire the lock to close the TOCTOU window opened by the two
        # awaits above. stop() sets _stopped=True under this same lock, so
        # either we see _stopped=True here (and raise, leaving no live task)
        # or stop() has not yet set it and will wait for us to release the
        # lock before it can run — either way it will see our task in _tasks.
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
            # create_task + insert are sync ⇒ check-and-claim is atomic w.r.t.
            # the lock; the task body only runs after we release (next loop tick).
            task = asyncio.create_task(
                self._run_pipeline(run_id, command, dict(context or {})),
                name=f"run-{run_id}",
            )
            self._tasks[run_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(run_id, None))

    async def resume(self, record: RunRecord) -> None:
        """Re-schedule an *existing* (already-persisted) run's pipeline (G-C8).

        Unlike :meth:`enqueue` this does NOT call ``state_store.create`` — the run
        row already exists (it survived the crash). It just re-launches the
        pipeline task, which drives the run forward from PLANNING again. Safe to
        call only for runs the recovery driver classified as resumable. Re-running
        is idempotent at the recovery-driver level (the current-state guard stops
        a second resume), and here we guard against double-scheduling a run that
        already has a live task.

        F10: the check ("not already scheduled") and the claim (insert into
        ``self._tasks``) happen ATOMICALLY under ``_lifecycle_lock`` — both the
        ``asyncio.create_task`` and the dict insert are synchronous (no ``await``),
        so two concurrent ``resume()`` calls for the same run can never both pass
        the check and launch two pipeline tasks (TOCTOU closed).
        """
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
            if record.run_id in self._tasks:
                # Already scheduled — do not double-launch.
                return
            # create_task + insert are sync ⇒ check-and-claim is atomic w.r.t. the
            # lock; the task body only runs after we release it (next loop tick).
            task = asyncio.create_task(
                self._run_pipeline(record.run_id, record.command, dict(record.context)),
                name=f"resume-{record.run_id}",
            )
            self._tasks[record.run_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(record.run_id, None))

    async def approve(self, run_id: str, *, approver: str = "human") -> None:
        await self._signal(run_id, ApprovalDecision(action="approve", approver=approver))

    async def reject(self, run_id: str, *, reason: str | None = None) -> None:
        await self._signal(run_id, ApprovalDecision(action="reject", reason=reason))

    async def amend(self, run_id: str, *, instruction: str) -> None:
        await self._signal(run_id, ApprovalDecision(action="amend", instruction=instruction))

    async def _signal(self, run_id: str, decision: ApprovalDecision) -> None:
        queue = self._approval_queues.get(run_id)
        if queue is None:
            raise KeyError(f"run {run_id} is not awaiting approval")
        await queue.put(decision)

    # ------------------------------------------------------------------ #
    # Observability helpers (used by FastAPI routes + tests)
    # ------------------------------------------------------------------ #

    async def get_record(self, run_id: str) -> RunRecord | None:
        return await self._store.get(run_id)

    async def list_events(self, run_id: str) -> list[RunEvent]:
        return await self._store.list_events(run_id)

    # ------------------------------------------------------------------ #
    # Pipeline
    # ------------------------------------------------------------------ #

    async def _run_pipeline(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        sem = self._semaphore
        assert sem is not None
        try:
            async with sem:
                if self._lease_manager is None:
                    await self._pipeline_inner(run_id, command, context)
                else:
                    await self._run_pipeline_leased(run_id, command, context)
        except asyncio.CancelledError:
            # stop() path. Record cancellation if not already terminal.
            rec = await self._store.get(run_id)
            if rec and rec.state not in _TERMINAL:
                await self._store.update_state(run_id, RunState.CANCELLED, failure_reason="cancelled")
                await self._record_and_publish(run_id, ET.RUN_CANCELLED, {"reason": "cancelled"})
            raise

    async def _run_pipeline_leased(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        """Run the pipeline only while holding this run's HA lease (G-C8).

        Fail-closed: if another node already holds the lease, this node does not
        dispatch the run and leaves its state untouched (the lease holder owns
        it). If the lease is lost mid-run we stop dispatching that run. The lease
        is always released on exit if (and only if) this node acquired it.
        """
        manager = self._lease_manager
        assert manager is not None
        try:
            await manager.acquire_run(run_id, self._worker_id, self._lease_ttl_seconds)
        except LeaseLostError:
            # Another node holds this run — do NOT dispatch and do NOT mutate
            # state. Record the deferral on the run's ribbon for auditability.
            _logger.info(
                "run %s lease held elsewhere; %s declines to dispatch",
                run_id,
                self._worker_id,
            )
            await self._record_and_publish(
                run_id,
                ET.RUN_HANDOVER,
                {
                    "run_id": run_id,
                    "action": "lease_held_elsewhere",
                    "reason": f"lease not acquired by {self._worker_id}",
                },
            )
            return
        # F4: keep the lease alive for the whole run. The lease TTL is short (60s
        # default) but a run can block far longer on the HITL approval gate, so a
        # background task renews it every ~ttl/3. If renewal fails (LeaseLostError
        # — another node took over) we abort the pipeline fail-closed so two nodes
        # never run the same run. The renew task is always cancelled before
        # release, and the lease is released only if (and only if) we acquired it.
        renew_task = asyncio.create_task(self._renew_lease_loop(manager, run_id), name=f"renew-{run_id}")
        pipeline_task = asyncio.create_task(
            self._pipeline_inner(run_id, command, context), name=f"pipeline-{run_id}"
        )
        try:
            done, _pending = await asyncio.wait(
                {renew_task, pipeline_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if pipeline_task in done:
                # Pipeline finished (success or its own failure handling) first —
                # surface any exception it raised, then stop renewing.
                pipeline_task.result()
                return
            # The renew task completed first — it only ever completes by RAISING:
            # LeaseLostError (another node took over) or a transient backend error
            # (e.g. a locked SQLite / a PG connection blip). Either way we abort the
            # in-flight pipeline and fail the run CLOSED into a terminal state so it
            # is never left mid-EXECUTING (boot recovery re-picks it up later).
            await self._cancel_task(pipeline_task)
            try:
                renew_task.result()  # re-raises the renew-side exception
            except LeaseLostError:
                _logger.warning(
                    "run %s lease lost mid-run by %s; stopping dispatch",
                    run_id,
                    self._worker_id,
                )
                await self._fail_run_closed(run_id, "lease_lost", f"lease lost mid-run by {self._worker_id}")
            except Exception as exc:  # transient renew error — still fail-closed
                _logger.warning(
                    "run %s lease renew failed (%s) by %s; stopping dispatch",
                    run_id,
                    type(exc).__name__,
                    self._worker_id,
                )
                await self._fail_run_closed(
                    run_id,
                    "renew_error",
                    f"lease renew failed ({type(exc).__name__}) by {self._worker_id}",
                )
        finally:
            await self._cancel_task(renew_task)
            await self._cancel_task(pipeline_task)
            await manager.release(run_id, self._worker_id)

    async def _fail_run_closed(self, run_id: str, action: str, reason: str) -> None:
        """Fail-closed terminal transition + handover audit for a lost/abandoned lease.

        Moves a non-terminal run to ``FAILED`` (so it never lingers mid-EXECUTING)
        and records a ``run.handover`` event. Shared by the lease-lost and the
        transient-renew-error paths so neither leaves a run non-terminal+silent.
        """
        rec = await self._store.get(run_id)
        if rec is not None and rec.state not in _TERMINAL:
            await self._store.update_state(run_id, RunState.FAILED, failure_reason=action)
        await self._record_and_publish(
            run_id,
            ET.RUN_HANDOVER,
            {"run_id": run_id, "action": action, "reason": reason},
        )

    async def _renew_lease_loop(self, manager: LeaseManager, run_id: str) -> None:
        """Renew this run's lease every ~ttl/3 until cancelled (F4).

        Raises :class:`LeaseLostError` the moment a renewal is rejected (another
        node now owns the lease) so the caller can abort the pipeline fail-closed.
        Sleeps ``ttl/3`` (floored at 50ms for very small test TTLs) between
        renewals so a TTL is refreshed ~3× before it could expire — tolerating one
        missed renewal. For the 60s production TTL this is a 20s interval."""
        interval = max(0.05, self._lease_ttl_seconds / 3.0)
        while True:
            await asyncio.sleep(interval)
            # A LeaseLostError here propagates out of the task (the caller surfaces
            # it via renew_task.result()); any other error also propagates rather
            # than being swallowed (fail-fast, §B-8).
            await manager.renew(run_id, self._worker_id, self._lease_ttl_seconds)

    @staticmethod
    async def _cancel_task(task: asyncio.Task[None]) -> None:
        """Cancel ``task`` and await it, swallowing the CancelledError only.

        A task that already finished is a no-op. Any non-cancellation exception
        the task carried is intentionally ignored here (the primary result/error
        was already surfaced by the caller); we only guarantee the task is done so
        no orphan coroutine outlives the run."""
        if task.done():
            # Retrieve any stored exception so asyncio does not log a spurious
            # "Task exception was never retrieved" when both tasks finished in the
            # same wait batch (the primary result was already surfaced by caller).
            if not task.cancelled():
                task.exception()
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: S110 - see docstring
            # Intentional: the primary result/error was already surfaced by the
            # caller; here we only guarantee the task is finished (no orphan
            # coroutine). Mirrors the cancellation handling in ``stop()``.
            pass

    async def _pipeline_inner(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        amendments: list[str] = []
        # ``tenant_id`` is the metric label (legacy default ``"unknown"`` for runs
        # without a tenant). ``_raw_tenant`` preserves whether a tenant was
        # actually supplied so the cost gate can fail-closed on a *missing* tenant
        # when metering is active (finding 6: a tenant-less run must not silently
        # share a global "unknown" budget under a ledger).
        _raw_tenant = context.get("tenant_id")
        tenant_id: str = str(_raw_tenant) if _raw_tenant is not None else "unknown"
        # S8E: record pipeline start time for RUN_LATENCY histogram.
        _start_time = time.monotonic()

        def _observe_latency(terminal_state: str) -> None:
            """Record run latency at any terminal transition (S8E)."""
            elapsed = time.monotonic() - _start_time
            RUN_LATENCY.labels(tenant_id=tenant_id, terminal_state=terminal_state).observe(elapsed)

        while True:
            # 1. PLANNING
            await self._store.update_state(run_id, RunState.PLANNING)
            plan_context = dict(context)
            if amendments:
                plan_context.setdefault("amendments", []).extend(amendments)
            try:
                plan = await self._planner.plan(run_id=run_id, command=command, context=plan_context)
            except PlannerFailedError as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=str(exc))
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED_ADAPTER,
                    {"reason_class": "PlannerFailedError", "detail": str(exc)},
                )
                return
            except Exception as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(
                    run_id,
                    reason=f"planning_error: {type(exc).__name__}: {exc}",
                )
                return
            await self._record_and_publish(
                run_id,
                ET.PLAN_CREATED,
                {"plan_id": plan.id, "summary": plan.summary, "steps": len(plan.steps)},
            )
            await self._store.update_state(
                run_id,
                RunState.PLANNING,
                plan={"id": plan.id, "summary": plan.summary, "steps": len(plan.steps)},
            )

            # 2. COST QUOTA GATE (BDP_03 item 12) — fail-closed BEFORE the human
            # approval gate. An over-budget run must be REFUSED on its own; it
            # must never sit in AWAITING_APPROVAL consuming a human's attention on
            # work that can never run (§12.6 I1, no silent pass). Enforcing here
            # (not after APPROVED) also means a reviewer never approves a plan that
            # the budget will then reject. ``None`` ledger ⇒ no gate (legacy).
            gate = await self._quota_gate(_raw_tenant)
            if gate is not None:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=gate)
                return

            # 3. APPROVAL GATE
            if self._config.auto_approve:
                decision = ApprovalDecision(action="approve", approver="auto")
            else:
                await self._store.update_state(run_id, RunState.AWAITING_APPROVAL)
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_AWAITING_APPROVAL,
                    {"plan_id": plan.id},
                )
                # S8E: track pending HITL approvals in the backlog gauge.
                HITL_BACKLOG.labels(tenant_id=tenant_id).inc()
                try:
                    decision = await self._wait_for_decision(run_id)
                except TimeoutError:
                    HITL_BACKLOG.labels(tenant_id=tenant_id).dec()
                    _observe_latency(RunState.FAILED.value)
                    await self._fail(run_id, reason="approval_timeout")
                    return
                finally:
                    pass
                # S8E: resolution received — decrement backlog.
                HITL_BACKLOG.labels(tenant_id=tenant_id).dec()

            if decision.action == "reject":
                _observe_latency(RunState.CANCELLED.value)
                await self._store.update_state(
                    run_id,
                    RunState.CANCELLED,
                    approver=decision.approver,
                    failure_reason=decision.reason or "rejected",
                )
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_REJECTED,
                    {"plan_id": plan.id, "reason": decision.reason},
                )
                await self._record_and_publish(
                    run_id, ET.RUN_CANCELLED, {"reason": decision.reason or "rejected"}
                )
                return

            if decision.action == "amend":
                amendments.append(decision.instruction or "")
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_AMENDED,
                    {"plan_id": plan.id, "instruction": decision.instruction},
                )
                continue  # back to PLANNING

            # approve
            await self._store.update_state(run_id, RunState.APPROVED, approver=decision.approver)
            await self._record_and_publish(
                run_id, ET.PLAN_APPROVED, {"plan_id": plan.id, "approver": decision.approver}
            )

            # 4. EXECUTING — the quota gate already ran (step 2) before approval.
            await self._store.update_state(run_id, RunState.EXECUTING)

            try:
                results = await self._dispatcher.dispatch(run_id=run_id, plan=plan)
            except DispatcherResultMalformed as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"dispatch_result_malformed: {exc}")
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED_ADAPTER,
                    {"reason_class": "DispatcherResultMalformed", "detail": str(exc)},
                )
                return
            except Exception as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"dispatch_error: {type(exc).__name__}: {exc}")
                return
            await self._record_and_publish(
                run_id,
                ET.DISPATCHER_ROUTED,
                {"plan_id": plan.id, "results": _summarise_results(results)},
            )

            # 4. REPORTING
            await self._store.update_state(run_id, RunState.REPORTING)
            partial = bool(results.get("partial_failure"))
            if partial and self._config.fail_fast:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"sub_error: {results.get('failure_reason', 'sub_failed')}")
                return

            terminal = RunState.COMPLETED if not partial else RunState.FAILED
            _observe_latency(terminal.value)
            await self._store.update_state(
                run_id,
                terminal,
                failure_reason=results.get("failure_reason") if partial else None,
            )
            if partial:
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED,
                    {
                        "reason": results.get("failure_reason", "sub_failed"),
                        "results": _summarise_results(results),
                    },
                )
            else:
                await self._record_and_publish(
                    run_id,
                    ET.RUN_COMPLETED,
                    {"results": _summarise_results(results)},
                )
            return

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _quota_gate(self, raw_tenant_id: object | None) -> str | None:
        """Decide whether this run may proceed past the cost gate (BDP_03 item 12).

        ``raw_tenant_id`` is the *unparsed* ``context["tenant_id"]`` value (``None``
        when the key was absent). Returns the run's ``failure_reason`` when the run
        must be REFUSED, or ``None`` when it may proceed:

        * No ledger attached ⇒ ``None`` (legacy callers unaffected, no gate).
        * Missing tenant (``None``) **with a ledger attached** ⇒ ``"invalid_tenant"``.
          A tenant-less run must not silently share a global "unknown" budget under
          an active meter (finding 6, L465) — deny-by-default.
        * ``tenant_id`` fails the :class:`TenantId` regex (empty, uppercase,
          leading hyphen, >63 chars, control/path chars, non-str) ⇒
          ``"invalid_tenant"``. For a **deny-by-default** budget control (A-2 #2,
          §B-8) an unidentifiable tenant must FAIL CLOSED — never skip the meter
          and run unbudgeted. Earlier code returned "allow" here, which let any
          programmatic/re-enqueue caller bypass the cap entirely (findings 1 & 6).
        * Over the daily/monthly cap ⇒ ``"quota_exceeded"``.
        * Otherwise ⇒ ``None``.

        The budget decision itself is never re-implemented here: it delegates to
        the single source of truth, :meth:`CostLedger.enforce_or_raise`.

        Concurrency note (edge case 12.7) — HONEST RESIDUAL, not a mitigated gap:
        this pre-flight gate (and the per-step ``SubAgent`` gate) is a pure READ,
        so two same-tenant runs admitted in the same instant both observe the same
        pre-spend total and may together overshoot the cap. The present bound is
        ONLY already-recorded (external / prior-run / cross-run) spend: in-run
        self-inflicted spend is NOT recorded live, because the sole per-call
        recorder (``ModelCascadeRouter.record_call`` → ``CostLedger.record``) is
        not yet invoked from the live dispatch path, so a run's own model calls do
        not grow the ledger total mid-run and the per-step gate cannot fire on
        self-inflicted overspend. A strict atomic admission reservation is
        intentionally NOT shipped: per-run spend is unknown at admission (it is
        metered per model-call), so any reserved amount would be arbitrary. This
        is a documented residual; do not read it as defence-in-depth the code does
        not provide (§B-8 fail-fast, §12.6 I1).
        """
        if self._cost_ledger is None:
            return None
        from secugent.core.tenancy import TenantId as _TenantId

        if raw_tenant_id is None:
            _logger.warning("quota gate: run has no tenant_id — refusing fail-closed")
            return "invalid_tenant"
        try:
            tid = _TenantId(str(raw_tenant_id))
        except ValueError:
            # Deny-by-default: a tenant we cannot identify cannot be metered, so
            # the only safe verdict is to refuse the run (fail-closed), not to
            # grant it unmetered execution (findings 1 & 6, §12.6 I1).
            _logger.warning(
                "quota gate: malformed tenant_id %r — refusing run fail-closed",
                raw_tenant_id,
            )
            return "invalid_tenant"
        # A non-None ledger is only ever injected by the Enterprise wiring, where
        # ``secugent.cost`` IS installed — so this lazy import never runs in the
        # public Core (which keeps ``cost_ledger is None`` and returned above).
        from secugent.cost.accounting import QuotaExceededError as _QuotaExceededError

        try:
            await self._cost_ledger.enforce_or_raise(tid)
        except _QuotaExceededError:
            return "quota_exceeded"
        return None

    async def _wait_for_decision(self, run_id: str) -> ApprovalDecision:
        queue: asyncio.Queue[ApprovalDecision] = asyncio.Queue()
        self._approval_queues[run_id] = queue
        try:
            return await asyncio.wait_for(queue.get(), timeout=self._config.approval_timeout_sec)
        finally:
            self._approval_queues.pop(run_id, None)

    async def _fail(self, run_id: str, *, reason: str) -> None:
        await self._store.update_state(run_id, RunState.FAILED, failure_reason=reason)
        await self._record_and_publish(run_id, ET.RUN_FAILED, {"reason": reason})
        _logger.error("run %s failed: %s", run_id, reason)

    async def _record_and_publish(self, run_id: str, topic: str, payload: dict[str, Any]) -> None:
        event = RunEvent(run_id=run_id, topic=topic, payload=payload)
        await self._store.append_event(run_id, event)
        try:
            await self._publish(run_id, topic, payload)
        except Exception:  # pragma: no cover - defensive
            _logger.exception("event publish failed for run=%s topic=%s", run_id, topic)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _noop_publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
    return None


_TERMINAL = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}


def _summarise_results(results: dict[str, Any]) -> dict[str, Any]:
    # Keep payloads small for events.
    out = {k: v for k, v in results.items() if k in ("partial_failure", "failure_reason")}
    subs = results.get("subs") or {}
    out["subs"] = (
        {k: {"status": v.get("status"), "completed_steps": v.get("completed_steps")} for k, v in subs.items()}
        if isinstance(subs, dict)
        else {}
    )
    return out
