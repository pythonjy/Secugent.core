# SPDX-License-Identifier: Apache-2.0
"""Task Dispatcher — routes approved plan steps to SUB agents.

Per Flowchart §1 + §4 + §6, the dispatcher groups steps by their assigned SUB
actor and invokes each SUB on its slice. The dispatcher does NOT re-run
oversight or risk — that's the SUB's job. It DOES verify that:

1. A plan-level approval covers every step it's about to dispatch.
2. Each SUB is created with that approval id so it can consume it.

Steps without an explicit ``assigned_subs`` entry fall back to ``step.actor``.

Concurrency (#5 Dispatcher 병렬화)
----------------------------------
Each ``actor`` group is independent — it processes only its own slice of steps
and shares no mutable dispatcher state. Approval ``consume`` is serialised by
the SQLite store's ``RLock`` and event ``append`` likewise, so the groups can
run concurrently in a :class:`~concurrent.futures.ThreadPoolExecutor` without
corrupting the audit hash chain. The ``envelope_hash`` is passed *explicitly*
to each worker's :data:`SubFactory` call (never via a contextvar) so the
thread boundary stays fail-closed (SG-20260603-01). The merged
:class:`DispatcherResult` is deterministic: results are keyed by ``actor`` and
therefore independent of the non-deterministic completion order.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from secugent.core.approval import ApprovalService
from secugent.core.contracts import Approval, ApprovalError, Event, Plan, Step
from secugent.core.event_store import EventStore
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.tenancy import TenantId

if TYPE_CHECKING:  # pragma: no cover - typing-only import, no runtime dependency.
    # ``secugent.agents.sub_agent`` eagerly imports the BSL-1.1 Enterprise quota
    # tier (``secugent.cost.accounting``) for token-budget enforcement and is NOT
    # shipped in the public OSS Core wheel. The dispatcher references ``SubAgent``
    # / ``SubAgentResult`` only in type annotations (and in the ``SubFactory``
    # alias below, as a string forward reference), so importing the module at
    # load time is unnecessary and would break standalone import of Core
    # (``ModuleNotFoundError: secugent.agents.sub_agent``) plus leak the tier
    # (open-core boundary I2/I8). The concrete SUB is injected via ``SubFactory``.
    from secugent.agents.sub_agent import SubAgent, SubAgentResult

_LEGACY_TENANT: TenantId = TenantId("legacy-default")

#: Conservative default worker count for concurrent SUB execution.
DEFAULT_MAX_WORKERS = 4

__all__ = [
    "DEFAULT_MAX_WORKERS",
    "Dispatcher",
    "DispatcherError",
    "DispatcherResult",
    "SubFactory",
]


class DispatcherError(RuntimeError):
    """Raised when a SUB worker raises an unexpected (non-domain) exception.

    Domain outcomes (hard_block, rejected, tool_failed, approval_failed) are
    carried inside :class:`SubAgentResult` and never surface as this error.
    A ``DispatcherError`` means a worker raised — e.g. the durable event store
    went down (``HardBlockException``) — and per §B-8 the dispatcher must NOT
    swallow it: it is logged to the audit trail and re-raised (fail-closed).
    """


SubFactory = Callable[[str, str, "str | None", "OversightEngine", str], "SubAgent"]
"""Signature ``(actor, plan_approval_id, envelope_hash, oversight,
regulations_version) -> SubAgent``.

``oversight`` and ``regulations_version`` are threaded explicitly per dispatch
(never via a contextvar — same fail-closed boundary as ``envelope_hash``,
SG-20260603-01) so each run's SUB workers read that run's effective tenant
REGULATIONS (G-H4) and stamp the effective policy version onto audit events."""


@dataclass
class DispatcherResult:
    plan_id: str
    sub_results: dict[str, SubAgentResult] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return bool(self.sub_results) and all(r.succeeded for r in self.sub_results.values())


class Dispatcher:
    def __init__(
        self,
        *,
        event_store: EventStore,
        approval_service: ApprovalService,
        max_workers: int = DEFAULT_MAX_WORKERS,
    ) -> None:
        if max_workers < 1:
            # Fail fast (§B-8): a non-positive pool size is a programming error.
            raise ValueError(f"max_workers must be >= 1, got {max_workers}")
        self._events = event_store
        self._approvals = approval_service
        self._max_workers = max_workers

    def dispatch(
        self,
        plan: Plan,
        approval: Approval,
        *,
        sub_factory: SubFactory,
        envelope_hash: str | None = None,
        oversight: OversightEngine,
        regulations_version: str,
    ) -> DispatcherResult:
        # Verify the approval is granted & covers the plan up front (per-step
        # verification still happens inside the SUB). Runs on the calling thread
        # before any worker starts (state-diagram invariant 1).
        self._sanity_check_approval(plan, approval)

        # Deterministic grouping: preserve plan.steps order per actor.
        groups: dict[str, list[Step]] = {}
        for step in plan.steps:
            actor = plan.assigned_subs.get(step.id, step.actor)
            groups.setdefault(actor, []).append(step)

        self._emit(
            "dispatch.started",
            run_id=plan.run_id,
            tenant_id=plan.tenant_id,
            payload={
                "plan_id": plan.id,
                "approval_id": approval.id,
                "groups": {a: [s.id for s in steps] for a, steps in groups.items()},
            },
        )

        results = self._run_groups(
            plan,
            approval,
            groups,
            sub_factory=sub_factory,
            envelope_hash=envelope_hash,
            oversight=oversight,
            regulations_version=regulations_version,
        )

        self._emit(
            "dispatch.completed",
            run_id=plan.run_id,
            tenant_id=plan.tenant_id,
            payload={
                "plan_id": plan.id,
                "succeeded": all(r.succeeded for r in results.values()),
            },
        )
        return DispatcherResult(plan_id=plan.id, sub_results=results)

    # ------------------------------------------------------------------ #
    # Concurrent group execution
    # ------------------------------------------------------------------ #

    def _run_groups(
        self,
        plan: Plan,
        approval: Approval,
        groups: dict[str, list[Step]],
        *,
        sub_factory: SubFactory,
        envelope_hash: str | None,
        oversight: OversightEngine,
        regulations_version: str,
    ) -> dict[str, SubAgentResult]:
        """Run each actor group, concurrently when there is more than one.

        Determinism boundary: completion order is non-deterministic but the
        returned mapping is keyed by actor, so the merged result is identical
        regardless of scheduling (spec invariant I1). A single group runs
        inline (no pool overhead) and is exactly equivalent to the old
        sequential path (I2).

        ``oversight`` is the per-run engine (G-H4) shared across this run's
        workers. The workers only ``evaluate`` (never mutate ``_patches``), and
        STEER writes to the SAME live engine are serialised: ``add_session_patch``
        swaps the patch list copy-on-write under a lock while the matchers read a
        lock-free per-evaluation snapshot. Concurrent group execution therefore
        stays race-free even while a STEER constraint is being added (spec
        invariant 2; SG-20260606-10).
        """
        if len(groups) <= 1:
            results: dict[str, SubAgentResult] = {}
            for actor, steps in groups.items():
                results[actor] = self._run_one(
                    actor, steps, approval, sub_factory, envelope_hash, oversight, regulations_version
                )
            return results

        worker_count = min(self._max_workers, len(groups))
        results = {}
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix=f"sub-{plan.run_id}") as pool:
            futures: dict[Future[SubAgentResult], str] = {
                pool.submit(
                    self._run_one,
                    actor,
                    steps,
                    approval,
                    sub_factory,
                    envelope_hash,
                    oversight,
                    regulations_version,
                ): actor
                for actor, steps in groups.items()
            }
            # Collect by actor key; completion order does not affect the merge.
            for future, actor in futures.items():
                results[actor] = self._collect(future, actor, plan)
        return results

    def _run_one(
        self,
        actor: str,
        steps: list[Step],
        approval: Approval,
        sub_factory: SubFactory,
        envelope_hash: str | None,
        oversight: OversightEngine,
        regulations_version: str,
    ) -> SubAgentResult:
        """Construct and run one SUB. ``envelope_hash``, ``oversight`` and
        ``regulations_version`` are passed explicitly to the factory (not via a
        contextvar) so the worker thread re-verifies the approval's envelope
        binding (I3) and reads the correct per-run policy + version (G-H4)."""
        sub = sub_factory(actor, approval.id, envelope_hash, oversight, regulations_version)
        return sub.run(steps)

    def _collect(self, future: Future[SubAgentResult], actor: str, plan: Plan) -> SubAgentResult:
        """Resolve a worker future, converting an unexpected raise into a
        logged, re-raised :class:`DispatcherError` (I6 — never swallow)."""
        try:
            return future.result()
        except BaseException as exc:  # noqa: BLE001 — re-raised below, not swallowed
            self._emit(
                "dispatch.sub_failed",
                run_id=plan.run_id,
                tenant_id=plan.tenant_id,
                payload={
                    "plan_id": plan.id,
                    "actor": actor,
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                severity="error",
            )
            raise DispatcherError(
                f"SUB worker for actor {actor!r} raised {type(exc).__name__}: {exc}"
            ) from exc

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _sanity_check_approval(self, plan: Plan, approval: Approval) -> None:
        if approval.status not in ("approved",):
            raise ApprovalError(
                f"dispatch refused: approval {approval.id} not granted (status={approval.status})"
            )
        scope = approval.scope
        if scope.run_id != plan.run_id:
            raise ApprovalError("dispatch: approval.scope.run_id != plan.run_id")
        if scope.plan_id is not None and scope.plan_id != plan.id:
            raise ApprovalError("dispatch: approval.scope.plan_id != plan.id")
        if not scope.step_ids:
            raise ApprovalError("dispatch: approval scope has no step_ids")
        plan_step_ids = {s.id for s in plan.steps}
        unknown = set(scope.step_ids) - plan_step_ids
        if unknown:
            raise ApprovalError(f"dispatch: approval scope includes unknown step ids {sorted(unknown)}")

    def _emit(
        self,
        event_type: str,
        *,
        run_id: str,
        payload: dict[str, Any] | None = None,
        severity: str = "info",
        tenant_id: TenantId | None = None,
    ) -> None:
        self._events.append_event(
            Event(
                tenant_id=tenant_id or _LEGACY_TENANT,
                actor="dispatcher",
                type=event_type,
                severity=severity,
                run_id=run_id,
                payload=payload or {},
            )
        )
