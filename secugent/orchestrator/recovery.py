# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — startup recovery of orphaned runs.

The orchestrator inspects runs whose state ∈ {PENDING, PLANNING,
AWAITING_APPROVAL, APPROVED, EXECUTING} but whose lease has expired (or was
never set, in fresh-DB cases). For each, it makes a deterministic decision:

* ``resume`` — safe to re-enqueue. PLANNING is idempotent (HEAD calls re-run
  cleanly), AWAITING_APPROVAL just resumes the wait, PENDING has no side
  effects yet.
* ``fail_worker_lost`` — DISPATCHING/EXECUTING involve external side effects
  (file writes, network calls). We can't safely retry without risk of
  duplication, so we mark the run FAILED with reason ``worker_lost``.
* ``skip`` — already terminal; nothing to do.

Every decision is recorded as a ``run.handover`` event so the audit log
shows the exact reasoning.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any, Literal

from secugent.orchestrator.events import OrchestratorEventType as ET
from secugent.orchestrator.lease import LeaseLostError, LeaseManager
from secugent.orchestrator.state import (
    RunRecord,
    RunState,
    RunStateStore,
)

__all__ = [
    "EnqueueFn",
    "PublishFn",
    "RecoveryDecision",
    "RecoveryReport",
    "decide_recovery_action",
    "plan_recovery",
    "run_recovery",
]

_logger = logging.getLogger("secugent.orchestrator.recovery")

# Boot-recovery driver callbacks.
EnqueueFn = Callable[[RunRecord], Awaitable[None]]
"""``async (record) -> None`` — re-enqueue a resumable run for re-execution."""

PublishFn = Callable[[str, str, dict[str, Any]], Awaitable[None]]
"""``async (run_id, topic, payload) -> None`` — emit a run-ribbon event."""


_RESUMABLE_STATES = {
    RunState.PENDING,
    RunState.PLANNING,
    RunState.AWAITING_APPROVAL,
}

# These states involve side effects that may have already started; re-doing
# them without coordination risks duplication.
_UNSAFE_STATES = {
    RunState.APPROVED,
    RunState.EXECUTING,
    RunState.REPORTING,
}

_TERMINAL_STATES = {
    RunState.COMPLETED,
    RunState.FAILED,
    RunState.CANCELLED,
}


@dataclass(frozen=True)
class RecoveryDecision:
    run_id: str
    action: Literal["resume", "fail_worker_lost", "skip"]
    reason: str


def decide_recovery_action(record: RunRecord) -> RecoveryDecision:
    """Pure function — given a stale run record, return the handover action.

    Pure (no IO) so it's easy to unit test and replays deterministically on
    the same input.
    """
    if record.state in _TERMINAL_STATES:
        return RecoveryDecision(
            run_id=record.run_id,
            action="skip",
            reason=f"already terminal ({record.state.value})",
        )
    if record.state in _RESUMABLE_STATES:
        return RecoveryDecision(
            run_id=record.run_id,
            action="resume",
            reason=f"safe to resume from {record.state.value}",
        )
    if record.state in _UNSAFE_STATES:
        return RecoveryDecision(
            run_id=record.run_id,
            action="fail_worker_lost",
            reason=(
                f"state {record.state.value} involves side effects that may have started; refusing to retry"
            ),
        )
    return RecoveryDecision(
        run_id=record.run_id,
        action="fail_worker_lost",
        reason=f"unrecognised state {record.state.value}",
    )


def plan_recovery(stale_records: Iterable[RunRecord]) -> list[RecoveryDecision]:
    """Decide on a batch of stale records — deterministic ordering by run_id."""
    return sorted(
        (decide_recovery_action(r) for r in stale_records),
        key=lambda d: d.run_id,
    )


@dataclass(frozen=True)
class RecoveryReport:
    """Result of one :func:`run_recovery` pass.

    Each tuple is sorted by ``run_id`` so the report is deterministic and so two
    idempotent passes produce comparable values. Entries reflect *applied*
    outcomes (after the current-state idempotency guard), not the raw plan: a run
    the plan wanted to resume but that is already terminal lands in ``skipped``.
    """

    resumed: tuple[str, ...]
    failed: tuple[str, ...]
    skipped: tuple[str, ...]


async def run_recovery(
    open_runs: Iterable[RunRecord],
    *,
    state_store: RunStateStore,
    enqueue: EnqueueFn,
    publish_event: PublishFn,
    lease_manager: LeaseManager | None = None,
    worker_id: str = "node-local",
    lease_ttl_seconds: int = 60,
) -> RecoveryReport:
    """Boot-time recovery driver — re-enqueue / fail-out / skip orphaned runs.

    Calls :func:`plan_recovery` for the deterministic decision list, then applies
    each decision **idempotently**: before acting it re-reads the run's *current*
    persisted state and only acts if that state still warrants the action. Re-
    running with the same ``open_runs`` therefore causes zero duplicate enqueue
    and zero duplicate state transitions (see the RECOVERY-IDEMPOTENCY invariant
    in docs/specs/2026-06-06-stage2-gc8-recovery-lease-ha.md).

    * ``resume`` — if still resumable, ``enqueue(record)`` and emit ``run.handover``.
    * ``fail_worker_lost`` — if still unsafe (non-terminal), transition to FAILED
      with ``failure_reason="worker_lost"`` and emit ``run.handover``.
    * ``skip`` (or guard miss) — no-op, no event.

    F9 (LEADER-SINGLETON): when ``lease_manager`` is set (HA multi-node), a run
    whose lease is currently held by ANOTHER worker is SKIPPED with NO state
    mutation — a booting node B must never fail-out or resume node A's live,
    lease-held run. We probe ownership via ``acquire_run``: a :class:`LeaseLostError`
    means another node owns it (skip); on success we immediately release so the
    resumed run's own pipeline re-acquires the lease cleanly. Single-node
    (``lease_manager is None``) keeps the original behaviour unchanged.

    :raises KeyError: if ``state_store.update_state`` is asked to mutate an
        unknown run (fail fast — the caller passed a record the store dropped).
    """
    resumed: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []

    for decision in plan_recovery(open_runs):
        run_id = decision.run_id
        current = await state_store.get(run_id)
        if current is None:
            # Record vanished between snapshot and apply — nothing safe to do.
            skipped.append(run_id)
            continue

        # F9: in HA mode, never touch a run another live node still owns.
        if (
            lease_manager is not None
            and decision.action in ("resume", "fail_worker_lost")
            and not await _claimable(lease_manager, run_id, worker_id, lease_ttl_seconds)
        ):
            skipped.append(run_id)
            continue

        if decision.action == "resume" and current.state in _RESUMABLE_STATES:
            await enqueue(current)
            await _emit_handover(publish_event, decision)
            resumed.append(run_id)
        elif decision.action == "fail_worker_lost" and current.state in _UNSAFE_STATES:
            await state_store.update_state(run_id, RunState.FAILED, failure_reason="worker_lost")
            await _emit_handover(publish_event, decision)
            failed.append(run_id)
        else:
            # decision.action == "skip", or the current state no longer matches
            # the planned action (already advanced / terminal) — idempotent no-op.
            skipped.append(run_id)

    return RecoveryReport(
        resumed=tuple(sorted(resumed)),
        failed=tuple(sorted(failed)),
        skipped=tuple(sorted(skipped)),
    )


async def _claimable(lease_manager: LeaseManager, run_id: str, worker_id: str, ttl_seconds: int) -> bool:
    """Return whether this worker may safely act on ``run_id`` (F9).

    Probes the lease by attempting to acquire it: a :class:`LeaseLostError` means
    another non-expired node holds it ⇒ NOT claimable (recovery must skip). On a
    successful acquire we release immediately — recovery only needed to confirm
    ownership; a resumed run's own pipeline re-acquires the lease when it runs."""
    try:
        await lease_manager.acquire_run(run_id, worker_id, ttl_seconds)
    except LeaseLostError:
        return False
    await lease_manager.release(run_id, worker_id)
    return True


async def _emit_handover(publish_event: PublishFn, decision: RecoveryDecision) -> None:
    """Append a ``run.handover`` ribbon event for a non-skip recovery decision."""
    payload = {
        "run_id": decision.run_id,
        "action": decision.action,
        "reason": decision.reason,
    }
    try:
        await publish_event(decision.run_id, ET.RUN_HANDOVER, payload)
    except Exception:  # pragma: no cover - defensive, mirrors runner._record_and_publish
        _logger.exception(
            "run.handover publish failed for run=%s action=%s",
            decision.run_id,
            decision.action,
        )
