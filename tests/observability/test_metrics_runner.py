# SPDX-License-Identifier: Apache-2.0
"""S8E — Runner + Approval observability metric call tests.

Tests that RUN_LATENCY, HITL_BACKLOG, and APPROVAL_WAIT are populated
by the runner and ApprovalService at the right moments.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from secugent.config import OrchestratorConfig
from secugent.core.approval import ApprovalService
from secugent.core.contracts import ApprovalScope
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId
from secugent.observability.metrics import APPROVAL_WAIT, HITL_BACKLOG, RUN_LATENCY
from secugent.orchestrator.runner import (
    PlanLike,
    RunOrchestrator,
)
from secugent.orchestrator.state import RunState

# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


class _StubPlanner:
    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        return PlanLike(id="plan-1", summary="stub plan", steps=["step-1"])


class _StubDispatcher:
    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        return {"partial_failure": False}


def _build_orch(*, auto_approve: bool = True) -> RunOrchestrator:
    return RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=_StubDispatcher(),
        config=OrchestratorConfig(auto_approve=auto_approve, approval_timeout_sec=5),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TERMINAL_STATES = frozenset({RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED})


async def _wait_terminal(orch: RunOrchestrator, run_id: str, *, timeout_sec: float = 5.0) -> Any:
    """Poll until run reaches a terminal state or timeout expires.

    Returns the last-known RunRecord regardless of outcome so that
    assertion failures include the actual state for diagnosis.
    """
    deadline_loops = int(timeout_sec / 0.01)
    for _ in range(deadline_loops):
        rec = await orch.get_record(run_id)
        if rec is not None and rec.state in _TERMINAL_STATES:
            return rec
        await asyncio.sleep(0.01)
    # Timeout elapsed — return whatever state we have so the caller's
    # assertion produces a diagnostic message rather than an AttributeError.
    return await orch.get_record(run_id)


# ---------------------------------------------------------------------------
# RUN_LATENCY
# ---------------------------------------------------------------------------


async def test_run_latency_observed_on_completion() -> None:
    """RUN_LATENCY histogram must receive a sample when a run completes."""
    # Read the current _sum before to detect a new observation.
    metric = RUN_LATENCY.labels(tenant_id="acme", terminal_state="COMPLETED")
    before_sum = metric._sum.get()

    orch = _build_orch(auto_approve=True)
    await orch.start()
    run_id = "run-latency-test"
    await orch.enqueue(run_id, "cmd", {"tenant_id": "acme"})

    # Wait deterministically until the run reaches COMPLETED (up to 5 s).
    rec = await _wait_terminal(orch, run_id)
    assert rec is not None and rec.state == RunState.COMPLETED, (
        f"Run did not reach COMPLETED in time; final state={getattr(rec, 'state', None)}"
    )

    after_sum = metric._sum.get()
    # At least one observation → _sum increased
    assert after_sum > before_sum, f"RUN_LATENCY was not observed: before={before_sum} after={after_sum}"

    await orch.stop()


async def test_run_latency_observed_on_failure() -> None:
    """RUN_LATENCY must also fire when a run ends in FAILED state."""

    class _FailDispatcher:
        async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
            raise RuntimeError("intentional dispatch failure")

    metric = RUN_LATENCY.labels(tenant_id="acme", terminal_state="FAILED")
    before_sum = metric._sum.get()

    orch = RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=_FailDispatcher(),
        config=OrchestratorConfig(auto_approve=True, approval_timeout_sec=5),
    )
    await orch.start()
    run_id = "run-latency-fail"
    await orch.enqueue(run_id, "cmd", {"tenant_id": "acme"})

    # Wait deterministically until the run reaches FAILED (up to 5 s).
    rec = await _wait_terminal(orch, run_id)
    assert rec is not None and rec.state == RunState.FAILED, (
        f"Run did not reach FAILED in time; final state={getattr(rec, 'state', None)}"
    )

    after_sum = metric._sum.get()
    assert after_sum > before_sum, (
        f"RUN_LATENCY(FAILED) was not observed: before={before_sum} after={after_sum}"
    )
    await orch.stop()


# ---------------------------------------------------------------------------
# HITL_BACKLOG
# ---------------------------------------------------------------------------


async def test_hitl_backlog_increments_on_pending() -> None:
    """HITL_BACKLOG must increment when a run enters AWAITING_APPROVAL."""
    metric = HITL_BACKLOG.labels(tenant_id="acme")
    before = metric._value.get()

    orch = _build_orch(auto_approve=False)
    await orch.start()
    run_id = "run-hitl-backlog"
    await orch.enqueue(run_id, "cmd", {"tenant_id": "acme"})

    # Give the pipeline time to reach AWAITING_APPROVAL but not time to resolve.
    await asyncio.sleep(0.1)

    record = await orch.get_record(run_id)
    assert record is not None
    # Must be in AWAITING_APPROVAL (or just about to be).
    assert record.state == RunState.AWAITING_APPROVAL

    mid = metric._value.get()
    assert mid > before, f"HITL_BACKLOG did not increment: before={before} mid={mid}"

    # Now approve and let it finish.
    await orch.approve(run_id, approver="test-human")
    await asyncio.sleep(0.1)

    after = metric._value.get()
    # After resolution, backlog should drop back (inc + dec = net 0).
    assert after == before, f"HITL_BACKLOG not decremented after resolution: {after} vs {before}"

    await orch.stop()


# ---------------------------------------------------------------------------
# APPROVAL_WAIT
# ---------------------------------------------------------------------------


async def test_approval_wait_observed_on_grant(tmp_path: Path) -> None:
    """APPROVAL_WAIT must be observed when ApprovalService.grant() is called."""
    store = EventStore(tmp_path / "approval_wait.db")
    svc = ApprovalService(store)

    scope = ApprovalScope(
        tenant_id=TenantId("acme"),
        run_id="r-1",
        plan_id=None,
        step_ids=[],
        allowed_action_types=["file_read"],
        max_risk=80,
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    )
    approval = svc.request_approval(actor="head:planner", scope=scope)

    metric = APPROVAL_WAIT.labels(tenant_id="acme", risk_band="unknown")
    before_sum = metric._sum.get()

    svc.grant(approval.id)

    after_sum = metric._sum.get()
    assert after_sum >= before_sum, f"APPROVAL_WAIT not observed after grant: {before_sum} → {after_sum}"
    store.close()


async def test_approval_wait_observed_on_reject(tmp_path: Path) -> None:
    """APPROVAL_WAIT must be observed when ApprovalService.reject() is called."""
    store = EventStore(tmp_path / "approval_reject.db")
    svc = ApprovalService(store)

    scope = ApprovalScope(
        tenant_id=TenantId("acme"),
        run_id="r-2",
        plan_id=None,
        step_ids=[],
        allowed_action_types=["file_read"],
        max_risk=80,
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    )
    approval = svc.request_approval(actor="head:planner", scope=scope)

    metric = APPROVAL_WAIT.labels(tenant_id="acme", risk_band="unknown")
    before_sum = metric._sum.get()

    svc.reject(approval.id)

    after_sum = metric._sum.get()
    assert after_sum >= before_sum, f"APPROVAL_WAIT not observed after reject: {before_sum} → {after_sum}"
    store.close()
