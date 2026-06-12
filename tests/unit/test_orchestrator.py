# SPDX-License-Identifier: Apache-2.0
"""Unit tests for RunOrchestrator (12 cases per master prompt §2.4)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from secugent.config import OrchestratorConfig
from secugent.orchestrator.runner import (
    DispatcherProtocol,
    OrchestratorStoppedError,
    PlanLike,
    PlannerProtocol,
    RunOrchestrator,
)
from secugent.orchestrator.state import InMemoryRunStateStore, RunState

# ---------------------------------------------------------------------------
# Stub planner / dispatcher
# ---------------------------------------------------------------------------


class _StubPlanner:
    def __init__(self) -> None:
        self.calls = 0

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        self.calls += 1
        amendments = context.get("amendments", [])
        return PlanLike(
            id=f"plan_{self.calls}",
            summary=f"{command} ({len(amendments)} amendments)",
            steps=[{"id": "s1"}, {"id": "s2"}],
        )


class _FailingPlanner:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        raise self.exc


class _StubDispatcher:
    def __init__(self, *, sleep_for: float = 0.0) -> None:
        self.calls = 0
        self.sleep_for = sleep_for

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        self.calls += 1
        if self.sleep_for > 0:
            await asyncio.sleep(self.sleep_for)
        return {
            "subs": {
                "sub:r": {"status": "completed", "completed_steps": len(plan.steps)},
            },
        }


class _FailingDispatcher:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        raise self.exc


class _PartialDispatcher:
    """Returns partial failure (some SUBs failed)."""

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        return {
            "partial_failure": True,
            "failure_reason": "sub:writer crashed",
            "subs": {
                "sub:reader": {"status": "completed", "completed_steps": 1},
                "sub:writer": {"status": "failed", "completed_steps": 0},
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_orch(
    *,
    auto_approve: bool = True,
    approval_timeout_sec: int = 600,
    max_concurrent_runs: int = 10,
    fail_fast: bool = True,
    planner: PlannerProtocol | None = None,
    dispatcher: DispatcherProtocol | None = None,
    events_sink: list[tuple[str, str, dict[str, Any]]] | None = None,
) -> RunOrchestrator:
    async def _publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        if events_sink is not None:
            events_sink.append((run_id, topic, payload))

    orch = RunOrchestrator(
        planner=planner or _StubPlanner(),
        dispatcher=dispatcher or _StubDispatcher(),
        state_store=InMemoryRunStateStore(),
        config=OrchestratorConfig(
            auto_approve=auto_approve,
            approval_timeout_sec=approval_timeout_sec,
            max_concurrent_runs=max_concurrent_runs,
            fail_fast=fail_fast,
        ),
        publish_event=_publish,
    )
    await orch.start()
    return orch


async def _wait_for_terminal(orch: RunOrchestrator, run_id: str, *, timeout: float = 5.0) -> RunState:  # noqa: ASYNC109 — test helper deadline pattern, not a production timeout param
    terminal = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        rec = await orch.get_record(run_id)
        if rec is not None and rec.state in terminal:
            return rec.state
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(
                f"run {run_id} did not reach terminal state within {timeout}s "
                f"(last_state={rec.state if rec else 'missing'})"
            )
        await asyncio.sleep(0.02)


async def _wait_for_state(
    orch: RunOrchestrator,
    run_id: str,
    state: RunState,
    *,
    timeout: float = 5.0,  # noqa: ASYNC109 — test helper deadline pattern, not a production timeout param
) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        rec = await orch.get_record(run_id)
        if rec is not None and rec.state is state:
            return
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(
                f"run {run_id} did not reach {state} within {timeout}s "
                f"(last_state={rec.state if rec else 'missing'})"
            )
        await asyncio.sleep(0.02)


# ---------------------------------------------------------------------------
# 1. Normal auto-approve path
# ---------------------------------------------------------------------------


async def test_auto_approve_full_transition() -> None:
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = await _make_orch(auto_approve=True, events_sink=events)
    try:
        await orch.enqueue("r1", "ingest", {})
        state = await _wait_for_terminal(orch, "r1")
        assert state is RunState.COMPLETED
        topics = [topic for run_id, topic, _ in events if run_id == "r1"]
        assert "command.received" in topics
        assert "plan.created" in topics
        assert "plan.approved" in topics
        assert "dispatcher.routed" in topics
        assert "run.completed" in topics
        # PHASE invariant: no PLAN_REJECTED / RUN_FAILED
        assert "plan.rejected" not in topics
        assert "run.failed" not in topics
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 2. Manual approval pauses at AWAITING_APPROVAL
# ---------------------------------------------------------------------------


async def test_manual_approval_pauses() -> None:
    orch = await _make_orch(auto_approve=False)
    try:
        await orch.enqueue("r2", "ingest", {})
        await _wait_for_state(orch, "r2", RunState.AWAITING_APPROVAL)
        await asyncio.sleep(0.05)
        rec = await orch.get_record("r2")
        assert rec is not None
        assert rec.state is RunState.AWAITING_APPROVAL
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 3. Approve unblocks pipeline
# ---------------------------------------------------------------------------


async def test_approve_resumes_pipeline() -> None:
    orch = await _make_orch(auto_approve=False)
    try:
        await orch.enqueue("r3", "ingest", {})
        await _wait_for_state(orch, "r3", RunState.AWAITING_APPROVAL)
        await orch.approve("r3", approver="alice")
        state = await _wait_for_terminal(orch, "r3")
        assert state is RunState.COMPLETED
        rec = await orch.get_record("r3")
        assert rec is not None
        assert rec.approver == "alice"
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 4. Reject cancels
# ---------------------------------------------------------------------------


async def test_reject_cancels_run() -> None:
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = await _make_orch(auto_approve=False, events_sink=events)
    try:
        await orch.enqueue("r4", "ingest", {})
        await _wait_for_state(orch, "r4", RunState.AWAITING_APPROVAL)
        await orch.reject("r4", reason="not now")
        state = await _wait_for_terminal(orch, "r4")
        assert state is RunState.CANCELLED
        topics = [t for run_id, t, _ in events if run_id == "r4"]
        assert "plan.rejected" in topics
        assert "run.cancelled" in topics
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 5. Amend re-plans
# ---------------------------------------------------------------------------


async def test_amend_replans() -> None:
    planner = _StubPlanner()
    orch = await _make_orch(auto_approve=False, planner=planner)
    try:
        await orch.enqueue("r5", "ingest", {})
        await _wait_for_state(orch, "r5", RunState.AWAITING_APPROVAL)
        await orch.amend("r5", instruction="also include glossary")
        # After amend the orchestrator transitions back to PLANNING and
        # re-invokes the planner. We poll on the planner call counter to
        # know the amended plan has been produced; merely re-checking the
        # state machine isn't reliable because AWAITING_APPROVAL appears
        # on both the original and amended cycles.
        deadline = asyncio.get_running_loop().time() + 5.0
        while planner.calls < 2:
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("planner was not re-invoked after amend")
            await asyncio.sleep(0.02)
        await _wait_for_state(orch, "r5", RunState.AWAITING_APPROVAL)
        await orch.approve("r5")
        state = await _wait_for_terminal(orch, "r5")
        assert state is RunState.COMPLETED
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 6. Approval timeout
# ---------------------------------------------------------------------------


async def test_approval_timeout_fails_run() -> None:
    orch = await _make_orch(auto_approve=False, approval_timeout_sec=1)
    try:
        await orch.enqueue("r6", "ingest", {})
        state = await _wait_for_terminal(orch, "r6", timeout=5.0)
        assert state is RunState.FAILED
        rec = await orch.get_record("r6")
        assert rec is not None
        assert rec.failure_reason == "approval_timeout"
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 7. HEAD exception → planning_error
# ---------------------------------------------------------------------------


async def test_head_exception_fails_with_planning_error() -> None:
    orch = await _make_orch(planner=_FailingPlanner(RuntimeError("HEAD down")))
    try:
        await orch.enqueue("r7", "ingest", {})
        state = await _wait_for_terminal(orch, "r7")
        assert state is RunState.FAILED
        rec = await orch.get_record("r7")
        assert rec is not None
        assert rec.failure_reason is not None
        assert rec.failure_reason.startswith("planning_error:")
        assert "HEAD down" in rec.failure_reason
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 8. Dispatcher exception → dispatch_error
# ---------------------------------------------------------------------------


async def test_dispatcher_exception_fails_with_dispatch_error() -> None:
    orch = await _make_orch(dispatcher=_FailingDispatcher(RuntimeError("dispatch boom")))
    try:
        await orch.enqueue("r8", "ingest", {})
        state = await _wait_for_terminal(orch, "r8")
        assert state is RunState.FAILED
        rec = await orch.get_record("r8")
        assert rec is not None
        assert rec.failure_reason is not None
        assert rec.failure_reason.startswith("dispatch_error:")
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 9. SUB exception + fail_fast=True → run FAILED with sub_error
# ---------------------------------------------------------------------------


async def test_sub_failure_fail_fast_true_run_fails() -> None:
    orch = await _make_orch(dispatcher=_PartialDispatcher(), fail_fast=True)
    try:
        await orch.enqueue("r9", "ingest", {})
        state = await _wait_for_terminal(orch, "r9")
        assert state is RunState.FAILED
        rec = await orch.get_record("r9")
        assert rec is not None
        assert "sub_error" in (rec.failure_reason or "")
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 10. SUB exception + fail_fast=False → other SUB completes, run FAILED
# ---------------------------------------------------------------------------


async def test_sub_failure_fail_fast_false_run_fails_partial() -> None:
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = await _make_orch(dispatcher=_PartialDispatcher(), fail_fast=False, events_sink=events)
    try:
        await orch.enqueue("r10", "ingest", {})
        state = await _wait_for_terminal(orch, "r10")
        assert state is RunState.FAILED
        topics = [t for run_id, t, _ in events if run_id == "r10"]
        assert "run.failed" in topics
        # The completed SUB's result is still in the payload of run.failed.
        failed_evt = next(
            payload for run_id, topic, payload in events if run_id == "r10" and topic == "run.failed"
        )
        results = failed_evt.get("results", {}).get("subs", {})
        assert "sub:reader" in results
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 11. Concurrency cap
# ---------------------------------------------------------------------------


async def test_max_concurrent_runs_throttles() -> None:
    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    class _TrackingDispatcher:
        async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
            nonlocal in_flight, peak
            async with lock:
                in_flight += 1
                peak = max(peak, in_flight)
            await asyncio.sleep(0.05)
            async with lock:
                in_flight -= 1
            return {"subs": {"sub:r": {"status": "completed", "completed_steps": 1}}}

    orch = await _make_orch(max_concurrent_runs=2, dispatcher=_TrackingDispatcher())
    try:
        for i in range(6):
            await orch.enqueue(f"r11-{i}", "g", {})
        for i in range(6):
            await _wait_for_terminal(orch, f"r11-{i}", timeout=5.0)
        assert peak <= 2
    finally:
        await orch.stop()


# ---------------------------------------------------------------------------
# 12. stop() cancels in-flight and refuses new enqueues
# ---------------------------------------------------------------------------


async def test_stop_cancels_and_refuses_enqueue() -> None:
    orch = await _make_orch(auto_approve=False, dispatcher=_StubDispatcher(sleep_for=2.0))
    await orch.enqueue("r12", "ingest", {})
    await _wait_for_state(orch, "r12", RunState.AWAITING_APPROVAL)
    await orch.stop()

    rec = await orch.get_record("r12")
    assert rec is not None
    assert rec.state is RunState.CANCELLED

    with pytest.raises(OrchestratorStoppedError):
        await orch.enqueue("r12-new", "g", {})
