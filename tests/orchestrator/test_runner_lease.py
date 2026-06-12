# SPDX-License-Identifier: Apache-2.0
"""G-C8 — RunOrchestrator HA lease gating (acquire on dispatch, release on exit).

The lease_manager param is OPTIONAL: when None the orchestrator behaves exactly
as before (covered by tests/unit/test_orchestrator.py). These tests cover the
HA-enabled path: a run is dispatched only while this node holds its lease;
acquire failure (held elsewhere) is fail-closed (no dispatch, state untouched);
the lease is released on terminal.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from secugent.config import OrchestratorConfig
from secugent.core.event_store_base import LeaseLostError, RunLease
from secugent.orchestrator.events import OrchestratorEventType as ET
from secugent.orchestrator.lease import InMemoryLeaseManager
from secugent.orchestrator.runner import PlanLike, RunOrchestrator
from secugent.orchestrator.state import InMemoryRunStateStore, RunState


class _StubPlanner:
    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        return PlanLike(id="p1", summary=command, steps=[{"id": "s1"}])


class _StubDispatcher:
    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        self.calls += 1
        return {"subs": {"sub:r": {"status": "completed", "completed_steps": 1}}}


class _SpyLeaseManager:
    """Wraps InMemoryLeaseManager and records acquire/release/renew calls."""

    def __init__(self) -> None:
        self._inner = InMemoryLeaseManager()
        self.acquired: list[str] = []
        self.released: list[str] = []
        self.renewed: list[str] = []
        self.acquire_error: Exception | None = None
        # When set to N, the N-th renew() call (1-based) raises LeaseLostError —
        # simulating another node stealing the lease mid-run (F4 abort path).
        self.fail_renew_after: int | None = None

    async def try_acquire_leader(self, worker_id: str) -> bool:
        return await self._inner.try_acquire_leader(worker_id)

    async def release_leader(self, worker_id: str) -> None:
        await self._inner.release_leader(worker_id)

    async def acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        if self.acquire_error is not None:
            raise self.acquire_error
        self.acquired.append(run_id)
        return await self._inner.acquire_run(run_id, worker_id, ttl_seconds)

    async def renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        self.renewed.append(run_id)
        if self.fail_renew_after is not None and len(self.renewed) >= self.fail_renew_after:
            raise LeaseLostError(f"renew rejected for {run_id}: stolen by another node")
        return await self._inner.renew(run_id, worker_id, ttl_seconds)

    async def release(self, run_id: str, worker_id: str) -> None:
        self.released.append(run_id)
        await self._inner.release(run_id, worker_id)

    async def list_stale(self) -> list[str]:
        return await self._inner.list_stale()


async def _wait_terminal(orch: RunOrchestrator, run_id: str, timeout_s: float = 5.0) -> RunState:
    terminal = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
    deadline = asyncio.get_running_loop().time() + timeout_s
    while True:
        rec = await orch.get_record(run_id)
        if rec is not None and rec.state in terminal:
            return rec.state
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"run {run_id} not terminal in {timeout_s}s")
        await asyncio.sleep(0.02)


async def _wait_released(spy: _SpyLeaseManager, run_id: str, timeout_s: float = 2.0) -> None:
    """Wait (bounded) until the run's HA lease is released.

    The orchestrator releases the lease in the ``finally`` of
    :meth:`RunOrchestrator._run_pipeline_leased`, which runs a few event-loop
    ticks AFTER the pipeline task makes the run observable as terminal (the task
    sets the terminal state; the outer leased wrapper then cancels the renew task
    and releases). Polling for terminal state and asserting ``spy.released`` in the
    same tick is therefore racy under cumulative load. This helper waits for the
    guaranteed-imminent release so the assertion is deterministic — without
    masking a genuinely-never-released lease: on timeout it simply returns and lets
    the caller's ``assert spy.released == [...]`` report the precise mismatch."""
    deadline = asyncio.get_running_loop().time() + timeout_s
    while run_id not in spy.released:
        if asyncio.get_running_loop().time() > deadline:
            return
        await asyncio.sleep(0.01)


def _make_orch(lease_manager: object, events: list[tuple[str, str, dict[str, Any]]]) -> RunOrchestrator:
    async def _publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        events.append((run_id, topic, payload))

    return RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=_StubDispatcher(),
        state_store=InMemoryRunStateStore(),
        config=OrchestratorConfig(auto_approve=True),
        publish_event=_publish,
        lease_manager=lease_manager,  # type: ignore[arg-type]  # structural LeaseManager
        worker_id="node-1",
        lease_ttl_seconds=60,
    )


async def test_lease_acquired_on_dispatch_and_released_on_terminal() -> None:
    spy = _SpyLeaseManager()
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = _make_orch(spy, events)
    await orch.start()
    try:
        await orch.enqueue("kr-1", "감사 실행", {})
        state = await _wait_terminal(orch, "kr-1")
        assert state is RunState.COMPLETED
        assert spy.acquired == ["kr-1"]
        await _wait_released(spy, "kr-1")
        assert spy.released == ["kr-1"]
    finally:
        await orch.stop()


async def test_lease_held_elsewhere_fail_closed_no_dispatch() -> None:
    spy = _SpyLeaseManager()
    spy.acquire_error = LeaseLostError("held by node-2")
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = _make_orch(spy, events)
    await orch.start()
    try:
        await orch.enqueue("kr-2", "감사 실행", {})
        # Give the pipeline task a chance to run.
        await asyncio.sleep(0.1)
        dispatcher = orch._dispatcher  # type: ignore[attr-defined]
        assert dispatcher.calls == 0  # never dispatched
        rec = await orch.get_record("kr-2")
        assert rec is not None
        # State left at PENDING — the lease holder owns it; we did not mutate it.
        assert rec.state is RunState.PENDING
        handovers = [e for e in events if e[1] == ET.RUN_HANDOVER]
        assert len(handovers) == 1
        assert handovers[0][2]["action"] == "lease_held_elsewhere"
    finally:
        await orch.stop()


async def test_none_lease_manager_is_backward_compatible() -> None:
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = _make_orch(None, events)
    await orch.start()
    try:
        await orch.enqueue("plain-1", "ingest", {})
        state = await _wait_terminal(orch, "plain-1")
        assert state is RunState.COMPLETED
        # No handover events in single-node mode.
        assert [e for e in events if e[1] == ET.RUN_HANDOVER] == []
    finally:
        await orch.stop()


# --------------------------------------------------------------------------- #
# F4 — the run lease is RENEWED for the whole run (no expiry on long HITL waits)
# --------------------------------------------------------------------------- #


class _BlockingDispatcher:
    """Dispatcher that blocks until ``release`` is set — simulates a long run
    (e.g. a HITL wait) that outlives the lease TTL."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.entered = asyncio.Event()
        self.calls = 0

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        return {"subs": {"sub:r": {"status": "completed", "completed_steps": 1}}}


def _make_orch_with(
    *,
    lease_manager: object,
    dispatcher: Any,
    events: list[tuple[str, str, dict[str, Any]]],
    ttl_seconds: int,
) -> RunOrchestrator:
    async def _publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        events.append((run_id, topic, payload))

    return RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=dispatcher,
        state_store=InMemoryRunStateStore(),
        config=OrchestratorConfig(auto_approve=True),
        publish_event=_publish,
        lease_manager=lease_manager,  # type: ignore[arg-type]  # structural LeaseManager
        worker_id="node-1",
        lease_ttl_seconds=ttl_seconds,
    )


async def test_lease_renewed_so_run_outlives_ttl() -> None:
    # TTL is 0.3s; the run blocks ~1s — without renewal the lease would expire and
    # a second node could acquire it. With F4 renewal, the lease stays live.
    spy = _SpyLeaseManager()
    dispatcher = _BlockingDispatcher()
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = _make_orch_with(lease_manager=spy, dispatcher=dispatcher, events=events, ttl_seconds=1)
    # Drive the renew interval down to ~0.1s by using a small ttl on the loop.
    orch._lease_ttl_seconds = 1  # type: ignore[attr-defined]
    await orch.start()
    try:
        await orch.enqueue("long-1", "감사 실행", {})
        await asyncio.wait_for(dispatcher.entered.wait(), timeout=2.0)
        # While the run is mid-dispatch, let several renew cycles elapse.
        await asyncio.sleep(0.8)
        # A SECOND node trying to acquire is rejected → the lease is still live
        # (renewal worked; it did not silently expire).
        with pytest.raises(LeaseLostError):
            await spy.acquire_run("long-1", "node-2", 1)
        assert spy.renewed, "expected at least one lease renewal during the long run"
        # Let the run finish.
        dispatcher.release.set()
        state = await _wait_terminal(orch, "long-1")
        assert state is RunState.COMPLETED
        await _wait_released(spy, "long-1")
        assert spy.released == ["long-1"]
    finally:
        dispatcher.release.set()
        await orch.stop()


async def test_renewal_failure_aborts_dispatch_fail_closed() -> None:
    # The first renew() raises LeaseLostError (another node stole the lease). The
    # in-flight pipeline must be aborted fail-closed with a lease_lost handover,
    # and the run must NOT reach COMPLETED.
    spy = _SpyLeaseManager()
    spy.fail_renew_after = 1
    dispatcher = _BlockingDispatcher()
    events: list[tuple[str, str, dict[str, Any]]] = []
    orch = _make_orch_with(lease_manager=spy, dispatcher=dispatcher, events=events, ttl_seconds=1)
    await orch.start()
    try:
        await orch.enqueue("steal-1", "감사 실행", {})
        await asyncio.wait_for(dispatcher.entered.wait(), timeout=2.0)
        # Wait for a renew to occur (and fail) and the pipeline to be aborted.
        state = await _wait_terminal(orch, "steal-1")
        # The dispatcher never completed normally; the run did not COMPLETE.
        assert state is not RunState.COMPLETED
        handovers = [e for e in events if e[1] == ET.RUN_HANDOVER]
        assert any(h[2]["action"] == "lease_lost" for h in handovers)
        await _wait_released(spy, "steal-1")
        assert spy.released == ["steal-1"]
    finally:
        dispatcher.release.set()
        await orch.stop()
