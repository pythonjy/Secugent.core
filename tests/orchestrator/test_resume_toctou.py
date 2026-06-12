# SPDX-License-Identifier: Apache-2.0
"""F10 — RunOrchestrator.resume() check-and-claim is atomic (no double-launch).

The double-launch guard read self._tasks under _lifecycle_lock but inserted the
task AFTER releasing the lock, so two concurrent resume() calls for the same
run could both pass the check and launch two pipeline tasks. The fix reserves
the task slot WHILE holding the lock; this test pins that exactly one pipeline
task runs per run_id under concurrent resume().
"""

from __future__ import annotations

import asyncio
from typing import Any

from secugent.config import OrchestratorConfig
from secugent.orchestrator.runner import PlanLike, RunOrchestrator
from secugent.orchestrator.state import InMemoryRunStateStore, RunState


class _CountingPlanner:
    """Counts how many times a run's pipeline reaches PLANNING (i.e. is launched)."""

    def __init__(self) -> None:
        self.calls: dict[str, int] = {}
        self.gate = asyncio.Event()

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        self.calls[run_id] = self.calls.get(run_id, 0) + 1
        # Hold the pipeline open briefly so a racing second resume() would overlap.
        await self.gate.wait()
        return PlanLike(id="p1", summary=command, steps=[{"id": "s1"}])


class _StubDispatcher:
    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        self.calls += 1
        return {"subs": {"sub:r": {"status": "completed", "completed_steps": 1}}}


class _YieldingLock:
    """An asyncio.Lock whose CONTEXT EXIT yields control once.

    Faithfully models "an await exists between the check and the task insert": if
    the insert happens AFTER the ``async with`` block (the pre-F10 bug), the yield
    on exit lets a racing second resume() slip in and double-launch. If the insert
    happens INSIDE the block (the fix), the slot is already claimed before the
    exit yields, so the second resume sees it. Delegates locking to a real Lock."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> None:
        await self._lock.acquire()

    async def __aexit__(self, *exc: object) -> None:
        self._lock.release()
        await asyncio.sleep(0)  # the window-exposing yield


async def test_resume_atomic_claim_under_window_yield() -> None:
    """F10 RED-first: with a yield in the check→claim window, two concurrent
    resume() calls must STILL launch exactly one task (atomic claim holds)."""
    store = InMemoryRunStateStore()
    await store.create("r-win", "감사 실행", {"tenant": "shinhan"})
    planner = _CountingPlanner()
    dispatcher = _StubDispatcher()
    record = await store.get("r-win")
    assert record is not None

    orch = RunOrchestrator(
        planner=planner,
        dispatcher=dispatcher,
        state_store=store,
        config=OrchestratorConfig(auto_approve=True),
    )
    orch._lifecycle_lock = _YieldingLock()  # type: ignore[assignment]  # window-exposing lock
    await orch.start()
    try:
        await asyncio.gather(orch.resume(record), orch.resume(record))
        # Exactly one pipeline task claimed the slot despite the window yield.
        assert len(orch._tasks) <= 1  # type: ignore[attr-defined]
        planner.gate.set()
        deadline = asyncio.get_running_loop().time() + 5.0
        while True:
            rec = await orch.get_record("r-win")
            if rec is not None and rec.state in {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}:
                break
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("run did not finish")
            await asyncio.sleep(0.02)
        assert planner.calls.get("r-win") == 1
        assert dispatcher.calls == 1
    finally:
        planner.gate.set()
        await orch.stop()


async def test_concurrent_resume_launches_exactly_one_task() -> None:
    store = InMemoryRunStateStore()
    # Seed an already-persisted, resumable run (as boot recovery would find it).
    await store.create("r-1", "감사 실행", {"tenant": "kbank"})

    planner = _CountingPlanner()
    dispatcher = _StubDispatcher()
    record = await store.get("r-1")
    assert record is not None

    orch = RunOrchestrator(
        planner=planner,
        dispatcher=dispatcher,
        state_store=store,
        config=OrchestratorConfig(auto_approve=True),
    )
    await orch.start()
    try:
        # Two concurrent resume() calls for the SAME run.
        await asyncio.gather(orch.resume(record), orch.resume(record))
        # Exactly one pipeline task was scheduled (the second resume saw the claim).
        assert len(orch._tasks) <= 1  # type: ignore[attr-defined]
        # Let the single pipeline proceed and finish.
        planner.gate.set()
        deadline = asyncio.get_running_loop().time() + 5.0
        while True:
            rec = await orch.get_record("r-1")
            if rec is not None and rec.state in {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}:
                break
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("run did not finish")
            await asyncio.sleep(0.02)
        # The pipeline ran exactly once — no duplicate planning/dispatch.
        assert planner.calls.get("r-1") == 1
        assert dispatcher.calls == 1
    finally:
        planner.gate.set()
        await orch.stop()
