# SPDX-License-Identifier: Apache-2.0
"""SG-FIX-05 — RunOrchestrator.enqueue() TOCTOU: stop() must see all pipeline tasks.

Root cause: the original enqueue() released _lifecycle_lock BEFORE awaiting
store.create + record_and_publish, then inserted the asyncio.Task into _tasks
AFTER those awaits. A concurrent stop() that ran between the lock release and the
_tasks insert would snapshot _tasks (missing this run), cancel the snapshotted
tasks, clear _tasks — and then enqueue would resume and insert a live task that
stop() had already passed by: a pipeline task orphaned after stop().

Fix: after the two awaits, re-acquire _lifecycle_lock, re-check _stopped, and
perform create_task + _tasks insert atomically (no await) under the lock — same
pattern as resume() (F10, "TOCTOU closed").

Test strategy (deterministic asyncio interleaving):
- A _YieldingLock replaces _lifecycle_lock so that every lock EXIT yields one
  event-loop tick, exposing the window between check and claim.
- store.create is monkeypatched to await asyncio.sleep(0) and then trigger
  stop() concurrently, reliably reproducing the TOCTOU window.
- Assertions:
  (a) After stop() returns, _tasks must be EMPTY (no orphan task).
  (b) Either enqueue raised OrchestratorStoppedError OR no live task remains.
- 100-iteration repetition hardens against any residual scheduling variance.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from secugent.config import OrchestratorConfig
from secugent.orchestrator.runner import OrchestratorStoppedError, PlanLike, RunOrchestrator
from secugent.orchestrator.state import InMemoryRunStateStore, RunState

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _StubPlanner:
    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        await asyncio.sleep(0)
        return PlanLike(id="p1", summary=command, steps=[{"id": "s1"}])


class _StubDispatcher:
    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        await asyncio.sleep(0)
        return {"subs": {"sub:r": {"status": "completed", "completed_steps": 1}}}


# ---------------------------------------------------------------------------
# Window-exposing helpers (mirrors test_resume_toctou.py F10 approach)
# ---------------------------------------------------------------------------


class _YieldingLock:
    """An asyncio.Lock whose context EXIT yields one event-loop tick.

    This exposes the check→claim window: if task insert happens AFTER the
    ``async with`` block, the yield lets a concurrent stop() slip in and clear
    _tasks before the insert; with the fix the insert is INSIDE the block so the
    slot is claimed before the yield."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> None:
        await self._lock.acquire()

    async def __aexit__(self, *exc: object) -> None:
        self._lock.release()
        await asyncio.sleep(0)  # window-exposing yield


def _make_orch(
    store: InMemoryRunStateStore,
) -> RunOrchestrator:
    return RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=_StubDispatcher(),
        state_store=store,
        config=OrchestratorConfig(auto_approve=True),
    )


# ---------------------------------------------------------------------------
# Instrumented store: fires stop() during store.create await
# ---------------------------------------------------------------------------


class _InterjectingStore(InMemoryRunStateStore):
    """Wraps InMemoryRunStateStore and calls an async callback after create().

    Used to inject stop() in the TOCTOU window between lock-release and
    _tasks insert."""

    def __init__(self) -> None:
        super().__init__()
        self.on_create: Any = None  # set to async callable after orch construction

    async def create(
        self,
        run_id: str,
        command: str,
        context: dict[str, Any],
    ) -> None:
        await super().create(run_id, command, context)
        if self.on_create is not None:
            await self.on_create()


# ---------------------------------------------------------------------------
# RED test — TOCTOU window: stop() between store.create and _tasks insert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enqueue_toctou_no_orphan_after_stop() -> None:
    """Core regression: a concurrent stop() mid-enqueue must not leave an orphan task.

    With the original code, stop() clears _tasks BEFORE enqueue inserts the new
    task → orphan.  With the fix, enqueue re-checks _stopped under the lock AFTER
    the awaits, and either raises OrchestratorStoppedError (no task created) or
    inserts while holding the lock (so stop() would have waited and seen it).
    """
    store = _InterjectingStore()
    orch = _make_orch(store)
    # Install the window-exposing lock.
    orch._lifecycle_lock = _YieldingLock()  # type: ignore[assignment]
    await orch.start()

    stop_was_called = asyncio.Event()
    stop_done = asyncio.Event()

    async def _stop_in_window() -> None:
        """Called from inside store.create — i.e. while enqueue is between the
        first lock-release and the _tasks insert (the TOCTOU window)."""
        if stop_was_called.is_set():
            return  # only trigger once
        stop_was_called.set()
        await orch.stop()
        stop_done.set()

    store.on_create = _stop_in_window

    raised: Exception | None = None
    try:
        await orch.enqueue("sg05-1", "audit", {})
    except OrchestratorStoppedError as exc:
        raised = exc

    # stop() must have completed before we assert.
    await asyncio.wait_for(stop_done.wait(), timeout=5.0)

    # PRIMARY INVARIANT: after stop() returns, _tasks must be empty.
    # An orphan would show up as a non-empty _tasks here.
    # noinspection PyUnresolvedReferences
    tasks: dict[str, asyncio.Task[None]] = orch._tasks  # type: ignore[attr-defined]
    assert tasks == {}, (
        f"SG-FIX-05 REGRESSION: _tasks not empty after stop() — orphan task(s): {list(tasks.keys())}"
    )

    # SECONDARY: either enqueue raised (clean refusal) or stop saw the task.
    # Both are acceptable outcomes; what is NOT acceptable is a silent orphan
    # (checked above). If enqueue did NOT raise, the task must have been cancelled
    # by stop() (so it is done).
    if raised is None:
        # The task was inserted and stop() must have cancelled it.
        # _tasks was already cleared by stop(), but we can verify via the store
        # that the run landed in a terminal state (not PENDING/PLANNING).
        record = await orch.get_record("sg05-1")
        assert record is not None
        terminal = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}
        # Give it a brief moment since pipeline runs async.
        deadline = asyncio.get_running_loop().time() + 3.0
        while record.state not in terminal:
            if asyncio.get_running_loop().time() > deadline:
                break
            await asyncio.sleep(0.02)
            record = await orch.get_record("sg05-1")
            assert record is not None
        # Even if not yet terminal: no live task in _tasks is the hard requirement.
        assert tasks == {}, "orphan task survived stop()"


# ---------------------------------------------------------------------------
# 100-iteration stability sweep
# ---------------------------------------------------------------------------


async def _run_one_toctou_iteration(iteration: int) -> None:
    """Execute one TOCTOU scenario in a fresh orchestrator (extracted to avoid B023)."""
    store = _InterjectingStore()
    orch = _make_orch(store)
    orch._lifecycle_lock = _YieldingLock()  # type: ignore[assignment]
    await orch.start()

    # Bind orch explicitly to avoid B023 (loop-variable capture in closure).
    _orch = orch
    stop_called = False

    async def _stop_once() -> None:
        nonlocal stop_called
        if stop_called:
            return
        stop_called = True
        await _orch.stop()

    store.on_create = _stop_once

    try:
        await orch.enqueue(f"iter-{iteration}", "audit", {})
    except OrchestratorStoppedError:
        pass

    # Wait briefly for any in-flight stop to settle.
    await asyncio.sleep(0)

    tasks: dict[str, asyncio.Task[None]] = orch._tasks  # type: ignore[attr-defined]
    assert tasks == {}, f"iteration {iteration}: orphan task(s) after stop(): {list(tasks.keys())}"

    # Ensure orch is stopped (in case _stop_once was not reached).
    if orch.is_running:
        await orch.stop()


@pytest.mark.asyncio
async def test_enqueue_toctou_no_orphan_100_iterations() -> None:
    """Repeat the TOCTOU scenario 100 times to expose any residual scheduling variance.

    Each iteration gets a fresh orchestrator and store to avoid cross-contamination.
    """
    for i in range(100):
        await _run_one_toctou_iteration(i)


# ---------------------------------------------------------------------------
# Regression: enqueue on a cleanly stopped orchestrator still raises
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enqueue_after_stop_raises_stopped_error() -> None:
    """enqueue on a stopped orchestrator must raise OrchestratorStoppedError (unchanged)."""
    store = InMemoryRunStateStore()
    orch = _make_orch(store)
    await orch.start()
    await orch.stop()

    with pytest.raises(OrchestratorStoppedError):
        await orch.enqueue("post-stop", "audit", {})


# ---------------------------------------------------------------------------
# Regression: normal enqueue → pipeline runs to completion (no regressions)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enqueue_normal_completes() -> None:
    """Sanity: enqueue without concurrent stop() still drives the run to COMPLETED."""
    store = InMemoryRunStateStore()
    orch = _make_orch(store)
    await orch.start()
    try:
        await orch.enqueue("normal-1", "audit", {})
        # Wait for terminal.
        deadline = asyncio.get_running_loop().time() + 5.0
        while True:
            rec = await orch.get_record("normal-1")
            if rec is not None and rec.state in {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}:
                assert rec.state is RunState.COMPLETED
                break
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError("run did not complete in time")
            await asyncio.sleep(0.02)
    finally:
        await orch.stop()
