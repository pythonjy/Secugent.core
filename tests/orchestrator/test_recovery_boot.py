# SPDX-License-Identifier: Apache-2.0
"""G-C8 — boot recovery driver (run_recovery) integration tests.

Covers re-enqueue of resumable runs, FAIL of unsafe (worker-lost) runs, skip of
terminal runs, run.handover emission, and IDEMPOTENCY (run twice → no duplicate
enqueue, identical final states). A Korean financial-domain run context is
included per §C-3.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from secugent.orchestrator.events import OrchestratorEventType as ET
from secugent.orchestrator.recovery import RecoveryReport, run_recovery
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunRecord,
    RunState,
)


class _RecordingPublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def __call__(self, run_id: str, topic: str, payload: dict[str, Any]) -> None:
        self.events.append((run_id, topic, payload))


class _RecordingEnqueue:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def __call__(self, record: RunRecord) -> None:
        self.calls.append(record.run_id)


async def _seed(
    store: InMemoryRunStateStore, run_id: str, state: RunState, *, command: str = "감사 실행"
) -> None:
    await store.create(run_id, command, {"tenant": "kr-finance"})
    if state is not RunState.PENDING:
        await store.update_state(run_id, state)


async def _records(store: InMemoryRunStateStore, run_ids: list[str]) -> list[RunRecord]:
    out: list[RunRecord] = []
    for rid in run_ids:
        rec = await store.get(rid)
        assert rec is not None
        out.append(rec)
    return out


async def test_resume_reenqueues_resumable_runs() -> None:
    store = InMemoryRunStateStore()
    await _seed(store, "r-pending", RunState.PENDING)
    await _seed(store, "r-planning", RunState.PLANNING)
    await _seed(store, "r-await", RunState.AWAITING_APPROVAL)
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()

    report = await run_recovery(
        await _records(store, ["r-pending", "r-planning", "r-await"]),
        state_store=store,
        enqueue=enqueue,
        publish_event=publisher,
    )

    assert report.resumed == ("r-await", "r-pending", "r-planning")
    assert report.failed == ()
    assert report.skipped == ()
    assert sorted(enqueue.calls) == ["r-await", "r-pending", "r-planning"]
    handovers = [e for e in publisher.events if e[1] == ET.RUN_HANDOVER]
    assert len(handovers) == 3
    assert all(e[2]["action"] == "resume" for e in handovers)


async def test_unsafe_runs_fail_with_worker_lost() -> None:
    store = InMemoryRunStateStore()
    await _seed(store, "r-approved", RunState.APPROVED)
    await _seed(store, "r-exec", RunState.EXECUTING)
    await _seed(store, "r-report", RunState.REPORTING)
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()

    report = await run_recovery(
        await _records(store, ["r-approved", "r-exec", "r-report"]),
        state_store=store,
        enqueue=enqueue,
        publish_event=publisher,
    )

    assert report.failed == ("r-approved", "r-exec", "r-report")
    assert report.resumed == ()
    assert enqueue.calls == []
    for rid in ("r-approved", "r-exec", "r-report"):
        rec = await store.get(rid)
        assert rec is not None
        assert rec.state is RunState.FAILED
        assert rec.failure_reason == "worker_lost"
    handovers = [e for e in publisher.events if e[1] == ET.RUN_HANDOVER]
    assert len(handovers) == 3
    assert all(e[2]["action"] == "fail_worker_lost" for e in handovers)


async def test_terminal_runs_skipped_no_event() -> None:
    store = InMemoryRunStateStore()
    await _seed(store, "r-done", RunState.COMPLETED)
    await _seed(store, "r-failed", RunState.FAILED)
    await _seed(store, "r-cancel", RunState.CANCELLED)
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()

    report = await run_recovery(
        await _records(store, ["r-done", "r-failed", "r-cancel"]),
        state_store=store,
        enqueue=enqueue,
        publish_event=publisher,
    )

    assert report.skipped == ("r-cancel", "r-done", "r-failed")
    assert report.resumed == ()
    assert report.failed == ()
    assert enqueue.calls == []
    assert [e for e in publisher.events if e[1] == ET.RUN_HANDOVER] == []


async def test_empty_open_runs_is_noop() -> None:
    store = InMemoryRunStateStore()
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()

    report = await run_recovery([], state_store=store, enqueue=enqueue, publish_event=publisher)

    assert report == RecoveryReport(resumed=(), failed=(), skipped=())
    assert enqueue.calls == []
    assert publisher.events == []


async def test_missing_record_at_apply_is_skipped() -> None:
    store = InMemoryRunStateStore()
    await _seed(store, "r-gone", RunState.PLANNING)
    snapshot = await _records(store, ["r-gone"])
    # Simulate the record vanishing between snapshot and apply by using a fresh
    # store that never saw it.
    fresh = InMemoryRunStateStore()
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()

    report = await run_recovery(snapshot, state_store=fresh, enqueue=enqueue, publish_event=publisher)

    assert report.skipped == ("r-gone",)
    assert enqueue.calls == []


async def test_idempotent_second_pass_no_duplicate_effects() -> None:
    """Applying run_recovery twice → zero extra enqueue, identical final states."""
    store = InMemoryRunStateStore()
    await _seed(store, "r-pending", RunState.PENDING)
    await _seed(store, "r-exec", RunState.EXECUTING)
    await _seed(store, "r-done", RunState.COMPLETED)
    enqueue = _RecordingEnqueue()
    publisher = _RecordingPublisher()
    snapshot = await _records(store, ["r-pending", "r-exec", "r-done"])

    # An enqueue that advances the run out of the resumable set, mimicking the
    # real orchestrator.resume → PLANNING/EXECUTING flow.
    async def advancing_enqueue(record: RunRecord) -> None:
        enqueue.calls.append(record.run_id)
        await store.update_state(record.run_id, RunState.EXECUTING)

    first = await run_recovery(
        snapshot, state_store=store, enqueue=advancing_enqueue, publish_event=publisher
    )
    states_after_first = {rid: (await store.get(rid)).state for rid in ("r-pending", "r-exec", "r-done")}  # type: ignore[union-attr]
    enqueue_after_first = list(enqueue.calls)

    second = await run_recovery(
        snapshot, state_store=store, enqueue=advancing_enqueue, publish_event=publisher
    )
    states_after_second = {rid: (await store.get(rid)).state for rid in ("r-pending", "r-exec", "r-done")}  # type: ignore[union-attr]

    # No additional enqueue on the second pass.
    assert enqueue.calls == enqueue_after_first
    # Final states unchanged by the second pass.
    assert states_after_first == states_after_second
    # First pass: pending resumed, exec failed, done skipped.
    assert first.resumed == ("r-pending",)
    assert first.failed == ("r-exec",)
    assert first.skipped == ("r-done",)
    # Second pass: everything already advanced/terminal → all skipped.
    assert second.resumed == ()
    assert second.failed == ()
    assert set(second.skipped) == {"r-pending", "r-exec", "r-done"}


async def test_handover_payload_shape() -> None:
    store = InMemoryRunStateStore()
    await _seed(store, "r-exec", RunState.EXECUTING)
    publisher = _RecordingPublisher()

    await run_recovery(
        await _records(store, ["r-exec"]),
        state_store=store,
        enqueue=_RecordingEnqueue(),
        publish_event=publisher,
    )

    run_id, topic, payload = publisher.events[0]
    assert topic == ET.RUN_HANDOVER
    assert payload["run_id"] == "r-exec"
    assert payload["action"] == "fail_worker_lost"
    assert "reason" in payload


def _now() -> datetime:
    return datetime.now(tz=UTC)
