# SPDX-License-Identifier: Apache-2.0
"""Unit tests for InMemoryRunStateStore.

SQLiteRunStateStore is now fully implemented (BE-20260603-03); its dedicated
coverage lives in ``tests/orchestrator/test_state_sqlite.py``.
"""

from __future__ import annotations

import pytest

from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunEvent,
    RunState,
)


async def test_create_then_get_returns_pending() -> None:
    store = InMemoryRunStateStore()
    await store.create("r1", "ingest", {"k": "v"})
    rec = await store.get("r1")
    assert rec is not None
    assert rec.state is RunState.PENDING
    assert rec.command == "ingest"
    assert rec.context == {"k": "v"}
    assert len(rec.state_history) == 1


async def test_update_state_appends_history_and_metadata() -> None:
    store = InMemoryRunStateStore()
    await store.create("r2", "g", {})
    await store.update_state("r2", RunState.PLANNING)
    await store.update_state("r2", RunState.AWAITING_APPROVAL)
    await store.update_state("r2", RunState.CANCELLED, failure_reason="user-rejected")
    rec = await store.get("r2")
    assert rec is not None
    states = [s for s, _ in rec.state_history]
    assert states == [
        RunState.PENDING,
        RunState.PLANNING,
        RunState.AWAITING_APPROVAL,
        RunState.CANCELLED,
    ]
    assert rec.failure_reason == "user-rejected"
    assert rec.finished_at is not None


async def test_update_state_unknown_run_raises() -> None:
    store = InMemoryRunStateStore()
    with pytest.raises(KeyError):
        await store.update_state("nope", RunState.PLANNING)


async def test_append_and_list_events() -> None:
    store = InMemoryRunStateStore()
    await store.create("r3", "g", {})
    await store.append_event("r3", RunEvent(run_id="r3", topic="plan.created"))
    await store.append_event("r3", RunEvent(run_id="r3", topic="run.completed"))
    events = await store.list_events("r3")
    assert [e.topic for e in events] == ["plan.created", "run.completed"]


async def test_get_returns_defensive_copy() -> None:
    store = InMemoryRunStateStore()
    await store.create("r4", "g", {})
    rec = await store.get("r4")
    assert rec is not None
    rec.command = "MUTATED"
    rec2 = await store.get("r4")
    assert rec2 is not None
    assert rec2.command == "g"


async def test_unknown_metadata_lands_in_extras() -> None:
    store = InMemoryRunStateStore()
    await store.create("r5", "g", {})
    await store.update_state("r5", RunState.PLANNING, weird_field="abc")
    rec = await store.get("r5")
    assert rec is not None
    assert rec.context.get("_extras", {}).get("weird_field") == "abc"
