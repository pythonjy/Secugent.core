# SPDX-License-Identifier: Apache-2.0
"""SQLiteRunStateStore — durable, restart-resilient RunStateStore tests.

Triple test obligation for a deterministic/critical module (CLAUDE.md §B-4a):
unit + property-based (hypothesis) + 100-run determinism, plus the headline
restart-resilience integration test.

The SQLite backend must be behaviour-equivalent to InMemoryRunStateStore for
the shared RunRecord/RunEvent contract.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunEvent,
    RunState,
    RunStateStore,
    SQLiteRunStateStore,
)


def _db_path(tmp_path: Path, name: str = "runs.db") -> str:
    return str(tmp_path / name)


async def test_sqlite_store_satisfies_protocol(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    assert isinstance(store, RunStateStore)


async def test_sqlite_store_in_memory_path_skips_mkdir() -> None:
    # ":memory:" must not be treated as a filesystem path (no parent mkdir).
    store = SQLiteRunStateStore(":memory:")
    await store.create("mem", "g", {})
    rec = await store.get("mem")
    assert rec is not None
    assert rec.state is RunState.PENDING
    store.close()


async def test_sqlite_store_create_and_get(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    # 한국어 픽스처 (§C-3)
    await store.create("run-1", "배포 승인 요청", {"테넌트": "kbank"})
    rec = await store.get("run-1")
    assert rec is not None
    assert rec.state is RunState.PENDING
    assert rec.command == "배포 승인 요청"
    assert rec.context == {"테넌트": "kbank"}
    assert rec.started_at is not None
    assert [s for s, _ in rec.state_history] == [RunState.PENDING]


async def test_sqlite_store_update_state_records_history(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-2", "g", {})
    await store.update_state("run-2", RunState.PLANNING)
    await store.update_state("run-2", RunState.AWAITING_APPROVAL, plan={"steps": []})
    await store.update_state("run-2", RunState.PLANNING)  # no-op? different -> appends
    await store.update_state("run-2", RunState.CANCELLED, failure_reason="user-rejected")
    rec = await store.get("run-2")
    assert rec is not None
    states = [s for s, _ in rec.state_history]
    assert states == [
        RunState.PENDING,
        RunState.PLANNING,
        RunState.AWAITING_APPROVAL,
        RunState.PLANNING,
        RunState.CANCELLED,
    ]
    assert rec.plan == {"steps": []}
    assert rec.failure_reason == "user-rejected"
    assert rec.finished_at is not None


async def test_sqlite_store_same_state_is_noop(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-noop", "g", {})
    await store.update_state("run-noop", RunState.PENDING)  # same -> no append
    rec = await store.get("run-noop")
    assert rec is not None
    assert [s for s, _ in rec.state_history] == [RunState.PENDING]


async def test_sqlite_store_unknown_metadata_lands_in_extras(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-x", "g", {})
    await store.update_state("run-x", RunState.PLANNING, weird_field="abc")
    rec = await store.get("run-x")
    assert rec is not None
    assert rec.context.get("_extras", {}).get("weird_field") == "abc"


async def test_sqlite_store_events_roundtrip(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-3", "g", {})
    await store.append_event("run-3", RunEvent(run_id="run-3", topic="plan.created"))
    await store.append_event("run-3", RunEvent(run_id="run-3", topic="step.started", payload={"i": 1}))
    await store.append_event("run-3", RunEvent(run_id="run-3", topic="run.completed"))
    events = await store.list_events("run-3")
    assert [e.topic for e in events] == [
        "plan.created",
        "step.started",
        "run.completed",
    ]
    assert events[1].payload == {"i": 1}


async def test_sqlite_store_persists_across_restarts(tmp_path: Path) -> None:
    """Headline integration test — survives a fresh store instance."""
    path = _db_path(tmp_path)
    store1 = SQLiteRunStateStore(path)
    await store1.create("run-persist", "데이터 추출", {"k": "v"})
    await store1.update_state("run-persist", RunState.PLANNING)
    await store1.update_state(
        "run-persist", RunState.AWAITING_APPROVAL, plan={"steps": [1, 2]}, approver=None
    )
    await store1.update_state("run-persist", RunState.COMPLETED, approver="alice")
    await store1.append_event("run-persist", RunEvent(run_id="run-persist", topic="plan.created"))
    await store1.append_event("run-persist", RunEvent(run_id="run-persist", topic="run.completed"))
    before = await store1.get("run-persist")
    events_before = await store1.list_events("run-persist")

    # Brand new instance, same DB file — simulates process restart.
    store2 = SQLiteRunStateStore(path)
    after = await store2.get("run-persist")
    events_after = await store2.list_events("run-persist")

    assert after == before
    assert after is not None
    assert after.state is RunState.COMPLETED
    assert after.approver == "alice"
    assert after.plan == {"steps": [1, 2]}
    assert after.finished_at is not None
    assert [s for s, _ in after.state_history] == [
        RunState.PENDING,
        RunState.PLANNING,
        RunState.AWAITING_APPROVAL,
        RunState.COMPLETED,
    ]
    assert [e.topic for e in events_after] == [e.topic for e in events_before]


async def test_sqlite_store_update_persists_command_and_started_at(
    tmp_path: Path,
) -> None:
    """SG-20260603-11 regression — ``command``/``started_at`` set via metadata
    must survive a process restart.

    These two columns were previously omitted from the UPDATE statement, so an
    in-memory record would diverge from what a fresh store instance reads back
    from disk. The values must be durably written, not just mutated in memory.
    """
    path = _db_path(tmp_path)
    store1 = SQLiteRunStateStore(path)
    await store1.create("run-cmd", "원본 명령", {})
    new_started = datetime(2026, 6, 3, 9, 0, 0, tzinfo=UTC)
    await store1.update_state(
        "run-cmd",
        RunState.PLANNING,
        command="갱신된 명령",
        started_at=new_started,
    )

    # Fresh instance against the same DB file — reads ONLY from disk.
    store2 = SQLiteRunStateStore(path)
    after = await store2.get("run-cmd")
    assert after is not None
    assert after.command == "갱신된 명령"
    assert after.started_at == new_started


async def test_sqlite_and_inmemory_update_command_equivalent(
    tmp_path: Path,
) -> None:
    """SG-20260603-11 — SQLite and in-memory stores must stay behaviour-equivalent
    when ``command``/``started_at`` are updated via metadata."""
    new_started = datetime(2026, 6, 3, 8, 30, 0, tzinfo=UTC)

    mem = InMemoryRunStateStore()
    await mem.create("r", "원본", {})
    await mem.update_state("r", RunState.PLANNING, command="갱신", started_at=new_started)
    mem_rec = await mem.get("r")

    path = _db_path(tmp_path)
    store = SQLiteRunStateStore(path)
    await store.create("r", "원본", {})
    await store.update_state("r", RunState.PLANNING, command="갱신", started_at=new_started)
    # Force a disk round-trip via a fresh instance.
    store.close()
    sql_rec = await SQLiteRunStateStore(path).get("r")

    assert mem_rec is not None
    assert sql_rec is not None
    assert sql_rec.command == mem_rec.command == "갱신"
    assert sql_rec.started_at == mem_rec.started_at == new_started


async def test_sqlite_store_get_unknown_returns_none(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    assert await store.get("nope") is None


async def test_sqlite_store_update_unknown_run_raises_key_error(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    with pytest.raises(KeyError):
        await store.update_state("nope", RunState.PLANNING)


async def test_sqlite_store_list_events_unknown_returns_empty(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    assert await store.list_events("nope") == []


async def test_sqlite_store_empty_context_and_none_plan(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-e", "g", {})
    rec = await store.get("run-e")
    assert rec is not None
    assert rec.context == {}
    assert rec.plan is None


async def test_sqlite_store_non_serialisable_context_raises(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    with pytest.raises(ValueError):
        await store.create("run-bad", "g", {"obj": object()})


async def test_sqlite_store_non_serialisable_event_payload_raises(
    tmp_path: Path,
) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("run-evt", "g", {})
    with pytest.raises(ValueError):
        await store.append_event("run-evt", RunEvent(run_id="run-evt", topic="t", payload={"o": object()}))


# --------------------------------------------------------------------------- #
# Property-based (hypothesis) — state_history order preservation
# --------------------------------------------------------------------------- #

_STATES = list(RunState)


@settings(max_examples=200, deadline=None)
@given(st.lists(st.sampled_from(_STATES), min_size=0, max_size=12))
def test_sqlite_store_state_history_order_preserved_prop(
    states: list[RunState],
) -> None:
    # Self-contained (no pytest fixtures) — hypothesis @given does not mix with
    # function-scoped fixtures under pytest-asyncio's auto mode.
    import asyncio
    import tempfile

    async def _run() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteRunStateStore(str(Path(tmp) / "runs.db"))
            await store.create("r", "g", {})
            expected = [RunState.PENDING]
            for s in states:
                await store.update_state("r", s)
                if s != expected[-1]:
                    expected.append(s)
            rec = await store.get("r")
            assert rec is not None
            assert [s for s, _ in rec.state_history] == expected
            store.close()

    asyncio.run(_run())


# --------------------------------------------------------------------------- #
# Determinism — identical sequence yields identical RunRecord, 100 runs
# --------------------------------------------------------------------------- #


async def _build_fixture_projection(path: str) -> dict[str, object]:
    """Run a fixed sequence and project to a wall-clock-independent shape."""
    store = SQLiteRunStateStore(path)
    await store.create("det", "결정성 검증", {"a": 1})
    await store.update_state("det", RunState.PLANNING)
    await store.update_state("det", RunState.AWAITING_APPROVAL, plan={"x": 1})
    await store.update_state("det", RunState.APPROVED, approver="bob")
    await store.append_event("det", RunEvent(run_id="det", topic="t1"))
    rec = await store.get("det")
    assert rec is not None
    events = await store.list_events("det")
    return {
        "run_id": rec.run_id,
        "command": rec.command,
        "context": rec.context,
        "state": rec.state,
        "plan": rec.plan,
        "approver": rec.approver,
        "failure_reason": rec.failure_reason,
        "history_states": [s for s, _ in rec.state_history],
        "event_topics": [e.topic for e in events],
    }


async def test_sqlite_store_deterministic_get_100_runs(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    expected = await _build_fixture_projection(str(tmp_path_factory.mktemp("d0") / "runs.db"))
    for i in range(100):
        got = await _build_fixture_projection(str(tmp_path_factory.mktemp(f"d{i + 1}") / "runs.db"))
        assert got == expected


# --------------------------------------------------------------------------- #
# list_open_runs (W1 G-C8 follow-up) — boot recovery enumeration
# --------------------------------------------------------------------------- #

_TERMINAL = (RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED)
_OPEN = (
    RunState.PENDING,
    RunState.PLANNING,
    RunState.AWAITING_APPROVAL,
    RunState.APPROVED,
    RunState.EXECUTING,
    RunState.REPORTING,
)


async def test_inmemory_list_open_runs_empty() -> None:
    store = InMemoryRunStateStore()
    assert await store.list_open_runs() == []


async def test_sqlite_list_open_runs_empty(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    assert await store.list_open_runs() == []


async def test_inmemory_list_open_runs_excludes_terminal() -> None:
    store = InMemoryRunStateStore()
    # 한국어 픽스처 (§C-3): 진행 중 run과 종료된 run을 섞는다.
    await store.create("진행중-1", "배포 승인 대기", {})
    await store.create("종료-완료", "배포 완료", {})
    await store.update_state("종료-완료", RunState.COMPLETED)
    await store.create("진행중-2", "데이터 추출 중", {})
    await store.update_state("진행중-2", RunState.EXECUTING)
    await store.create("종료-실패", "롤백", {})
    await store.update_state("종료-실패", RunState.FAILED, failure_reason="boom")
    open_ids = {r.run_id for r in await store.list_open_runs()}
    assert open_ids == {"진행중-1", "진행중-2"}


async def test_sqlite_list_open_runs_excludes_terminal(tmp_path: Path) -> None:
    store = SQLiteRunStateStore(_db_path(tmp_path))
    await store.create("open-a", "g", {})
    await store.create("open-b", "g", {})
    await store.update_state("open-b", RunState.AWAITING_APPROVAL)
    await store.create("term-c", "g", {})
    await store.update_state("term-c", RunState.CANCELLED)
    open_ids = {r.run_id for r in await store.list_open_runs()}
    assert open_ids == {"open-a", "open-b"}


async def test_sqlite_list_open_runs_survives_restart(tmp_path: Path) -> None:
    path = _db_path(tmp_path)
    store1 = SQLiteRunStateStore(path)
    await store1.create("durable-open", "재시작 복구", {})
    await store1.update_state("durable-open", RunState.PLANNING)
    store1.close()
    store2 = SQLiteRunStateStore(path)
    open_runs = await store2.list_open_runs()
    assert [r.run_id for r in open_runs] == ["durable-open"]
    assert open_runs[0].state is RunState.PLANNING


async def test_list_open_runs_inmemory_sqlite_equivalent(tmp_path: Path) -> None:
    mem = InMemoryRunStateStore()
    sql = SQLiteRunStateStore(_db_path(tmp_path))
    for store in (mem, sql):
        for state in _OPEN:
            rid = f"run-{state.value}"
            await store.create(rid, "g", {})
            if state is not RunState.PENDING:
                await store.update_state(rid, state)
        for state in _TERMINAL:
            rid = f"term-{state.value}"
            await store.create(rid, "g", {})
            await store.update_state(rid, state)
    mem_ids = {r.run_id for r in await mem.list_open_runs()}
    sql_ids = {r.run_id for r in await sql.list_open_runs()}
    assert mem_ids == sql_ids == {f"run-{s.value}" for s in _OPEN}


async def test_list_open_runs_is_mandatory_run_state_store_member(tmp_path: Path) -> None:
    """F12: ``list_open_runs`` is now a MANDATORY member of RunStateStore (the
    separate OpenRunSource opt-in Protocol was removed as statically dead). Both
    concrete stores structurally satisfy the full RunStateStore Protocol."""
    from secugent.orchestrator.state import RunStateStore

    assert isinstance(InMemoryRunStateStore(), RunStateStore)
    assert isinstance(SQLiteRunStateStore(_db_path(tmp_path)), RunStateStore)
