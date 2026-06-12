# SPDX-License-Identifier: Apache-2.0
"""Run lifecycle state + storage abstraction.

The orchestrator distinguishes between:

* :class:`RunState`  — coarse pipeline phase used to gate transitions
* :class:`RunRecord` — durable snapshot (state + plan + approver + reasons)
* :class:`RunEvent`  — per-run audit ribbon, used by SSE replay

Storage backends:

* :class:`InMemoryRunStateStore` — process-local; sufficient for v0.1
* :class:`SQLiteRunStateStore`  — durable, restart-resilient SQLite backend
  (stdlib :mod:`sqlite3` + :class:`asyncio.Lock`); behaviour-equivalent to the
  in-memory store but survives process restarts.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "InMemoryRunStateStore",
    "RunEvent",
    "RunRecord",
    "RunState",
    "RunStateStore",
    "SQLiteRunStateStore",
]


class RunState(StrEnum):
    PENDING = "PENDING"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


@dataclass
class RunEvent:
    """Per-run audit ribbon entry."""

    run_id: str
    topic: str
    ts: datetime = field(default_factory=_utcnow)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "topic": self.topic,
            "ts": self.ts.isoformat(),
            "payload": self.payload,
        }


@dataclass
class RunRecord:
    run_id: str
    command: str
    context: dict[str, Any] = field(default_factory=dict)
    state: RunState = RunState.PENDING
    plan: dict[str, Any] | None = None
    approver: str | None = None
    failure_reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    state_history: list[tuple[RunState, datetime]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "command": self.command,
            "context": self.context,
            "state": self.state.value,
            "plan": self.plan,
            "approver": self.approver,
            "failure_reason": self.failure_reason,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "state_history": [{"state": s.value, "ts": t.isoformat()} for s, t in self.state_history],
        }


# ---------------------------------------------------------------------------
# Store protocol
# ---------------------------------------------------------------------------


# Terminal run states — a run in any of these has finished and must NOT be
# re-enqueued by boot-recovery. Shared by the open-run enumeration on both
# stores (and mirrored by ``orchestrator.recovery._TERMINAL_STATES``).
_TERMINAL_STATES = frozenset({RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED})


@runtime_checkable
class RunStateStore(Protocol):
    async def create(self, run_id: str, command: str, context: dict[str, Any]) -> None: ...
    async def get(self, run_id: str) -> RunRecord | None: ...
    async def update_state(
        self,
        run_id: str,
        state: RunState,
        **metadata: Any,
    ) -> None: ...
    async def append_event(self, run_id: str, event: RunEvent) -> None: ...
    async def list_events(self, run_id: str) -> list[RunEvent]: ...
    async def list_open_runs(self) -> list[RunRecord]:
        """Return all runs NOT in a terminal state (boot-recovery source).

        Open = ``state`` ∉ {COMPLETED, FAILED, CANCELLED}. The boot-recovery
        hook (:func:`secugent.orchestrator.wiring.recover_open_runs`) enumerates
        these to decide which orphaned runs to resume / fail-out after a restart.
        """
        ...


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class InMemoryRunStateStore:
    """Process-local, asyncio-safe :class:`RunStateStore`."""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._events: dict[str, list[RunEvent]] = {}
        self._lock = asyncio.Lock()

    async def create(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        async with self._lock:
            now = _utcnow()
            self._runs[run_id] = RunRecord(
                run_id=run_id,
                command=command,
                context=dict(context or {}),
                state=RunState.PENDING,
                started_at=now,
                state_history=[(RunState.PENDING, now)],
            )
            self._events.setdefault(run_id, [])

    async def get(self, run_id: str) -> RunRecord | None:
        async with self._lock:
            rec = self._runs.get(run_id)
            if rec is None:
                return None
            # Defensive copy — callers shouldn't mutate the live record.
            return _clone_record(rec)

    async def update_state(self, run_id: str, state: RunState, **metadata: Any) -> None:
        async with self._lock:
            rec = self._runs.get(run_id)
            if rec is None:
                raise KeyError(f"unknown run_id {run_id}")
            now = _utcnow()
            if rec.state != state:
                rec.state = state
                rec.state_history.append((state, now))
                if state in (RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED):
                    rec.finished_at = now
            for k, v in metadata.items():
                if hasattr(rec, k):
                    setattr(rec, k, v)
                else:
                    rec.context.setdefault("_extras", {})[k] = v

    async def append_event(self, run_id: str, event: RunEvent) -> None:
        async with self._lock:
            self._events.setdefault(run_id, []).append(event)

    async def list_events(self, run_id: str) -> list[RunEvent]:
        async with self._lock:
            return list(self._events.get(run_id, ()))

    async def list_open_runs(self) -> list[RunRecord]:
        async with self._lock:
            return [_clone_record(rec) for rec in self._runs.values() if rec.state not in _TERMINAL_STATES]


# ---------------------------------------------------------------------------
# SQLite implementation
# ---------------------------------------------------------------------------


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    context TEXT NOT NULL,
    state TEXT NOT NULL,
    plan TEXT,
    approver TEXT,
    failure_reason TEXT,
    started_at TEXT,
    finished_at TEXT,
    state_history TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    topic TEXT NOT NULL,
    ts TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id);
"""

# Known RunRecord fields that update_state metadata may set directly. Anything
# else is funnelled into context["_extras"], matching InMemoryRunStateStore.
_RECORD_FIELDS = frozenset(
    {
        "command",
        "context",
        "state",
        "plan",
        "approver",
        "failure_reason",
        "started_at",
        "finished_at",
        "state_history",
    }
)


def _dumps(value: Any) -> str:
    """JSON-serialise, failing fast (ValueError) on non-serialisable input."""
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value not JSON-serialisable: {exc}") from exc


def _history_to_json(history: list[tuple[RunState, datetime]]) -> str:
    return _dumps([{"state": s.value, "ts": t.isoformat()} for s, t in history])


def _history_from_json(raw: str) -> list[tuple[RunState, datetime]]:
    items = json.loads(raw)
    return [(RunState(item["state"]), datetime.fromisoformat(item["ts"])) for item in items]


class SQLiteRunStateStore:
    """Durable, restart-resilient :class:`RunStateStore`.

    Behaviour-equivalent to :class:`InMemoryRunStateStore` for the shared
    ``RunRecord``/``RunEvent`` contract, but persists to a SQLite file so that
    run state and the per-run audit ribbon survive a process restart (open a
    fresh instance against the same path and ``get`` returns the same record).

    Concurrency: stdlib :mod:`sqlite3` guarded by an :class:`asyncio.Lock`
    (no external dependency — see docs/specs/2026-06-03-sqlite-run-state-store.md
    §동시성). A single event loop serialises all DB access through the lock.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # ``check_same_thread=False`` is safe because the asyncio.Lock serialises
        # access within the single owning event loop.
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; explicit BEGIN/COMMIT where needed
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SQLITE_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    async def create(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        now = _utcnow()
        context_json = _dumps(dict(context or {}))
        history_json = _history_to_json([(RunState.PENDING, now)])
        async with self._lock:
            self._conn.execute(
                "INSERT INTO runs(run_id, command, context, state, plan, approver, "
                "failure_reason, started_at, finished_at, state_history) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    command,
                    context_json,
                    RunState.PENDING.value,
                    None,
                    None,
                    None,
                    now.isoformat(),
                    None,
                    history_json,
                ),
            )

    async def get(self, run_id: str) -> RunRecord | None:
        async with self._lock:
            return self._get_locked(run_id)

    def _get_locked(self, run_id: str) -> RunRecord | None:
        cur = self._conn.execute(
            "SELECT run_id, command, context, state, plan, approver, "
            "failure_reason, started_at, finished_at, state_history "
            "FROM runs WHERE run_id=?",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return _row_to_record(row)

    async def update_state(self, run_id: str, state: RunState, **metadata: Any) -> None:
        async with self._lock:
            rec = self._get_locked(run_id)
            if rec is None:
                raise KeyError(f"unknown run_id {run_id}")
            now = _utcnow()
            if rec.state != state:
                rec.state = state
                rec.state_history.append((state, now))
                if state in (RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED):
                    rec.finished_at = now
            for key, value in metadata.items():
                if key in _RECORD_FIELDS:
                    setattr(rec, key, value)
                else:
                    rec.context.setdefault("_extras", {})[key] = value
            # Serialise *before* touching the DB so a non-serialisable plan/context
            # fails fast without leaving a partially-applied write.
            context_json = _dumps(rec.context)
            plan_json = _dumps(rec.plan) if rec.plan is not None else None
            history_json = _history_to_json(rec.state_history)
            self._conn.execute(
                "UPDATE runs SET command=?, state=?, context=?, plan=?, approver=?, "
                "failure_reason=?, started_at=?, finished_at=?, state_history=? "
                "WHERE run_id=?",
                (
                    rec.command,
                    rec.state.value,
                    context_json,
                    plan_json,
                    rec.approver,
                    rec.failure_reason,
                    rec.started_at.isoformat() if rec.started_at else None,
                    rec.finished_at.isoformat() if rec.finished_at else None,
                    history_json,
                    run_id,
                ),
            )

    async def append_event(self, run_id: str, event: RunEvent) -> None:
        payload_json = _dumps(event.payload)
        async with self._lock:
            self._conn.execute(
                "INSERT INTO run_events(run_id, topic, ts, payload) VALUES(?,?,?,?)",
                (run_id, event.topic, event.ts.isoformat(), payload_json),
            )

    async def list_events(self, run_id: str) -> list[RunEvent]:
        async with self._lock:
            cur = self._conn.execute(
                "SELECT run_id, topic, ts, payload FROM run_events WHERE run_id=? ORDER BY id ASC",
                (run_id,),
            )
            rows = cur.fetchall()
        return [
            RunEvent(
                run_id=row[0],
                topic=row[1],
                ts=datetime.fromisoformat(row[2]),
                payload=json.loads(row[3]),
            )
            for row in rows
        ]

    async def list_open_runs(self) -> list[RunRecord]:
        # Filter terminal states in SQL so a large completed-run history does not
        # have to be materialised + decoded just to be discarded. Parameter
        # binding keeps it injection-safe (states are an enum, but never trust the
        # string interpolation path).
        placeholders = ",".join("?" for _ in _TERMINAL_STATES)
        terminal_values = tuple(s.value for s in _TERMINAL_STATES)
        async with self._lock:
            cur = self._conn.execute(
                # ``placeholders`` is built only from literal ``?`` chars (one per
                # terminal state) — no caller data is interpolated, so this is not
                # an injection vector; the values bind through ``terminal_values``.
                "SELECT run_id, command, context, state, plan, approver, "  # noqa: S608
                "failure_reason, started_at, finished_at, state_history "
                f"FROM runs WHERE state NOT IN ({placeholders}) ORDER BY run_id ASC",
                terminal_values,
            )
            rows = cur.fetchall()
        return [_row_to_record(row) for row in rows]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_record(row: tuple[Any, ...]) -> RunRecord:
    """Decode a ``runs`` table row (the canonical 10-column projection) into a
    :class:`RunRecord`. Shared by :meth:`SQLiteRunStateStore._get_locked` and
    :meth:`SQLiteRunStateStore.list_open_runs` so the column order lives once."""
    return RunRecord(
        run_id=row[0],
        command=row[1],
        context=json.loads(row[2]),
        state=RunState(row[3]),
        plan=json.loads(row[4]) if row[4] is not None else None,
        approver=row[5],
        failure_reason=row[6],
        started_at=datetime.fromisoformat(row[7]) if row[7] else None,
        finished_at=datetime.fromisoformat(row[8]) if row[8] else None,
        state_history=_history_from_json(row[9]),
    )


def _clone_record(rec: RunRecord) -> RunRecord:
    return RunRecord(
        run_id=rec.run_id,
        command=rec.command,
        context=dict(rec.context),
        state=rec.state,
        plan=dict(rec.plan) if rec.plan is not None else None,
        approver=rec.approver,
        failure_reason=rec.failure_reason,
        started_at=rec.started_at,
        finished_at=rec.finished_at,
        state_history=list(rec.state_history),
    )
