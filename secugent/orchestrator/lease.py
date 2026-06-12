# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — leader election + per-run lease management.

The lease/leader primitives live behind a :class:`LeaseManager` Protocol so
the orchestrator can ride on three back-ends:

* :class:`InMemoryLeaseManager` — for unit tests (no IO)
* :class:`SQLiteLeaseManager` — same-process or single-host development
* PG-backed via :class:`secugent.core.event_store_pg.PgEventStore` — leader
  via ``pg_advisory_lock`` and run lease via ``SELECT FOR UPDATE
  SKIP LOCKED``. The PG implementation lives in the event_store_pg module so
  it can reuse the same connection pool.

Per PHASE 10 plan §P10-2 the user chose Leader+Standby — only the in-process
``InMemoryLeaseManager`` and SQLite implementation are built here; the PG
back-end implementation in ``event_store_pg.py`` is conditional on the
asyncpg dependency.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, runtime_checkable

from secugent.core.event_store_base import (
    LeaderLostError,
    LeaseLostError,
    RunLease,
)

__all__ = [
    "InMemoryLeaseManager",
    "LeaseManager",
    "LeaderLostError",
    "LeaseLostError",
    "PgLeaseManager",
    "PgLeasePrimitives",
    "RunLease",
    "SQLiteLeaseManager",
]


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class LeaseManager(Protocol):
    async def try_acquire_leader(self, worker_id: str) -> bool: ...
    async def is_leader(self, worker_id: str) -> bool: ...
    async def release_leader(self, worker_id: str) -> None: ...
    async def acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def release(self, run_id: str, worker_id: str) -> None: ...
    async def list_stale(self) -> list[str]: ...


# ---------------------------------------------------------------------------
# InMemoryLeaseManager — unit-test backend
# ---------------------------------------------------------------------------


@dataclass
class _RunLeaseRow:
    worker_id: str
    expires_at: datetime
    acquired_at: datetime


class InMemoryLeaseManager:
    """Single-process lease tracker; thread-safe."""

    def __init__(self) -> None:
        self._leader_worker: str | None = None
        self._runs: dict[str, _RunLeaseRow] = {}
        self._lock = asyncio.Lock()

    async def try_acquire_leader(self, worker_id: str) -> bool:
        async with self._lock:
            if self._leader_worker is None or self._leader_worker == worker_id:
                self._leader_worker = worker_id
                return True
            return False

    async def is_leader(self, worker_id: str) -> bool:
        """Read-only: is ``worker_id`` the CURRENT holder? Never acquires.

        Distinct from :meth:`try_acquire_leader`, which claims a free slot. A
        guard ("am I still the writer?") must use this so a non-leader is never
        silently promoted as a side effect of being checked (deny-by-default).
        """
        async with self._lock:
            return self._leader_worker == worker_id

    async def release_leader(self, worker_id: str) -> None:
        async with self._lock:
            if self._leader_worker == worker_id:
                self._leader_worker = None

    async def acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        async with self._lock:
            existing = self._runs.get(run_id)
            now = _utcnow()
            if existing is not None and existing.expires_at > now and existing.worker_id != worker_id:
                raise LeaseLostError(
                    f"lease for {run_id} held by {existing.worker_id} until {existing.expires_at.isoformat()}"
                )
            expires = now + timedelta(seconds=ttl_seconds)
            self._runs[run_id] = _RunLeaseRow(worker_id=worker_id, expires_at=expires, acquired_at=now)
            return RunLease(run_id=run_id, worker_id=worker_id, acquired_at=now, expires_at=expires)

    async def renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        async with self._lock:
            existing = self._runs.get(run_id)
            if existing is None or existing.worker_id != worker_id:
                raise LeaseLostError(f"cannot renew {run_id}: lease not held by {worker_id}")
            now = _utcnow()
            existing.expires_at = now + timedelta(seconds=ttl_seconds)
            return RunLease(
                run_id=run_id,
                worker_id=worker_id,
                acquired_at=existing.acquired_at,
                expires_at=existing.expires_at,
            )

    async def release(self, run_id: str, worker_id: str) -> None:
        async with self._lock:
            existing = self._runs.get(run_id)
            if existing is not None and existing.worker_id == worker_id:
                self._runs.pop(run_id, None)

    async def list_stale(self) -> list[str]:
        async with self._lock:
            now = _utcnow()
            return [rid for rid, row in self._runs.items() if row.expires_at <= now]


# ---------------------------------------------------------------------------
# SQLiteLeaseManager — single-host development backend
# ---------------------------------------------------------------------------


class SQLiteLeaseManager:
    """SQLite-backed lease manager (no advisory locks — table rows + WHERE).

    Used for development environments that don't have PostgreSQL. The PG
    backend (``event_store_pg.PgLeaseManager``) is the production target.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS run_leases (
        run_id TEXT PRIMARY KEY,
        worker_id TEXT NOT NULL,
        acquired_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS leader_lock (
        lock_key INTEGER PRIMARY KEY,
        worker_id TEXT NOT NULL,
        acquired_at TEXT NOT NULL
    );
    """

    _LEADER_KEY: int = 1  # only one leader per database

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._conn.executescript(self._SCHEMA)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass

    async def try_acquire_leader(self, worker_id: str) -> bool:
        return await asyncio.to_thread(self._sync_try_acquire_leader, worker_id)

    def _sync_try_acquire_leader(self, worker_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO leader_lock(lock_key, worker_id, acquired_at) VALUES(?,?,?)",
                (self._LEADER_KEY, worker_id, _utcnow().isoformat()),
            )
            if cur.rowcount == 1:
                return True
            existing = self._conn.execute(
                "SELECT worker_id FROM leader_lock WHERE lock_key=?",
                (self._LEADER_KEY,),
            ).fetchone()
            return existing is not None and existing[0] == worker_id

    async def is_leader(self, worker_id: str) -> bool:
        return await asyncio.to_thread(self._sync_is_leader, worker_id)

    def _sync_is_leader(self, worker_id: str) -> bool:
        """Read-only leader check (no INSERT/acquire). See InMemory.is_leader."""
        with self._lock:
            existing = self._conn.execute(
                "SELECT worker_id FROM leader_lock WHERE lock_key=?",
                (self._LEADER_KEY,),
            ).fetchone()
            return existing is not None and existing[0] == worker_id

    async def release_leader(self, worker_id: str) -> None:
        await asyncio.to_thread(self._sync_release_leader, worker_id)

    def _sync_release_leader(self, worker_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM leader_lock WHERE lock_key=? AND worker_id=?",
                (self._LEADER_KEY, worker_id),
            )

    async def acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await asyncio.to_thread(self._sync_acquire_run, run_id, worker_id, ttl_seconds)

    def _sync_acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        with self._lock:
            now = _utcnow()
            expires = now + timedelta(seconds=ttl_seconds)
            row = self._conn.execute(
                "SELECT worker_id, expires_at FROM run_leases WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is not None:
                existing_worker, existing_expires = row
                if datetime.fromisoformat(existing_expires) > now and existing_worker != worker_id:
                    raise LeaseLostError(f"run {run_id} held by {existing_worker} until {existing_expires}")
            self._conn.execute(
                "INSERT INTO run_leases(run_id, worker_id, acquired_at, expires_at) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET worker_id=excluded.worker_id, "
                "acquired_at=excluded.acquired_at, expires_at=excluded.expires_at",
                (run_id, worker_id, now.isoformat(), expires.isoformat()),
            )
            return RunLease(run_id=run_id, worker_id=worker_id, acquired_at=now, expires_at=expires)

    async def renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await asyncio.to_thread(self._sync_renew, run_id, worker_id, ttl_seconds)

    def _sync_renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        with self._lock:
            row = self._conn.execute(
                "SELECT worker_id, acquired_at FROM run_leases WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if row is None or row[0] != worker_id:
                raise LeaseLostError(f"cannot renew {run_id}: lease not held by {worker_id}")
            now = _utcnow()
            expires = now + timedelta(seconds=ttl_seconds)
            self._conn.execute(
                "UPDATE run_leases SET expires_at=? WHERE run_id=? AND worker_id=?",
                (expires.isoformat(), run_id, worker_id),
            )
            return RunLease(
                run_id=run_id,
                worker_id=worker_id,
                acquired_at=datetime.fromisoformat(row[1]),
                expires_at=expires,
            )

    async def release(self, run_id: str, worker_id: str) -> None:
        await asyncio.to_thread(self._sync_release, run_id, worker_id)

    def _sync_release(self, run_id: str, worker_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM run_leases WHERE run_id=? AND worker_id=?",
                (run_id, worker_id),
            )

    async def list_stale(self) -> list[str]:
        return await asyncio.to_thread(self._sync_list_stale)

    def _sync_list_stale(self) -> list[str]:
        with self._lock:
            now_iso = _utcnow().isoformat()
            cur = self._conn.execute("SELECT run_id FROM run_leases WHERE expires_at <= ?", (now_iso,))
            return [row[0] for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# PgLeaseManager — production adapter over PgEventStore primitives
# ---------------------------------------------------------------------------


@runtime_checkable
class PgLeasePrimitives(Protocol):
    """The HA-lease surface of :class:`PgEventStore` / :class:`PgChainedEventStore`.

    Declared structurally so :class:`PgLeaseManager` never imports the (heavy,
    asyncpg-gated) PG module — the adapter only needs these six coroutines. The
    method *names* and the keyword-only signatures deliberately differ from the
    :class:`LeaseManager` Protocol (``acquire_run_lease`` vs ``acquire_run``,
    etc.); :class:`PgLeaseManager` is precisely the shim that bridges them.
    """

    async def try_acquire_leader(self, worker_id: str, *, lock_key: int = ...) -> bool: ...
    async def is_leader(self, worker_id: str, *, lock_key: int = ...) -> bool: ...
    async def release_leader(self, worker_id: str, *, lock_key: int = ...) -> None: ...
    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def release_lease(self, *, run_id: str, worker_id: str) -> None: ...
    async def list_stale_leases(self) -> list[str]: ...


class PgLeaseManager:
    """Thin :class:`LeaseManager` adapter delegating to a PG event store.

    The PG HA primitives already exist (``pg_advisory_lock`` for leader election,
    ``SELECT FOR UPDATE SKIP LOCKED`` + ``INSERT … ON CONFLICT`` for run leases)
    in :mod:`secugent.core.event_store_pg`. This adapter performs **zero SQL** —
    it only renames methods and converts the positional ``LeaseManager`` Protocol
    arguments into the keyword-only arguments the PG store expects, and lets the
    ``lock_key`` default (``0xDEADBEEF``) on the PG side stand. All errors
    (:class:`LeaseLostError`, :class:`LeaderLostError`) propagate unchanged.
    """

    def __init__(self, store: PgLeasePrimitives) -> None:
        self._store = store

    async def try_acquire_leader(self, worker_id: str) -> bool:
        return await self._store.try_acquire_leader(worker_id)

    async def is_leader(self, worker_id: str) -> bool:
        return await self._store.is_leader(worker_id)

    async def release_leader(self, worker_id: str) -> None:
        await self._store.release_leader(worker_id)

    async def acquire_run(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await self._store.acquire_run_lease(
            run_id=run_id, worker_id=worker_id, ttl_seconds=ttl_seconds
        )

    async def renew(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await self._store.renew_lease(run_id=run_id, worker_id=worker_id, ttl_seconds=ttl_seconds)

    async def release(self, run_id: str, worker_id: str) -> None:
        await self._store.release_lease(run_id=run_id, worker_id=worker_id)

    async def list_stale(self) -> list[str]:
        return await self._store.list_stale_leases()
