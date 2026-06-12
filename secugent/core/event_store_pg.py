# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — PostgreSQL backend (SQLAlchemy async + asyncpg).

Install / run (H-4)::

    pip install 'secugent[pg]'
    export DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db

Production target for multi-tenant SecuGent. The fail-closed construction path
is regression-tested in ``tests/integration/test_pg_event_store.py``; a real
Postgres lease round-trip there runs only when ``DATABASE_URL`` is set and the
``pg`` extra is installed (otherwise it skips).

This module imports ``asyncpg`` and ``sqlalchemy[asyncio]`` lazily so that
SecuGent boots on hosts without these binaries — the only consequence is
that ``backend="postgres"`` configurations fail explicitly at backend
construction with :class:`PgEventStoreError`.

RLS policy is documented in ``migrations/0002_rls.sql``; queries set
``app.tenant_id`` via ``SET LOCAL`` inside each transaction so PostgreSQL's
row-level security enforces tenant isolation even when the application code
forgets to filter.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from secugent.audit.hash_chain import (
    GENESIS,
    AuditChainBrokenError,
    ChainedEventRecord,
    canonical,
    compute_chain_hash,
    stored_view,
)
from secugent.core.contracts import Approval, ApprovalScope, Event, Run
from secugent.core.event_store import EventStoreError
from secugent.core.event_store_base import (
    LeaseLostError,
    RunLease,
)
from secugent.core.logger import redact
from secugent.core.tenancy import TenantId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

__all__ = [
    "PgChainedEventStore",
    "PgEventStore",
    "PgEventStoreError",
    "is_pg_available",
]

_logger = logging.getLogger("secugent.core.event_store_pg")


class PgEventStoreError(RuntimeError):
    """Raised on PG backend construction / startup failures."""


def is_pg_available() -> bool:
    """Quick check used by tests / factory wiring."""
    try:
        import asyncpg  # noqa: F401
        import sqlalchemy  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------------------
# DDL — applied via ``ensure_schema()`` on first connect
# ---------------------------------------------------------------------------


_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    severity TEXT NOT NULL,
    run_id TEXT,
    step_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_tenant_run ON events(tenant_id, run_id);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    scope JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    run_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals(tenant_id);

CREATE TABLE IF NOT EXISTS run_leases (
    run_id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS event_chain (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    body_canonical TEXT NOT NULL,
    UNIQUE (tenant_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_event_chain_tenant_seq ON event_chain(tenant_id, seq);

CREATE TABLE IF NOT EXISTS events_archive (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ts TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    payload JSONB NOT NULL,
    severity TEXT NOT NULL,
    run_id TEXT,
    step_id TEXT,
    archived_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_archive_tenant_ts ON events_archive(tenant_id, ts);
"""

# RLS is ENABLEd *and* FORCEd on every tenant-scoped table. In PostgreSQL,
# ENABLE alone does NOT apply policies to the table OWNER — and SecuGent commonly
# connects as the owner — so without FORCE the ``current_setting('app.tenant_id')``
# predicate is silently ignored for owner connections and queries would see ALL
# tenants' rows. FORCE closes that owner-bypass (G-C6 Stage-5 hardening). FORCE
# needs no explicit downgrade: dropping the policy/table reverses it.
_RLS_POLICY = """
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE runs FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_iso_events ON events;
CREATE POLICY tenant_iso_events ON events
    USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_iso_runs ON runs;
CREATE POLICY tenant_iso_runs ON runs
    USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_iso_approvals ON approvals;
CREATE POLICY tenant_iso_approvals ON approvals
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE event_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_chain FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_event_chain ON event_chain;
CREATE POLICY tenant_iso_event_chain ON event_chain
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE events_archive ENABLE ROW LEVEL SECURITY;
ALTER TABLE events_archive FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_iso_events_archive ON events_archive;
CREATE POLICY tenant_iso_events_archive ON events_archive
    USING (tenant_id = current_setting('app.tenant_id', true));
"""


# ---------------------------------------------------------------------------
# Backend (lazy import — raises only when actually instantiated)
# ---------------------------------------------------------------------------


class PgEventStore:
    """Async PG-backed event store + lease manager.

    Constructed with an SQLAlchemy async DSN like
    ``postgresql+asyncpg://user:pw@host:5432/db``. ``ensure_schema()`` runs
    the DDL + RLS policy once per connection pool initialisation.
    """

    def __init__(self, dsn: str) -> None:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ImportError as exc:  # pragma: no cover - env-specific
            raise PgEventStoreError(f"sqlalchemy[asyncio] required but not installed: {exc}") from exc
        if not is_pg_available():
            raise PgEventStoreError("asyncpg or sqlalchemy not installed — see `pip install 'secugent[pg]'`")
        self._dsn = dsn
        self._engine = create_async_engine(dsn, pool_pre_ping=True)

    @property
    def engine(self) -> Any:
        return self._engine

    async def ensure_schema(self, *, enable_rls: bool = True) -> None:
        """Create the schema in-process. **Dev-only** (G-H14).

        In production the schema is owned by Alembic (``alembic upgrade head``,
        ``migrations/versions/0001_baseline.py``) so that DDL is reviewed,
        versioned and reversible. ``ensure_schema`` must NOT be the production DDL
        path — the boot wiring (``api/main.py``) only calls it when
        ``SECUGENT_ENV=dev``. The Alembic baseline is byte-equivalent to
        ``_DDL`` + ``_RLS_POLICY`` (the ``drift-0`` invariant), so this dev
        convenience and the production migration produce the same schema.
        """
        from sqlalchemy import text

        async with self._engine.begin() as conn:
            for stmt in _DDL.strip().split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                await conn.execute(text(stmt))
            if enable_rls:
                for stmt in _RLS_POLICY.strip().split(";"):
                    stmt = stmt.strip()
                    if not stmt:
                        continue
                    await conn.execute(text(stmt))

    async def close(self) -> None:
        await self._engine.dispose()

    # ------------------------------------------------------------------ #
    # CRUD (G-C9) — SQLite EventStore semantics 1:1.
    #
    # Every method opens one transaction, sets ``app.tenant_id`` via
    # ``set_config`` (RLS) *and* filters with an explicit ``WHERE tenant_id``
    # (defence in depth: RLS enforces isolation even if a query forgets the
    # filter, the explicit filter enforces it even before non-owner RLS roles
    # land in Stage 5). ``set_config`` is parameter-bound so the tenant id is
    # never string-interpolated into SQL (SET LOCAL cannot bind parameters).
    # ------------------------------------------------------------------ #

    @staticmethod
    async def _bind_tenant(conn: AsyncConnection, tenant: str) -> None:
        from sqlalchemy import text

        # set_config(name, value, is_local=true) == SET LOCAL, but value is a
        # bound parameter so a hostile tenant string cannot break out of SQL.
        await conn.execute(
            text("SELECT set_config('app.tenant_id', :tenant, true)"),
            {"tenant": tenant},
        )

    async def append(self, event: Event) -> None:
        """Append-only event INSERT. Duplicate id → :class:`EventStoreError`."""
        await self.append_event_atomic(event, within_txn=_noop_within_txn)

    async def append_event_atomic(
        self,
        event: Event,
        *,
        within_txn: Callable[[AsyncConnection], Awaitable[None]],
    ) -> None:
        """Insert ``event`` and run ``within_txn`` in a single transaction.

        Mirrors the sync :meth:`EventStore.append_event_atomic`: either the event
        row and everything ``within_txn`` writes (e.g. an ``event_chain`` row)
        commit together, or the whole unit rolls back. Duplicate id or any
        durable-write failure → :class:`EventStoreError` (fail-closed).
        """
        from sqlalchemy import text
        from sqlalchemy.exc import IntegrityError, SQLAlchemyError

        try:
            payload_json = json.dumps(redact(event.payload), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise EventStoreError(f"event payload not JSON-serialisable: {exc}") from exc

        tenant = str(event.tenant_id)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                await conn.execute(
                    text(
                        "INSERT INTO events(id, tenant_id, ts, actor, type, payload, "
                        "severity, run_id, step_id) "
                        "VALUES(:id, :tenant, :ts, :actor, :type, CAST(:payload AS JSONB), "
                        ":severity, :run_id, :step_id)"
                    ),
                    {
                        "id": event.id,
                        "tenant": tenant,
                        "ts": _to_utc(event.ts),
                        "actor": event.actor,
                        "type": event.type,
                        "payload": payload_json,
                        "severity": event.severity,
                        "run_id": event.run_id,
                        "step_id": event.step_id,
                    },
                )
                await within_txn(conn)
        except IntegrityError as exc:
            raise EventStoreError(f"failed to append event {event.id}: {exc}") from exc
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to append event {event.id}: {exc}") from exc

    async def query(
        self,
        *,
        tenant_id: TenantId,
        run_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(tenant_id)
        sql = (
            "SELECT id, tenant_id, ts, actor, type, payload, severity, run_id, step_id "
            "FROM events WHERE tenant_id = :tenant"
        )
        params: dict[str, Any] = {"tenant": tenant}
        if run_id is not None:
            sql += " AND run_id = :run_id"
            params["run_id"] = run_id
        sql += " ORDER BY ts DESC LIMIT :limit"
        params["limit"] = int(limit)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                rows = (await conn.execute(text(sql), params)).fetchall()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to query events for {tenant}: {exc}") from exc
        return [_row_to_event(row) for row in rows]

    async def get_event(self, *, tenant_id: TenantId, event_id: str) -> Event | None:
        """Fetch a single event by id under the bound tenant.

        Mirrors the sync :meth:`EventStore.get_event`: the audit hash chain uses
        this to cross-check each chained record against the durable ``events``
        row without loading the whole tenant history. Non-existent → ``None``;
        any durable-read failure → :class:`EventStoreError` (fail-closed).
        """
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(tenant_id)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                row = (
                    await conn.execute(
                        text(
                            "SELECT id, tenant_id, ts, actor, type, payload, severity, "
                            "run_id, step_id FROM events WHERE id = :id AND tenant_id = :tenant"
                        ),
                        {"id": event_id, "tenant": tenant},
                    )
                ).first()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to get event {event_id}: {exc}") from exc
        if row is None:
            return None
        return _row_to_event(row)

    async def upsert_run(self, run: Run) -> None:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(run.tenant_id)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                await conn.execute(
                    text(
                        "INSERT INTO runs(id, tenant_id, goal, status, created_at, updated_at) "
                        "VALUES(:id, :tenant, :goal, :status, :created_at, :updated_at) "
                        "ON CONFLICT (id) DO UPDATE SET goal=EXCLUDED.goal, "
                        "status=EXCLUDED.status, updated_at=EXCLUDED.updated_at"
                    ),
                    {
                        "id": run.id,
                        "tenant": tenant,
                        "goal": run.goal,
                        "status": run.status,
                        "created_at": _to_utc(run.created_at),
                        "updated_at": _to_utc(run.updated_at),
                    },
                )
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to upsert run {run.id}: {exc}") from exc

    async def get_run(self, *, tenant_id: TenantId, run_id: str) -> Run | None:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(tenant_id)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                row = (
                    await conn.execute(
                        text(
                            "SELECT id, tenant_id, goal, status, created_at, updated_at "
                            "FROM runs WHERE id = :id AND tenant_id = :tenant"
                        ),
                        {"id": run_id, "tenant": tenant},
                    )
                ).first()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to get run {run_id}: {exc}") from exc
        if row is None:
            return None
        return Run(
            id=row[0],
            tenant_id=row[1],
            goal=row[2],
            status=row[3],
            created_at=row[4],
            updated_at=row[5],
        )

    async def save_approval(self, approval: Approval) -> None:
        from sqlalchemy import text
        from sqlalchemy.exc import IntegrityError, SQLAlchemyError

        tenant = str(approval.scope.tenant_id)
        scope_json = json.dumps(approval.scope.model_dump(mode="json"), ensure_ascii=False)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                await conn.execute(
                    text(
                        "INSERT INTO approvals(id, tenant_id, actor, scope, expires_at, "
                        "nonce, status, reason, created_at, run_id) "
                        "VALUES(:id, :tenant, :actor, CAST(:scope AS JSONB), :expires_at, "
                        ":nonce, :status, :reason, :created_at, :run_id) "
                        "ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, "
                        "reason=EXCLUDED.reason"
                    ),
                    {
                        "id": approval.id,
                        "tenant": tenant,
                        "actor": approval.actor,
                        "scope": scope_json,
                        "expires_at": _to_utc(approval.expires_at),
                        "nonce": approval.nonce,
                        "status": approval.status,
                        "reason": approval.reason,
                        "created_at": _to_utc(approval.created_at),
                        "run_id": approval.scope.run_id,
                    },
                )
        except IntegrityError as exc:
            # nonce UNIQUE violation → contract-equivalent with SQLite.
            raise EventStoreError(f"approval nonce conflict for {approval.id}: {exc}") from exc
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to save approval {approval.id}: {exc}") from exc

    async def get_approval(self, *, tenant_id: TenantId, approval_id: str) -> Approval | None:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(tenant_id)
        try:
            async with self._engine.begin() as conn:
                await self._bind_tenant(conn, tenant)
                row = (
                    await conn.execute(
                        text(
                            "SELECT id, actor, scope, expires_at, nonce, status, reason, "
                            "created_at FROM approvals WHERE id = :id AND tenant_id = :tenant"
                        ),
                        {"id": approval_id, "tenant": tenant},
                    )
                ).first()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to get approval {approval_id}: {exc}") from exc
        if row is None:
            return None
        return _row_to_approval(row)

    async def list_pending_approvals(self, *, tenant_id: TenantId | None = None) -> list[Approval]:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        sql = (
            "SELECT id, actor, scope, expires_at, nonce, status, reason, created_at "
            "FROM approvals WHERE status = 'pending'"
        )
        params: dict[str, Any] = {}
        tenant = str(tenant_id) if tenant_id is not None else None
        if tenant is not None:
            sql += " AND tenant_id = :tenant"
            params["tenant"] = tenant
        sql += " ORDER BY created_at ASC"
        try:
            async with self._engine.begin() as conn:
                # tenant_id=None is the owner/admin cross-tenant read (matches the
                # sync EventStore: all tenants). The explicit ``WHERE tenant_id``
                # above is the active scope when a tenant *is* given; ``set_config``
                # binds RLS to either the tenant or "" (no-tenant). In Stage 1 the
                # app connects as the table owner, which BYPASSES RLS (no FORCE RLS
                # yet — that is Stage 5 G-C6), so the owner sees all pending here,
                # exactly like the SQLite reference. When non-owner roles + FORCE
                # RLS land, this no-tenant path is blocked at the DB — documented
                # divergence; Stage 1's boot replay stays on SQLite so it is not hit.
                await self._bind_tenant(conn, tenant if tenant is not None else "")
                rows = (await conn.execute(text(sql), params)).fetchall()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to list pending approvals: {exc}") from exc
        return [_row_to_approval(row) for row in rows]

    # ------------------------------------------------------------------ #
    # Lease primitives — `pg_advisory_lock` + `SELECT FOR UPDATE SKIP LOCKED`
    # ------------------------------------------------------------------ #

    async def try_acquire_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        # WARNING (session-scope vs pool): ``pg_try_advisory_lock`` is SESSION
        # scoped, but this acquires it on a pooled connection that is RETURNED to
        # the pool on ``async with`` exit (not closed). The lock therefore rides
        # an orphaned pooled session and is NOT durably held for the caller, and
        # ``release_leader`` may run ``pg_advisory_unlock`` on a *different*
        # pooled session (no-op). This primitive is consequently NOT a reliable
        # cross-process single-writer fence on its own — it is provisioned, not
        # the live I3 guarantee. A durable leader lease needs a dedicated
        # long-lived connection or a TTL+heartbeat row; tracked for the live PG
        # HA wiring. Do not credit this method as the split-brain guard in docs.
        from sqlalchemy import text

        async with self._engine.connect() as conn:
            result = await conn.execute(
                text("SELECT pg_try_advisory_lock(:key)"),
                {"key": lock_key},
            )
            row = result.first()
            return bool(row and row[0])

    async def is_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        """Best-effort read-only check: is the advisory ``lock_key`` held by ANY session?

        Non-mutating (never calls ``pg_try_advisory_lock``) so a guard can ask
        "is the writer lock currently held?" without acquiring it. NOTE: this
        reflects whether *some* backend session holds the key, not necessarily
        *this* worker — the same session-vs-pool caveat as
        :meth:`try_acquire_leader` applies, so it is not a substitute for a real
        per-worker leader lease. Returns ``False`` when the lock is free.
        """
        from sqlalchemy import text

        async with self._engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT count(*) > 0 FROM pg_locks "
                    "WHERE locktype = 'advisory' AND objid = :key AND granted"
                ),
                {"key": lock_key & 0xFFFFFFFF},
            )
            row = result.first()
            return bool(row and row[0])

    async def release_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> None:
        from sqlalchemy import text

        async with self._engine.connect() as conn:
            await conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": lock_key})

    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        from sqlalchemy import text

        now = datetime.now(tz=UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        async with self._engine.begin() as conn:
            # Check existing lease under FOR UPDATE; if expired or held by us, claim it.
            existing = (
                await conn.execute(
                    text(
                        "SELECT worker_id, expires_at FROM run_leases "
                        "WHERE run_id=:rid FOR UPDATE SKIP LOCKED"
                    ),
                    {"rid": run_id},
                )
            ).first()
            if existing is not None:
                row_worker, row_expires = existing
                if row_expires > now and row_worker != worker_id:
                    raise LeaseLostError(f"run {run_id} held by {row_worker} until {row_expires.isoformat()}")
            await conn.execute(
                text(
                    "INSERT INTO run_leases(run_id, worker_id, acquired_at, expires_at) "
                    "VALUES(:rid, :wid, :acq, :exp) "
                    "ON CONFLICT (run_id) DO UPDATE SET worker_id=EXCLUDED.worker_id, "
                    "acquired_at=EXCLUDED.acquired_at, expires_at=EXCLUDED.expires_at"
                ),
                {"rid": run_id, "wid": worker_id, "acq": now, "exp": expires},
            )
        return RunLease(run_id=run_id, worker_id=worker_id, acquired_at=now, expires_at=expires)

    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        from sqlalchemy import text

        now = datetime.now(tz=UTC)
        expires = now + timedelta(seconds=ttl_seconds)
        async with self._engine.begin() as conn:
            result = await conn.execute(
                text(
                    "UPDATE run_leases SET expires_at=:exp WHERE run_id=:rid AND "
                    "worker_id=:wid AND expires_at > :now RETURNING acquired_at"
                ),
                {
                    "rid": run_id,
                    "wid": worker_id,
                    "exp": expires,
                    "now": now,
                },
            )
            row = result.first()
            if row is None:
                raise LeaseLostError(f"cannot renew lease for {run_id}: lost to expiry or another worker")
            acquired_at = row[0]
        return RunLease(
            run_id=run_id,
            worker_id=worker_id,
            acquired_at=acquired_at,
            expires_at=expires,
        )

    async def release_lease(self, *, run_id: str, worker_id: str) -> None:
        from sqlalchemy import text

        async with self._engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM run_leases WHERE run_id=:rid AND worker_id=:wid"),
                {"rid": run_id, "wid": worker_id},
            )

    async def list_stale_leases(self) -> list[str]:
        from sqlalchemy import text

        now = datetime.now(tz=UTC)
        async with self._engine.connect() as conn:
            result = await conn.execute(
                text("SELECT run_id FROM run_leases WHERE expires_at <= :now"),
                {"now": now},
            )
            return [row[0] for row in result.fetchall()]

    # ------------------------------------------------------------------ #
    # Retention (G-H2) — RLS-aware archive-table pattern. Each call runs in
    # one transaction that binds ``app.tenant_id`` via ``set_config(..., true)``
    # (SET LOCAL) *and* filters ``WHERE tenant_id`` (defence in depth: RLS +
    # explicit). Archiving COPIES rows into ``events_archive``; purge deletes
    # only hot rows already mirrored there (fail-closed against data loss).
    # ------------------------------------------------------------------ #

    @staticmethod
    def _day_bounds_utc(day: date) -> tuple[datetime, datetime]:
        start = datetime(day.year, day.month, day.day, tzinfo=UTC)
        return start, start + timedelta(days=1)

    async def archive_day(self, *, tenant_id: str, day: date) -> int:
        """Copy a day's events into ``events_archive``; return rows newly added.

        Idempotent via ``ON CONFLICT (id) DO NOTHING``. Does NOT delete from the
        hot table. RLS-bound: ``set_config('app.tenant_id', ..., true)`` (SET
        LOCAL) + explicit ``WHERE tenant_id``.
        """
        from sqlalchemy import text

        start, end = self._day_bounds_utc(day)
        archived_at = datetime.now(tz=UTC)
        async with self._engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            result = await conn.execute(
                text(
                    "INSERT INTO events_archive("
                    "id, tenant_id, ts, actor, type, payload, severity, run_id, "
                    "step_id, archived_at) "
                    "SELECT id, tenant_id, ts, actor, type, payload, severity, "
                    "run_id, step_id, :arch FROM events "
                    "WHERE tenant_id=:tid AND ts >= :start AND ts < :end "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {"arch": archived_at, "tid": tenant_id, "start": start, "end": end},
            )
            return int(result.rowcount or 0)

    async def purge_day(self, *, tenant_id: str, day: date) -> int:
        """Delete a day's hot rows already mirrored in archive; return deleted.

        Fail-closed against data loss: only deletes hot rows whose ``id`` exists
        in ``events_archive`` for the same tenant. RLS-bound as in
        :meth:`archive_day`.
        """
        from sqlalchemy import text

        start, end = self._day_bounds_utc(day)
        async with self._engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            result = await conn.execute(
                text(
                    "DELETE FROM events WHERE tenant_id=:tid AND ts >= :start "
                    "AND ts < :end AND id IN ("
                    "SELECT id FROM events_archive WHERE tenant_id=:tid)"
                ),
                {"tid": tenant_id, "start": start, "end": end},
            )
            return int(result.rowcount or 0)

    async def is_day_archived(self, *, tenant_id: str, day: date) -> bool:
        """True iff every hot event for ``(tenant_id, day)`` is mirrored in archive."""
        from sqlalchemy import text

        start, end = self._day_bounds_utc(day)
        async with self._engine.begin() as conn:
            await conn.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            result = await conn.execute(
                text(
                    "SELECT COUNT(*) FROM events WHERE tenant_id=:tid AND ts >= :start "
                    "AND ts < :end AND id NOT IN ("
                    "SELECT id FROM events_archive WHERE tenant_id=:tid)"
                ),
                {"tid": tenant_id, "start": start, "end": end},
            )
            row = result.first()
            return bool(row is not None and int(row[0]) == 0)


# ---------------------------------------------------------------------------
# Row → model helpers (module-level; shared by CRUD + chain read path)
# ---------------------------------------------------------------------------


def _to_utc(dt: datetime) -> datetime:
    """Normalise a datetime to a tz-aware UTC value (matches SQLite ``_iso``)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _json_field(value: Any) -> Any:
    """JSONB columns come back as already-parsed objects under asyncpg; tolerate
    a str (some drivers / CAST paths) by parsing it once."""
    if isinstance(value, str):
        return json.loads(value)
    return value


def _row_to_event(row: Any) -> Event:
    return Event(
        id=row[0],
        tenant_id=row[1],
        ts=row[2],
        actor=row[3],
        type=row[4],
        payload=_json_field(row[5]),
        severity=row[6],
        run_id=row[7],
        step_id=row[8],
    )


def _row_to_approval(row: Any) -> Approval:
    scope = ApprovalScope.model_validate(_json_field(row[2]))
    return Approval(
        id=row[0],
        actor=row[1],
        scope=scope,
        expires_at=row[3],
        nonce=row[4],
        status=row[5],
        reason=row[6],
        created_at=row[7],
    )


async def _noop_within_txn(conn: AsyncConnection) -> None:
    """Default ``within_txn`` for a plain (unchained) append — does nothing."""
    return None


# ---------------------------------------------------------------------------
# PgChainedEventStore (G-M8) — hash chain persisted in PG ``event_chain``
# ---------------------------------------------------------------------------


class PgChainedEventStore:
    """PG hash-chained event store.

    Delegates the CRUD contract to an inner :class:`PgEventStore`; overrides
    :meth:`append` to write the event row and its ``event_chain`` row in a single
    transaction, serialised per tenant by ``pg_advisory_xact_lock`` so the chain
    is a single continuous ``prev_hash`` → ``event_hash`` sequence even under
    concurrent writers. The chain link hashes are computed by the public,
    backend-agnostic functions in :mod:`secugent.audit.hash_chain` — so the PG
    chain is byte-identical to the SQLite chain for the same event stream.
    """

    def __init__(self, inner: PgEventStore) -> None:
        self._inner = inner

    @property
    def inner(self) -> PgEventStore:
        return self._inner

    # -- write path (chained) ------------------------------------------- #

    async def append(self, event: Event) -> None:
        from sqlalchemy import text

        tenant = str(event.tenant_id)
        # Hash the redacted/normalised stored view so the chain never carries
        # plaintext PII and re-derivation matches the persisted body.
        body = canonical(stored_view(event))

        async def _write_chain_row(conn: AsyncConnection) -> None:
            # Per-tenant serialisation: hold a transaction-scoped advisory lock so
            # two concurrent appends cannot read the same tail and fork the chain.
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:tenant))"),
                {"tenant": tenant},
            )
            tail = (
                await conn.execute(
                    text(
                        "SELECT event_hash, seq FROM event_chain WHERE tenant_id = :tenant "
                        "ORDER BY seq DESC LIMIT 1"
                    ),
                    {"tenant": tenant},
                )
            ).first()
            if tail is None:
                prev_hash, seq = GENESIS, 0
            else:
                prev_hash, seq = tail[0], int(tail[1]) + 1
            event_hash = compute_chain_hash(prev_hash, body)
            await conn.execute(
                text(
                    "INSERT INTO event_chain(event_id, tenant_id, seq, prev_hash, "
                    "event_hash, body_canonical) "
                    "VALUES(:event_id, :tenant, :seq, :prev_hash, :event_hash, :body)"
                ),
                {
                    "event_id": event.id,
                    "tenant": tenant,
                    "seq": seq,
                    "prev_hash": prev_hash,
                    "event_hash": event_hash,
                    "body": body,
                },
            )

        await self._inner.append_event_atomic(event, within_txn=_write_chain_row)

    # -- read path + verification --------------------------------------- #

    async def read_chain(self, *, tenant_id: TenantId) -> list[ChainedEventRecord]:
        return [rec for rec, _body in await self._iter_chain_rows(tenant_id=tenant_id)]

    async def _iter_chain_rows(self, *, tenant_id: TenantId) -> list[tuple[ChainedEventRecord, str]]:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError

        tenant = str(tenant_id)
        try:
            async with self._inner.engine.begin() as conn:
                await PgEventStore._bind_tenant(conn, tenant)
                rows = (
                    await conn.execute(
                        text(
                            "SELECT event_id, seq, prev_hash, event_hash, body_canonical "
                            "FROM event_chain WHERE tenant_id = :tenant ORDER BY seq ASC"
                        ),
                        {"tenant": tenant},
                    )
                ).fetchall()
        except SQLAlchemyError as exc:
            raise EventStoreError(f"failed to read chain for {tenant}: {exc}") from exc
        out: list[tuple[ChainedEventRecord, str]] = []
        for event_id, seq, prev_hash, event_hash, body_canonical in rows:
            try:
                event = Event.model_validate(json.loads(body_canonical))
            except (json.JSONDecodeError, ValidationError) as exc:
                raise AuditChainBrokenError(
                    f"event {event_id} chain body is corrupt at seq={seq}: {exc}"
                ) from exc
            out.append(
                (
                    ChainedEventRecord(event=event, seq=int(seq), prev_hash=prev_hash, event_hash=event_hash),
                    body_canonical,
                )
            )
        return out

    async def verify_chain(self, *, tenant_id: TenantId) -> bool:
        """Walk the chain front-to-back, re-deriving each link, and cross-check
        every record against the live ``events`` table.

        Raises :class:`AuditChainBrokenError` on the first inconsistency —
        observably equivalent to the SQLite
        :meth:`secugent.audit.hash_chain.ChainedEventStore.verify_chain`: a
        ``prev_hash`` break, an ``event_hash`` mismatch (chain-table tamper), an
        event present in the chain but missing from the store (partial-write gap),
        or an ``events`` row whose canonical form no longer matches the chained
        body (underlying store tamper). The chain table is NOT a second source of
        truth: the ``events`` table is (SECURITY_CONTRACT §5/§10.1)."""
        last_hash = GENESIS
        for record, body_canonical in await self._iter_chain_rows(tenant_id=tenant_id):
            expected = compute_chain_hash(last_hash, body_canonical)
            if record.prev_hash != last_hash:
                raise AuditChainBrokenError(
                    f"prev_hash mismatch at seq={record.seq} (event={record.event.id})"
                )
            if record.event_hash != expected:
                raise AuditChainBrokenError(
                    f"event_hash mismatch at seq={record.seq} "
                    f"(event={record.event.id}) — chain record tampered"
                )
            # Cross-check the live ``events`` row (store = source of truth). The
            # chain stores the redacted, UTC-normalised body, so re-normalise the
            # live row through ``stored_view`` before comparing — byte-equivalent
            # to the SQLite reference's ``_canonical(live)``.
            live = await self._inner.get_event(tenant_id=tenant_id, event_id=record.event.id)
            if live is None:
                raise AuditChainBrokenError(
                    f"event {record.event.id} present in chain but missing from store"
                )
            if canonical(stored_view(live)) != body_canonical:
                raise AuditChainBrokenError(
                    f"event_hash mismatch at seq={record.seq} "
                    f"(event={record.event.id}) — underlying payload tampered"
                )
            last_hash = record.event_hash
        return True

    # -- CRUD delegation ------------------------------------------------ #

    async def query(self, *, tenant_id: TenantId, run_id: str | None = None, limit: int = 100) -> list[Event]:
        return await self._inner.query(tenant_id=tenant_id, run_id=run_id, limit=limit)

    async def upsert_run(self, run: Run) -> None:
        await self._inner.upsert_run(run)

    async def get_run(self, *, tenant_id: TenantId, run_id: str) -> Run | None:
        return await self._inner.get_run(tenant_id=tenant_id, run_id=run_id)

    async def save_approval(self, approval: Approval) -> None:
        await self._inner.save_approval(approval)

    async def get_approval(self, *, tenant_id: TenantId, approval_id: str) -> Approval | None:
        return await self._inner.get_approval(tenant_id=tenant_id, approval_id=approval_id)

    async def list_pending_approvals(self, *, tenant_id: TenantId | None = None) -> list[Approval]:
        return await self._inner.list_pending_approvals(tenant_id=tenant_id)

    # -- HA primitives (delegate to inner PgEventStore) ----------------- #

    async def try_acquire_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        return await self._inner.try_acquire_leader(worker_id, lock_key=lock_key)

    async def is_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        return await self._inner.is_leader(worker_id, lock_key=lock_key)

    async def release_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> None:
        await self._inner.release_leader(worker_id, lock_key=lock_key)

    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await self._inner.acquire_run_lease(
            run_id=run_id, worker_id=worker_id, ttl_seconds=ttl_seconds
        )

    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await self._inner.renew_lease(run_id=run_id, worker_id=worker_id, ttl_seconds=ttl_seconds)

    async def release_lease(self, *, run_id: str, worker_id: str) -> None:
        await self._inner.release_lease(run_id=run_id, worker_id=worker_id)

    async def list_stale_leases(self) -> list[str]:
        return await self._inner.list_stale_leases()

    # -- Retention (G-H2) — delegate to inner PgEventStore -------------- #

    async def archive_day(self, *, tenant_id: str, day: date) -> int:
        return await self._inner.archive_day(tenant_id=tenant_id, day=day)

    async def purge_day(self, *, tenant_id: str, day: date) -> int:
        return await self._inner.purge_day(tenant_id=tenant_id, day=day)

    async def is_day_archived(self, *, tenant_id: str, day: date) -> bool:
        return await self._inner.is_day_archived(tenant_id=tenant_id, day=day)
