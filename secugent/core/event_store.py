# SPDX-License-Identifier: Apache-2.0
"""SQLite-backed durable event/audit store.

The store is the *single source of truth* for state
transitions. Every important event must be appended here **before** being
broadcast on the Event Bus, and the store must survive server restarts so that
pending approvals and the most recent events can be recovered.

The implementation is intentionally dependency-free (stdlib :mod:`sqlite3`).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

from secugent.core.agent_config import AgentConfig
from secugent.core.contracts import Approval, ApprovalScope, ApprovalStatus, Event, Run
from secugent.core.logger import redact

__all__ = ["EventStore", "EventStoreError"]

_LEGACY_TENANT_ID = "legacy-default"
_TENANT_TABLES = ("events", "approvals", "runs")

# Fixed column projections (no user input) used by single-event reads. Written as
# plain string literals (no interpolation) so the table name can never be tainted
# — parameters are always bound positionally — while keeping the live∪archive
# union read in :meth:`EventStore.get_event`.
_EVENT_SELECT_HOT = "SELECT id, tenant_id, ts, actor, type, payload, severity, run_id, step_id FROM events"
_EVENT_SELECT_ARCHIVE = (
    "SELECT id, tenant_id, ts, actor, type, payload, severity, run_id, step_id FROM events_archive"
)


class EventStoreError(RuntimeError):
    """Raised on durable append failures.

    Callers MUST treat this as fail-closed (do not continue auto-execution).
    """


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL,
    severity TEXT NOT NULL,
    run_id TEXT,
    step_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_tenant_run ON events(tenant_id, run_id);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL,
    run_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_run ON approvals(run_id);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant ON approvals(tenant_id);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_tenant ON runs(tenant_id);

CREATE TABLE IF NOT EXISTS agent_configs (
    tenant_id TEXT PRIMARY KEY,
    config TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events_archive (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL,
    severity TEXT NOT NULL,
    run_id TEXT,
    step_id TEXT,
    archived_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_archive_tenant_ts ON events_archive(tenant_id, ts);
"""


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_legacy_schema(conn: sqlite3.Connection) -> None:
    """Upgrade pre-multitenancy SQLite stores in place.

    SQLite's ``CREATE TABLE IF NOT EXISTS`` does not add columns to existing
    tables, so a PHASE 0 database can fail later when tenant indexes are
    created. Existing rows pre-date tenancy and are assigned to the legacy
    default tenant.
    """

    for table in _TENANT_TABLES:
        columns = _table_columns(conn, table)
        if columns and "tenant_id" not in columns:
            conn.execute(
                f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '{_LEGACY_TENANT_ID}'"
            )

    if _table_columns(conn, "approvals"):
        rows = conn.execute("SELECT id, scope FROM approvals").fetchall()
        for approval_id, scope_text in rows:
            try:
                scope = json.loads(scope_text)
            except (TypeError, ValueError):
                continue
            if isinstance(scope, dict) and "tenant_id" not in scope:
                scope["tenant_id"] = _LEGACY_TENANT_ID
                conn.execute(
                    "UPDATE approvals SET scope=? WHERE id=?",
                    (json.dumps(scope, ensure_ascii=False), approval_id),
                )


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


class EventStore:
    """Thread-safe SQLite event store.

    Designed for moderate write concurrency (a single FastAPI process).
    All writes go through a process-level lock to serialize SQLite access.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        try:
            self._conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
                isolation_level=None,  # autocommit; we manage transactions
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            _migrate_legacy_schema(self._conn)
            self._conn.executescript(_SCHEMA)
        except sqlite3.Error as exc:  # pragma: no cover - environment-specific
            raise EventStoreError(f"failed to open event store at {self._path}: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass

    @property
    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #

    def append_event(self, event: Event) -> None:
        """Persist an event. On failure, raises :class:`EventStoreError`.

        Payload is redacted before being JSON-serialised.
        """
        try:
            redacted_payload = redact(event.payload)
            serialised = json.dumps(redacted_payload, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise EventStoreError(f"event payload not JSON-serialisable: {exc}") from exc

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO events(id, tenant_id, ts, actor, type, payload, severity, "
                    "run_id, step_id) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        event.id,
                        str(event.tenant_id),
                        _iso(event.ts),
                        event.actor,
                        event.type,
                        serialised,
                        event.severity,
                        event.run_id,
                        event.step_id,
                    ),
                )
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to append event {event.id}: {exc}") from exc

    def append_event_atomic(
        self,
        event: Event,
        *,
        within_txn: Callable[[sqlite3.Connection], None],
    ) -> None:
        """Append ``event`` and run ``within_txn`` in a single SQLite transaction.

        the audit hash chain needs the event body and its chain
        row to be written *atomically*. The callback receives this store's live
        connection and may issue additional INSERTs (e.g. into ``event_chain``)
        in the same DB file; either everything commits or — on any failure in the
        event INSERT or the callback — the whole transaction rolls back. No
        partial write (a chain row with no matching event, or vice versa) can
        survive to permanently invalidate :meth:`verify_chain`.

        Raises :class:`EventStoreError` on any durable-write failure (fail-closed).
        """
        try:
            redacted_payload = redact(event.payload)
            serialised = json.dumps(redacted_payload, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise EventStoreError(f"event payload not JSON-serialisable: {exc}") from exc

        try:
            with self._lock:
                self._conn.execute("BEGIN")
                try:
                    self._conn.execute(
                        "INSERT INTO events(id, tenant_id, ts, actor, type, payload, "
                        "severity, run_id, step_id) VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            event.id,
                            str(event.tenant_id),
                            _iso(event.ts),
                            event.actor,
                            event.type,
                            serialised,
                            event.severity,
                            event.run_id,
                            event.step_id,
                        ),
                    )
                    within_txn(self._conn)
                    self._conn.execute("COMMIT")
                except BaseException:
                    # Roll back the whole unit so neither the event nor the
                    # callback's writes persist. Re-raise to the caller.
                    self._conn.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to append event {event.id}: {exc}") from exc

    @staticmethod
    def _gate_clause(gate: str) -> tuple[str, list[Any]]:
        """Build a SQL predicate that matches a decision-gate event for ``gate``.

        A row matches when its ``payload.gate`` equals ``gate`` OR its ``type``
        begins with ``<gate>`` (e.g. ``hitl.decided`` for ``gate="hitl"``). The
        predicate is pushed into SQL — NOT applied after pagination — so OFFSET,
        LIMIT and the row count are all computed over the *filtered* set. Applying
        it post-slice (the old console behaviour) produced an empty first page
        while ``pages>1`` because the filter only saw the current page window
        (adversarial finding-1).

        The ``type LIKE <gate>%`` arm has its LIKE metacharacters escaped (``%``,
        ``_``, ``\\``) with an explicit ``ESCAPE '\\'`` so a gate value such as
        ``a_b`` cannot widen the match to ``axb``.
        """
        escaped = gate.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clause = "(json_extract(payload, '$.gate') = ? OR type LIKE ? ESCAPE '\\')"
        return clause, [gate, f"{escaped}%"]

    def count_events(
        self,
        *,
        tenant_id: str | None = None,
        run_id: str | None = None,
        event_type: str | None = None,
        gate: str | None = None,
    ) -> int:
        """Count events matching the same filters :meth:`list_events` accepts.

        Used by the console AuditExplorer route to compute ``total``/``pages`` over
        the *filtered* set so pagination stays consistent with a ``gate`` filter
        (finding-1). Pure read; never mutates.
        """
        query = "SELECT COUNT(*) FROM events"
        clauses, params = self._filter_clauses(
            tenant_id=tenant_id, run_id=run_id, event_type=event_type, gate=gate
        )
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        with self._lock:
            cur = self._conn.execute(query, params)
            row = cur.fetchone()
        return int(row[0]) if row is not None else 0

    @classmethod
    def _filter_clauses(
        cls,
        *,
        tenant_id: str | None,
        run_id: str | None,
        event_type: str | None,
        gate: str | None,
    ) -> tuple[list[str], list[Any]]:
        """Shared WHERE-clause builder for the equality/gate filters.

        Centralising it keeps :meth:`list_events` and :meth:`count_events`
        byte-for-byte consistent — the count must select exactly the rows the
        listing paginates over, or ``total``/``pages`` drift from ``events``.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if event_type is not None:
            clauses.append("type = ?")
            params.append(event_type)
        if gate is not None:
            gate_clause, gate_params = cls._gate_clause(gate)
            clauses.append(gate_clause)
            params.extend(gate_params)
        return clauses, params

    def list_events(
        self,
        *,
        tenant_id: str | None = None,
        run_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        since: datetime | None = None,
        event_type: str | None = None,
        gate: str | None = None,
        keyset_before: tuple[datetime, str] | None = None,
    ) -> list[Event]:
        """Return events newest-first under a **total order** ``(ts DESC, id DESC)``.

        The ``id`` tiebreaker makes the sort a total order: events sharing a ``ts``
        (the common case) have a deterministic, stable position across queries
        instead of SQLite's unspecified tie order. Without it, OFFSET paging over
        a concurrently-mutated table can skip or duplicate rows whose ``ts`` is
        equal (adversarial-review finding-3).

        ``gate`` pushes the console decision-gate filter into SQL (see
        :meth:`_gate_clause`) so it is applied BEFORE ``OFFSET``/``LIMIT`` — the
        page and the count both span the filtered set.

        ``keyset_before`` selects the page strictly *after* a ``(ts, id)`` cursor
        (``WHERE (ts, id) < (cursor_ts, cursor_id)`` under the same total order),
        enabling race-free keyset pagination: unlike OFFSET, a concurrent
        append/purge cannot shift the window and cause a skip/duplicate. When set,
        ``offset`` is ignored (the two paging modes are mutually exclusive).
        """
        query = "SELECT id, tenant_id, ts, actor, type, payload, severity, run_id, step_id FROM events"
        clauses, params = self._filter_clauses(
            tenant_id=tenant_id, run_id=run_id, event_type=event_type, gate=gate
        )
        if since is not None:
            clauses.append("ts >= ?")
            params.append(_iso(since))
        if keyset_before is not None:
            # Keyset cursor: rows strictly before (cursor_ts, cursor_id) under the
            # (ts DESC, id DESC) total order. SQLite has no row-value comparison in
            # this dialect path, so expand it explicitly: ts < cur_ts, OR equal ts
            # with id < cur_id.
            cursor_ts, cursor_id = keyset_before
            clauses.append("(ts < ? OR (ts = ? AND id < ?))")
            iso_cursor = _iso(cursor_ts)
            params.extend((iso_cursor, iso_cursor, cursor_id))
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(int(limit))
        if keyset_before is None:
            query += " OFFSET ?"
            params.append(int(offset))

        with self._lock:
            cur = self._conn.execute(query, params)
            rows = cur.fetchall()

        return [self._row_to_event(row) for row in rows]

    def get_event(self, event_id: str, *, tenant_id: str | None = None) -> Event | None:
        """Fetch a single event by id (optionally scoped to a tenant).

        Used by the audit hash chain to verify each chained event against the
        durable store without loading the whole tenant history into memory.

        Reads the *union* of the hot ``events`` table and ``events_archive``:
        once a sealed-and-expired day is archived+purged its rows leave
        the hot table, but :meth:`ChainedEventStore.verify_chain` must still
        resolve them to confirm the append-only chain links cleanly. The hot
        table takes precedence (it should never disagree, but a deterministic
        tie-break keeps reads stable).
        """
        params: list[Any] = [event_id]
        tenant_clause = ""
        if tenant_id is not None:
            tenant_clause = " AND tenant_id=?"
            params.append(tenant_id)
        hot_q = _EVENT_SELECT_HOT + " WHERE id=?" + tenant_clause
        archive_q = _EVENT_SELECT_ARCHIVE + " WHERE id=?" + tenant_clause
        with self._lock:
            cur = self._conn.execute(hot_q, params)
            row = cur.fetchone()
            if row is None:
                cur = self._conn.execute(archive_q, params)
                row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_event(row)

    # ------------------------------------------------------------------ #
    # Retention — archive-table pattern. Append-only is preserved:
    # archiving COPIES rows into ``events_archive``; purge only deletes hot
    # rows already confirmed present in the archive. The ``event_chain`` table
    # is never touched, and ``get_event`` reads the live∪archive union so
    # ``verify_chain`` still resolves archived events.
    # ------------------------------------------------------------------ #

    @staticmethod
    def _day_bounds_utc(day: date) -> tuple[str, str]:
        """Return ``[day, day+1)`` as ISO-8601 UTC strings (half-open range).

        Event ``ts`` is normalised to UTC ISO on write (:func:`_iso`), so a
        lexicographic comparison on the stored string selects exactly the
        events whose UTC date equals ``day`` — the same UTC boundary the daily
        Merkle sealer uses (``iter_hashes_for_day`` default tz=UTC).
        """
        start = datetime(day.year, day.month, day.day, tzinfo=UTC)
        end = start + timedelta(days=1)
        return _iso(start), _iso(end)

    def archive_day(self, *, tenant_id: str, day: date) -> int:
        """Copy a day's events into ``events_archive``; return rows newly added.

        Idempotent: ``INSERT OR IGNORE`` skips rows already archived (PK = id).
        Does NOT delete from the hot table — purge is a separate, verify-gated
        step. Raises :class:`EventStoreError` on durable-write failure.
        """
        start, end = self._day_bounds_utc(day)
        archived_at = _iso(datetime.now(tz=UTC))
        try:
            with self._lock:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO events_archive("
                    "id, tenant_id, ts, actor, type, payload, severity, run_id, "
                    "step_id, archived_at) "
                    "SELECT id, tenant_id, ts, actor, type, payload, severity, "
                    "run_id, step_id, ? FROM events "
                    "WHERE tenant_id=? AND ts >= ? AND ts < ?",
                    (archived_at, tenant_id, start, end),
                )
                return int(cur.rowcount)
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to archive day {day.isoformat()} for {tenant_id}: {exc}") from exc

    def purge_day(self, *, tenant_id: str, day: date) -> int:
        """Delete a day's hot rows that are already archived; return rows deleted.

        Fail-closed against data loss (I5): only deletes hot ``events`` rows
        whose ``id`` exists in ``events_archive`` for the same tenant. A hot row
        with no archive copy is left untouched. Raises :class:`EventStoreError`
        on durable-write failure.
        """
        start, end = self._day_bounds_utc(day)
        try:
            with self._lock:
                cur = self._conn.execute(
                    "DELETE FROM events WHERE tenant_id=? AND ts >= ? AND ts < ? "
                    "AND id IN (SELECT id FROM events_archive WHERE tenant_id=?)",
                    (tenant_id, start, end, tenant_id),
                )
                return int(cur.rowcount)
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to purge day {day.isoformat()} for {tenant_id}: {exc}") from exc

    def is_day_archived(self, *, tenant_id: str, day: date) -> bool:
        """True iff every hot event for ``(tenant_id, day)`` is mirrored in archive.

        Used by the retention service to decide a day is safe to purge. A day
        with zero hot events is trivially "archived" (nothing to lose).
        """
        start, end = self._day_bounds_utc(day)
        with self._lock:
            cur = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE tenant_id=? AND ts >= ? AND ts < ? "
                "AND id NOT IN (SELECT id FROM events_archive WHERE tenant_id=?)",
                (tenant_id, start, end, tenant_id),
            )
            unarchived = int(cur.fetchone()[0])
        return unarchived == 0

    @staticmethod
    def _row_to_event(row: Iterable[Any]) -> Event:
        cols = list(row)
        return Event(
            id=cols[0],
            tenant_id=cols[1],
            ts=_parse_dt(cols[2]),
            actor=cols[3],
            type=cols[4],
            payload=json.loads(cols[5]),
            severity=cols[6],
            run_id=cols[7],
            step_id=cols[8],
        )

    # ------------------------------------------------------------------ #
    # Runs
    # ------------------------------------------------------------------ #

    def upsert_run(self, run: Run) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO runs(id, tenant_id, goal, status, created_at, updated_at) "
                    "VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET goal=excluded.goal, status=excluded.status, "
                    "updated_at=excluded.updated_at",
                    (
                        run.id,
                        str(run.tenant_id),
                        run.goal,
                        run.status,
                        _iso(run.created_at),
                        _iso(run.updated_at),
                    ),
                )
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to upsert run {run.id}: {exc}") from exc

    def get_run(self, run_id: str, *, tenant_id: str | None = None) -> Run | None:
        query = "SELECT id, tenant_id, goal, status, created_at, updated_at FROM runs WHERE id=?"
        params: list[Any] = [run_id]
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        with self._lock:
            cur = self._conn.execute(query, params)
            row = cur.fetchone()
        if row is None:
            return None
        return Run(
            id=row[0],
            tenant_id=row[1],
            goal=row[2],
            status=row[3],
            created_at=_parse_dt(row[4]),
            updated_at=_parse_dt(row[5]),
        )

    # ------------------------------------------------------------------ #
    # Agent configuration
    # ------------------------------------------------------------------ #

    def save_agent_config(self, config: AgentConfig) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO agent_configs(tenant_id, config, updated_at) "
                    "VALUES(?,?,?) "
                    "ON CONFLICT(tenant_id) DO UPDATE SET "
                    "config=excluded.config, updated_at=excluded.updated_at",
                    (
                        str(config.tenant_id),
                        config.model_dump_json(),
                        _iso(config.updated_at),
                    ),
                )
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to save agent config for {config.tenant_id}: {exc}") from exc

    def get_agent_config(self, tenant_id: str) -> AgentConfig | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT config FROM agent_configs WHERE tenant_id=?",
                (tenant_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        try:
            return AgentConfig.model_validate_json(row[0])
        except ValueError as exc:
            raise EventStoreError(f"stored agent config for {tenant_id} is invalid: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Approvals
    # ------------------------------------------------------------------ #

    def save_approval(self, approval: Approval) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO approvals(id, tenant_id, actor, scope, expires_at, nonce, status, "
                    "reason, created_at, run_id) VALUES(?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET status=excluded.status, reason=excluded.reason",
                    (
                        approval.id,
                        str(approval.scope.tenant_id),
                        approval.actor,
                        approval.scope.model_dump_json(),
                        _iso(approval.expires_at),
                        approval.nonce,
                        approval.status,
                        approval.reason,
                        _iso(approval.created_at),
                        approval.scope.run_id,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EventStoreError(f"approval nonce conflict for {approval.id}: {exc}") from exc
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to save approval {approval.id}: {exc}") from exc

    def update_approval_status(
        self, approval_id: str, status: ApprovalStatus, reason: str | None = None
    ) -> None:
        try:
            with self._lock:
                self._conn.execute(
                    "UPDATE approvals SET status=?, reason=COALESCE(?, reason) WHERE id=?",
                    (status, reason, approval_id),
                )
        except sqlite3.Error as exc:
            raise EventStoreError(f"failed to update approval {approval_id}: {exc}") from exc

    def get_approval(self, approval_id: str, *, tenant_id: str | None = None) -> Approval | None:
        query = (
            "SELECT id, actor, scope, expires_at, nonce, status, reason, created_at FROM approvals WHERE id=?"
        )
        params: list[Any] = [approval_id]
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        with self._lock:
            cur = self._conn.execute(query, params)
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_approval(row)

    def list_pending_approvals(self, *, tenant_id: str | None = None) -> list[Approval]:
        query = (
            "SELECT id, actor, scope, expires_at, nonce, status, reason, created_at "
            "FROM approvals WHERE status='pending'"
        )
        params: list[Any] = []
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        query += " ORDER BY created_at ASC"
        with self._lock:
            cur = self._conn.execute(query, params)
            rows = cur.fetchall()
        return [self._row_to_approval(r) for r in rows]

    def find_approval_by_nonce(self, nonce: str) -> Approval | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, actor, scope, expires_at, nonce, status, reason, created_at "
                "FROM approvals WHERE nonce=?",
                (nonce,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_approval(row)

    @staticmethod
    def _row_to_approval(row: Iterable[Any]) -> Approval:
        cols = list(row)
        scope = ApprovalScope.model_validate_json(cols[2])
        return Approval(
            id=cols[0],
            actor=cols[1],
            scope=scope,
            expires_at=_parse_dt(cols[3]),
            nonce=cols[4],
            status=cols[5],
            reason=cols[6],
            created_at=_parse_dt(cols[7]),
        )
