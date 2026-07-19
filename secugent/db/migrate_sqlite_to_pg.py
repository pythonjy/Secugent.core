# SPDX-License-Identifier: Apache-2.0
"""Append-only SQLite→PG migration with hash-chain re-verification.

Copies the durable run + hash-chained event history from the SQLite
reference store into PostgreSQL **in chain order**, then re-verifies the chain on
the PG side (reusing :mod:`secugent.audit.hash_chain` semantics via
:meth:`PgChainedEventStore.verify_chain`) and asserts the PG chain reproduces the
SQLite source **byte-identically** (the tail ``event_hash`` must match). Any
break, truncation, or divergence aborts the migration non-zero (fail-closed) and
leaves explicit evidence — never a partial "success" / cutover flag (INV-C1-1).

Order of operations per tenant (fail-closed at each step):

1. Verify the SQLite **source** chain first (``ChainedEventStore.verify_chain``).
   A broken/tampered source aborts BEFORE any PG write — we never copy a chain we
   cannot trust.
2. Copy ``runs`` (``upsert_run``), then append every chained event in ``seq``
   order (the PG chained store recomputes each link from the same canonical body,
   so the hashes reproduce identically). Idempotent/resumable: events already
   present in PG are skipped.
3. Re-verify the **PG** chain end to end (``verify_chain``).
4. Assert the PG tail ``event_hash`` equals the SQLite source tail (identical
   reproduction — no re-hash, no reorder).

The async sink is a Protocol so unit tests pass an in-memory fake (no Postgres);
the live path passes a real :class:`PgChainedEventStore`. A real-PG round-trip is
infra-gated (staged) and not asserted in CI.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from secugent.audit.hash_chain import ChainedEventRecord, ChainedEventStore
from secugent.core.contracts import Event, Run
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

__all__ = [
    "AsyncChainSink",
    "MigrationError",
    "MigrationReport",
    "migrate_sqlite_to_pg",
]


class MigrationError(RuntimeError):
    """Raised when the SQLite→PG migration cannot complete fail-closed.

    Carries no row content / secret — only counts and the tenant/seq context
    needed for an operator to act (no-leak).
    """


class AsyncChainSink(Protocol):
    """The async PG chained-store surface the migration writes to.

    Satisfied structurally by
    :class:`secugent.core.event_store_pg.PgChainedEventStore`.
    """

    async def upsert_run(self, run: Run) -> None: ...
    async def append(self, event: Event) -> None: ...
    async def verify_chain(self, *, tenant_id: TenantId) -> bool: ...
    async def read_chain(self, *, tenant_id: TenantId) -> list[ChainedEventRecord]: ...


@dataclass(frozen=True)
class MigrationReport:
    """Outcome evidence for an operator. ``verified`` is True only when every
    tenant's PG chain re-verified AND reproduced the SQLite tail identically."""

    tenants: tuple[str, ...]
    runs_copied: int
    events_copied: int
    events_skipped: int
    verified: bool


def _distinct_tenants(conn: sqlite3.Connection) -> list[str]:
    """All tenants that own a run or a chained event in the source DB (sorted)."""
    tenants: set[str] = set()
    for table in ("runs", "event_chain"):
        try:
            rows = conn.execute(f"SELECT DISTINCT tenant_id FROM {table}").fetchall()  # noqa: S608 - fixed identifier
        except sqlite3.OperationalError:
            # Table absent in a fresh/partial DB ⇒ no tenants from it.
            continue
        tenants.update(str(r[0]) for r in rows)
    return sorted(tenants)


def _require_source_exists(path: Path) -> None:
    """Fail closed (sync) if the source DB is absent — never migrate an empty DB.

    ``EventStore`` would otherwise CREATE a fresh empty SQLite file on open, so a
    typo in ``--sqlite`` would silently "migrate" zero rows and report success.
    """
    if not path.exists():
        raise MigrationError(f"source SQLite store not found: {path}")


def _runs_for_tenant(conn: sqlite3.Connection, tenant: str) -> list[Run]:
    """Reconstruct ``Run`` rows for a tenant from the SQLite ``runs`` table."""
    try:
        rows = conn.execute(
            "SELECT id, tenant_id, goal, status, created_at, updated_at "
            "FROM runs WHERE tenant_id = ? ORDER BY created_at ASC",
            (tenant,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []
    return [
        Run(
            id=row[0],
            tenant_id=row[1],
            goal=row[2],
            status=row[3],
            created_at=row[4],
            updated_at=row[5],
        )
        for row in rows
    ]


async def migrate_sqlite_to_pg(
    *,
    sqlite_path: str | Path,
    sink: AsyncChainSink,
    tenants: Sequence[str] | None = None,
) -> MigrationReport:
    """Migrate the SQLite chain at ``sqlite_path`` into ``sink`` (PG), fail-closed.

    ``tenants`` restricts the migration to specific tenants (default: every
    tenant found in the source). Raises :class:`MigrationError` (or
    :class:`secugent.audit.hash_chain.AuditChainBrokenError`) on any break — the
    caller (CLI) maps that to a non-zero exit and prints the evidence.
    """
    path = Path(sqlite_path)
    _require_source_exists(path)

    store = EventStore(path)
    chained = ChainedEventStore(store)
    # A second read-only connection for enumeration (the chained store owns its
    # own connection; we never write to SQLite here — migration is one-way).
    enum_conn = sqlite3.connect(str(path))
    try:
        all_tenants = _distinct_tenants(enum_conn)
        if tenants is not None:
            requested = list(dict.fromkeys(str(t) for t in tenants))
            unknown = [t for t in requested if t not in all_tenants]
            if unknown:
                raise MigrationError(f"requested tenant(s) not present in source: {unknown}")
            selected = requested
        else:
            selected = all_tenants

        runs_copied = 0
        events_copied = 0
        events_skipped = 0

        for tenant in selected:
            tid = TenantId(tenant)
            # 1. Source chain must verify BEFORE we copy anything (fail-closed).
            #    Raises AuditChainBrokenError on a broken/tampered source.
            chained.verify_chain(tenant_id=tenant)

            # 2a. Copy runs.
            for run in _runs_for_tenant(enum_conn, tenant):
                await sink.upsert_run(run)
                runs_copied += 1

            # 2b. Append chained events in seq order; skip those already in PG
            #     (idempotent resume). The PG chained store recomputes each link
            #     from the identical canonical body, so hashes reproduce exactly.
            source_records = chained.read_chain(tenant_id=tenant)
            present = {rec.event.id for rec in await sink.read_chain(tenant_id=tid)}
            for rec in source_records:
                if rec.event.id in present:
                    events_skipped += 1
                    continue
                await sink.append(rec.event)
                events_copied += 1

            # 3. Re-verify the PG chain end to end (raises on any break).
            await sink.verify_chain(tenant_id=tid)

            # 4. Identical-reproduction proof: the PG tail hash must equal the
            #    SQLite source tail hash (no re-hash / reorder). Skip when the
            #    tenant has no chained events (trivially continuous).
            if source_records:
                pg_records = await sink.read_chain(tenant_id=tid)
                if not pg_records:
                    raise MigrationError(
                        f"tenant {tenant!r}: PG chain empty after copy of {len(source_records)} event(s)"
                    )
                if pg_records[-1].event_hash != source_records[-1].event_hash:
                    raise MigrationError(
                        f"tenant {tenant!r}: PG tail hash diverged from SQLite "
                        f"source at seq={source_records[-1].seq} — aborting (no cutover)"
                    )

        return MigrationReport(
            tenants=tuple(selected),
            runs_copied=runs_copied,
            events_copied=events_copied,
            events_skipped=events_skipped,
            verified=True,
        )
    finally:
        enum_conn.close()
        chained.close()
