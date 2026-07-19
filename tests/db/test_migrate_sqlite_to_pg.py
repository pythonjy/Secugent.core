# SPDX-License-Identifier: Apache-2.0
"""SQLite→PG migration round-trip + chain re-verification (fake PG sink).

Korean-context fixtures (§C-3): finance/public tenant ids (``kb-fin``,
``mois-gov``). The end-to-end migration against a REAL Postgres is infra-gated and
skipped unless ``DATABASE_URL`` is present (no false green).
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from secugent.audit.hash_chain import AuditChainBrokenError, ChainedEventStore
from secugent.core.contracts import Event, Run
from secugent.core.event_store import EventStore
from secugent.core.event_store_pg import is_pg_available
from secugent.core.tenancy import TenantId
from secugent.db.migrate_sqlite_to_pg import (
    MigrationError,
    migrate_sqlite_to_pg,
)
from tests.db._fakes import FakeAsyncPgChain

_KB = TenantId("kb-fin")
_GOV = TenantId("mois-gov")


def _seed_source(db: Path) -> dict[str, str]:
    """Build a two-tenant SQLite chain; return each tenant's source tail hash."""
    store = EventStore(db)
    chained = ChainedEventStore(store)
    try:
        store.upsert_run(Run(tenant_id=_KB, goal="대외비 파일 접근 검토", status="planning"))
        store.upsert_run(Run(tenant_id=_GOV, goal="국정원 N2SF 통제 점검", status="planning"))
        tails: dict[str, str] = {}
        for evt_type in ("plan.created", "hitl.requested", "approval.granted"):
            rec = chained.append_event(Event(tenant_id=_KB, actor="head:planner", type=evt_type))
            tails[str(_KB)] = rec.event_hash
        rec = chained.append_event(Event(tenant_id=_GOV, actor="head:planner", type="plan.created"))
        tails[str(_GOV)] = rec.event_hash
        return tails
    finally:
        chained.close()


async def test_round_trip_copies_and_reverifies(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    source_tails = _seed_source(db)

    sink = FakeAsyncPgChain()
    report = await migrate_sqlite_to_pg(sqlite_path=db, sink=sink)

    assert report.verified is True
    assert set(report.tenants) == {str(_KB), str(_GOV)}
    assert report.runs_copied == 2
    assert report.events_copied == 4
    assert report.events_skipped == 0
    # INV-C1-1 identical reproduction: PG tail hash == SQLite source tail hash.
    for tenant, tail in source_tails.items():
        pg_chain = await sink.read_chain(tenant_id=TenantId(tenant))
        assert pg_chain[-1].event_hash == tail


async def test_idempotent_resume_skips_already_copied(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    _seed_source(db)
    sink = FakeAsyncPgChain()

    first = await migrate_sqlite_to_pg(sqlite_path=db, sink=sink)
    assert first.events_copied == 4

    # Second run against the SAME sink must copy nothing (idempotent resume).
    second = await migrate_sqlite_to_pg(sqlite_path=db, sink=sink)
    assert second.events_copied == 0
    assert second.events_skipped == 4
    assert second.verified is True


async def test_broken_source_aborts_before_any_pg_write(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    _seed_source(db)
    # Tamper a chain body so the SOURCE verify fails (fail-closed BEFORE copy).
    conn = sqlite3.connect(str(db))
    conn.execute(
        "UPDATE event_chain SET body_canonical = ? WHERE tenant_id = ? AND seq = 0",
        ('{"tampered": true}', str(_KB)),
    )
    conn.commit()
    conn.close()

    sink = FakeAsyncPgChain()
    with pytest.raises(AuditChainBrokenError):
        await migrate_sqlite_to_pg(sqlite_path=db, sink=sink, tenants=[str(_KB)])

    # No partial cutover: nothing was written to the PG sink for the bad tenant.
    assert sink.runs == {}
    assert sink._chains == {}


async def test_pg_side_chain_break_aborts(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    _seed_source(db)
    sink = FakeAsyncPgChain(fail_verify=True)  # PG re-verify raises

    with pytest.raises(AuditChainBrokenError):
        await migrate_sqlite_to_pg(sqlite_path=db, sink=sink)


async def test_pg_tail_hash_divergence_aborts(tmp_path: Path) -> None:
    """INV-C1-1: if the PG copy's tail hash differs from the SQLite source (a
    re-hash/reorder), abort fail-closed even though verify_chain passed."""
    from secugent.audit.hash_chain import ChainedEventRecord

    class _Divergent(FakeAsyncPgChain):
        async def read_chain(self, *, tenant_id: TenantId) -> list[ChainedEventRecord]:
            recs = await super().read_chain(tenant_id=tenant_id)
            if recs:
                tail = recs[-1]
                recs[-1] = ChainedEventRecord(
                    event=tail.event, seq=tail.seq, prev_hash=tail.prev_hash, event_hash="DIVERGENT"
                )
            return recs

    db = tmp_path / "events.db"
    _seed_source(db)
    with pytest.raises(MigrationError, match="diverged"):
        await migrate_sqlite_to_pg(sqlite_path=db, sink=_Divergent(), tenants=[str(_KB)])


async def test_pg_empty_after_copy_aborts(tmp_path: Path) -> None:
    """If the PG chain is empty after copying a non-empty source, abort."""
    from secugent.audit.hash_chain import ChainedEventRecord

    class _Empty(FakeAsyncPgChain):
        async def read_chain(self, *, tenant_id: TenantId) -> list[ChainedEventRecord]:
            return []  # nothing present (skip-check) AND nothing after copy

    db = tmp_path / "events.db"
    _seed_source(db)
    with pytest.raises(MigrationError, match="empty after copy"):
        await migrate_sqlite_to_pg(sqlite_path=db, sink=_Empty(), tenants=[str(_KB)])


async def test_unknown_tenant_filter_fails_closed(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    _seed_source(db)
    sink = FakeAsyncPgChain()
    with pytest.raises(MigrationError, match="not present in source"):
        await migrate_sqlite_to_pg(sqlite_path=db, sink=sink, tenants=["ghost-tenant"])


async def test_missing_source_fails_closed(tmp_path: Path) -> None:
    sink = FakeAsyncPgChain()
    with pytest.raises(MigrationError, match="not found"):
        await migrate_sqlite_to_pg(sqlite_path=tmp_path / "nope.db", sink=sink)


async def test_empty_source_migrates_trivially(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    EventStore(db).close()  # create empty schema, no rows
    sink = FakeAsyncPgChain()
    report = await migrate_sqlite_to_pg(sqlite_path=db, sink=sink)
    assert report.tenants == ()
    assert report.events_copied == 0
    assert report.verified is True


@pytest.mark.skipif(
    not (os.getenv("DATABASE_URL") and is_pg_available()),
    reason="live SQLite→PG cutover needs a staged Postgres; SQLite is the "
    "dev/air-gap default — not asserted in CI (no false green).",
)
async def test_live_pg_migration_round_trip(tmp_path: Path) -> None:  # pragma: no cover - infra-gated
    """End-to-end migration into a REAL PgChainedEventStore. Staged handoff."""
    from secugent.core.event_store_pg import PgChainedEventStore, PgEventStore

    db = tmp_path / "events.db"
    _seed_source(db)
    dsn = os.environ["DATABASE_URL"]
    pg = PgEventStore(dsn)
    await pg.ensure_schema()
    try:
        report = await migrate_sqlite_to_pg(sqlite_path=db, sink=PgChainedEventStore(pg))
        assert report.verified is True
    finally:
        await pg.close()
