# SPDX-License-Identifier: Apache-2.0
"""DA-C1 B3 — AsyncLiveStore async-facade unit + property tests (no Postgres).

The SQLite branch must be BYTE-IDENTICAL to the sync reference (CLAUDE.md §B
"행동·순서 동일"): same canonical bytes, same chain tail hash, same event ORDER —
the ``async def`` facade only wraps the identical sync call the live handler makes
today. The PG branch (``FakeAsyncPgChain`` — real hashing, in-memory) must produce
the SAME chain for the SAME event stream, so a future cutover preserves §C-2
verifiability. Determinism (§B-4a): the same input replayed 100× → same hash.

C-3 Korean-finance fixtures: tenant ``금융-kr``, goal "2026년 1분기 마감 보고서 업로드".
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.audit.hash_chain import AuditChainBrokenError, ChainedEventRecord, ChainedEventStore
from secugent.core.contracts import Approval, ApprovalScope, Event, Run
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId
from secugent.db.store_facade import AsyncLiveStore
from tests.db._fakes import FakeAsyncPgChain

_TENANT = "kr-finance"  # §C-3 Korean finance tenant (TenantId is an ASCII slug)
_GOAL = "2026년 1분기 마감 보고서 업로드"  # Korean context lives in the free-form goal/payload
_TS0 = datetime(2026, 3, 31, 9, 0, 0, tzinfo=UTC)


def _evt(
    i: int, *, evt_type: str = "file.uploaded", run_id: str = "run-q1", payload: dict | None = None
) -> Event:
    """A reproducible event (fixed id + ts) so the chain hash is deterministic."""
    return Event(
        id=f"evt-{i:04d}",
        tenant_id=TenantId(_TENANT),
        ts=_TS0 + timedelta(seconds=i),
        actor="head:planner",
        type=evt_type,
        severity="info",
        run_id=run_id,
        payload=payload if payload is not None else {"seq": i},
    )


def _run(run_id: str = "run-q1") -> Run:
    return Run(id=run_id, tenant_id=TenantId(_TENANT), goal=_GOAL, status="planning")


def _approval(approval_id: str = "apv-1", *, run_id: str = "run-q1") -> Approval:
    scope = ApprovalScope(
        tenant_id=TenantId(_TENANT),
        run_id=run_id,
        expires_at=_TS0 + timedelta(hours=1),
    )
    return Approval(
        id=approval_id, actor="human:admin", scope=scope, expires_at=scope.expires_at, nonce="n-1"
    )


def _sqlite_live(tmp: Path, name: str = "live.db") -> tuple[AsyncLiveStore, ChainedEventStore]:
    chain = ChainedEventStore(EventStore(str(tmp / name)))
    return AsyncLiveStore(sqlite=chain, pg=None, backend="sqlite"), chain


def _pg_live() -> tuple[AsyncLiveStore, FakeAsyncPgChain]:
    fake = FakeAsyncPgChain()
    return AsyncLiveStore(sqlite=None, pg=fake, backend="postgres"), fake


# --------------------------------------------------------------------------- #
# fail-closed construction (INV-C1-3)
# --------------------------------------------------------------------------- #


def test_sqlite_backend_requires_sqlite_store() -> None:
    with pytest.raises(ValueError, match="requires a sqlite"):
        AsyncLiveStore(sqlite=None, pg=None, backend="sqlite")


def test_postgres_backend_requires_pg_store() -> None:
    with pytest.raises(ValueError, match="requires a PgChainedEventStore"):
        AsyncLiveStore(sqlite=None, pg=None, backend="postgres")


def test_backend_property_reports_selection(tmp_path: Path) -> None:
    live, _ = _sqlite_live(tmp_path)
    assert live.backend == "sqlite"
    pg_live, _ = _pg_live()
    assert pg_live.backend == "postgres"


# --------------------------------------------------------------------------- #
# SQLite branch == sync reference (byte-identical chain)
# --------------------------------------------------------------------------- #


async def test_sqlite_branch_chain_is_byte_identical_to_sync_reference(tmp_path: Path) -> None:
    """The facade's SQLite append_chained must produce the SAME chain as the sync
    ChainedEventStore the live path uses today — same tail hash, same records."""
    live, live_chain = _sqlite_live(tmp_path, "facade.db")
    ref = ChainedEventStore(EventStore(str(tmp_path / "ref.db")))

    events = [_evt(i, evt_type=t) for i, t in enumerate(["command.received", "plan.created", "hitl.decided"])]
    for ev in events:
        rec = await live.append_chained(ev)
        ref_rec = ref.append_event(ev)
        assert isinstance(rec, ChainedEventRecord)
        # Each link is byte-identical across the facade and the sync reference.
        assert rec.seq == ref_rec.seq
        assert rec.prev_hash == ref_rec.prev_hash
        assert rec.event_hash == ref_rec.event_hash

    assert await live.verify_chain(tenant_id=_TENANT) is True
    facade_chain = live_chain.read_chain(tenant_id=_TENANT)
    ref_chain = ref.read_chain(tenant_id=_TENANT)
    assert [r.event_hash for r in facade_chain] == [r.event_hash for r in ref_chain]
    ref.close()


async def test_append_chained_links_increment_and_chain(tmp_path: Path) -> None:
    live, _ = _sqlite_live(tmp_path)
    r0 = await live.append_chained(_evt(0))
    r1 = await live.append_chained(_evt(1))
    assert r0.seq == 0 and r1.seq == 1
    assert r1.prev_hash == r0.event_hash  # the chain links


# --------------------------------------------------------------------------- #
# SQLite ≡ PG branch equivalence (same stream → same chain)
# --------------------------------------------------------------------------- #


async def test_sqlite_and_pg_branches_produce_identical_chain(tmp_path: Path) -> None:
    live_sq, _ = _sqlite_live(tmp_path)
    live_pg, fake = _pg_live()
    events = [_evt(i, evt_type=t) for i, t in enumerate(["a", "b", "c", "d"])]
    sq_tail = pg_tail = ""
    for ev in events:
        sq_tail = (await live_sq.append_chained(ev)).event_hash
        pg_tail = (await live_pg.append_chained(ev)).event_hash
    # Backend-agnostic hash_chain math ⇒ identical tail for the identical stream.
    assert sq_tail == pg_tail
    assert await live_sq.verify_chain(tenant_id=_TENANT) is True
    assert await live_pg.verify_chain(tenant_id=_TENANT) is True


async def test_verify_chain_propagates_break_from_pg_branch() -> None:
    """A PG-side chain break surfaces as AuditChainBrokenError through the facade."""
    live, fake = _pg_live()
    fake.fail_verify = True
    await live.append_chained(_evt(0))
    with pytest.raises(AuditChainBrokenError):
        await live.verify_chain(tenant_id=_TENANT)


# --------------------------------------------------------------------------- #
# Read surface on BOTH branches
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
async def test_read_surface_both_branches(backend: str, tmp_path: Path) -> None:
    if backend == "sqlite":
        live, _ = _sqlite_live(tmp_path)
    else:
        live, _ = _pg_live()

    await live.upsert_run(_run())
    await live.append_event(_evt(0, evt_type="command.received"))  # raw row
    await live.append_chained(_evt(1, evt_type="plan.created"))
    await live.save_approval(_approval())

    assert await live.count_events(tenant_id=_TENANT, run_id="run-q1") >= 1
    listed = await live.list_events(tenant_id=_TENANT, run_id="run-q1")
    assert any(e.id == "evt-0001" for e in listed)
    run = await live.get_run(tenant_id=_TENANT, run_id="run-q1")
    assert run is not None and run.goal == _GOAL
    got = await live.get_event(tenant_id=_TENANT, event_id="evt-0001")
    assert got is not None and got.id == "evt-0001"
    apv = await live.get_approval(tenant_id=_TENANT, approval_id="apv-1")
    assert apv is not None and apv.nonce == "n-1"
    pending = await live.list_pending_approvals(tenant_id=_TENANT)
    assert any(a.id == "apv-1" for a in pending)


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
async def test_cross_tenant_reads_are_isolated(backend: str, tmp_path: Path) -> None:
    """A wrong-tenant id must not surface another tenant's run/event (RLS parity)."""
    if backend == "sqlite":
        live, _ = _sqlite_live(tmp_path)
    else:
        live, _ = _pg_live()
    await live.upsert_run(_run())
    await live.append_chained(_evt(1))
    assert await live.get_run(tenant_id="other-tenant", run_id="run-q1") is None
    assert await live.get_event(tenant_id="other-tenant", event_id="evt-0001") is None


# --------------------------------------------------------------------------- #
# Property: round-trip + cross-backend chain equivalence (hypothesis)
# --------------------------------------------------------------------------- #


_PAYLOADS = st.lists(
    st.dictionaries(
        keys=st.sampled_from(["amount", "note", "ratio", "count"]),
        values=st.one_of(
            st.floats(min_value=0, max_value=1e6, allow_nan=False, allow_infinity=False),
            st.integers(min_value=-1000, max_value=1000),
            st.text(max_size=12),
        ),
        max_size=3,
    ),
    min_size=1,
    max_size=8,
)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(payloads=_PAYLOADS)
def test_append_chained_then_verify_roundtrips_and_branches_agree(
    payloads: list[dict], tmp_path: Path
) -> None:
    """For ANY event stream: append_chained → verify_chain == OK on both branches,
    and the SQLite tail hash equals the PG tail hash (canonical equivalence)."""

    async def _run_case() -> None:
        # Unique sqlite file per example so hypothesis re-runs don't collide on ids.
        name = f"hp-{uuid.uuid4().hex}.db"
        live_sq = AsyncLiveStore(
            sqlite=ChainedEventStore(EventStore(str(tmp_path / name))), pg=None, backend="sqlite"
        )
        live_pg, _ = _pg_live()
        sq_tail = pg_tail = ""
        for i, payload in enumerate(payloads):
            sq_tail = (await live_sq.append_chained(_evt(i, payload=payload))).event_hash
            pg_tail = (await live_pg.append_chained(_evt(i, payload=payload))).event_hash
        assert await live_sq.verify_chain(tenant_id=_TENANT) is True
        assert await live_pg.verify_chain(tenant_id=_TENANT) is True
        assert sq_tail == pg_tail

    asyncio.run(_run_case())


# --------------------------------------------------------------------------- #
# Determinism: same input 100× → same chain hash (§B-4a)
# --------------------------------------------------------------------------- #


def test_chain_hash_is_deterministic_over_100_runs(tmp_path: Path) -> None:
    """Same fixed event stream replayed 100× (fresh store each time) → one hash."""
    fixed = [
        _evt(0, evt_type="command.received", payload={"file": "마감보고서.xlsx", "ratio": 1.50}),
        _evt(1, evt_type="plan.created", payload={"steps": 3}),
        _evt(2, evt_type="hitl.decided", payload={"decision": "approve"}),
    ]

    async def _tail(idx: int) -> str:
        live = AsyncLiveStore(
            sqlite=ChainedEventStore(EventStore(str(tmp_path / f"det-{idx}.db"))), pg=None, backend="sqlite"
        )
        tail = ""
        for ev in fixed:
            tail = (await live.append_chained(ev)).event_hash
        assert await live.verify_chain(tenant_id=_TENANT) is True
        return tail

    hashes = {asyncio.run(_tail(i)) for i in range(100)}
    assert len(hashes) == 1, f"non-deterministic chain hash across 100 runs: {hashes}"
