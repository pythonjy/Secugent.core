# SPDX-License-Identifier: Apache-2.0
"""Stage 1 (G-C9) — shared contract-equivalence suite for AsyncEventStore.

The SQLite-backed :class:`SqliteAsyncEventStore` (always exercised in CI) and the
PostgreSQL :class:`PgChainedEventStore` (exercised only when ``DATABASE_URL`` is
set AND the ``pg`` extra is installed) MUST exhibit identical *observable*
behaviour for the CRUD contract: DESC event ordering, run upsert, approval
save/get, FIFO pending-approval ordering, nonce conflict → ``EventStoreError``,
tenant isolation (cross-tenant read = 0 rows), missing → ``None``, append-only,
and ``limit``.

Korean enterprise fixtures (§C-3): a 시행사 (``financial-kr``) issuer tenant and
a 운용사 (``securities-kr``) asset-manager tenant, with Korean-language goals.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

from secugent.core.contracts import Approval, ApprovalScope, Event, Run
from secugent.core.event_store import EventStore, EventStoreError
from secugent.core.event_store_async import SqliteAsyncEventStore
from secugent.core.event_store_base import AsyncEventStore
from secugent.core.event_store_pg import is_pg_available
from secugent.core.tenancy import TenantId

DATABASE_URL = os.getenv("DATABASE_URL")

# 한국어 픽스처 (§C-3): 시행사 / 운용사 테넌트.
T_ISSUER = TenantId("financial-kr")
T_ASSET = TenantId("securities-kr")
ISSUER_GOAL = "분기 마감 보고서를 사내 포털에 업로드"
ASSET_GOAL = "고객 펀드 잔고를 조회하고 운용 보고서를 생성"


def _event(tenant: TenantId, *, run_id: str, idx: int, ts: datetime) -> Event:
    return Event(
        id=f"evt_{tenant}_{idx}",
        tenant_id=tenant,
        ts=ts,
        actor="head:planner",
        type="plan.created",
        run_id=run_id,
        payload={"단계": idx, "메모": "민원 처리"},
    )


def _run(tenant: TenantId, *, run_id: str, goal: str) -> Run:
    now = datetime.now(tz=UTC)
    return Run(
        id=run_id,
        tenant_id=tenant,
        goal=goal,
        status="planning",
        created_at=now,
        updated_at=now,
    )


def _approval(
    tenant: TenantId,
    *,
    run_id: str,
    nonce: str,
    created_at: datetime,
    approval_id: str | None = None,
) -> Approval:
    scope = ApprovalScope(
        tenant_id=tenant,
        run_id=run_id,
        step_ids=["step_1"],
        allowed_action_types=["file_read"],
        max_risk=40,
        expires_at=created_at + timedelta(hours=1),
    )
    return Approval(
        id=approval_id or f"apv_{uuid.uuid4().hex[:12]}",
        actor="human:심사역",
        scope=scope,
        expires_at=created_at + timedelta(hours=1),
        nonce=nonce,
        status="pending",
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Backend fixtures — sqlite_async always, pg only with DATABASE_URL + extra
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def sqlite_async(tmp_path_factory: pytest.TempPathFactory) -> AsyncIterator[AsyncEventStore]:
    db = tmp_path_factory.mktemp("contract") / "store.db"
    inner = EventStore(db)
    store = SqliteAsyncEventStore(inner)
    try:
        yield store
    finally:
        inner.close()


@pytest_asyncio.fixture
async def pg_async() -> AsyncIterator[AsyncEventStore]:
    if not (DATABASE_URL and is_pg_available()):
        pytest.skip("DATABASE_URL unset or pg extra missing — PG contract test skipped")
    from secugent.core.event_store_pg import PgChainedEventStore, PgEventStore

    assert DATABASE_URL is not None
    inner = PgEventStore(DATABASE_URL)
    await inner.ensure_schema()
    store = PgChainedEventStore(inner)
    try:
        yield store
    finally:
        await inner.close()


# Each test runs against every available backend. ``indirect`` resolves the
# fixture name to the actual store instance.
BACKENDS = ["sqlite_async", "pg_async"]


@pytest.fixture
def store(request: pytest.FixtureRequest) -> AsyncEventStore:
    backend: AsyncEventStore = request.getfixturevalue(request.param)
    return backend


# Helper to keep a per-run unique nonce/run_id when running against a *shared*
# real Postgres (rows persist across param values within a session).
def _u() -> str:
    return uuid.uuid4().hex[:10]


parametrize_backends: Callable[..., pytest.MarkDecorator] = pytest.mark.parametrize(
    "store", BACKENDS, indirect=True
)


# ---------------------------------------------------------------------------
# Contract tests
# ---------------------------------------------------------------------------


@parametrize_backends
async def test_append_then_query_desc_order(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    base = datetime(2026, 6, 1, 9, 0, 0, tzinfo=UTC)
    for i in range(3):
        await store.append(_event(T_ISSUER, run_id=run_id, idx=i, ts=base + timedelta(minutes=i)))
    events = await store.query(tenant_id=T_ISSUER, run_id=run_id)
    assert [e.payload["단계"] for e in events] == [2, 1, 0]  # ts DESC


@parametrize_backends
async def test_query_limit_caps_rows(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    base = datetime(2026, 6, 2, 9, 0, 0, tzinfo=UTC)
    for i in range(5):
        await store.append(_event(T_ISSUER, run_id=run_id, idx=i, ts=base + timedelta(minutes=i)))
    events = await store.query(tenant_id=T_ISSUER, run_id=run_id, limit=2)
    assert len(events) == 2
    assert [e.payload["단계"] for e in events] == [4, 3]  # newest first


@parametrize_backends
async def test_query_missing_run_returns_empty(store: AsyncEventStore) -> None:
    events = await store.query(tenant_id=T_ISSUER, run_id=f"nope_{_u()}")
    assert events == []


@parametrize_backends
async def test_append_only_duplicate_id_raises(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    ts = datetime(2026, 6, 3, 9, 0, 0, tzinfo=UTC)
    ev = _event(T_ISSUER, run_id=run_id, idx=0, ts=ts)
    ev = ev.model_copy(update={"id": f"evt_dup_{_u()}"})
    await store.append(ev)
    with pytest.raises(EventStoreError):
        await store.append(ev)  # same id → append-only violation


@parametrize_backends
async def test_upsert_run_then_get(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    run = _run(T_ISSUER, run_id=run_id, goal=ISSUER_GOAL)
    await store.upsert_run(run)
    got = await store.get_run(tenant_id=T_ISSUER, run_id=run_id)
    assert got is not None
    assert got.goal == ISSUER_GOAL
    assert got.status == "planning"

    # upsert again → goal + status updated, tenant + created_at preserved.
    updated = run.model_copy(update={"goal": "마감 재처리", "status": "executing"})
    await store.upsert_run(updated)
    got2 = await store.get_run(tenant_id=T_ISSUER, run_id=run_id)
    assert got2 is not None
    assert got2.goal == "마감 재처리"
    assert got2.status == "executing"
    assert got2.tenant_id == T_ISSUER


@parametrize_backends
async def test_get_run_missing_returns_none(store: AsyncEventStore) -> None:
    assert await store.get_run(tenant_id=T_ISSUER, run_id=f"nope_{_u()}") is None


@parametrize_backends
async def test_save_approval_then_get(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    nonce = f"nonce_{_u()}"
    apv = _approval(T_ASSET, run_id=run_id, nonce=nonce, created_at=datetime.now(tz=UTC))
    await store.save_approval(apv)
    got = await store.get_approval(tenant_id=T_ASSET, approval_id=apv.id)
    assert got is not None
    assert got.nonce == nonce
    assert got.scope.tenant_id == T_ASSET
    assert got.status == "pending"


@parametrize_backends
async def test_get_approval_missing_returns_none(store: AsyncEventStore) -> None:
    assert await store.get_approval(tenant_id=T_ASSET, approval_id=f"nope_{_u()}") is None


@parametrize_backends
async def test_nonce_conflict_raises_event_store_error(store: AsyncEventStore) -> None:
    nonce = f"nonce_dup_{_u()}"
    now = datetime.now(tz=UTC)
    a1 = _approval(T_ASSET, run_id=f"run_{_u()}", nonce=nonce, created_at=now)
    a2 = _approval(T_ASSET, run_id=f"run_{_u()}", nonce=nonce, created_at=now)
    await store.save_approval(a1)
    with pytest.raises(EventStoreError):
        await store.save_approval(a2)  # duplicate nonce (different id)


@parametrize_backends
async def test_list_pending_approvals_fifo(store: AsyncEventStore) -> None:
    tenant = TenantId(f"fifo-{_u()}")
    base = datetime(2026, 6, 4, 9, 0, 0, tzinfo=UTC)
    ids: list[str] = []
    for i in range(3):
        apv = _approval(
            tenant,
            run_id=f"run_{_u()}",
            nonce=f"nonce_{_u()}",
            created_at=base + timedelta(minutes=i),
        )
        ids.append(apv.id)
        await store.save_approval(apv)
    pending = await store.list_pending_approvals(tenant_id=tenant)
    assert [p.id for p in pending] == ids  # created_at ASC (FIFO)


@parametrize_backends
async def test_tenant_isolation_cross_read_is_zero(store: AsyncEventStore) -> None:
    run_id = f"run_{_u()}"
    ts = datetime(2026, 6, 5, 9, 0, 0, tzinfo=UTC)
    iss = _event(T_ISSUER, run_id=run_id, idx=0, ts=ts).model_copy(update={"id": f"evt_iso_{_u()}"})
    await store.append(iss)
    # Asset-manager tenant must see ZERO of the issuer's events.
    cross = await store.query(tenant_id=T_ASSET, run_id=run_id)
    assert cross == []
