# SPDX-License-Identifier: Apache-2.0
"""Audit retention 단위 + 시나리오 테스트.

결정적 모듈(secugent/audit/retention.py) → 단위 + 속성(별도 파일) + 시나리오
회귀 + 100회 결정성. 한국어 픽스처(`kb-bank`) 포함(§C-3).

검증 불변조건:
* I1 append-only 체인: archive/purge 후에도 verify_chain True.
* I2 retain-window: 윈도 안의 sealed day는 절대 purge 안 됨.
* I3 sealed-only: unsealed day는 절대 archive/purge 안 됨.
* I4 verify-gated purge: archive 성공 + verify 실패 ⇒ purge 안 됨.
* I5 archive completeness: archive 안 된 hot row는 절대 삭제 안 됨.
* I6 determinism: plan 동일 입력 → 동일 출력 100회.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from secugent.audit.hash_chain import ChainedEventStore
from secugent.audit.retention import (
    ChainedStoreRetentionAdapter,
    DayRetentionOutcome,
    RetentionPlan,
    RetentionService,
    plan,
    wire_retention_hook,
)
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore, EventStoreError

_TENANT = "kb-bank"  # 한국 금융 픽스처 (§C-3)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def chain_store(tmp_path: Path) -> ChainedEventStore:
    store = ChainedEventStore(EventStore(tmp_path / "audit.db"))
    yield store
    store.close()


def _seed(store: ChainedEventStore, *, tenant: str, ts: datetime, type_: str = "plan.created") -> str:
    rec = store.append_event(
        Event(
            tenant_id=tenant,
            actor="sub:researcher",
            type=type_,
            ts=ts,
            payload={"메모": "한국어 페이로드"},
        )
    )
    return rec.event.id


def _adapter(chain: ChainedEventStore) -> ChainedStoreRetentionAdapter:
    return ChainedStoreRetentionAdapter(chain, archive_store=chain.inner)


# --------------------------------------------------------------------------- #
# plan — PURE, boundary days
# --------------------------------------------------------------------------- #


def test_plan_purges_only_strictly_older_than_retain_days() -> None:
    now = date(2026, 6, 6)
    retain = 180
    # exactly retain_days old → RETAINED (strict >)
    boundary = now - timedelta(days=retain)
    # retain_days + 1 → PURGED
    expired = now - timedelta(days=retain + 1)
    fresh = now - timedelta(days=1)
    p = plan(now=now, sealed_days=[boundary, expired, fresh], retain_days=retain)
    assert p.purge_days == (expired,)
    assert boundary in p.retained_sealed_days
    assert fresh in p.retained_sealed_days


def test_plan_boundary_equal_is_retained() -> None:
    now = date(2026, 6, 6)
    boundary = now - timedelta(days=180)
    p = plan(now=now, sealed_days=[boundary], retain_days=180)
    assert p.purge_days == ()
    assert p.retained_sealed_days == (boundary,)


def test_plan_boundary_plus_one_is_purged() -> None:
    now = date(2026, 6, 6)
    expired = now - timedelta(days=181)
    p = plan(now=now, sealed_days=[expired], retain_days=180)
    assert p.purge_days == (expired,)


def test_plan_empty_sealed_days() -> None:
    p = plan(now=date(2026, 6, 6), sealed_days=[], retain_days=180)
    assert p.purge_days == ()
    assert p.retained_sealed_days == ()


def test_plan_dedupes_and_sorts() -> None:
    now = date(2026, 6, 6)
    d1 = now - timedelta(days=400)
    d2 = now - timedelta(days=300)
    p = plan(now=now, sealed_days=[d2, d1, d2, d1], retain_days=180)
    assert p.purge_days == (d1, d2)  # sorted asc, deduped


def test_plan_retain_days_zero_purges_all_past() -> None:
    now = date(2026, 6, 6)
    yesterday = now - timedelta(days=1)
    p = plan(now=now, sealed_days=[yesterday, now], retain_days=0)
    # today: age 0, not > 0 → retained; yesterday: age 1 > 0 → purged
    assert p.purge_days == (yesterday,)
    assert now in p.retained_sealed_days


def test_plan_negative_retain_days_rejected() -> None:
    with pytest.raises(ValueError, match="retain_days"):
        plan(now=date(2026, 6, 6), sealed_days=[], retain_days=-1)


# --------------------------------------------------------------------------- #
# I6 — determinism (100x same input → same plan)
# --------------------------------------------------------------------------- #


def test_plan_determinism_100x() -> None:
    now = date(2026, 6, 6)
    sealed = [now - timedelta(days=n) for n in (400, 300, 181, 180, 1)]
    first = plan(now=now, sealed_days=sealed, retain_days=180)
    for _ in range(100):
        again = plan(now=now, sealed_days=list(sealed), retain_days=180)
        assert again == first


# --------------------------------------------------------------------------- #
# EventStore archive/purge primitives
# --------------------------------------------------------------------------- #


def test_archive_then_purge_removes_from_hot_keeps_in_archive(chain_store: ChainedEventStore) -> None:
    day = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    store = chain_store.inner

    assert store.archive_day(tenant_id=_TENANT, day=day) == 1
    assert store.is_day_archived(tenant_id=_TENANT, day=day) is True
    assert store.purge_day(tenant_id=_TENANT, day=day) == 1

    # list_events (hot only) no longer returns it; get_event (union) still does.
    hot = store.list_events(tenant_id=_TENANT, limit=100)
    assert all(e.id != eid for e in hot)
    assert store.get_event(eid, tenant_id=_TENANT) is not None


def test_archive_is_idempotent(chain_store: ChainedEventStore) -> None:
    day = date(2026, 1, 1)
    _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    store = chain_store.inner
    assert store.archive_day(tenant_id=_TENANT, day=day) == 1
    assert store.archive_day(tenant_id=_TENANT, day=day) == 0  # already archived


def test_purge_without_archive_is_noop(chain_store: ChainedEventStore) -> None:
    """I5: a hot row with no archive copy is never deleted."""
    day = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    store = chain_store.inner
    assert store.purge_day(tenant_id=_TENANT, day=day) == 0
    assert store.get_event(eid, tenant_id=_TENANT) is not None
    assert store.is_day_archived(tenant_id=_TENANT, day=day) is False


def test_day_bounds_are_utc_half_open(chain_store: ChainedEventStore) -> None:
    """Events at 23:59:59.999 of D and 00:00 of D+1 fall on different days."""
    store = chain_store.inner
    late = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 23, 59, 59, tzinfo=UTC))
    next_day = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 2, 0, 0, 0, tzinfo=UTC))
    assert store.archive_day(tenant_id=_TENANT, day=date(2026, 1, 1)) == 1
    store.purge_day(tenant_id=_TENANT, day=date(2026, 1, 1))
    remaining = {e.id for e in store.list_events(tenant_id=_TENANT, limit=100)}
    assert next_day in remaining
    assert late not in remaining


def test_archive_isolates_tenant(chain_store: ChainedEventStore) -> None:
    day = date(2026, 1, 1)
    ts = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    _seed(chain_store, tenant="kb-bank", ts=ts)
    other = _seed(chain_store, tenant="nh-bank", ts=ts)
    store = chain_store.inner
    assert store.archive_day(tenant_id="kb-bank", day=day) == 1
    store.purge_day(tenant_id="kb-bank", day=day)
    # nh-bank untouched
    assert any(e.id == other for e in store.list_events(tenant_id="nh-bank", limit=100))


# --------------------------------------------------------------------------- #
# RetentionService.apply — I1, I4
# --------------------------------------------------------------------------- #


async def test_apply_archives_verifies_purges(chain_store: ChainedEventStore) -> None:
    expired = date(2026, 1, 1)
    _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 10, 0, tzinfo=UTC))

    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    result = await svc.apply(p)

    assert result.archived_total == 2
    assert result.purged_total == 2
    assert all(o.purged for o in result.outcomes)
    # I1: chain still verifies after archive+purge.
    assert chain_store.verify_chain(tenant_id=_TENANT) is True
    # hot table emptied for that day.
    assert chain_store.inner.list_events(tenant_id=_TENANT, event_type="plan.created", limit=100) == []


async def test_apply_verify_fail_blocks_purge(chain_store: ChainedEventStore) -> None:
    """I4: archive OK but verify_chain False ⇒ NO purge, hot rows survive."""
    expired = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))

    class _VerifyFails(ChainedStoreRetentionAdapter):
        def verify_chain(self, *, tenant_id: str) -> bool:
            return False

    adapter = _VerifyFails(chain_store, archive_store=chain_store.inner)
    svc = RetentionService(store=adapter, tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    result = await svc.apply(p)

    assert result.purged_total == 0
    assert result.outcomes[0].verified is False
    assert result.outcomes[0].purged is False
    assert result.outcomes[0].error is not None
    # archive happened, but the hot row is preserved.
    assert chain_store.inner.get_event(eid, tenant_id=_TENANT) is not None
    hot = chain_store.inner.list_events(tenant_id=_TENANT, limit=100)
    assert any(e.id == eid for e in hot)


async def test_apply_verify_raise_blocks_purge(chain_store: ChainedEventStore) -> None:
    """verify_chain raising (tamper detected) is downgraded to a per-day skip."""
    expired = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))

    class _VerifyRaises(ChainedStoreRetentionAdapter):
        def verify_chain(self, *, tenant_id: str) -> bool:
            raise RuntimeError("tamper")

    adapter = _VerifyRaises(chain_store, archive_store=chain_store.inner)
    svc = RetentionService(store=adapter, tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    result = await svc.apply(p)
    assert result.purged_total == 0
    assert "verify_chain raised" in (result.outcomes[0].error or "")
    assert chain_store.inner.get_event(eid, tenant_id=_TENANT) is not None


async def test_apply_incomplete_archive_blocks_purge(chain_store: ChainedEventStore) -> None:
    """I5 (service level): is_day_archived False ⇒ purge skipped, hot rows kept."""
    expired = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))

    class _ArchiveIncomplete(ChainedStoreRetentionAdapter):
        def is_day_archived(self, *, tenant_id: str, day: date) -> bool:
            return False

    adapter = _ArchiveIncomplete(chain_store, archive_store=chain_store.inner)
    svc = RetentionService(store=adapter, tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    result = await svc.apply(p)
    assert result.purged_total == 0
    assert result.outcomes[0].verified is False
    assert "archive incomplete" in (result.outcomes[0].error or "")
    assert chain_store.inner.get_event(eid, tenant_id=_TENANT) is not None


async def test_apply_empty_plan_is_noop(chain_store: ChainedEventStore) -> None:
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(), retained_sealed_days=())
    result = await svc.apply(p)
    assert result == result.__class__(outcomes=(), archived_total=0, purged_total=0)


async def test_apply_day_with_no_events_purges_zero(chain_store: ChainedEventStore) -> None:
    """A purge-candidate day with zero events: archive 0, verify trivially ok."""
    empty_day = date(2026, 1, 1)
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(empty_day,), retained_sealed_days=())
    result = await svc.apply(p)
    out = result.outcomes[0]
    assert out.archived_count == 0
    assert out.verified is True
    assert out.purged is True
    assert out.purged_count == 0


async def test_apply_idempotent_rerun(chain_store: ChainedEventStore) -> None:
    expired = date(2026, 1, 1)
    _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    first = await svc.apply(p)
    assert first.purged_total == 1
    second = await svc.apply(p)  # nothing left to archive/purge
    assert second.archived_total == 0
    assert second.purged_total == 0
    assert chain_store.verify_chain(tenant_id=_TENANT) is True


async def test_apply_multi_tenant(chain_store: ChainedEventStore) -> None:
    expired = date(2026, 1, 1)
    ts = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    _seed(chain_store, tenant="kb-bank", ts=ts)
    _seed(chain_store, tenant="nh-bank", ts=ts)
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=["kb-bank", "nh-bank"])
    p = RetentionPlan(now=date(2026, 7, 1), retain_days=180, purge_days=(expired,), retained_sealed_days=())
    result = await svc.apply(p)
    assert result.purged_total == 2
    assert {o.tenant_id for o in result.outcomes} == {"kb-bank", "nh-bank"}
    assert chain_store.verify_chain(tenant_id="kb-bank") is True
    assert chain_store.verify_chain(tenant_id="nh-bank") is True


# --------------------------------------------------------------------------- #
# wire_retention_hook
# --------------------------------------------------------------------------- #


def test_wire_retention_hook_runs_apply(chain_store: ChainedEventStore) -> None:
    expired = date(2026, 1, 1)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    hook = wire_retention_hook(
        service=svc,
        sealed_days=lambda: [expired],
        retain_days=180,
        now_fn=lambda: date(2026, 7, 1),
    )
    hook(date(2026, 6, 30))  # the just-sealed day argument is ignored by plan here
    # the expired day was archived+purged out of the hot table.
    assert chain_store.inner.get_event(eid, tenant_id=_TENANT) is not None
    assert chain_store.inner.list_events(tenant_id=_TENANT, limit=100) == []


def test_wire_retention_hook_rejects_negative_retain_days(chain_store: ChainedEventStore) -> None:
    """Fail-fast at wire/boot time: a negative ``retain_days`` is a compliance
    misconfiguration. Previously it only raised later inside the per-seal hook,
    where the scheduler swallows per-seal errors by design → retention would
    silently never run. Validate at construction so boot fails loudly instead."""
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    with pytest.raises(ValueError, match="retain_days"):
        wire_retention_hook(
            service=svc,
            sealed_days=lambda: [],
            retain_days=-1,
        )


def test_wire_retention_hook_accepts_zero_retain_days(chain_store: ChainedEventStore) -> None:
    """retain_days=0 is a valid (purge-everything-past) config — must NOT raise
    at wire time (only strictly-negative is rejected)."""
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    hook = wire_retention_hook(service=svc, sealed_days=lambda: [], retain_days=0)
    assert callable(hook)


def test_wire_retention_hook_rejects_bool_retain_days(chain_store: ChainedEventStore) -> None:
    """A ``bool`` is technically an ``int`` subclass; treating ``True``/``False``
    as a retention window is a config error, so it is rejected at wire time."""
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    with pytest.raises(ValueError, match="must be an int"):
        # bool is an int subclass at runtime; the guard rejects it explicitly.
        wire_retention_hook(
            service=svc,
            sealed_days=lambda: [],
            retain_days=True,  # type: ignore[arg-type]  # deliberate config-error input
        )


def test_wire_retention_hook_noop_when_nothing_expired(chain_store: ChainedEventStore) -> None:
    fresh = date(2026, 6, 30)
    eid = _seed(chain_store, tenant=_TENANT, ts=datetime(2026, 6, 30, 9, 0, tzinfo=UTC))
    svc = RetentionService(store=_adapter(chain_store), tenant_ids=[_TENANT])
    ran: list[object] = []

    def _runner(coro: object) -> object:
        ran.append(coro)
        return None

    hook = wire_retention_hook(
        service=svc,
        sealed_days=lambda: [fresh],
        retain_days=180,
        runner=_runner,
        now_fn=lambda: date(2026, 7, 1),
    )
    hook(fresh)
    assert ran == []  # no purge candidates → runner never invoked
    assert any(e.id == eid for e in chain_store.inner.list_events(tenant_id=_TENANT, limit=100))


# --------------------------------------------------------------------------- #
# EventStoreError propagation
# --------------------------------------------------------------------------- #


def test_archive_day_wraps_sqlite_error(chain_store: ChainedEventStore) -> None:
    store = chain_store.inner
    store.close()  # force a broken connection
    with pytest.raises(EventStoreError):
        store.archive_day(tenant_id=_TENANT, day=date(2026, 1, 1))


def test_outcome_dataclass_is_frozen() -> None:
    out = DayRetentionOutcome(
        day=date(2026, 1, 1),
        tenant_id=_TENANT,
        archived_count=1,
        verified=True,
        purged=True,
        purged_count=1,
        error=None,
    )
    with pytest.raises(FrozenInstanceError):
        out.purged = False  # type: ignore[misc]
