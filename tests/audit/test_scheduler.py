# SPDX-License-Identifier: Apache-2.0
"""20260603-02-BE — DailyMerkleScheduler 3중 테스트.

결정적 모듈(secugent/audit/) → 단위 + 속성(hypothesis) + 시나리오 회귀 + 100회
결정성 + 통합(라이프사이클). 한국어 픽스처(`kb-bank`) 포함(§C-3).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, date, datetime, timedelta, tzinfo
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.audit.hash_chain import ChainedEventStore
from secugent.audit.merkle import (
    LocalHmacKmsProvider,
    MerkleSigner,
    SignedMerkleRoot,
)
from secugent.audit.retention import (
    ChainedStoreRetentionAdapter,
    RetentionService,
    plan,
    wire_retention_hook,
)
from secugent.audit.scheduler import DailyMerkleScheduler
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore

_KEY_ID = "audit-merkle-2026"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _signer() -> MerkleSigner:
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY_ID, b"audit-merkle-secret")
    return MerkleSigner(kms=kms, key_id=_KEY_ID)


@pytest.fixture
def chain_store(tmp_path: Path) -> ChainedEventStore:
    store = ChainedEventStore(EventStore(tmp_path / "audit.db"))
    yield store
    store.close()


# Default seed day — the day most run_once(...) calls below seal. Pinning the
# event timestamp here (rather than _utcnow) keeps the day-filtered sealer
# (SG-20260603-20) inclusive of these events regardless of the wall-clock date.
_SEED_TS = datetime(2026, 6, 2, 12, 0, tzinfo=UTC)


def _seed_event(store: ChainedEventStore, tenant_id: str, type_: str) -> None:
    store.append_event(
        Event(
            tenant_id=tenant_id,
            actor="sub:researcher",
            type=type_,
            ts=_SEED_TS,
            payload={"메모": "한국어 페이로드"},
        )
    )


def _seed_event_at(store: ChainedEventStore, tenant_id: str, type_: str, ts: datetime) -> None:
    """Seed an event pinned to a specific UTC timestamp (day-filter tests)."""
    store.append_event(
        Event(
            tenant_id=tenant_id,
            actor="sub:researcher",
            type=type_,
            ts=ts,
            payload={"메모": "한국어 페이로드"},
        )
    )


# --------------------------------------------------------------------------- #
# 단위 — run_once
# --------------------------------------------------------------------------- #


def test_init_rejects_bad_hour(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    with pytest.raises(ValueError):
        DailyMerkleScheduler(
            chain_store=chain_store,
            signer=_signer(),
            tenant_ids=["kb-bank"],
            output_dir=tmp_path / "out",
            run_hour_utc=24,
        )


def test_run_once_single_tenant(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    assert len(roots) == 1
    assert isinstance(roots[0], SignedMerkleRoot)
    assert roots[0].day == date(2026, 6, 2)
    assert len(roots[0].root_hex) == 64


def test_run_once_seals_only_target_day(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    """SG-20260603-20: events on D-1 and D-2 → run_once(D-1) seals ONLY D-1.

    The cumulative chain holds both days' events; the day-filtered root and
    ``event_count`` must reflect D-1's two events alone, never the superset.
    """
    d1 = date(2026, 6, 1)
    d2 = date(2026, 6, 2)
    # Two events on D-1, one on D-2 (UTC).
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 1, 9, 0, tzinfo=UTC))
    _seed_event_at(chain_store, "kb-bank", "approval.granted", datetime(2026, 6, 1, 23, 30, tzinfo=UTC))
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 2, 1, 0, tzinfo=UTC))

    out = tmp_path / "out"
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=out,
    )
    roots = sched.run_once(day=d1)

    # The root must equal the Merkle root over EXACTLY D-1's two event hashes.
    d1_hashes = list(chain_store.iter_hashes_for_day(tenant_id="kb-bank", day=d1, tz=UTC))
    assert len(d1_hashes) == 2
    assert roots[0].root_hex == MerkleSigner.build_root(d1_hashes)

    record = json.loads((out / "2026" / "06" / "merkle_20260601.json").read_text(encoding="utf-8").strip())
    assert record["day"] == "2026-06-01"
    assert record["event_count"] == 2  # NOT 3 (the cumulative chain)

    # Sealing D-2 separately must cover only its one event — no D-1 bleed-in.
    roots2 = sched.run_once(day=d2)
    d2_hashes = list(chain_store.iter_hashes_for_day(tenant_id="kb-bank", day=d2, tz=UTC))
    assert len(d2_hashes) == 1
    assert roots2[0].root_hex == MerkleSigner.build_root(d2_hashes)
    assert roots2[0].root_hex != roots[0].root_hex


def test_run_once_empty_day_is_sentinel_not_cumulative(
    tmp_path: Path, chain_store: ChainedEventStore
) -> None:
    """SG-20260603-20: a day with no events seals the empty-tree sentinel,
    even when the tenant chain holds events on OTHER days (invariant #2)."""
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 1, 9, 0, tzinfo=UTC))
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    # Seal a day with zero events for this tenant.
    roots = sched.run_once(day=date(2026, 6, 5))
    assert roots[0].root_hex == MerkleSigner.build_root([])


def test_run_once_writes_evidence_before_seal_event(
    tmp_path: Path, chain_store: ChainedEventStore, caplog: pytest.LogCaptureFixture
) -> None:
    """SG-20260603-21: if the evidence-file write fails, NO dangling seal event
    is appended to the chain (evidence file is written first)."""
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 2, 9, 0, tzinfo=UTC))
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )

    def _boom(out_path: Path, lines: list[str]) -> None:
        raise OSError("disk full")

    sched._write_evidence = _boom  # type: ignore[method-assign]  # noqa: SLF001
    with caplog.at_level("ERROR"):
        with pytest.raises(OSError):
            sched.run_once(day=date(2026, 6, 2))

    # No audit.merkle_sealed event leaked into the chain for the failed write.
    records = chain_store.read_chain(tenant_id="kb-bank")
    assert not any(r.event.type == "audit.merkle_sealed" for r in records)


def test_run_once_multiple_tenants(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")
    _seed_event(chain_store, "nh-bank", "approval.granted")
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank", "nh-bank"],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    assert len(roots) == 2


def test_run_once_empty_events_uses_sentinel(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    assert len(roots) == 1
    assert roots[0].root_hex == MerkleSigner.build_root([])


def test_run_once_empty_tenant_list(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=[],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    assert roots == []
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").rglob("*.json"))


def test_run_once_day_none_seals_yesterday(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=None)
    today = datetime.now(tz=UTC).date()
    assert roots[0].day < today


def test_rerun_same_day_raises_file_exists(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    sched.run_once(day=date(2026, 6, 2))
    with pytest.raises(FileExistsError):
        sched.run_once(day=date(2026, 6, 2))


def test_partial_failure_skips_tenant(
    tmp_path: Path,
    chain_store: ChainedEventStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")

    class _FailingChain:
        def __init__(self, inner: ChainedEventStore) -> None:
            self._inner = inner

        def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = UTC) -> list[str]:
            if tenant_id == "broken":
                raise RuntimeError("iter_hashes boom")
            return list(self._inner.iter_hashes_for_day(tenant_id=tenant_id, day=day, tz=tz))

        def append_event(self, event: Event) -> object:
            return self._inner.append_event(event)

    sched = DailyMerkleScheduler(
        chain_store=_FailingChain(chain_store),  # type: ignore[arg-type]
        signer=_signer(),
        tenant_ids=["broken", "kb-bank"],
        output_dir=tmp_path / "out",
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    assert [r for r in roots] != []
    assert all(r.day == date(2026, 6, 2) for r in roots)
    assert len(roots) == 1  # only kb-bank survived
    assert any("broken" in rec.message for rec in caplog.records)


def test_output_file_schema(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")
    out = tmp_path / "out"
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=out,
    )
    sched.run_once(day=date(2026, 6, 2))
    path = out / "2026" / "06" / "merkle_20260602.json"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    record = json.loads(lines[0])
    for key in (
        "day",
        "tenant_id",
        "root_hex",
        "signature_hex",
        "key_id",
        "algorithm",
        "generated_at",
        "event_count",
    ):
        assert key in record
    assert record["day"] == "2026-06-02"
    assert record["tenant_id"] == "kb-bank"
    assert record["generated_at"].endswith("+09:00")  # KST


def test_seal_event_appended_to_chain(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    sched.run_once(day=date(2026, 6, 2))
    records = chain_store.read_chain(tenant_id="kb-bank")
    seal = [r for r in records if r.event.type == "audit.merkle_sealed"]
    assert len(seal) == 1
    assert seal[0].event.actor == "system"
    assert seal[0].event.payload["gate"] == "audit"
    assert chain_store.verify_chain(tenant_id="kb-bank") is True


# --------------------------------------------------------------------------- #
# 속성 기반 (hypothesis)
# --------------------------------------------------------------------------- #

_HEX64 = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)


@given(hashes=st.lists(_HEX64, max_size=12))
@settings(max_examples=120)
def test_property_root_determinism(hashes: list[str]) -> None:
    r1 = MerkleSigner.build_root(hashes)
    r2 = MerkleSigner.build_root(hashes)
    assert r1 == r2
    assert len(r1) == 64


_TENANT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-",
    min_size=2,
    max_size=20,
).filter(lambda s: s[0] != "-" and s[-1] != "-")


@given(
    tenants=st.lists(_TENANT, min_size=1, max_size=5, unique=True),
    seal_day=st.dates(min_value=date(2020, 1, 1), max_value=date(2030, 12, 31)),
)
@settings(max_examples=80, deadline=None)
def test_property_one_file_per_day(tenants: list[str], seal_day: date) -> None:
    base = Path("/audit/out")
    # Evidence is per-day, not per-tenant → all tenants of a day share one path,
    # and that path is unique per day (no cross-day collision).
    path = DailyMerkleScheduler._output_path(base, seal_day)  # noqa: SLF001
    assert str(seal_day.year) in str(path)
    assert path.name == f"merkle_{seal_day.strftime('%Y%m%d')}.json"
    other_day = seal_day.replace(day=1) if seal_day.day != 1 else seal_day.replace(day=2)
    if other_day != seal_day:
        assert DailyMerkleScheduler._output_path(base, other_day) != path  # noqa: SLF001
    assert len(tenants) >= 1


# --------------------------------------------------------------------------- #
# 결정성 100회
# --------------------------------------------------------------------------- #


class _FixedHashStore:
    """Stub chain store yielding a fixed hash list — isolates sealer determinism
    from per-event random ids/timestamps."""

    def __init__(self, hashes: list[str]) -> None:
        self._hashes = hashes
        self.events: list[Event] = []

    def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = UTC) -> list[str]:
        return list(self._hashes)

    def append_event(self, event: Event) -> None:
        self.events.append(event)


def test_determinism_100_runs(tmp_path: Path) -> None:
    fixed_hashes = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
    expected = MerkleSigner.build_root(fixed_hashes)
    for _ in range(100):
        assert MerkleSigner.build_root(fixed_hashes) == expected

    # full run_once determinism: identical hashes → identical root_hex every run
    roots: set[str] = set()
    for i in range(100):
        sched = DailyMerkleScheduler(
            chain_store=_FixedHashStore(fixed_hashes),  # type: ignore[arg-type]
            signer=_signer(),
            tenant_ids=["kb-bank"],
            output_dir=tmp_path / f"out{i}",
        )
        roots.add(sched.run_once(day=date(2026, 6, 2))[0].root_hex)
    assert len(roots) == 1
    assert roots == {expected}


# --------------------------------------------------------------------------- #
# 통합 — 라이프사이클 (스레드 누수 0)
# --------------------------------------------------------------------------- #


def test_start_stop_lifecycle_no_thread_leak(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    before = threading.active_count()
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    sched.start()
    assert threading.active_count() == before + 1
    sched.stop()
    assert threading.active_count() == before


def test_stop_is_idempotent(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    sched.stop()  # never started
    sched.start()
    sched.stop()
    sched.stop()  # double stop


def test_integration_end_to_end(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")
    _seed_event(chain_store, "kb-bank", "approval.granted")
    out = tmp_path / "evidence"
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=out,
    )
    roots = sched.run_once(day=date(2026, 6, 2))
    # signature verifies against the same KMS key
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY_ID, b"audit-merkle-secret")
    assert roots[0].verify_against(kms) is True
    assert chain_store.verify_chain(tenant_id="kb-bank") is True
    assert (out / "2026" / "06" / "merkle_20260602.json").exists()


def test_start_twice_is_noop(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    before = threading.active_count()
    sched.start()
    sched.start()  # already running → no second thread
    try:
        assert threading.active_count() == before + 1
    finally:
        sched.stop()


def test_loop_runs_once_then_stops(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    """Drive the background loop deterministically: schedule the next run ~now
    so the loop wakes, seals yesterday, then stops on the next cycle."""
    _seed_event(chain_store, "kb-bank", "plan.created")
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
        run_hour_utc=datetime.now(tz=UTC).hour,
    )
    # Force the loop to wake immediately on each cycle.
    sched._seconds_until_next_run = lambda now: 0.0  # type: ignore[method-assign]  # noqa: SLF001
    sched.start()
    yesterday = (datetime.now(tz=UTC) - timedelta(days=1)).date()
    expected = sched._output_path(tmp_path / "out", yesterday)  # noqa: SLF001
    deadline = time.monotonic() + 5.0
    while not expected.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    sched.stop()
    assert expected.exists()


def test_loop_survives_run_once_error(
    tmp_path: Path, chain_store: ChainedEventStore, caplog: pytest.LogCaptureFixture
) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    boom = threading.Event()

    def _explode(*, day: date | None = None) -> list[SignedMerkleRoot]:
        boom.set()
        raise RuntimeError("seal boom")

    sched.run_once = _explode  # type: ignore[method-assign]
    sched._seconds_until_next_run = lambda now: 0.0  # type: ignore[method-assign]  # noqa: SLF001
    with caplog.at_level("ERROR"):
        sched.start()
        assert boom.wait(timeout=5.0)
        sched.stop()
    assert any("run_once failed" in rec.message for rec in caplog.records)


def test_seconds_until_next_run_rolls_to_tomorrow(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
        run_hour_utc=3,
    )
    # now is *after* the target hour → next run is tomorrow (< 24h away, > 0).
    now = datetime(2026, 6, 2, 10, 0, 0, tzinfo=UTC)
    secs = sched._seconds_until_next_run(now)  # noqa: SLF001
    assert 0 < secs <= 24 * 60 * 60


def test_seal_event_append_failure_is_logged(
    tmp_path: Path, chain_store: ChainedEventStore, caplog: pytest.LogCaptureFixture
) -> None:
    _seed_event(chain_store, "kb-bank", "plan.created")

    class _AppendFails:
        def __init__(self, inner: ChainedEventStore) -> None:
            self._inner = inner

        def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = UTC) -> list[str]:
            return list(self._inner.iter_hashes_for_day(tenant_id=tenant_id, day=day, tz=tz))

        def append_event(self, event: Event) -> object:
            raise RuntimeError("append boom")

    sched = DailyMerkleScheduler(
        chain_store=_AppendFails(chain_store),  # type: ignore[arg-type]
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
    )
    with caplog.at_level("ERROR"):
        roots = sched.run_once(day=date(2026, 6, 2))
    # File (primary evidence) still written; only the chain event failed.
    assert len(roots) == 1
    assert (tmp_path / "out" / "2026" / "06" / "merkle_20260602.json").exists()
    assert any("seal-event append failed" in rec.message for rec in caplog.records)


def test_all_tenants_fail_writes_no_file(
    tmp_path: Path, chain_store: ChainedEventStore, caplog: pytest.LogCaptureFixture
) -> None:
    class _AllFail:
        def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = UTC) -> list[str]:
            raise RuntimeError("boom")

        def append_event(self, event: Event) -> object:  # pragma: no cover
            return None

    out = tmp_path / "out"
    sched = DailyMerkleScheduler(
        chain_store=_AllFail(),  # type: ignore[arg-type]
        signer=_signer(),
        tenant_ids=["kb-bank", "nh-bank"],
        output_dir=out,
    )
    with caplog.at_level("ERROR"):
        roots = sched.run_once(day=date(2026, 6, 2))
    assert roots == []
    # no evidence file when every tenant was skipped
    assert not (out / "2026" / "06" / "merkle_20260602.json").exists()


def test_kst_fallback_when_no_tzdata(monkeypatch: pytest.MonkeyPatch) -> None:
    import zoneinfo

    from secugent.audit import scheduler as sched_mod

    def _raise(*_args: object, **_kwargs: object) -> object:
        raise zoneinfo.ZoneInfoNotFoundError("no tzdata")

    monkeypatch.setattr(zoneinfo, "ZoneInfo", _raise)
    tz = sched_mod._kst_zone()  # noqa: SLF001
    assert tz.utcoffset(None) == timedelta(hours=9)


# --------------------------------------------------------------------------- #
# G-H2 retention — 시나리오 회귀 (200-day accumulation, chain continuity)
# --------------------------------------------------------------------------- #


def _adapter(chain: ChainedEventStore) -> ChainedStoreRetentionAdapter:
    return ChainedStoreRetentionAdapter(chain, archive_store=chain.inner)


def test_scenario_200_day_accumulation_archives_expired_keeps_chain(
    tmp_path: Path, chain_store: ChainedEventStore
) -> None:
    """200 일치 누적: retain_days=180 기준 만료일은 archive+purge, 윈도 안은 보존.

    핵심 회귀: archive+purge 후에도 verify_chain 이 끊기지 않고(I1), hot 테이블엔
    윈도 안의 이벤트만 남는다.
    """
    base = date(2026, 1, 1)
    # One event per day for 200 consecutive days, all for kb-bank.
    for n in range(200):
        day = base + timedelta(days=n)
        _seed_event_at(
            chain_store,
            "kb-bank",
            "plan.created",
            datetime(day.year, day.month, day.day, 12, 0, tzinfo=UTC),
        )

    now = base + timedelta(days=199)  # last seeded day == "today"
    sealed = [base + timedelta(days=n) for n in range(200)]
    retain = 180
    retention_plan = plan(now=now, sealed_days=sealed, retain_days=retain)
    # Days 0..18 (age 181..199) are expired (>180); days 19..199 are retained.
    assert len(retention_plan.purge_days) == 19

    svc = RetentionService(store=_adapter(chain_store), tenant_ids=["kb-bank"])
    import asyncio

    result = asyncio.run(svc.apply(retention_plan))

    assert result.purged_total == 19
    assert all(o.purged and o.verified for o in result.outcomes)
    # I1: chain continuity preserved across the purge.
    assert chain_store.verify_chain(tenant_id="kb-bank") is True
    # Hot table holds only the 181 in-window events.
    hot = chain_store.inner.list_events(tenant_id="kb-bank", limit=1000)
    assert len(hot) == 181
    # All purged events are still resolvable via the archive (get_event union).
    full_chain = chain_store.read_chain(tenant_id="kb-bank")
    for rec in full_chain:
        assert chain_store.inner.get_event(rec.event.id, tenant_id="kb-bank") is not None


def test_scheduler_retention_hook_runs_after_seal(tmp_path: Path, chain_store: ChainedEventStore) -> None:
    """run_once invokes the retention hook AFTER the seal commits (fail-closed)."""
    # An old event well outside the window + a fresh one inside it.
    old_day = date(2026, 1, 1)
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 1, 1, 9, 0, tzinfo=UTC))
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 30, 9, 0, tzinfo=UTC))

    svc = RetentionService(store=_adapter(chain_store), tenant_ids=["kb-bank"])
    hook = wire_retention_hook(
        service=svc,
        sealed_days=lambda: [old_day],
        retain_days=180,
        now_fn=lambda: date(2026, 7, 1),
    )
    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
        retention_hook=hook,
    )
    sched.run_once(day=date(2026, 6, 30))
    # Seal evidence written (primary artifact).
    assert (tmp_path / "out" / "2026" / "06" / "merkle_20260630.json").exists()
    # Retention ran: the old day's hot rows are gone, chain still verifies.
    assert chain_store.verify_chain(tenant_id="kb-bank") is True
    remaining_days = {
        e.ts.astimezone(UTC).date()
        for e in chain_store.inner.list_events(tenant_id="kb-bank", limit=1000)
        if e.type == "plan.created"
    }
    assert old_day not in remaining_days


def test_scheduler_retention_hook_failure_does_not_break_seal(
    tmp_path: Path, chain_store: ChainedEventStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A raising retention hook is logged and swallowed; the seal is unaffected."""
    _seed_event_at(chain_store, "kb-bank", "plan.created", datetime(2026, 6, 30, 9, 0, tzinfo=UTC))

    def _boom(_day: date) -> None:
        raise RuntimeError("retention boom")

    sched = DailyMerkleScheduler(
        chain_store=chain_store,
        signer=_signer(),
        tenant_ids=["kb-bank"],
        output_dir=tmp_path / "out",
        retention_hook=_boom,
    )
    with caplog.at_level("ERROR"):
        roots = sched.run_once(day=date(2026, 6, 30))
    assert len(roots) == 1
    assert (tmp_path / "out" / "2026" / "06" / "merkle_20260630.json").exists()
    assert chain_store.verify_chain(tenant_id="kb-bank") is True
    assert any("retention hook failed" in rec.message for rec in caplog.records)
