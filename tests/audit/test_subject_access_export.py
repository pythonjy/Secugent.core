# SPDX-License-Identifier: Apache-2.0
"""정보주체 열람권(Right-to-Access) export 3중 테스트.

결정적 모듈(`audit/export.py`)의 ``SubjectAccessExporter`` 를 단위 + 속성기반 +
시나리오(회귀) 로 검증한다. 핵심 불변식(spec Part B):
  INV-1 테넌트 격리 · INV-2 결정성 · INV-3 완전성 · INV-4 스키마 검증 ·
  INV-5 PII 보호 · INV-6 체인 불변(별도 test_export_chain_invariant) · INV-7 fail-fast.

한국어 픽스처: 개인정보보호위원회 / 금융 테넌트 정보주체(금융 SUB).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.audit.export import (
    EDiscoveryExporter,
    SubjectAccessExporter,
    _subject_matches,
    _within_kst_period,
)
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

# 금융 테넌트 + 개인정보보호위원회 컨텍스트(§C-3 한국어 픽스처).
T_FINANCE = TenantId("kb-finance")
T_OTHER = TenantId("shinhan")
SUBJECT = "kim-cheolsu-880101"  # 금융 정보주체(가명)


def _exporter(store: EventStore) -> SubjectAccessExporter:
    return SubjectAccessExporter(EDiscoveryExporter(store))


def _seed_finance(store: EventStore) -> None:
    """대상 정보주체 2건 + 무관 주체 1건 + 타 테넌트 1건을 적재."""
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="role:operator",
            type="plan.review",
            payload={
                "gate": "plan_review",
                "decision": "approve",
                "rationale": "개인정보보호위원회 신고 대비 계좌조회 승인",
                "subject_id": SUBJECT,
                "rule_of_two_axes": ["sensitive_access"],
            },
            run_id="r-fin-1",
        )
    )
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="sub:finance-writer",
            type="hitl.decided",
            payload={
                "gate": "hitl",
                "decision": "approve",
                "rationale": "정보주체 본인 확인 후 송금",
                "data_subject_id": SUBJECT,  # 별칭 키
            },
            run_id="r-fin-1",
        )
    )
    # 무관 주체(매칭되면 안 됨).
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="sub:finance-writer",
            type="step.completed",
            payload={"subject_id": "other-person-990202", "note": "무관"},
            run_id="r-fin-2",
        )
    )
    # 타 테넌트, 같은 subject_id(격리되어 보이면 안 됨).
    store.append_event(
        Event(
            tenant_id=T_OTHER,
            actor="role:operator",
            type="plan.review",
            payload={"gate": "plan_review", "subject_id": SUBJECT},
            run_id="r-other-1",
        )
    )


# --------------------------------------------------------------------------- #
# 단위 테스트
# --------------------------------------------------------------------------- #


def test_collects_subject_events_only(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    _seed_finance(store)
    rec = _exporter(store).collect(
        tenant_id=str(T_FINANCE),
        subject_id=SUBJECT,
        generated_at=datetime(2026, 6, 25, 12, 0, tzinfo=UTC),
    )
    # 대상 주체 2건만(무관 주체·타 테넌트 제외) — INV-1.
    assert rec.event_count == 2
    types = {e["type"] for e in rec.events}
    assert types == {"plan.review", "hitl.decided"}


def test_tenant_isolation_excludes_other_tenant(tmp_path: object) -> None:
    """타 테넌트의 동일 subject_id 이벤트는 절대 보이지 않는다 — INV-1."""
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    _seed_finance(store)
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
    for ev in rec.events:
        assert ev["tenant_id"] == str(T_FINANCE)
    # 타 테넌트로 조회하면 그 테넌트 1건만.
    rec_other = _exporter(store).collect(tenant_id=str(T_OTHER), subject_id=SUBJECT)
    assert rec_other.event_count == 1


def test_actor_match(tmp_path: object) -> None:
    """actor == subject_id 인 이벤트도 그 주체의 처리기록으로 포함된다."""
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    store.append_event(Event(tenant_id=T_FINANCE, actor=SUBJECT, type="login.ok", payload={}, run_id="r1"))
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
    assert rec.event_count == 1
    assert rec.events[0]["actor"] == SUBJECT


def test_empty_subject_history_no_crash(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    _seed_finance(store)
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id="nobody-000")
    assert rec.event_count == 0
    assert rec.events == ()


def test_period_filter(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 5, 1, 3, 0, tzinfo=UTC),
            type="a",
            payload={"subject_id": SUBJECT},
        )
    )
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 6, 20, 3, 0, tzinfo=UTC),
            type="b",
            payload={"subject_id": SUBJECT},
        )
    )
    rec = _exporter(store).collect(
        tenant_id=str(T_FINANCE),
        subject_id=SUBJECT,
        period=(date(2026, 6, 1), date(2026, 6, 30)),
    )
    assert rec.event_count == 1
    assert rec.events[0]["type"] == "b"


def test_pii_of_other_subjects_masked(tmp_path: object) -> None:
    """대상 주체 이벤트 안의 *타인* PII(이메일/RRN/전화)는 마스킹된다 — INV-5."""
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="role:operator",
            type="plan.review",
            payload={
                "subject_id": SUBJECT,
                "note": "담당자 lee@bank.co.kr 010-9876-5432 가 처리",
            },
        )
    )
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, redact_pii=True)
    blob = rec.to_json()
    assert "lee@bank.co.kr" not in blob
    assert "010-9876-5432" not in blob
    assert "[REDACTED:PII]" in blob


def test_fail_fast_empty_subject(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    with pytest.raises(ValueError, match="subject_id"):
        _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id="")


def test_fail_fast_bad_page_size(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    with pytest.raises(ValueError, match="page_size"):
        _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, page_size=0)


def test_fail_fast_inverted_period(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    with pytest.raises(ValueError, match="period|inverted"):
        _exporter(store).collect(
            tenant_id=str(T_FINANCE),
            subject_id=SUBJECT,
            period=(date(2026, 6, 30), date(2026, 6, 1)),
        )


def test_fail_fast_bad_tenant(tmp_path: object) -> None:
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    with pytest.raises(ValueError):
        _exporter(store).collect(tenant_id="UPPER CASE", subject_id=SUBJECT)


def test_events_schema_valid(tmp_path: object) -> None:
    """산출 이벤트는 Event 모델을 통과한 형태만 포함 — INV-4."""
    store = EventStore(tmp_path / "sa.db")  # type: ignore[operator]
    _seed_finance(store)
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
    for ev in rec.events:
        # 필수 키 존재(Event 직렬화 형태).
        assert {"id", "tenant_id", "ts", "actor", "type", "payload"} <= set(ev.keys())


# --------------------------------------------------------------------------- #
# 속성 기반 테스트(INV-2 결정성 · INV-1 격리)
# --------------------------------------------------------------------------- #


@given(
    n_subject=st.integers(min_value=0, max_value=6),
    n_noise=st.integers(min_value=0, max_value=6),
)
@settings(max_examples=120, deadline=None)
def test_property_isolation_and_count(n_subject: int, n_noise: int) -> None:
    import tempfile
    from pathlib import Path

    tmpdir = Path(tempfile.mkdtemp())
    store = EventStore(tmpdir / "p.db")
    try:
        for i in range(n_subject):
            store.append_event(
                Event(
                    tenant_id=T_FINANCE,
                    actor="role:operator",
                    type=f"evt.{i}",
                    payload={"subject_id": SUBJECT},
                )
            )
        for j in range(n_noise):
            store.append_event(
                Event(
                    tenant_id=T_FINANCE,
                    actor="role:operator",
                    type=f"noise.{j}",
                    payload={"subject_id": f"someone-{j}"},
                )
            )
        rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
        # 정확히 대상 주체 건수만(noise 제외).
        assert rec.event_count == n_subject
    finally:
        store.close()


@given(seed=st.integers(min_value=0, max_value=5))
@settings(max_examples=60, deadline=None)
def test_property_determinism_bytes(seed: int) -> None:
    """동일 입력 → 바이트 동일 to_json() — INV-2."""
    import tempfile
    from pathlib import Path

    tmpdir = Path(tempfile.mkdtemp())
    store = EventStore(tmpdir / "d.db")
    try:
        for i in range(seed + 1):
            store.append_event(
                Event(
                    tenant_id=T_FINANCE,
                    actor="role:operator",
                    ts=datetime(2026, 6, 1, 0, 0, i % 60, tzinfo=UTC),
                    type=f"evt.{i}",
                    payload={"subject_id": SUBJECT, "i": i},
                )
            )
        gen = datetime(2026, 6, 25, 9, 0, tzinfo=UTC)
        a = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, generated_at=gen)
        b = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, generated_at=gen)
        assert a.to_json() == b.to_json()
    finally:
        store.close()


# --------------------------------------------------------------------------- #
# 시나리오 회귀 테스트(결정성 100회 — §B-4a)
# --------------------------------------------------------------------------- #


def test_scenario_determinism_100_runs(tmp_path: object) -> None:
    """고정 픽스처에 대해 to_json() 이 100회 동일(결정성 증명)."""
    store = EventStore(tmp_path / "s.db")  # type: ignore[operator]
    _seed_finance(store)
    gen = datetime(2026, 6, 25, 12, 0, tzinfo=UTC)
    expected = (
        _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, generated_at=gen).to_json()
    )
    for _ in range(100):
        got = (
            _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, generated_at=gen).to_json()
        )
        assert got == expected
    # 산출물이 KST 생성시각을 담는지(§C-3 KST).
    parsed = json.loads(expected)
    assert parsed["generated_at_kst"].endswith("+09:00")
    assert parsed["tenant_id"] == str(T_FINANCE)
    assert parsed["subject_id"] == SUBJECT


def test_within_kst_period_defensive_branches() -> None:
    """비-str ts / 파싱 불가 ts / naive ts 의 방어 분기를 직접 검증(fail-closed)."""
    period = (date(2026, 6, 1), date(2026, 6, 30))
    # 비-str ts → False (deny-by-default).
    assert _within_kst_period(12345, period) is False
    # 파싱 불가 문자열 → False.
    assert _within_kst_period("not-a-timestamp", period) is False
    # naive ISO(타임존 없음) → UTC 가정 후 KST 평가. 06-15 03:00 UTC == 06-15 KST(범위 안).
    assert _within_kst_period("2026-06-15T03:00:00", period) is True


def test_subject_matches_payload_not_dict() -> None:
    """payload 가 dict 가 아니면 (subject/data_subject) 키 매칭 불성립 — deny-by-default."""
    assert _subject_matches({"actor": "x", "payload": "notdict"}, SUBJECT) is False
    # actor 매칭은 payload 모양과 무관하게 성립.
    assert _subject_matches({"actor": SUBJECT, "payload": None}, SUBJECT) is True


def test_payload_not_dict_not_matched(tmp_path: object) -> None:
    """payload 가 dict 가 아닌(또는 subject 키 없는) 이벤트는 actor 매칭 외엔 제외 — deny-by-default."""
    store = EventStore(tmp_path / "nd.db")  # type: ignore[operator]
    # actor 도 다르고 payload 에 subject 키도 없음 → 비매칭.
    store.append_event(
        Event(tenant_id=T_FINANCE, actor="someone-else", type="x", payload={"k": "v"}, run_id="r1")
    )
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
    assert rec.event_count == 0


def test_period_excludes_naive_and_out_of_range(tmp_path: object) -> None:
    """period 지정 시 범위 밖(이전) 이벤트는 제외되고 경계는 KST 로 평가된다."""
    store = EventStore(tmp_path / "pn.db")  # type: ignore[operator]
    # 2026-05-31 18:00 UTC == 2026-06-01 03:00 KST → period [06-01, 06-30] 안.
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 5, 31, 18, 0, tzinfo=UTC),
            type="in_kst",
            payload={"subject_id": SUBJECT},
        )
    )
    # 2026-05-31 03:00 UTC == 2026-05-31 12:00 KST → period 밖(이전).
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 5, 31, 3, 0, tzinfo=UTC),
            type="before",
            payload={"subject_id": SUBJECT},
        )
    )
    rec = _exporter(store).collect(
        tenant_id=str(T_FINANCE),
        subject_id=SUBJECT,
        period=(date(2026, 6, 1), date(2026, 6, 30)),
    )
    assert {e["type"] for e in rec.events} == {"in_kst"}


def test_generated_at_naive_assumed_utc(tmp_path: object) -> None:
    """naive generated_at 은 UTC 로 간주되어 KST(+09:00) 로 변환된다."""
    store = EventStore(tmp_path / "g.db")  # type: ignore[operator]
    _seed_finance(store)
    naive = datetime(2026, 6, 25, 0, 0)  # tz 없음 → UTC 가정 → 09:00 KST
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, generated_at=naive)
    assert rec.generated_at_kst == "2026-06-25T09:00:00+09:00"


def test_period_excludes_event_after_end_but_after_since(tmp_path: object) -> None:
    """Branch 461->462/462: an event whose ts is AFTER the period end (so it
    survives the SQL ``since`` push-down, since since=period start) is still
    excluded by the KST upper-bound check (``continue``).

    period=[2026-06-01, 2026-06-30] → since=2026-05-31T15:00Z. The event at
    2026-07-05T03:00Z is >= since (passes SQL) but its KST date 2026-07-05 is
    > end 2026-06-30 → _within_kst_period False → continue → not counted.
    """
    store = EventStore(tmp_path / "after_end.db")  # type: ignore[operator]
    # In-range anchor so the result is non-trivially "filtered", not just empty.
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 6, 15, 3, 0, tzinfo=UTC),
            type="in_range",
            payload={"subject_id": SUBJECT},
        )
    )
    # After the period END but AFTER the SQL since cutoff → reaches the continue.
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="x",
            ts=datetime(2026, 7, 5, 3, 0, tzinfo=UTC),
            type="after_end",
            payload={"subject_id": SUBJECT},
        )
    )
    rec = _exporter(store).collect(
        tenant_id=str(T_FINANCE),
        subject_id=SUBJECT,
        period=(date(2026, 6, 1), date(2026, 6, 30)),
    )
    assert rec.event_count == 1  # the after_end event was EXCLUDED by the upper bound
    assert {e["type"] for e in rec.events} == {"in_range"}


def test_no_redaction_skips_export_pii_scrub(tmp_path: object) -> None:
    """Branch 468->471 (``redact_pii`` False): the export-level PII scrub block is
    SKIPPED, so no ``[REDACTED:PII]`` token is injected — the payload is surfaced
    exactly as the store holds it.

    A phone number survives ``EventStore``'s write-time mask verbatim, so it is the
    clean raw-vs-scrubbed witness: with ``redact_pii=False`` the export does NOT
    touch it (raw ``010-9876-5432`` preserved); with ``redact_pii=True`` the SAME
    row is scrubbed to ``[REDACTED:PII]``. The contrast proves the False arm
    genuinely diverges (non-vacuous).
    """
    store = EventStore(tmp_path / "raw_pii.db")  # type: ignore[operator]
    store.append_event(
        Event(
            tenant_id=T_FINANCE,
            actor="role:operator",
            type="plan.review",
            payload={
                "subject_id": SUBJECT,
                "note": "담당자 연락처 010-9876-5432",
            },
        )
    )
    rec_off = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, redact_pii=False)
    assert rec_off.event_count == 1
    assert rec_off.redaction_applied is False
    note_off = rec_off.events[0]["payload"]["note"]  # type: ignore[index]
    assert "[REDACTED:PII]" not in note_off
    assert "010-9876-5432" in note_off  # raw PII preserved verbatim — scrub did NOT run

    # Contrast: with redaction ON the SAME row is scrubbed to [REDACTED:PII],
    # proving the False arm above genuinely diverges.
    rec_on = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT, redact_pii=True)
    assert rec_on.redaction_applied is True
    assert "010-9876-5432" not in rec_on.events[0]["payload"]["note"]  # type: ignore[index]
    assert "[REDACTED:PII]" in rec_on.events[0]["payload"]["note"]  # type: ignore[index]


def test_ediscovery_iter_events_single_page(tmp_path: object) -> None:
    """EDiscoveryExporter.iter_events yields each event as a json-mode dict
    (legacy single-page path, lines 198-200)."""
    store = EventStore(tmp_path / "iter.db")  # type: ignore[operator]
    store.append_event(Event(tenant_id=T_FINANCE, actor="x", type="a", payload={"k": "v"}, run_id="r1"))
    store.append_event(Event(tenant_id=T_FINANCE, actor="y", type="b", payload={"k": "w"}, run_id="r1"))
    exporter = EDiscoveryExporter(store)
    rows = list(exporter.iter_events(tenant_id=str(T_FINANCE)))
    assert len(rows) == 2
    assert all(isinstance(r, dict) for r in rows)
    assert {r["type"] for r in rows} == {"a", "b"}


def test_scenario_stable_sort_same_ts(tmp_path: object) -> None:
    """같은 ts 다수 이벤트도 (ts, id) 총 순서로 안정 정렬 — INV-2."""
    store = EventStore(tmp_path / "ss.db")  # type: ignore[operator]
    ts = datetime(2026, 6, 10, 1, 2, 3, tzinfo=UTC)
    for i in range(5):
        store.append_event(
            Event(
                id=f"evt-{i:02d}",
                tenant_id=T_FINANCE,
                actor="x",
                ts=ts,
                type=f"t{i}",
                payload={"subject_id": SUBJECT},
            )
        )
    rec = _exporter(store).collect(tenant_id=str(T_FINANCE), subject_id=SUBJECT)
    ids = [e["id"] for e in rec.events]
    assert ids == sorted(ids)
