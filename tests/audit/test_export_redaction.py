# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — e-discovery export + PII redaction."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from secugent.audit.export import EDiscoveryExporter
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

T_A = TenantId("acme")


def _seed(store: EventStore) -> None:
    store.append_event(
        Event(
            tenant_id=T_A,
            actor="role:operator",
            type="step.completed",
            payload={
                "note": "contact alice@corp.com or 010-1234-5678",
                "subject_id": "user-7",
            },
            run_id="r1",
        )
    )
    store.append_event(
        Event(
            tenant_id=T_A,
            actor="sub:writer",
            type="approval.granted",
            payload={"reason": "ok", "user_id": "900101-1234567"},
            run_id="r1",
        )
    )


def test_export_jsonl_without_redaction(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "ex.db")
    _seed(store)
    out = tmp_path / "events.jsonl"
    EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="jsonl")
    text = out.read_text(encoding="utf-8")
    # PHASE 0 redact_string already masks emails inside store, so the email
    # will appear masked but should still be present in some form.
    assert text.count("\n") >= 2  # 2 events written


def test_export_jsonl_with_pii_redaction(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "ex.db")
    _seed(store)
    out = tmp_path / "events.jsonl"
    EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="jsonl", redact_pii=True)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    blob = json.dumps(rows, ensure_ascii=False)
    assert "alice@corp.com" not in blob
    assert "010-1234-5678" not in blob
    assert "900101-1234567" not in blob
    assert "[REDACTED:PII]" in blob


def test_export_csv_format(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "ex.db")
    _seed(store)
    out = tmp_path / "events.csv"
    n = EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="csv")
    assert n == 2
    text = out.read_text(encoding="utf-8")
    assert "id,ts,actor,type,severity" in text


def test_scrub_masks_kr_bank_account() -> None:
    # 적대적 리뷰 finding-2: KR 계좌번호(하이픈 구분 숫자그룹)는 이 도메인(전자금융감독
    # 규정/계좌정보)의 정전 PII 다 — disclosure 산출물에서 마스킹돼야 한다.
    from secugent.audit.export import scrub_pii_for_disclosure

    masked = scrub_pii_for_disclosure("이체 계좌 123-456-789012 확인")
    assert "123-456-789012" not in masked
    assert "[REDACTED:PII]" in masked


def test_scrub_masks_kr_bank_account_four_groups() -> None:
    from secugent.audit.export import scrub_pii_for_disclosure

    masked = scrub_pii_for_disclosure("계좌 1002-123-456789 송금")
    assert "1002-123-456789" not in masked
    assert "[REDACTED:PII]" in masked


def test_scrub_does_not_mask_short_date_like_pairs() -> None:
    # 과대 마스킹 방지: 짧은 두-그룹(예: 날짜/버전 2026-06)은 계좌로 오인하지 않는다.
    from secugent.audit.export import scrub_pii_for_disclosure

    out = scrub_pii_for_disclosure("기간 2026-06 버전 1-2")
    assert "2026-06" in out
    assert "1-2" in out


def test_scrub_masks_16_digit_card_pan_hyphenated() -> None:
    # 적대적 리뷰 finding-1: 16자리 결제 카드 PAN(하이픈 4그룹)은 규제기관 제출
    # 문서로 흘러가면 안 되는 정전 금융 PII 다 — disclosure 산출물에서 마스킹돼야 한다.
    # 1234-5678-9012-3456 은 Luhn-valid 한 테스트 PAN(Visa 테스트 번호 계열)이다.
    from secugent.audit.export import scrub_pii_for_disclosure

    masked = scrub_pii_for_disclosure("카드 4111-1111-1111-1111 결제")
    assert "4111-1111-1111-1111" not in masked
    assert "[REDACTED:PII]" in masked


def test_scrub_masks_16_digit_card_pan_contiguous() -> None:
    from secugent.audit.export import scrub_pii_for_disclosure

    masked = scrub_pii_for_disclosure("카드 4111111111111111 결제")
    assert "4111111111111111" not in masked
    assert "[REDACTED:PII]" in masked


def test_scrub_masks_card_pan_with_spaces() -> None:
    from secugent.audit.export import scrub_pii_for_disclosure

    masked = scrub_pii_for_disclosure("card 4111 1111 1111 1111 ok")
    assert "4111 1111 1111 1111" not in masked
    assert "[REDACTED:PII]" in masked


def test_redact_string_masks_card_pan_symmetric() -> None:
    # finding-1: write-time redact_string 와 disclosure scrub 가 대칭이어야 한다 —
    # 카드 PAN 은 쓰기 시점에도 저장소로 들어가기 전에 마스킹돼야 한다.
    from secugent.core.logger import redact_string

    out = redact_string("PAN 4111-1111-1111-1111 stored")
    assert "4111-1111-1111-1111" not in out


def test_scrub_does_not_mask_non_luhn_16_digit_run() -> None:
    # 과대 마스킹 방지: Luhn 체크를 통과하지 못하는 16자리 숫자열(예: 일련번호/주문번호)은
    # 카드 PAN 으로 오인하지 않는다.
    from secugent.audit.export import scrub_pii_for_disclosure

    out = scrub_pii_for_disclosure("주문번호 1234567890123456 확인")
    assert "1234567890123456" in out
    assert "[REDACTED:PII]" not in out


def test_scrub_masks_kr_account_seven_digit_final_group() -> None:
    # 적대적 리뷰 finding-2: 마지막 그룹이 7자리인 실제 KR 계좌 형식
    # (100-2034-5678901 = 14자리, 카카오뱅크식 3333-12-3456789 = 13자리)도
    # disclosure 에서 마스킹돼야 한다 — 그룹당 6자리 상한이 이를 누락시켰다.
    from secugent.audit.export import scrub_pii_for_disclosure

    for account in ("100-2034-5678901", "3333-12-3456789"):
        masked = scrub_pii_for_disclosure(f"이체 계좌 {account} 확인")
        assert account not in masked, f"{account} leaked"
        assert "[REDACTED:PII]" in masked


def test_export_pages_through_all_events_no_silent_truncation(tmp_path: Path) -> None:
    """e-discovery export must be exhaustive — it must page until the source is
    drained instead of taking a single capped page (item-9 finding-1).

    ``list_events`` orders ``ts DESC``, so a single capped page drops the OLDEST
    rows (the tail). We seed more events than ``page_size`` and export with that
    small ``page_size``; every seeded event — newest AND oldest — must appear in
    the legal disclosure. A single-page implementation (``iter_events(limit=...)``)
    would silently lose the tail and fail this.
    """
    store = EventStore(tmp_path / "ex.db")
    seeded = 25
    expected_ids: set[str] = set()
    for i in range(seeded):
        # Distinct ts (ascending) so ts DESC has a deterministic newest→oldest
        # order; the oldest is event 0, which a capped page would drop.
        ts = datetime(2026, 5, 1, 0, 0, i, tzinfo=UTC)
        ev = Event(
            id=f"evt_{i:03d}",
            tenant_id=T_A,
            ts=ts,
            actor="role:operator",
            type="step.completed",
            payload={"seq": i},
            run_id="r1",
        )
        store.append_event(ev)
        expected_ids.add(ev.id)

    out = tmp_path / "events.jsonl"
    n = EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="jsonl", page_size=10)
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    got_ids = {row["id"] for row in rows}
    assert n == seeded
    assert got_ids == expected_ids  # oldest (evt_000) must NOT be dropped
    # No duplicates: keyset paging yields each in-range event exactly once.
    assert len(rows) == seeded


def test_export_rejects_non_positive_page_size(tmp_path: Path) -> None:
    """``page_size < 1`` is a paging DoS (0 never terminates; <0 → SQLite LIMIT
    unbounded → infinite duplicate yield). Fail fast at call time (§B-8), mirroring
    ``iter_all_events``' own guard, so the e-discovery path can't hang/OOM."""
    store = EventStore(tmp_path / "ex.db")
    _seed(store)
    out = tmp_path / "events.jsonl"
    for bad in (0, -1):
        with pytest.raises(ValueError, match="page_size"):
            EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="jsonl", page_size=bad)


def test_export_until_upper_bound_preserved_with_paging(tmp_path: Path) -> None:
    """The ``until`` upper-bound filter must still apply after migrating to paging —
    events strictly after ``until`` are excluded from the disclosure."""
    store = EventStore(tmp_path / "ex.db")
    in_range = datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC)
    out_of_range = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    store.append_event(
        Event(
            id="evt_in",
            tenant_id=T_A,
            ts=in_range,
            actor="role:operator",
            type="step.completed",
            payload={"x": 1},
            run_id="r1",
        )
    )
    store.append_event(
        Event(
            id="evt_out",
            tenant_id=T_A,
            ts=out_of_range,
            actor="role:operator",
            type="step.completed",
            payload={"x": 2},
            run_id="r1",
        )
    )
    out = tmp_path / "events.jsonl"
    n = EDiscoveryExporter(store).export(
        tenant_id=str(T_A),
        out_path=out,
        fmt="jsonl",
        until=datetime(2026, 5, 15, 0, 0, 0, tzinfo=UTC),
        page_size=10,
    )
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert n == 1
    assert {row["id"] for row in rows} == {"evt_in"}


def test_export_tenant_isolation(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "ex.db")
    _seed(store)
    # Different tenant
    store.append_event(
        Event(
            tenant_id=TenantId("contoso"),
            actor="other",
            type="step.completed",
            payload={"x": 1},
            run_id="rx",
        )
    )
    out = tmp_path / "events.jsonl"
    n = EDiscoveryExporter(store).export(tenant_id=str(T_A), out_path=out, fmt="jsonl")
    assert n == 2  # contoso event excluded
