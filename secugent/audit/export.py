# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — e-discovery export CLI.

Usage::

    python -m secugent.audit.export --db .secugent/secugent.db \
        --tenant acme --from 2026-05-01 --to 2026-05-31 \
        --format jsonl --redact pii --out events.jsonl

The export honours PHASE 0 redaction rules and adds an optional
``--redact pii`` pass that scrubs free-form PII patterns (email / KR RRN /
phone) inside payload string values regardless of their key name.

This module also provides :class:`SubjectAccessExporter` — PIPA §35 / GDPR
Art.15 **subject-level Right-to-Access** export: a tenant-isolated, schema-
validated, KST-stamped, deterministic dump of one data subject's processing
records (read-only; never mutates the audit hash chain).

.. note::
   PIPA §36 / GDPR Art.17 Right-to-**Erasure** is **design only**. Erasure on an
   append-only, hash-chained log conflicts with audit integrity (re-deriving the
   chain is rejected); tombstone / crypto-shredding options were evaluated and
   implementation deferred. It is NOT implemented here.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

__all__ = [
    "EDiscoveryExporter",
    "SubjectAccessExporter",
    "SubjectAccessRecord",
    "main",
    "scrub_pii_for_disclosure",
    "walk_strings",
]

#: KST (UTC+9) — 정보주체 열람권 산출물의 생성 시각 타임존.
_KST = timezone(timedelta(hours=9), name="KST")


#: KR bank-account numbers: 3+ hyphen-separated digit groups, 10–14 total digits
#: (e.g. ``123-456-789012``, ``1002-123-456789``, ``100-2034-5678901``). The RRN
#: pattern (``\d{6}-\d{7}``, exactly two groups) is matched first, so RRNs are never
#: mis-handled by this. The per-group cap is intentionally loose (``\d{2,8}``) so
#: real segmentations with a 7-digit final group (Kakao-Bank / securities accounts,
#: ``100-2034-5678901``, ``3333-12-3456789``) are not excluded; the *total* digit
#: count (10–14, checked in :func:`_mask_bank_account`) is the real discriminator,
#: not the per-group width (adversarial-review finding-2). The 3-group minimum +
#: total-digit floor still avoids over-masking short date/version pairs (``2026-06``,
#: ``1-2``), which are two groups and below the digit floor.
_KR_BANK_ACCOUNT = re.compile(r"\b\d{2,8}(?:-\d{2,8}){2,}\b")

#: Payment-card PANs (credit/debit): 13–19 digits, either contiguous or in
#: hyphen/space groups (the canonical ``1234-5678-9012-3456`` 16-digit layout). The
#: bank-account masker bounds total digits to 10–14, which EXCLUDES the most common
#: 16-digit card length, so a PAN embedded in a free-form rationale would otherwise
#: flow verbatim into a regulator-facing report (adversarial-review finding-1). A
#: Luhn check (:func:`_luhn_valid`) gates masking so incidental 13–19 digit runs
#: (order/serial numbers) are not over-masked. ``[ -]?`` between digits matches the
#: grouped layout without spanning unrelated tokens.
_CARD_PAN = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def _luhn_valid(digits: str) -> bool:
    """Return ``True`` iff ``digits`` (a digit-only string) satisfies the Luhn checksum.

    Used to distinguish real payment-card PANs from incidental long digit runs so
    the card masker does not over-mask order/serial numbers. ``digits`` is assumed
    to contain only ``0-9`` (the caller strips separators first).
    """
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48  # '0' == 48; caller guarantees digits-only
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card_pan(value: str) -> str:
    """Mask Luhn-valid 13–19 digit payment-card PANs (contiguous or grouped).

    Applied BEFORE the bank-account masker so a 16-digit grouped PAN is caught by
    the card rule (its total digit count falls outside the 10–14 account band). The
    Luhn gate avoids masking incidental long digit runs that are not real cards.
    """

    def _sub(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return "[REDACTED:PII]" if 13 <= len(digits) <= 19 and _luhn_valid(digits) else match.group(0)

    return _CARD_PAN.sub(_sub, value)


def _mask_bank_account(value: str) -> str:
    """Mask only hyphen-grouped runs whose total digit count is a plausible account.

    Applied after the fixed patterns. The regex already requires 3+ groups; here we
    additionally bound the *total* digit count to 10–14 so genuine account numbers
    are masked while incidental multi-hyphen tokens with too few/many digits are
    left intact (fail-open on non-account shapes, never under-mask a real account).
    The per-group regex cap is loose (``\\d{2,8}``) so the total-digit band — not the
    segment width — is the discriminator; this masks real 7-digit-final-group
    accounts (``100-2034-5678901``) that a 6-digit cap silently leaked (finding-2).
    """

    def _sub(match: re.Match[str]) -> str:
        digits = match.group(0).replace("-", "")
        return "[REDACTED:PII]" if 10 <= len(digits) <= 14 else match.group(0)

    return _KR_BANK_ACCOUNT.sub(_sub, value)


_PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{6}-\d{7}\b"),
    re.compile(r"\b01\d-?\d{3,4}-?\d{4}\b"),
)


def scrub_pii_for_disclosure(value: str) -> str:
    """Mask free-form PII for any disclosure artifact.

    Masks: **email**, **KR RRN** (``\\d{6}-\\d{7}``), **KR mobile phone**
    (``01x-...``), **payment-card PANs** (Luhn-valid 13–19 digit runs, contiguous or
    grouped), and **KR bank-account numbers** (3+ hyphen-grouped digit runs of
    10–14 total digits). Cards and bank accounts are the canonical PII for the
    KR-finance domain the compliance feature targets (전자금융감독규정 / 계좌정보 /
    카드정보 contexts), so they are masked here rather than leaking into the
    regulator-facing artifact (adversarial-review findings 1/2). NOT covered:
    free-form short tokens / API keys (no reliable shape) — those remain an
    accepted, documented gap.

    Shared redact-for-disclosure helper: any artifact leaving the system to an
    external party (e-discovery export, compliance evidence report) MUST run
    free-form text through this so the disclosure surface is at least as strong
    as ``export --redact pii``. Stronger than the write-time
    :func:`secugent.core.logger.redact_string`, which does NOT cover KR
    phone-number / bank-account formats (``redact_string`` mirrors the card-PAN
    rule for write/disclosure symmetry).
    """
    # Card PANs first: a 16-digit grouped PAN must be caught here before the
    # bank-account masker (whose 10–14 band excludes the common 16-digit length).
    value = _mask_card_pan(value)
    for pattern in _PII_PATTERNS:
        value = pattern.sub("[REDACTED:PII]", value)
    # Bank-account masking runs last (after RRN, which is exactly two groups) and is
    # digit-count-bounded to avoid over-masking short multi-hyphen tokens.
    return _mask_bank_account(value)


def walk_strings(payload: object, fn: Callable[[str], str]) -> object:
    """Apply ``fn`` to every string leaf of a JSON-like structure (recursive)."""
    if isinstance(payload, str):
        return fn(payload)
    if isinstance(payload, dict):
        return {k: walk_strings(v, fn) for k, v in payload.items()}
    if isinstance(payload, list):
        return [walk_strings(v, fn) for v in payload]
    return payload


# Backward-compatible private aliases (existing callers/tests import the ``_`` names).
_pii_scrub = scrub_pii_for_disclosure
_walk_strings = walk_strings


class EDiscoveryExporter:
    def __init__(self, store: EventStore) -> None:
        self._store = store

    def iter_events(
        self,
        *,
        tenant_id: str,
        since: datetime | None = None,
        limit: int = 100_000,
        offset: int = 0,
    ) -> Iterable[dict[str, object]]:
        events = self._store.list_events(tenant_id=tenant_id, limit=limit, since=since, offset=offset)
        for event in events:
            yield event.model_dump(mode="json")

    def iter_all_events(
        self,
        *,
        tenant_id: str,
        since: datetime | None = None,
        page_size: int = 10_000,
    ) -> Iterable[dict[str, object]]:
        """Yield **every** event for a tenant by paging until the source is exhausted.

        Unlike :meth:`iter_events` (which caps at a single ``limit`` page and so
        silently drops the oldest rows once a tenant exceeds it), this pages with a
        ``(ts, id)`` **keyset cursor** until a short page is returned, so no in-range
        event is ever truncated. A legal compliance-evidence generator MUST use this
        (fail-complete, not fail-soft).

        **Concurrency (adversarial-review finding-3):** the store releases its lock
        between pages (there is no snapshot spanning the multi-page loop). OFFSET
        paging over a non-unique order would therefore skip rows when a concurrent
        ``append_event`` shifts later pages forward, or duplicate rows when a
        concurrent ``purge_day`` DELETE shifts them backward — corrupting the very
        Art.12/N²SF completeness count this method guarantees. Keyset pagination
        anchored on the ``(ts DESC, id DESC)`` **total order** (the ``id`` tiebreaker
        added in :meth:`EventStore.list_events`) is immune: the next page is defined
        relative to the last row seen, not a positional offset, so an insert/delete
        elsewhere cannot move the window. The cursor advances monotonically, so each
        in-range event is yielded **exactly once**.

        ``page_size`` MUST be ``>= 1``: the termination invariant
        ``len(page) < page_size`` is only valid for a positive page. ``page_size == 0``
        makes ``list_events(limit=0)`` return ``[]`` so ``0 < 0`` is False and the loop
        never terminates; ``page_size < 0`` makes SQLite treat ``LIMIT -1`` as unbounded
        so every page re-returns all rows and the loop yields duplicates without bound.
        Both are resource-exhaustion / DoS on the compliance-evidence path, so we
        fail fast at *call* time instead of hanging. The validation is eager
        (raised before the inner generator is
        returned) so the ``ValueError`` surfaces even if the caller never iterates.
        """
        if page_size < 1:
            raise ValueError(f"page_size must be >= 1, got {page_size}")
        return self._iter_all_events(tenant_id=tenant_id, since=since, page_size=page_size)

    def _iter_all_events(
        self,
        *,
        tenant_id: str,
        since: datetime | None,
        page_size: int,
    ) -> Iterable[dict[str, object]]:
        # Keyset pagination over the (ts DESC, id DESC) total order: each page is
        # anchored on the LAST row of the previous page rather than a positional
        # OFFSET, so a concurrent append/purge between pages cannot skip or
        # duplicate an in-range event (finding-3). The first page uses no cursor.
        cursor: tuple[datetime, str] | None = None
        while True:
            page = self._store.list_events(
                tenant_id=tenant_id,
                limit=page_size,
                since=since,
                keyset_before=cursor,
            )
            for event in page:
                yield event.model_dump(mode="json")
            if len(page) < page_size:
                return
            last = page[-1]
            cursor = (last.ts, last.id)

    def export(
        self,
        *,
        tenant_id: str,
        out_path: Path,
        fmt: Literal["jsonl", "csv"],
        redact_pii: bool = False,
        since: datetime | None = None,
        until: datetime | None = None,
        page_size: int = 10_000,
    ) -> int:
        """Write **every** in-range event for ``tenant_id`` to ``out_path``.

        The e-discovery export is a legal-disclosure artifact for courts/regulators,
        so it MUST be exhaustive (fail-complete, not fail-soft). It pages through
        :meth:`iter_all_events` (race-free ``(ts, id)`` keyset cursor) until the
        source is drained, instead of taking a single ``iter_events(limit=100_000)``
        page that — because ``list_events`` orders ``ts DESC`` — would silently drop
        the OLDEST rows once a tenant exceeds the cap (item-9 finding-1). This makes
        the disclosure as complete as the compliance-evidence report, which already
        migrated to ``iter_all_events``.

        ``since`` is pushed down to the store as a lower bound; ``until`` is applied
        here as an inclusive upper bound (events strictly after it are excluded).
        ``page_size`` MUST be ``>= 1`` — :meth:`iter_all_events` raises ``ValueError``
        eagerly for non-positive values (0 never terminates; <0 makes SQLite treat
        ``LIMIT -1`` as unbounded → infinite duplicate yield → OOM), so a misuse fails
        fast at call time rather than hanging the disclosure path.
        """
        rows = []
        for event in self.iter_all_events(tenant_id=tenant_id, since=since, page_size=page_size):
            if until is not None and datetime.fromisoformat(str(event["ts"])) > until:
                continue
            if redact_pii:
                event["payload"] = _walk_strings(event["payload"], _pii_scrub)
                event["actor"] = _pii_scrub(str(event["actor"]))
            rows.append(event)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "jsonl":
            with out_path.open("w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        else:
            fieldnames = [
                "id",
                "ts",
                "actor",
                "type",
                "severity",
                "run_id",
                "step_id",
                "tenant_id",
                "payload",
            ]
            with out_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    payload_str = json.dumps(row.get("payload", {}), ensure_ascii=False)
                    writer.writerow(
                        {**{k: row.get(k) for k in fieldnames if k != "payload"}, "payload": payload_str}
                    )
        return len(rows)


# ---------------------------------------------------------------------------
# PIPA §35 / GDPR Art.15 — subject-level Right-to-Access export
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubjectAccessRecord:
    """한 정보주체 열람권 추출 결과(불변, 스키마 검증된 직렬화 단위).

    ``events`` 는 ``Event`` 모델을 통과한 형태(``model_dump(mode="json")``)만 담으며
    ``(ts, id)`` 총 순서로 안정 정렬된다(spec INV-2/INV-4). ``to_json`` 은 ``sort_keys``
    로 결정적이라 동일 입력은 바이트 동일 산출물을 만든다(INV-2).
    """

    subject_id: str
    tenant_id: str
    generated_at_kst: str
    period: tuple[date, date] | None
    event_count: int
    events: tuple[dict[str, object], ...]
    redaction_applied: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "tenant_id": self.tenant_id,
            "generated_at_kst": self.generated_at_kst,
            "period": (
                [self.period[0].isoformat(), self.period[1].isoformat()] if self.period is not None else None
            ),
            "event_count": self.event_count,
            "redaction_applied": self.redaction_applied,
            "events": list(self.events),
        }

    def to_json(self) -> str:
        """결정적 JSON 직렬화(sort_keys, ensure_ascii=False) — 한국어 보존."""
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)


def _subject_matches(raw: dict[str, object], subject_id: str) -> bool:
    """이벤트가 ``subject_id`` 에 '관한' 처리기록인지 결정적으로 판정(deny-by-default).

    인정 조건(정확 문자열 일치만 — 부분일치/정규식 금지로 타 주체 누출 방지):
      1. ``payload.subject_id == subject_id``
      2. ``payload.data_subject_id == subject_id`` (별칭)
      3. ``actor == subject_id`` (그 주체가 직접 행위자)
    payload 가 dict 가 아니면 (1)(2) 불성립.
    """
    if raw.get("actor") == subject_id:
        return True
    payload = raw.get("payload")
    if not isinstance(payload, dict):
        return False
    return payload.get("subject_id") == subject_id or payload.get("data_subject_id") == subject_id


def _within_kst_period(ts_value: object, period: tuple[date, date]) -> bool:
    """이벤트 UTC 타임스탬프를 KST 날짜로 변환해 ``[start, end]`` 포함성을 본다."""
    if not isinstance(ts_value, str):
        return False
    try:
        parsed = datetime.fromisoformat(ts_value)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    kst_date = parsed.astimezone(_KST).date()
    start, end = period
    return start <= kst_date <= end


class SubjectAccessExporter:
    """정보주체 단위 열람권(PIPA §35 / GDPR Art.15) 추출기.

    기존 :class:`EDiscoveryExporter` 가 테넌트 전체 e-discovery 라면, 본 추출기는 **한
    정보주체로 필터**한 처리기록을 빠짐없이·테넌트 격리하에·스키마 검증된 형태로 모은다.

    **읽기 전용(INV-6)**: 감사 해시체인(``compute_chain_hash``/``canonical``/chain 테이블)
    을 절대 호출·수정하지 않는다. 오직 race-free ``iter_all_events`` (keyset) 로 읽기만
    하므로 det ``9b99792311ebcc94`` 는 불변이다.
    """

    def __init__(self, exporter: EDiscoveryExporter) -> None:
        self._exporter = exporter

    def collect(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        period: tuple[date, date] | None = None,
        generated_at: datetime | None = None,
        redact_pii: bool = True,
        page_size: int = 10_000,
    ) -> SubjectAccessRecord:
        """``subject_id`` 에 관한 ``tenant_id`` 의 처리기록을 빠짐없이 모은다.

        **인가 계약**: ``tenant_id`` 는 경계에서 :class:`TenantId` 정규식으로 검증된다 —
        형식 위반은 즉시 :class:`ValueError`. 호출자(API 라우트)는 *이미 인증된 테넌트와
        요청 테넌트가 일치함*을 추가로 보장해야 한다(cross-tenant 읽기 방지, fail-closed).

        **fail-fast**: 빈 ``subject_id`` (전체 덤프 방지) · 뒤집힌 ``period`` ·
        ``page_size < 1`` (자원고갈 차단) 은 즉시 :class:`ValueError`.

        **완전성(INV-3)**: ``iter_all_events`` (keyset 커서) 로 소스를 소진할 때까지
        페이징하므로 100k 캡으로 가장 오래된 이벤트가 잘리지 않는다.

        **PII 보호(INV-5)**: ``redact_pii=True`` (기본) 시 대상 이벤트 안의 *타 정보주체*
        PII(이메일/RRN/전화/카드/계좌)를 :func:`scrub_pii_for_disclosure` 로 마스킹한다.
        대상 주체 식별자(``subject_id``) 자체는 매칭 키이므로 보존(매칭 후 적용).
        """
        if not subject_id:
            raise ValueError("subject_id must be a non-empty string (refusing to dump whole tenant)")
        if page_size < 1:
            raise ValueError(f"page_size must be >= 1, got {page_size}")
        if period is not None and period[0] > period[1]:
            raise ValueError(
                f"inverted period: start {period[0].isoformat()} must be <= end {period[1].isoformat()}"
            )
        # 경계 검증(finding-2 류): 잘못된 tenant_id 는 스토어 도달 전 ValueError.
        tid = str(TenantId(tenant_id))

        since = _period_start_utc(period[0]) if period is not None else None
        matched: list[dict[str, object]] = []
        for raw in self._exporter.iter_all_events(tenant_id=tid, since=since, page_size=page_size):
            if period is not None and not _within_kst_period(raw.get("ts"), period):
                continue
            if not _subject_matches(raw, subject_id):
                continue
            # 스키마 검증(INV-4): 산출 전 Event 모델을 통과한 정규형만 담는다.
            event = Event.model_validate(raw)
            row = event.model_dump(mode="json")
            if redact_pii:
                row["payload"] = walk_strings(row.get("payload"), scrub_pii_for_disclosure)
                row["actor"] = scrub_pii_for_disclosure(str(row["actor"]))
            matched.append(row)

        # (ts, id) 총 순서로 안정 정렬(체인 정렬 규칙과 동일 — INV-2).
        matched.sort(key=lambda e: (str(e.get("ts")), str(e.get("id"))))
        return SubjectAccessRecord(
            subject_id=subject_id,
            tenant_id=tid,
            generated_at_kst=_format_kst(generated_at),
            period=period,
            event_count=len(matched),
            events=tuple(matched),
            redaction_applied=redact_pii,
        )


def _period_start_utc(start: date) -> datetime:
    """기간 시작 KST 자정을 UTC 로 변환해 SQL ``since`` 푸시다운에 쓴다.

    KST 날짜 ``start`` 의 00:00 KST 는 UTC 로 전날 15:00 이다. 이 시각 이후만 스토어에서
    읽으면 범위 밖(이전) 이벤트를 미리 잘라낸다(상한은 ``_within_kst_period`` 가 처리).
    """
    kst_midnight = datetime(start.year, start.month, start.day, tzinfo=_KST)
    return kst_midnight.astimezone(UTC)


def _format_kst(generated_at: datetime | None) -> str:
    """생성 시각을 KST ISO8601 문자열로(미지정 시 현재 KST)."""
    moment = generated_at if generated_at is not None else datetime.now(tz=_KST)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(_KST).isoformat()


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - CLI shell
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--from", dest="from_", type=str, default=None)
    parser.add_argument("--to", type=str, default=None)
    parser.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    parser.add_argument("--redact", choices=("none", "pii"), default="none")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    since = datetime.fromisoformat(args.from_) if args.from_ else None
    until = datetime.fromisoformat(args.to) if args.to else None
    store = EventStore(args.db)
    try:
        exporter = EDiscoveryExporter(store)
        n = exporter.export(
            tenant_id=args.tenant,
            out_path=args.out,
            fmt=args.format,
            redact_pii=(args.redact == "pii"),
            since=since,
            until=until,
        )
        print(f"exported {n} events → {args.out}")
        return 0
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
