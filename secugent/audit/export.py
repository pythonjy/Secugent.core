# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — e-discovery export CLI.

Usage::

    python -m secugent.audit.export --db .secugent/secugent.db \
        --tenant acme --from 2026-05-01 --to 2026-05-31 \
        --format jsonl --redact pii --out events.jsonl

The export honours PHASE 0 redaction rules and adds an optional
``--redact pii`` pass that scrubs free-form PII patterns (email / KR RRN /
phone) inside payload string values regardless of their key name.

.. note::
   GDPR / PIPA Right-to-Erasure (an in-place ``--erase`` that rewrites a
   subject's events and re-derives the hash chain) is **not implemented yet**.
   It is a deliberate follow-up: erasure on an append-only, hash-chained log
   requires a spec'd re-derivation + re-signing workflow (§B-1). Until then
   this CLI only reads and exports.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import Literal

from secugent.core.event_store import EventStore

__all__ = ["EDiscoveryExporter", "main", "scrub_pii_for_disclosure", "walk_strings"]


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
        fail fast (§B-8) at *call* time instead of hanging (adversarial-review
        finding-3). The validation is eager (raised before the inner generator is
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
        fast at call time rather than hanging the disclosure path (§B-8).
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
