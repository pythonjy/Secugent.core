# SPDX-License-Identifier: Apache-2.0
"""PG chain body round-trip invariance (the false-break guards).

A PostgreSQL ``event_chain`` row stores the §C-2 link as ``body_canonical`` TEXT
and the event itself as JSONB. Two PG behaviours would make a *naive* verifier
false-trip :class:`AuditChainBrokenError` even though nothing was tampered:

  1. **JSONB numeric re-formatting** — ``1.50`` is stored/returned as ``1.5``.
  2. **TIMESTAMPTZ normalisation** — the stored ts is re-rendered (UTC, fixed
     precision) on read-back.

The design neutralises both by (a) hashing the *canonical stored view* (never the
raw payload) and (b) verifying every link against the STORED ``body_canonical``
bytes — and cross-checking the live row via ``canonical(stored_view(live))``, NOT
the raw JSONB. This module pins the underlying invariants WITHOUT a live Postgres
(a real round-trip is the skip-gated ``tests/integration/test_pg_live_path_cutover``):

  * ``canonical(stored_view(e))`` is INVARIANT under JSON float spelling
    (``1.50`` ≡ ``1.5``) — same canonical bytes, same chain hash.
  * the canonical body is IDEMPOTENT under a reparse round-trip
    (``canonical(stored_view(reparse(body))) == body``), so re-deriving a link
    from the persisted body reproduces the exact hash (no false break).
  * a UTC-normalised timestamp survives the reparse round-trip unchanged.

§C-3 Korean-finance fixtures (goal/payload carry the Korean context; ``TenantId``
is an ASCII slug ``kr-finance``).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.audit.hash_chain import (
    ChainedEventStore,
    canonical,
    compute_chain_hash,
    stored_view,
)
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

_TENANT = "kr-finance"
_TS = datetime(2026, 3, 31, 9, 0, 0, 123456, tzinfo=UTC)  # microsecond-bearing ts


def _evt(payload: dict, *, evt_id: str = "evt-0") -> Event:
    return Event(
        id=evt_id,
        tenant_id=TenantId(_TENANT),
        ts=_TS,
        actor="head:planner",
        type="file.uploaded",
        severity="info",
        run_id="run-q1",
        payload=payload,
    )


def _reparse(body_canonical: str) -> Event:
    """Simulate the PG read-back: parse the stored canonical body into an Event."""
    return Event.model_validate(json.loads(body_canonical))


def test_float_spelling_does_not_change_canonical_or_hash() -> None:
    """``1.50`` and ``1.5`` are the SAME number — identical canonical → identical hash."""
    e_padded = _evt({"ratio": 1.50, "amount": 100.0})
    e_plain = _evt({"ratio": 1.5, "amount": 100.0})
    b1 = canonical(stored_view(e_padded))
    b2 = canonical(stored_view(e_plain))
    assert b1 == b2
    assert compute_chain_hash("GENESIS", b1) == compute_chain_hash("GENESIS", b2)


def test_canonical_body_is_idempotent_under_reparse() -> None:
    """Re-deriving the body from the persisted canonical bytes reproduces them
    exactly — so verifying against ``body_canonical`` never false-breaks."""
    e = _evt({"ratio": 1.50, "note": "마감 보고서", "count": 3})
    body = canonical(stored_view(e))
    again = canonical(stored_view(_reparse(body)))
    assert again == body
    # And therefore the chain hash is identical on re-derivation.
    assert compute_chain_hash("GENESIS", body) == compute_chain_hash("GENESIS", again)


def test_utc_timestamp_survives_reparse_roundtrip() -> None:
    e = _evt({"k": "v"})
    body = canonical(stored_view(e))
    reparsed = _reparse(body)
    # The canonical ts representation is stable across the round-trip.
    assert canonical(stored_view(reparsed)) == body


def test_chained_store_verify_holds_after_body_reparse(tmp_path: Path) -> None:
    """End-to-end on the SQLite reference: appended links verify, and each stored
    body re-derives to its own hash (the property the PG verifier relies on)."""
    chain = ChainedEventStore(EventStore(str(tmp_path / "rt.db")))
    payloads = [{"ratio": 1.50}, {"amount": 1000.00, "note": "원리금"}, {"count": 0}]
    for i, p in enumerate(payloads):
        chain.append_event(_evt(p, evt_id=f"evt-{i}"))
    assert chain.verify_chain(tenant_id=_TENANT) is True
    last = "GENESIS"
    for rec in chain.read_chain(tenant_id=_TENANT):
        body = canonical(stored_view(rec.event))
        assert rec.event_hash == compute_chain_hash(last, body)
        last = rec.event_hash


@settings(max_examples=80, deadline=None)
@given(
    ratio=st.floats(min_value=0, max_value=1e6, allow_nan=False, allow_infinity=False),
    note=st.text(max_size=20),
)
def test_canonical_idempotent_property(ratio: float, note: str) -> None:
    """For ANY float/text payload: canonical(stored_view(reparse(body))) == body."""
    body = canonical(stored_view(_evt({"ratio": ratio, "note": note})))
    assert canonical(stored_view(_reparse(body))) == body
