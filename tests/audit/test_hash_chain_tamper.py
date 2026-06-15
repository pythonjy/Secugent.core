# SPDX-License-Identifier: Apache-2.0
"""Tamper-detection scenario regression tests for the audit hash chain.

§B-4a deterministic-module discipline: ``secugent.audit.hash_chain`` is the
append-only audit trail's integrity primitive. Its *trust claim* is that a
single-byte mutation anywhere in either backing table (``events`` or
``event_chain``) is detected and surfaced as :class:`AuditChainBrokenError`
rather than silently accepted. These tests build a valid chain deterministically
and then tamper exactly one record per case to exercise every fail-closed RAISE
path in :meth:`ChainedEventStore.verify_chain` and
:meth:`ChainedEventStore._iter_chain_rows`:

* corrupt canonical body  → ``_iter_chain_rows`` fails closed (not a raw parse error)
* ``prev_hash`` desync     → chain-link break
* ``event_hash`` desync    → chain-record tamper
* chained-but-missing      → SG-05 partial-write gap (store row deleted)
* underlying payload tamper → store-table mutation desyncs from chain body
* ``iter_hashes`` traversal → Merkle feed reads the full chain

All cases use fixed ids/timestamps/payloads so the derived hashes are
reproducible run-to-run (no time/uuid nondeterminism).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from secugent.audit.hash_chain import (
    GENESIS,
    AuditChainBrokenError,
    ChainedEventStore,
    canonical,
    compute_chain_hash,
)
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

T_A = TenantId("acme")


def _event(seq: int) -> Event:
    """A deterministic event (fixed id/ts/payload) for reproducible hashing."""
    return Event(
        id=f"evt_{seq:03d}",
        tenant_id=T_A,
        ts=datetime(2026, 5, 1, 0, 0, seq, tzinfo=UTC),
        actor="role:operator",
        type="step.completed",
        payload={"seq": seq, "note": "deterministic"},
        run_id="r1",
        step_id=f"s{seq}",
    )


def _build_chain(tmp_path: Path, n: int = 3) -> ChainedEventStore:
    """Append ``n`` events through a fresh chain and assert it verifies clean."""
    store = ChainedEventStore(EventStore(tmp_path / "chain.db"))
    for i in range(1, n + 1):
        store.append_event(_event(i))
    assert store.verify_chain(tenant_id=str(T_A)) is True
    return store


def _raw_conn(store: ChainedEventStore) -> sqlite3.Connection:
    """A second connection to the same DB file for out-of-band tampering.

    Mutating through a *separate* connection (autocommit) models an attacker who
    edits the durable SQLite file directly, bypassing the append-only API — the
    exact threat ``verify_chain`` must catch.
    """
    return sqlite3.connect(str(store.inner.path), isolation_level=None)


# --------------------------------------------------------------------------- #
# Baseline: a clean, untampered chain verifies and is deterministic.
# --------------------------------------------------------------------------- #


def test_clean_chain_verifies(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    assert store.verify_chain(tenant_id=str(T_A)) is True
    store.close()


def test_chain_hashes_are_deterministic(tmp_path: Path) -> None:
    """Same event stream → byte-identical hash sequence across builds (§B-4a)."""
    seqs_a = list(_build_chain(tmp_path / "a").iter_hashes(tenant_id=str(T_A)))
    seqs_b = list(_build_chain(tmp_path / "b").iter_hashes(tenant_id=str(T_A)))
    assert seqs_a == seqs_b
    # First link is genesis-anchored; verify the public pure functions agree.
    first_body = canonical(_event(1))
    assert seqs_a[0] == compute_chain_hash(GENESIS, first_body)


# --------------------------------------------------------------------------- #
# RAISE path 1 (lines 227-231): a chain row whose body is no longer a valid
# Event must fail closed in _iter_chain_rows as a chain break, NOT leak a raw
# JSON/validation error.
# --------------------------------------------------------------------------- #


def test_corrupt_canonical_body_invalid_json(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    conn.execute(
        "UPDATE event_chain SET body_canonical=? WHERE event_id=?",
        ("{not valid json", "evt_002"),
    )
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="chain body is corrupt"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


def test_corrupt_canonical_body_valid_json_not_event(tmp_path: Path) -> None:
    """Well-formed JSON that is not a valid Event (missing required fields) must
    also fail closed via the ValidationError arm, not crash with a raw error."""
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    conn.execute(
        "UPDATE event_chain SET body_canonical=? WHERE event_id=?",
        (json.dumps({"id": "evt_002", "unexpected": True}), "evt_002"),
    )
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="chain body is corrupt"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


# --------------------------------------------------------------------------- #
# RAISE path 2 (line 258): prev_hash desync — a chain link no longer points at
# the previous event's hash.
# --------------------------------------------------------------------------- #


def test_prev_hash_mismatch(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    # Flip prev_hash on the 2nd event to a wrong-but-syntactically-valid value.
    conn.execute(
        "UPDATE event_chain SET prev_hash=? WHERE event_id=?",
        ("0" * 64, "evt_002"),
    )
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="prev_hash mismatch"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


# --------------------------------------------------------------------------- #
# RAISE path 3 (line 260): event_hash desync — the stored chain-record hash no
# longer matches sha256(prev || body). Must trip BEFORE the prev_hash check, so
# we keep prev_hash consistent and only corrupt event_hash.
# --------------------------------------------------------------------------- #


def test_event_hash_mismatch_chain_record_tampered(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    # Tamper the genesis event's stored event_hash. prev_hash stays GENESIS
    # (consistent with last_hash), so the prev_hash guard passes and execution
    # reaches the event_hash mismatch raise.
    conn.execute(
        "UPDATE event_chain SET event_hash=? WHERE event_id=?",
        ("f" * 64, "evt_001"),
    )
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="chain record tampered"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


# --------------------------------------------------------------------------- #
# RAISE path 4 (line 265): an event is chained but its row is gone from the
# underlying store (SG-05 partial-write / store-table deletion gap).
# --------------------------------------------------------------------------- #


def test_event_chained_but_missing_from_store(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    # Delete the store row but leave the chain row intact: the chain still links
    # cleanly (hashes untouched) yet the durable event has vanished.
    conn.execute("DELETE FROM events WHERE id=?", ("evt_002",))
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="present in chain but missing from store"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


# --------------------------------------------------------------------------- #
# RAISE path 5 (line 267): the underlying store payload is mutated so its
# re-derived canonical form no longer matches the chain's body_canonical.
# --------------------------------------------------------------------------- #


def test_underlying_store_payload_tampered(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    # Mutate ONLY the events-table payload (not the chain row). The chain link
    # hashes still verify against body_canonical, but live canonical(store row)
    # now diverges → underlying-payload-tamper raise.
    tampered_payload = json.dumps({"seq": 2, "note": "TAMPERED"}, ensure_ascii=False)
    conn.execute("UPDATE events SET payload=? WHERE id=?", (tampered_payload, "evt_002"))
    conn.close()
    with pytest.raises(AuditChainBrokenError, match="underlying payload tampered"):
        store.verify_chain(tenant_id=str(T_A))
    store.close()


# --------------------------------------------------------------------------- #
# RAISE path 6 (lines 278-279): iter_hashes walks the full chain (Merkle feed).
# --------------------------------------------------------------------------- #


def test_iter_hashes_traverses_full_chain(tmp_path: Path) -> None:
    store = _build_chain(tmp_path, n=4)
    hashes = list(store.iter_hashes(tenant_id=str(T_A)))
    records = store.read_chain(tenant_id=str(T_A))
    # One hash per chained event, in seq order, matching each record's event_hash.
    assert hashes == [r.event_hash for r in records]
    assert len(hashes) == 4
    # All distinct (each link folds in the prior hash + a unique body).
    assert len(set(hashes)) == 4
    store.close()


def test_iter_hashes_empty_for_unknown_tenant(tmp_path: Path) -> None:
    store = _build_chain(tmp_path)
    assert list(store.iter_hashes(tenant_id="no-such-tenant")) == []
    store.close()


def test_iter_hashes_for_day_filters_to_target_day(tmp_path: Path) -> None:
    """The daily Merkle sealer feed yields only the chosen UTC day's hashes,
    in chain-seq order, deterministically (fixed day + tenant)."""
    store = _build_chain(tmp_path, n=3)
    # All seeded events share UTC date 2026-05-01 (see ``_event``).
    on_day = list(store.iter_hashes_for_day(tenant_id=str(T_A), day=date(2026, 5, 1)))
    full = list(store.iter_hashes(tenant_id=str(T_A)))
    assert on_day == full  # every event falls on the target day
    # A day with no events yields nothing (additive companion is exhaustive but
    # scoped — it must not bleed other days into the daily root).
    off_day = list(store.iter_hashes_for_day(tenant_id=str(T_A), day=date(2026, 4, 30)))
    assert off_day == []
    store.close()


# --------------------------------------------------------------------------- #
# Cross-cutting: tampering is detected regardless of which record is hit, and a
# detected break is order-independent (front-to-back walk stops at first break).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("victim", ["evt_001", "evt_002", "evt_003"])
def test_any_payload_tamper_is_detected(tmp_path: Path, victim: str) -> None:
    store = _build_chain(tmp_path)
    conn = _raw_conn(store)
    conn.execute(
        "UPDATE events SET payload=? WHERE id=?",
        (json.dumps({"seq": -1, "note": "x"}, ensure_ascii=False), victim),
    )
    conn.close()
    with pytest.raises(AuditChainBrokenError):
        store.verify_chain(tenant_id=str(T_A))
    store.close()
