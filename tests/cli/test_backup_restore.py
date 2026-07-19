# SPDX-License-Identifier: Apache-2.0
"""DETERMINISTIC suite for ``secugent backup`` / ``restore`` (DA-H6, §B-4a).

The restore re-verification path is tied to audit/hash_chain integrity, so this
exercises it three ways:

* unit — backup is atomic + refuses overwrite; restore applies a clean candidate,
  preserves a pre-restore backup, and REFUSES a tampered/truncated candidate
  (exit!=0, live store untouched); empty + self-restore edges.
* property (hypothesis) — for a random valid chain, backup→restore round-trips
  byte-for-byte AND any single-event tamper / tail truncation is ALWAYS refused.
* scenario regression — backup→restore preserves the chain so ``verify --chain``
  stays green across the round trip (incl. a Korean-labelled tenant, C-3).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.audit.hash_chain import ChainedEventStore
from secugent.cli.backup import run_backup
from secugent.cli.restore import CandidateBroken, run_restore, verify_candidate_chain
from secugent.cli.verify import verify_audit_chain
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

T_A = TenantId("acme")
T_B = TenantId("kbfg-financial")  # second tenant; Korean labels live in payloads (C-3)


def _event(idx: int, tenant: TenantId = T_A) -> Event:
    return Event(
        tenant_id=tenant,
        actor=f"sub:{idx}",
        type="step.completed",
        run_id=f"r{idx}",
        payload={"i": idx, "note": f"이벤트 {idx}"},  # Korean label (C-3)
    )


def _build_store(db: Path, *, n: int, tenant: TenantId = T_A) -> None:
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(n):
            chained.append_event(_event(i, tenant))
    finally:
        chained.close()


def _chain_digest(db: Path, tenant: str) -> tuple[str, ...]:
    """Ordered (prev_hash, event_hash) pairs — a stable chain fingerprint."""
    uri = f"file:{db.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        rows = conn.execute(
            "SELECT prev_hash, event_hash FROM event_chain WHERE tenant_id=? ORDER BY seq ASC",
            (tenant,),
        ).fetchall()
    finally:
        conn.close()
    return tuple(f"{p}:{e}" for p, e in rows)


def _tamper_one_event(db: Path) -> None:
    """Flip a byte inside a stored chained event body (breaks event_hash)."""
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "UPDATE event_chain SET body_canonical = body_canonical || ' ' "
            "WHERE seq = (SELECT MIN(seq) FROM event_chain)"
        )
        conn.commit()
    finally:
        conn.close()


def _truncate_file(db: Path) -> None:
    """Physically truncate the backup file (interrupted/partial copy).

    A backup cut short on disk is a corrupt SQLite image; restore must refuse it
    before it ever reaches the chain verifier (fail-closed at the file gate).
    """
    data = db.read_bytes()
    db.write_bytes(data[: len(data) // 2])


# --------------------------------------------------------------------------- #
# backup — unit
# --------------------------------------------------------------------------- #


def test_backup_creates_self_verified_snapshot(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    out = tmp_path / "backup.db"
    _build_store(db, n=4)

    assert run_backup(db_path=db, out_path=out, overwrite=False) == 0
    assert out.exists()
    # No leftover temp artifact.
    assert not out.with_name(out.name + ".tmp").exists()
    # Snapshot itself verifies clean.
    assert verify_audit_chain(tenant_id=str(T_A), store_path=out).ok


def test_backup_refuses_existing_out_without_overwrite(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    out = tmp_path / "backup.db"
    _build_store(db, n=2)
    out.write_bytes(b"existing")

    assert run_backup(db_path=db, out_path=out, overwrite=False) == 1
    assert out.read_bytes() == b"existing"  # untouched
    assert run_backup(db_path=db, out_path=out, overwrite=True) == 0


def test_backup_missing_source_fails(tmp_path: Path) -> None:
    assert run_backup(db_path=tmp_path / "nope.db", out_path=tmp_path / "b.db", overwrite=False) == 1


# --------------------------------------------------------------------------- #
# restore — unit
# --------------------------------------------------------------------------- #


def test_restore_clean_candidate_succeeds_and_preserves_prior(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=3)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0

    # Append more to the live store, then restore the older backup over it.
    _build_store(db, n=0)  # no-op, keep db
    before = _chain_digest(backup, str(T_A))
    assert run_restore(src_path=backup, db_path=db, force=True) == 0
    assert _chain_digest(db, str(T_A)) == before
    # A reversible pre-restore copy exists.
    pre = list(tmp_path.glob("events.db.pre-restore.*"))
    assert len(pre) == 1


def test_restore_refuses_tampered_candidate_live_untouched(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=4)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    live_before = db.read_bytes()

    _tamper_one_event(backup)
    assert run_restore(src_path=backup, db_path=db, force=True) == 1
    assert db.read_bytes() == live_before  # live store NOT mutated
    # No pre-restore backup written (we never reached the apply stage).
    assert list(tmp_path.glob("events.db.pre-restore.*")) == []


def test_restore_refuses_truncated_candidate(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=5)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    live_before = db.read_bytes()

    _truncate_file(backup)
    assert run_restore(src_path=backup, db_path=db, force=True) == 1
    assert db.read_bytes() == live_before  # live store untouched


def test_restore_force_cannot_bypass_integrity_gate(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=3)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    _tamper_one_event(backup)
    # --force only relaxes the overwrite confirmation; the chain gate still fails.
    assert run_restore(src_path=backup, db_path=db, force=True) == 1


def test_restore_refuses_existing_without_force(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=2)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    assert run_restore(src_path=backup, db_path=db, force=False) == 1


def test_restore_self_path_refused(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    _build_store(db, n=2)
    assert run_restore(src_path=db, db_path=db, force=True) == 1


def test_restore_missing_source_fails(tmp_path: Path) -> None:
    assert run_restore(src_path=tmp_path / "nope.db", db_path=tmp_path / "events.db", force=True) == 1


def test_restore_non_sqlite_candidate_refused(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    junk = tmp_path / "junk.db"
    _build_store(db, n=1)
    junk.write_bytes(b"not a sqlite file at all")
    assert run_restore(src_path=junk, db_path=db, force=True) == 1


def test_restore_empty_zero_byte_candidate_refused(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    empty = tmp_path / "empty.db"
    _build_store(db, n=1)
    empty.write_bytes(b"")
    assert run_restore(src_path=empty, db_path=db, force=True) == 1


def test_verify_candidate_empty_chain_is_vacuously_intact(tmp_path: Path) -> None:
    # A fresh store with the schema but zero events is allowed (0 tenants).
    db = tmp_path / "events.db"
    EventStore(db).close()
    verify_candidate_chain(db)  # must not raise


def test_restore_multi_tenant_partial_break_rejects_whole(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=3, tenant=T_A)
    _build_store(db, n=3, tenant=T_B)
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    # Break only tenant A's first event; the whole restore must still be refused.
    _tamper_one_event(backup)
    with pytest.raises(CandidateBroken):
        verify_candidate_chain(backup)
    assert run_restore(src_path=backup, db_path=db, force=True) == 1


# --------------------------------------------------------------------------- #
# property (hypothesis)
# --------------------------------------------------------------------------- #


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(n=st.integers(min_value=1, max_value=12))
def test_property_roundtrip_preserves_chain(tmp_path_factory: pytest.TempPathFactory, n: int) -> None:
    base = tmp_path_factory.mktemp("rt")
    db = base / "events.db"
    backup = base / "backup.db"
    _build_store(db, n=n)
    assert run_backup(db_path=db, out_path=backup, overwrite=True) == 0
    before = _chain_digest(db, str(T_A))
    assert run_restore(src_path=backup, db_path=db, force=True) == 0
    assert _chain_digest(db, str(T_A)) == before


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(n=st.integers(min_value=2, max_value=12))
def test_property_any_tamper_always_refused(tmp_path_factory: pytest.TempPathFactory, n: int) -> None:
    base = tmp_path_factory.mktemp("tamper")
    db = base / "events.db"
    backup = base / "backup.db"
    _build_store(db, n=n)
    assert run_backup(db_path=db, out_path=backup, overwrite=True) == 0
    _tamper_one_event(backup)
    with pytest.raises(CandidateBroken):
        verify_candidate_chain(backup)
    assert run_restore(src_path=backup, db_path=db, force=True) == 1


# --------------------------------------------------------------------------- #
# scenario regression
# --------------------------------------------------------------------------- #


def test_scenario_verify_chain_green_across_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "events.db"
    backup = tmp_path / "backup.db"
    _build_store(db, n=4, tenant=T_B)  # Korean tenant
    assert verify_audit_chain(tenant_id=str(T_B), store_path=db).ok
    assert run_backup(db_path=db, out_path=backup, overwrite=False) == 0
    assert run_restore(src_path=backup, db_path=db, force=True) == 0
    assert verify_audit_chain(tenant_id=str(T_B), store_path=db).ok
