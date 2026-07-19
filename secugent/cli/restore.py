# SPDX-License-Identifier: Apache-2.0
"""``secugent restore`` — fail-closed restore of the audit event store (DA-H6).

Restoring the append-only audit store is a trust-critical operation: a restore
that silently accepts a tamper-broken database would destroy the very
tamper-evidence the hash chain exists to provide (§C-1 / §C-2). This command
therefore *re-verifies the hash chain of the candidate database before it is
applied* and refuses (non-zero, live store untouched) on any break, truncation,
or divergence — ``--force`` relaxes only the "overwrite the existing store"
confirmation, never the integrity gate (INV-RESTORE-1).

The re-verification reuses the exact read-only chain verifier behind
``secugent verify --chain`` (:func:`secugent.cli.verify.verify_audit_chain`),
enumerating every tenant in the candidate and requiring *all* of them intact —
a single broken tenant fails the whole restore (no partial restore).

Import closure is PUBLIC_CORE only: ``secugent.cli`` + ``secugent.audit`` via
the verifier; no api/cost/enterprise/identity tiers.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secugent.cli.verify import VerifyInputError, _emit, verify_audit_chain

__all__ = [
    "CandidateBroken",
    "run_restore",
    "verify_candidate_chain",
    "main",
]

# SQLite file magic header (first 16 bytes of every well-formed DB).
_SQLITE_MAGIC: bytes = b"SQLite format 3\x00"

# KST without depending on tzdata being present (mirrors the notifier fallback
# pattern): a fixed +9h offset is correct for Korea (no DST).
_KST = timezone(timedelta(hours=9), name="KST")


class CandidateBroken(Exception):
    """Raised when a restore candidate fails hash-chain re-verification.

    Carrying the offending tenant + violation keeps the failure auditable: the
    operator sees *which* tenant's chain is broken, not a bare boolean.
    """


def _kst_stamp() -> str:
    """A filesystem-safe KST timestamp for the pre-restore backup filename."""
    return datetime.now(_KST).strftime("%Y%m%dT%H%M%S%z")


def _is_sqlite_file(path: Path) -> bool:
    """True iff ``path`` begins with the SQLite magic header.

    A 0-byte file, a truncated header, or a non-SQLite blob all read as False so
    a restore from a corrupt/empty artifact fails fast (fail-closed) rather than
    handing a junk file to the chain verifier.
    """
    try:
        with path.open("rb") as fh:
            return fh.read(16) == _SQLITE_MAGIC
    except OSError:
        return False


def _distinct_chain_tenants(candidate: Path) -> list[str]:
    """Enumerate every tenant owning a chained event in ``candidate`` (sorted).

    Opens strictly read-only (``mode=ro``) so enumeration can never mutate the
    candidate. A DB with no ``event_chain`` table yields zero tenants — a
    vacuously-intact empty store the caller may legitimately restore.
    """
    uri = f"file:{candidate.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise CandidateBroken(f"cannot open candidate {candidate}: {exc}") from exc
    try:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_chain'"
        ).fetchone()
        if has_table is None:
            return []
        rows = conn.execute("SELECT DISTINCT tenant_id FROM event_chain").fetchall()
    except sqlite3.DatabaseError as exc:
        # A malformed/encrypted DB that passed the magic check but is unreadable
        # is a broken candidate, not a usable one.
        raise CandidateBroken(f"candidate {candidate} is not a readable store: {exc}") from exc
    finally:
        conn.close()
    return sorted(str(r[0]) for r in rows)


def verify_candidate_chain(candidate: Path) -> None:
    """Re-verify every tenant's hash chain in ``candidate``; raise on any break.

    This is the single integrity gate shared by ``backup`` (write-time self
    check) and ``restore`` (pre-apply gate). It raises :class:`CandidateBroken`
    on the first broken/truncated/diverged tenant chain and returns ``None`` only
    when *all* tenants verify clean (or the store is empty — vacuously intact).
    """
    if not candidate.exists():
        raise CandidateBroken(f"candidate does not exist: {candidate}")
    if candidate.stat().st_size == 0:
        raise CandidateBroken(f"candidate is empty (0 bytes): {candidate}")
    if not _is_sqlite_file(candidate):
        raise CandidateBroken(f"candidate is not a SQLite database: {candidate}")

    for tenant in _distinct_chain_tenants(candidate):
        try:
            report = verify_audit_chain(tenant_id=tenant, store_path=candidate)
        except VerifyInputError as exc:
            raise CandidateBroken(f"tenant {tenant!r}: {exc}") from exc
        if not report.ok:
            raise CandidateBroken(f"tenant {tenant!r} chain broken: {report.first_violation}")


def run_restore(*, src_path: Path, db_path: Path, force: bool) -> int:
    """Restore ``src_path`` onto ``db_path`` only if its hash chain re-verifies.

    Returns a process exit code: 0 on success, 1 on any failure. The live store
    is *never* mutated unless the candidate passes the integrity gate; the prior
    store is preserved as ``<db>.pre-restore.<KST>`` so the operation is
    reversible (INV-RESTORE-2).
    """
    if not src_path.exists():
        _emit(f"secugent restore: source not found: {src_path}", stderr=True)
        return 1

    # Self-restore (src == live db) is a no-op that could only corrupt via the
    # atomic-replace temp dance; refuse it explicitly.
    try:
        same = db_path.exists() and src_path.resolve() == db_path.resolve()
    except OSError:
        same = False
    if same:
        _emit(
            f"secugent restore: --from equals --db ({db_path}); nothing to restore",
            stderr=True,
        )
        return 1

    # Integrity gate (INV-RESTORE-1): verify the candidate BEFORE touching the
    # live store. --force cannot bypass this.
    try:
        verify_candidate_chain(src_path)
    except CandidateBroken as exc:
        _emit(f"secugent restore: REFUSED — candidate chain failed re-verification: {exc}", stderr=True)
        _emit(
            "aborted: live store left untouched. Discard this backup; use a known-good snapshot.", stderr=True
        )
        return 1

    if db_path.exists() and not force:
        _emit(
            f"secugent restore: {db_path} already exists; pass --force to overwrite "
            "(a pre-restore backup is kept either way)",
            stderr=True,
        )
        return 1

    db_path.parent.mkdir(parents=True, exist_ok=True)

    pre_restore: Path | None = None
    if db_path.exists():
        pre_restore = db_path.with_name(f"{db_path.name}.pre-restore.{_kst_stamp()}")
        try:
            shutil.copy2(db_path, pre_restore)
        except OSError as exc:
            _emit(f"secugent restore: cannot back up existing store: {exc}", stderr=True)
            return 1

    # Stage the candidate beside the live store then atomically swap it in, so a
    # crash mid-copy never exposes a half-written live DB (INV-RESTORE-2).
    tmp_path = db_path.with_name(f"{db_path.name}.restore.tmp")
    try:
        shutil.copy2(src_path, tmp_path)
        os.replace(tmp_path, db_path)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        _emit(f"secugent restore: copy/replace failed: {exc}", stderr=True)
        return 1

    # Post-apply confirmation: the live store must now re-verify. (The candidate
    # already passed; this catches a copy-layer fault before we report success.)
    try:
        verify_candidate_chain(db_path)
    except CandidateBroken as exc:
        _emit(
            f"secugent restore: applied copy failed post-verify: {exc}; "
            f"prior store preserved at {pre_restore}",
            stderr=True,
        )
        return 1

    _emit(f"secugent restore: OK — {src_path} restored to {db_path}, chain re-verified.")
    if pre_restore is not None:
        _emit(f"  prior store preserved at {pre_restore} (revertible).")
    return 0


def _parse_args(rest: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secugent restore",
        description="Restore the audit event store, re-verifying its hash chain (DA-H6).",
    )
    parser.add_argument(
        "--from",
        dest="src",
        required=True,
        metavar="PATH",
        help="Backup file to restore from.",
    )
    parser.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="Live store path to restore onto (default: $SECUGENT_DB_PATH).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing live store (the integrity gate still applies).",
    )
    return parser.parse_args(rest)


def main(rest: list[str]) -> int:
    """``secugent restore`` entry point. Returns a process exit code."""
    args = _parse_args(rest)
    db = args.db or os.environ.get("SECUGENT_DB_PATH")
    if not db:
        _emit(
            "secugent restore: no target store — set $SECUGENT_DB_PATH or pass --db",
            stderr=True,
        )
        return 2
    return run_restore(src_path=Path(args.src), db_path=Path(db), force=args.force)


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
