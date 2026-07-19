# SPDX-License-Identifier: Apache-2.0
"""``secugent backup`` — atomic, lock-safe snapshot of the audit store (DA-H6).

Uses the SQLite *online backup API* (:meth:`sqlite3.Connection.backup`) rather
than a raw file copy, so a consistent snapshot — including any in-flight WAL
frames — is taken even while the live store is being written (lock-safe). The
snapshot is written to a temporary file and swapped into place with
``os.replace`` so a crash mid-backup never leaves a half-written artifact
(INV-BACKUP-1).

Immediately after writing, the backup re-verifies its own hash chain (the same
gate ``restore`` applies) so a broken snapshot is never produced and silently
trusted: a backup that fails self-verification is deleted and the command fails
closed.

Import closure is PUBLIC_CORE only: ``secugent.cli`` (verify + restore
re-verify); no api/cost/enterprise tiers.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path

from secugent.cli.restore import CandidateBroken, verify_candidate_chain
from secugent.cli.verify import _emit

__all__ = ["run_backup", "main"]


def _online_backup(src: Path, dst: Path) -> None:
    """Copy ``src`` to ``dst`` via the SQLite online backup API (lock-safe).

    Opens the source read-only so the backup can never mutate the live store;
    the destination is a fresh file written page-by-page by SQLite itself.
    """
    src_uri = f"file:{src.as_posix()}?mode=ro"
    source = sqlite3.connect(src_uri, uri=True)
    try:
        dest = sqlite3.connect(str(dst))
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()


def run_backup(*, db_path: Path, out_path: Path, overwrite: bool) -> int:
    """Back up ``db_path`` to ``out_path`` atomically, then self-verify.

    Returns a process exit code: 0 on success, 1 on any failure. The output is
    written to ``<out>.tmp`` then atomically swapped in; a broken snapshot is
    deleted and the command fails closed (INV-BACKUP-1).
    """
    if not db_path.exists():
        _emit(f"secugent backup: source store not found: {db_path}", stderr=True)
        return 1
    if out_path.exists() and not overwrite:
        _emit(
            f"secugent backup: {out_path} already exists; pass --overwrite to replace it",
            stderr=True,
        )
        return 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(f"{out_path.name}.tmp")
    tmp_path.unlink(missing_ok=True)

    try:
        _online_backup(db_path, tmp_path)
    except (sqlite3.Error, OSError) as exc:
        tmp_path.unlink(missing_ok=True)
        _emit(f"secugent backup: snapshot failed: {exc}", stderr=True)
        return 1

    # Write-time integrity: never produce a backup we could not restore.
    try:
        verify_candidate_chain(tmp_path)
    except CandidateBroken as exc:
        tmp_path.unlink(missing_ok=True)
        _emit(f"secugent backup: REFUSED — snapshot failed self-verification: {exc}", stderr=True)
        return 1

    try:
        os.replace(tmp_path, out_path)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        _emit(f"secugent backup: atomic replace failed: {exc}", stderr=True)
        return 1

    _emit(f"secugent backup: OK — {db_path} snapshotted to {out_path}, chain self-verified.")
    return 0


def _parse_args(rest: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secugent backup",
        description="Atomic, lock-safe SQLite snapshot of the audit store (DA-H6).",
    )
    parser.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="Live store path to back up (default: $SECUGENT_DB_PATH).",
    )
    parser.add_argument(
        "--out",
        required=True,
        metavar="PATH",
        help="Destination backup file path.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing --out file (default: refuse, fail-closed).",
    )
    return parser.parse_args(rest)


def main(rest: list[str]) -> int:
    """``secugent backup`` entry point. Returns a process exit code."""
    args = _parse_args(rest)
    db = args.db or os.environ.get("SECUGENT_DB_PATH")
    if not db:
        _emit(
            "secugent backup: no source store — set $SECUGENT_DB_PATH or pass --db",
            stderr=True,
        )
        return 2
    return run_backup(db_path=Path(db), out_path=Path(args.out), overwrite=args.overwrite)


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
