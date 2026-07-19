# SPDX-License-Identifier: Apache-2.0
"""``secugent migrate-store`` — SQLite→PG audit-chain migration (DA-C1).

Copies the append-only run + hash-chained event history from the SQLite
reference store into PostgreSQL **in order**, then re-verifies the hash chain on
the PG side and exits non-zero (fail-closed) if the chain is broken/truncated or
the PG copy diverges from the SQLite source. SQLite remains the dev/air-gap live
default; this is the one-way cutover-prep step run by an operator against a real,
Alembic-managed Postgres.

Usage::

    DATABASE_URL=postgresql+asyncpg://user:pw@host:5432/db \\
        secugent migrate-store --sqlite ./data/events.db [--ensure-schema] \\
        [--tenant t1 --tenant t2]

Exit codes: 0 success (chain re-verified); 1 migration/verification failure
(evidence printed to stderr); 2 usage/precondition error (no DSN, pg extra
missing, source not found).
"""

from __future__ import annotations

import argparse
import asyncio
import os

from secugent.audit.hash_chain import AuditChainBrokenError
from secugent.cli.verify import _emit
from secugent.core.event_store import EventStoreError
from secugent.db.migrate_sqlite_to_pg import (
    MigrationError,
    MigrationReport,
    migrate_sqlite_to_pg,
)

__all__ = ["main"]


def _parse_args(rest: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secugent migrate-store",
        description="Migrate the append-only audit chain from SQLite to PostgreSQL (DA-C1).",
    )
    parser.add_argument(
        "--sqlite",
        required=True,
        metavar="PATH",
        help="Source SQLite event store path (e.g. ./data/events.db).",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        metavar="DSN",
        help="Target PG DSN (default: $DATABASE_URL). postgresql+asyncpg://…",
    )
    parser.add_argument(
        "--tenant",
        action="append",
        default=None,
        metavar="TENANT",
        help="Restrict to specific tenant(s); repeatable. Default: all tenants.",
    )
    parser.add_argument(
        "--ensure-schema",
        action="store_true",
        help="DEV ONLY: create the PG schema in-process before copying. In prod "
        "the schema is owned by Alembic (`alembic upgrade head`); omit this flag.",
    )
    return parser.parse_args(rest)


async def _run_migration(
    *,
    sqlite_path: str,
    dsn: str,
    tenants: list[str] | None,
    ensure_schema: bool,
) -> MigrationReport:
    """Construct the live PG chained store and run the migration (fail-closed)."""
    from secugent.core.event_store_pg import PgChainedEventStore, PgEventStore

    pg = PgEventStore(dsn)
    try:
        if ensure_schema:
            await pg.ensure_schema()
        else:
            # Prove the operator-managed (Alembic) schema is reachable before we
            # start copying — fail closed on an unreachable/misconfigured DB.
            await _verify_reachable(pg)
        chained = PgChainedEventStore(pg)
        return await migrate_sqlite_to_pg(
            sqlite_path=sqlite_path,
            sink=chained,
            tenants=tenants,
        )
    finally:
        await pg.close()


async def _verify_reachable(pg: object) -> None:
    """SELECT 1 round-trip — mirror ``api.main._verify_pg_connection`` without
    importing the heavy FastAPI app from the CLI."""
    from sqlalchemy import text

    engine = pg.engine  # type: ignore[attr-defined]  # PgEventStore.engine (Any)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


def main(rest: list[str]) -> int:
    """``secugent migrate-store`` entry point. Returns a process exit code."""
    args = _parse_args(rest)

    dsn = args.database_url or os.environ.get("DATABASE_URL")
    if not dsn:
        _emit(
            "secugent migrate-store: no target DSN — set $DATABASE_URL or pass --database-url",
            stderr=True,
        )
        return 2

    from secugent.core.event_store_pg import is_pg_available

    if not is_pg_available():
        _emit(
            "secugent migrate-store: PG driver unavailable — `pip install 'secugent[pg]'`",
            stderr=True,
        )
        return 2

    try:
        report = asyncio.run(
            _run_migration(
                sqlite_path=args.sqlite,
                dsn=dsn,
                tenants=args.tenant,
                ensure_schema=args.ensure_schema,
            )
        )
    except (AuditChainBrokenError, MigrationError) as exc:
        # Fail-closed: chain break / truncation / divergence. No partial cutover.
        _emit(f"secugent migrate-store: chain re-verification FAILED — {exc}", stderr=True)
        _emit("aborted: PG left as-is, no cutover. Investigate the source chain.", stderr=True)
        return 1
    except EventStoreError as exc:
        _emit(f"secugent migrate-store: durable write/read failed — {exc}", stderr=True)
        return 1

    _emit(
        "secugent migrate-store: OK — chain re-verified on PG.\n"
        f"  tenants={list(report.tenants)} runs_copied={report.runs_copied} "
        f"events_copied={report.events_copied} events_skipped={report.events_skipped} "
        f"verified={report.verified}"
    )
    return 0
