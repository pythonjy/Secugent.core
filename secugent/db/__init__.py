# SPDX-License-Identifier: Apache-2.0
"""Data-plane seam (W5-a / DA-C1).

The live request/audit/STEER path persists to SQLite by default (dev/air-gap).
When ``DATABASE_URL`` is set the production target is PostgreSQL
(``secugent.core.event_store_pg``). This package holds the config-driven
store-selection seam (:mod:`secugent.db.store_facade`) and the append-only
SQLite→PG migration with hash-chain re-verification
(:mod:`secugent.db.migrate_sqlite_to_pg`).

DA-C1 is §B-10 formal + infra-gated: the seam, the synchronous bridge over the
async PG store, the migration, and the single-writer fence are all unit-tested
against SQLite + fakes; the *live request-path swap* onto PG requires a real
Postgres (staged) and is documented, never asserted green.
"""

from __future__ import annotations

__all__ = [
    "LiveWriteStore",
    "MigrationReport",
    "SyncPgEventStore",
    "migrate_sqlite_to_pg",
    "select_live_store",
]

from secugent.db.migrate_sqlite_to_pg import MigrationReport, migrate_sqlite_to_pg
from secugent.db.store_facade import LiveWriteStore, SyncPgEventStore, select_live_store
