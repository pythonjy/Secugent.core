# SPDX-License-Identifier: Apache-2.0
"""``secugent migrate-store`` CLI precondition / fail-closed wiring.

The end-to-end migration needs a real Postgres (infra-gated, covered by
``tests/db/test_migrate_sqlite_to_pg.py::test_live_pg_migration_round_trip``).
Here we assert the CLI's fail-closed preconditions and dispatch without a DB.
"""

from __future__ import annotations

import pytest

from secugent.cli import migrate_store
from secugent.cli.__main__ import main as cli_main


def test_no_dsn_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("DATABASE_URL", raising=False)
    code = migrate_store.main(["--sqlite", str(tmp_path / "events.db")])
    assert code == 2


def test_dispatch_routes_to_migrate_store(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    """``secugent migrate-store`` reaches the subcommand (no DSN ⇒ exit 2)."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    code = cli_main(["migrate-store", "--sqlite", str(tmp_path / "events.db")])
    assert code == 2


def test_missing_required_sqlite_arg_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as exc:
        migrate_store.main([])
    assert exc.value.code == 2
