# SPDX-License-Identifier: Apache-2.0
"""DA-C1 — store-selection seam unit tests (no infra).

``select_live_store`` is the pure, config-driven decision: ``DATABASE_URL`` unset
⇒ SQLite (dev/air-gap default, unchanged → the determinism path is untouched);
set ⇒ the PG bridge, NEVER a silent SQLite fallback (INV-C1-3).
"""

from __future__ import annotations

import pytest

from secugent.core.contracts import Event, Run
from secugent.db.store_facade import select_live_store


class _FakeStore:
    """Satisfies the ``LiveWriteStore`` structural protocol."""

    def __init__(self, name: str) -> None:
        self.name = name

    def upsert_run(self, run: Run) -> None:  # pragma: no cover - never invoked here
        raise AssertionError("not called in seam tests")

    def append_event(self, event: Event) -> None:  # pragma: no cover - never invoked here
        raise AssertionError("not called in seam tests")


def test_unset_database_url_selects_sqlite() -> None:
    sqlite = _FakeStore("sqlite")
    calls = {"factory": 0}

    def factory() -> _FakeStore:
        calls["factory"] += 1
        return _FakeStore("pg")

    store, backend = select_live_store(database_url=None, sqlite_store=sqlite, pg_bridge_factory=factory)

    assert store is sqlite
    assert backend == "sqlite"
    # INV: the PG factory is NEVER constructed on the SQLite branch (no thread/loop).
    assert calls["factory"] == 0


@pytest.mark.parametrize("blank", ["", "   ", "\t", "\n"])
def test_blank_database_url_selects_sqlite(blank: str) -> None:
    sqlite = _FakeStore("sqlite")
    store, backend = select_live_store(
        database_url=blank,
        sqlite_store=sqlite,
        pg_bridge_factory=lambda: _FakeStore("pg"),
    )
    assert store is sqlite
    assert backend == "sqlite"


def test_set_database_url_selects_pg_bridge() -> None:
    sqlite = _FakeStore("sqlite")
    pg = _FakeStore("pg")

    store, backend = select_live_store(
        database_url="postgresql+asyncpg://u:p@h:5432/db",
        sqlite_store=sqlite,
        pg_bridge_factory=lambda: pg,
    )

    assert store is pg
    assert backend == "postgres"


def test_pg_factory_error_propagates_no_sqlite_fallback() -> None:
    """INV-C1-3: a PG construction failure must NOT silently degrade to SQLite —
    the operator believes Postgres is live, so the error fails the boot closed."""
    sqlite = _FakeStore("sqlite")

    def boom() -> _FakeStore:
        raise RuntimeError("pg extra missing")

    with pytest.raises(RuntimeError, match="pg extra missing"):
        select_live_store(
            database_url="postgresql+asyncpg://u:p@h/db",
            sqlite_store=sqlite,
            pg_bridge_factory=boom,
        )
