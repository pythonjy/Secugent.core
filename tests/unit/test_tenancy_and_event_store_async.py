# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.tenancy and secugent.core.event_store_async.

Covers missed branches to reach the 90% core+audit+regulations gate.

Missed lines targeted:
- tenancy.py L64: TenantId.__new__ with non-str raises ValueError
- tenancy.py L77: _tenant_id_validate passes through an existing TenantId unchanged
- tenancy.py L80: _tenant_id_validate with neither str nor TenantId raises ValueError
- tenancy.py L141: set_current_tenant called with a plain str coerces to TenantId
- event_store_async.py L108: SQLiteEventStore.is_leader raises NotImplementedError

Korean actor fixture (§C-3): 신용정보원-테스트
"""

from __future__ import annotations

import pytest

from secugent.core.tenancy import TenantId, _tenant_id_validate, set_current_tenant

# ---------------------------------------------------------------------------
# TenantId
# ---------------------------------------------------------------------------


def test_tenant_id_new_non_str_raises() -> None:
    """L64: TenantId.__new__ must reject non-str values."""
    with pytest.raises(ValueError, match="must be str"):
        TenantId(123)  # type: ignore[arg-type]


def test_tenant_id_new_valid_ascii() -> None:
    """TenantId accepts a valid ASCII slug."""
    tid = TenantId("test-tenant-01")
    assert str(tid) == "test-tenant-01"
    assert isinstance(tid, TenantId)


# ---------------------------------------------------------------------------
# _tenant_id_validate (Pydantic hook)
# ---------------------------------------------------------------------------


def test_tenant_id_validate_passthrough_tenant_id() -> None:
    """L77: _tenant_id_validate returns a TenantId unchanged (no re-wrap)."""
    original = TenantId("existing-tenant")
    result = _tenant_id_validate(original)
    assert result is original  # same object, not a new instance


def test_tenant_id_validate_converts_str() -> None:
    """_tenant_id_validate wraps a valid str in TenantId."""
    result = _tenant_id_validate("valid-slug-01")
    assert isinstance(result, TenantId)
    assert str(result) == "valid-slug-01"


def test_tenant_id_validate_non_str_raises() -> None:
    """L80: _tenant_id_validate raises for non-str, non-TenantId input."""
    with pytest.raises(ValueError, match="must be str"):
        _tenant_id_validate({"bad": "type"})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# set_current_tenant
# ---------------------------------------------------------------------------


def test_set_current_tenant_with_plain_str() -> None:
    """L141: set_current_tenant accepts a plain str and coerces to TenantId."""
    # When called with a str (not TenantId), L140 is True → L141 runs
    with set_current_tenant("test-tenant-kr") as tid:  # type: ignore[arg-type]
        assert isinstance(tid, TenantId)
        assert str(tid) == "test-tenant-kr"


# ---------------------------------------------------------------------------
# SQLiteEventStore HA primitives (event_store_async.py)
# ---------------------------------------------------------------------------


async def test_sqlite_async_is_leader_raises_not_implemented() -> None:
    """L108: SqliteAsyncEventStore.is_leader raises NotImplementedError (SQLite-only).

    Korean actor fixture (§C-3): 신용정보원-테스트
    """
    # Use a pytest tmp_path-equivalent via NamedTemporaryFile to avoid the
    # Windows PermissionError on directory teardown with SQLite file locks.
    import tempfile
    from pathlib import Path

    from secugent.core.event_store import EventStore
    from secugent.core.event_store_async import SqliteAsyncEventStore

    # Create the db file and close the handle before EventStore opens it
    fd, db_path_str = tempfile.mkstemp(suffix=".db", prefix="secugent_test_")
    import os

    os.close(fd)
    inner = EventStore(path=Path(db_path_str))
    store = SqliteAsyncEventStore(inner=inner)
    with pytest.raises(NotImplementedError, match="SQLite backend"):
        await store.is_leader(worker_id="신용정보원-테스트", lock_key=42)
