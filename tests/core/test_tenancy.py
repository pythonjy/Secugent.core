# SPDX-License-Identifier: Apache-2.0
"""PHASE 9 — tenancy core unit tests (RED first)."""

from __future__ import annotations

import asyncio

import pytest

from secugent.core.tenancy import (
    Principal,
    TenantId,
    current_tenant,
    set_current_tenant,
)

# ---------------------------------------------------------------------------
# TenantId — regex strict validation (^[a-z0-9][a-z0-9-]{1,62}$)
# ---------------------------------------------------------------------------


def test_tenant_id_accepts_valid_format() -> None:
    tid = TenantId("acme")
    assert isinstance(tid, str)
    assert tid == "acme"


def test_tenant_id_uppercase_rejected() -> None:
    with pytest.raises(ValueError, match="tenant_id"):
        TenantId("Acme")


def test_tenant_id_empty_rejected() -> None:
    with pytest.raises(ValueError):
        TenantId("")


def test_tenant_id_single_char_rejected() -> None:
    with pytest.raises(ValueError):
        TenantId("a")


def test_tenant_id_starts_with_hyphen_rejected() -> None:
    with pytest.raises(ValueError):
        TenantId("-acme")


def test_tenant_id_too_long_rejected() -> None:
    with pytest.raises(ValueError):
        TenantId("a" + "b" * 63)  # 64 chars total → fails {1,62} constraint


# ---------------------------------------------------------------------------
# ContextVar
# ---------------------------------------------------------------------------


def test_current_tenant_lookup_error_when_unset() -> None:
    with pytest.raises(LookupError):
        current_tenant()


def test_set_current_tenant_context_manager_restores() -> None:
    outer = TenantId("acme")
    inner = TenantId("contoso")
    with set_current_tenant(outer):
        assert current_tenant() == outer
        with set_current_tenant(inner):
            assert current_tenant() == inner
        assert current_tenant() == outer
    with pytest.raises(LookupError):
        current_tenant()


def test_set_current_tenant_isolated_across_async_tasks() -> None:
    """ContextVar 는 asyncio.Task 마다 독립적이어야 한다."""

    seen: list[str] = []

    async def _task(name: str) -> None:
        with set_current_tenant(TenantId(name)):
            await asyncio.sleep(0.01)
            seen.append(str(current_tenant()))

    async def _runner() -> None:
        await asyncio.gather(_task("alpha"), _task("bravo"), _task("charlie"))

    asyncio.run(_runner())
    assert sorted(seen) == ["alpha", "bravo", "charlie"]


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


def test_principal_round_trip() -> None:
    p = Principal(
        user_id="alice@corp",
        tenant_id=TenantId("acme"),
        role="operator",
        groups=["sg-operators"],
        mfa_satisfied=True,
    )
    data = p.model_dump(mode="json")
    again = Principal.model_validate(data)
    assert again == p


def test_principal_unknown_role_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Principal(
            user_id="x",
            tenant_id=TenantId("acme"),
            role="superadmin",  # type: ignore[arg-type]
            groups=[],
            mfa_satisfied=False,
        )
