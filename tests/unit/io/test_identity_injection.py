# SPDX-License-Identifier: Apache-2.0
"""EM-06 — on-behalf-of identity resolution (OBO inject vs attribution-only)."""

from __future__ import annotations

import pytest

from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.identity import CallIdentity, IdentityStrategy


def _principal(user_id: str = "alice@corp") -> Principal:
    return Principal(user_id=user_id, tenant_id=TenantId("acme"), role="operator")


def test_attribution_when_obo_unsupported() -> None:
    ident = IdentityStrategy().resolve(_principal(), supports_obo=False, run_id="r1")
    assert ident.mode == "attribution"
    assert ident.injected is False
    assert ident.on_behalf_of == "alice@corp"
    assert ident.audit_meta["on_behalf_of"] == "alice@corp"
    assert ident.audit_meta["tenant_id"] == "acme"
    assert ident.audit_meta["run_id"] == "r1"
    assert ident.audit_meta["mode"] == "attribution"


def test_obo_inject_when_supported() -> None:
    ident = IdentityStrategy().resolve(_principal(), supports_obo=True, run_id="r1")
    assert ident.mode == "obo"
    assert ident.injected is True
    assert ident.audit_meta["mode"] == "obo"
    # even OBO records the attributed user (never "one bot")
    assert ident.audit_meta["on_behalf_of"] == "alice@corp"


def test_empty_user_id_rejected() -> None:
    # attribution requires a real principal — never a blank/anonymous bot
    with pytest.raises(ValueError):
        IdentityStrategy().resolve(_principal(user_id=""), supports_obo=False, run_id="r1")


def test_resolve_deterministic_100x() -> None:
    strategy = IdentityStrategy()
    base = strategy.resolve(_principal(), supports_obo=False, run_id="r1")
    assert all(strategy.resolve(_principal(), supports_obo=False, run_id="r1") == base for _ in range(100))


def test_call_identity_is_frozen() -> None:
    ident = IdentityStrategy().resolve(_principal(), supports_obo=False, run_id="r1")
    assert isinstance(ident, CallIdentity)
    with pytest.raises(AttributeError):
        ident.mode = "obo"  # type: ignore[misc]  # frozen dataclass
