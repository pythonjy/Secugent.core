# SPDX-License-Identifier: Apache-2.0
"""EM-04 — behavior preview + sign-off gate (admin+MFA + fixtures all pass)."""

from __future__ import annotations

import pytest

from secugent.audit.merkle import LocalHmacKmsProvider
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import (
    AuthoringError,
    Fixture,
    Match,
    PolicyDoc,
    Rule,
    preview,
    sign_off,
    verify_bundle,
)
from secugent.core.tenancy import Principal, TenantId

_KEY = "policy-key-1"


def _kms() -> LocalHmacKmsProvider:
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY, b"a-32-byte-or-longer-secret-key!!!")
    return kms


def _draft() -> PolicyDoc:
    return PolicyDoc(
        version="1",
        tenant_id="_base",
        rules=[Rule(id="d", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="no secrets")],
    )


def _secret_eff() -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target="c:/secret/a.txt", sink_class=SinkClass.LOCAL_SANDBOX)


def _good_fixtures() -> list[Fixture]:
    return [Fixture(_secret_eff(), DataLabel.PUBLIC, "deny")]


def _admin(*, mfa: bool = True) -> Principal:
    return Principal(user_id="alice", tenant_id=TenantId("acme"), role="admin", mfa_satisfied=mfa)


def test_preview_shows_behavior() -> None:
    rows = preview(_draft(), _good_fixtures())
    assert rows[0].outcome == "deny"
    assert rows[0].matches_expected is True


def test_sign_off_success_produces_verifiable_bundle() -> None:
    kms = _kms()
    bundle = sign_off(_draft(), _good_fixtures(), approver=_admin(), kms=kms, key_id=_KEY)
    restored = verify_bundle(bundle, kms=kms, allowed_key_ids={_KEY})
    assert restored.rules[0].id == "d"


def test_sign_off_requires_admin() -> None:
    operator = Principal(user_id="bob", tenant_id=TenantId("acme"), role="operator", mfa_satisfied=True)
    with pytest.raises(AuthoringError):
        sign_off(_draft(), _good_fixtures(), approver=operator, kms=_kms(), key_id=_KEY)


def test_sign_off_requires_mfa() -> None:
    with pytest.raises(AuthoringError):
        sign_off(_draft(), _good_fixtures(), approver=_admin(mfa=False), kms=_kms(), key_id=_KEY)


def test_sign_off_blocked_when_fixtures_fail() -> None:
    # draft denies c:/secret/*, but this fixture expects allow → mismatch → blocked
    bad = [Fixture(_secret_eff(), DataLabel.PUBLIC, "allow")]
    with pytest.raises(AuthoringError):
        sign_off(_draft(), bad, approver=_admin(), kms=_kms(), key_id=_KEY)
