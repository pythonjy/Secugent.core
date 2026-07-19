# SPDX-License-Identifier: Apache-2.0
"""S4 G-H3 — ``build_kms_provider`` boot factory + det-invariant proof.

The factory selects the Enterprise ``VaultTransitProvider`` when a Transit KMS is
configured, else the dev-only ``LocalHmacKmsProvider``. The integration step
(create_app) then wraps the returned provider in a ``MerkleSigner``.

CRITICAL determinism proof (det ``9b99932311ebcc94``): KMS signing is computed
OVER the Merkle root and is NEVER fed back into the chain-hash input
(``compute_chain_hash`` over ``prev_hash || canonical_body``). Swapping the KMS
provider / signature must leave BOTH ``compute_chain_hash`` AND ``build_root``
byte-identical. These tests pin that invariant against a fixed Korean finance
fixture so a regression that leaked the signature into the chain trips here.

The Vault Transit transport is mocked (no live cloud). A Korean finance fixture
(KB국민은행 일일 머클 봉인 키) exercises the audit-evidence path (§C-3).
"""

from __future__ import annotations

import sys
import types
from datetime import UTC, date, datetime
from typing import Any

import pytest
from pydantic import SecretStr

from secugent.audit.hash_chain import GENESIS, canonical, compute_chain_hash
from secugent.audit.merkle import (
    KmsProvider,
    KmsSettings,
    LocalHmacKmsProvider,
    MerkleSigner,
    SignedMerkleRoot,
    build_kms_provider,
)
from secugent.core.contracts import Event
from secugent.core.tenancy import TenantId

# Korean finance fixture (§C-3): KB국민은행 일일 감사 머클 봉인 키.
_KB_KEY_ID = "kb-bank-audit-merkle-2026"
_KB_TENANT = TenantId("kb-bank")
# A FIXED timestamp anchors the chain-hash determinism: Event.ts defaults to the
# wall clock (default_factory=_utcnow), which would make the chain hash vary per
# call. Pinning ts is exactly what proves det 9b99932311ebcc94 — the chain hash
# is a pure function of the canonical body, with no wall-clock/uuid dependency.
_KB_TS = datetime(2026, 6, 25, 0, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# KmsSettings
# --------------------------------------------------------------------------- #


def test_settings_default_is_local() -> None:
    s = KmsSettings()
    assert s.provider == "local"
    assert s.key_id == "merkle-dev"


def test_settings_from_env_local_default() -> None:
    assert KmsSettings.from_env({}).provider == "local"


def test_settings_from_env_vault_transit() -> None:
    env = {
        "SECUGENT_KMS_PROVIDER": "vault_transit",
        "SECUGENT_KMS_KEY_ID": _KB_KEY_ID,
        "VAULT_ADDR": "https://vault.internal:8200",
        "VAULT_TOKEN": "s.kms-token",
    }
    s = KmsSettings.from_env(env)
    assert s.provider == "vault_transit"
    assert s.key_id == _KB_KEY_ID
    assert s.vault_addr == "https://vault.internal:8200"
    assert s.vault_token is not None
    assert s.vault_token.get_secret_value() == "s.kms-token"


def test_settings_token_redacts_on_repr() -> None:
    s = KmsSettings(provider="vault_transit", vault_addr="https://v:8200", vault_token=SecretStr("s.zzz"))
    assert "s.zzz" not in repr(s)


# --------------------------------------------------------------------------- #
# build_kms_provider — selection
# --------------------------------------------------------------------------- #


def test_build_returns_local_by_default() -> None:
    provider = build_kms_provider(KmsSettings())
    assert isinstance(provider, LocalHmacKmsProvider)


def test_build_local_provider_can_sign_and_verify() -> None:
    provider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    root = bytes.fromhex("ab" * 32)
    sig = provider.sign(root_bytes=root, key_id=_KB_KEY_ID)
    assert provider.verify(root_bytes=root, signature_bytes=sig, key_id=_KB_KEY_ID) is True


def test_build_vault_transit_selected_when_configured() -> None:
    from secugent.enterprise.kms import VaultTransitProvider

    provider = build_kms_provider(
        KmsSettings(
            provider="vault_transit",
            key_id=_KB_KEY_ID,
            vault_addr="https://vault.internal:8200",
            vault_token=SecretStr("s.kms-token"),
        )
    )
    assert isinstance(provider, VaultTransitProvider)


def test_build_vault_transit_without_addr_raises() -> None:
    with pytest.raises(ValueError, match="vault_addr"):
        build_kms_provider(KmsSettings(provider="vault_transit", key_id=_KB_KEY_ID))


# --------------------------------------------------------------------------- #
# Vault Transit sign/verify round-trip + tamper-fail (via the factory, mocked)
# --------------------------------------------------------------------------- #


def _install_fake_hvac_transit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject a fake ``hvac`` whose Transit engine HMACs the prehashed input."""
    import base64
    import hashlib
    import hmac

    secret = b"vault-transit-secret-kb"

    def _mac(raw: bytes) -> bytes:
        return hmac.new(secret, raw, hashlib.sha256).digest()

    class _Transit:
        def sign_data(self, *, name: str, hash_input: str, prehashed: bool) -> dict[str, Any]:
            raw = base64.b64decode(hash_input)
            sig = base64.b64encode(_mac(raw)).decode("ascii")
            return {"data": {"signature": f"vault:v1:{sig}"}}

        def verify_signed_data(
            self, *, name: str, hash_input: str, signature: str, prehashed: bool
        ) -> dict[str, Any]:
            raw = base64.b64decode(hash_input)
            prefix = "vault:v1:"
            if not signature.startswith(prefix):
                return {"data": {"valid": False}}
            got = base64.b64decode(signature[len(prefix) :])
            return {"data": {"valid": hmac.compare_digest(_mac(raw), got)}}

    class _Secrets:
        def __init__(self) -> None:
            self.transit = _Transit()

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            self.secrets = _Secrets()

    hvac = types.ModuleType("hvac")
    hvac.Client = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hvac", hvac)

    import importlib.util

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())


def test_factory_vault_transit_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_hvac_transit(monkeypatch)
    provider = build_kms_provider(
        KmsSettings(
            provider="vault_transit",
            key_id=_KB_KEY_ID,
            vault_addr="https://vault.internal:8200",
            vault_token=SecretStr("s.kms-token"),
        )
    )
    root = bytes.fromhex("cd" * 32)
    sig = provider.sign(root_bytes=root, key_id=_KB_KEY_ID)
    assert provider.verify(root_bytes=root, signature_bytes=sig, key_id=_KB_KEY_ID) is True


def test_factory_vault_transit_tamper_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_hvac_transit(monkeypatch)
    provider = build_kms_provider(
        KmsSettings(
            provider="vault_transit",
            key_id=_KB_KEY_ID,
            vault_addr="https://vault.internal:8200",
            vault_token=SecretStr("s.kms-token"),
        )
    )
    root = bytes.fromhex("11" * 32)
    sig = provider.sign(root_bytes=root, key_id=_KB_KEY_ID)
    tampered = bytes.fromhex("22" * 32)
    assert provider.verify(root_bytes=tampered, signature_bytes=sig, key_id=_KB_KEY_ID) is False


# --------------------------------------------------------------------------- #
# MerkleSigner uses the INJECTED provider (not a hardcoded one)
# --------------------------------------------------------------------------- #


class _RecordingKms:
    """A KmsProvider that records which provider actually signed."""

    algorithm = "RECORDING"

    def __init__(self) -> None:
        self.signed: list[bytes] = []

    def sign(self, *, root_bytes: bytes, key_id: str) -> bytes:
        self.signed.append(root_bytes)
        return b"recording-signature"

    def verify(self, *, root_bytes: bytes, signature_bytes: bytes, key_id: str) -> bool:
        return signature_bytes == b"recording-signature"


def test_merkle_signer_uses_injected_provider() -> None:
    kms = _RecordingKms()
    signer = MerkleSigner(kms=kms, key_id=_KB_KEY_ID)
    bundle = signer.sign_day(day=date(2026, 6, 25), hashes=["a" * 64, "b" * 64])
    assert len(kms.signed) == 1  # the injected provider was actually called
    assert bundle.algorithm == "RECORDING"
    assert bundle.signature_hex == b"recording-signature".hex()


# --------------------------------------------------------------------------- #
# det 9b99932311ebcc94 — signing is OVER the root and NEVER enters the chain hash
# --------------------------------------------------------------------------- #


def _kb_chain_hashes() -> list[str]:
    """A fixed KB국민은행 (§C-3) event chain → the day's chain-hash sequence.

    Deterministic: fixed tenant/actor/run/payload, no wall-clock/uuid. This is the
    audit-chain determinism anchor referenced project-wide as ``9b99932311ebcc94``.
    """
    prev = GENESIS
    hashes: list[str] = []
    for i in range(3):
        event = Event(
            id=f"kb-evt-{i}",
            tenant_id=_KB_TENANT,
            ts=_KB_TS,
            actor=f"sub:{i}",
            type="approval.granted",
            run_id="kb-merkle-day",
            payload={"메모": f"국민은행 감사 이벤트 {i}", "차수": i},
        )
        h = compute_chain_hash(prev, canonical(event))
        hashes.append(h)
        prev = h
    return hashes


# Pinned reference values for the KB fixture. Computed from the Core determinism
# primitives (compute_chain_hash / build_root) which are out of S4's behavioral
# scope; if S4 ever perturbed them these literals would trip (regression gate).
_KB_CHAIN_TAIL = "f39d08b3e04c714edd2500100ed00dc78bcaf172ba597b9d5aae654acd05a0e4"
_KB_MERKLE_ROOT = "7f5f55ac8087405cdc067d4248eee1a12847cb25cd8eebc4066c0dd9f0973ac4"


def test_chain_hash_independent_of_kms_provider() -> None:
    """INV-S4-3: the chain-hash sequence is identical no matter which KMS signs.

    The signature is computed OVER the Merkle root downstream; it cannot reach
    ``compute_chain_hash``. We sign the same chain with two DIFFERENT providers and
    assert the underlying chain hashes are byte-identical.
    """
    hashes = _kb_chain_hashes()

    local = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    recording = _RecordingKms()

    signer_a = MerkleSigner(kms=local, key_id=_KB_KEY_ID)
    signer_b = MerkleSigner(kms=recording, key_id=_KB_KEY_ID)

    bundle_a = signer_a.sign_day(day=date(2026, 6, 25), hashes=hashes)
    bundle_b = signer_b.sign_day(day=date(2026, 6, 25), hashes=hashes)

    # Different providers ⇒ different signatures …
    assert bundle_a.signature_hex != bundle_b.signature_hex
    # … but the Merkle root (the signed input) is IDENTICAL …
    assert bundle_a.root_hex == bundle_b.root_hex
    # … and the chain-hash sequence is untouched by signing.
    assert _kb_chain_hashes() == hashes


def test_merkle_root_excludes_signature() -> None:
    """INV-S4-3: build_root depends only on the chain hashes, never the signature.

    Re-deriving the root from the chain hashes alone must equal the signed root —
    proving the signature is layered OVER the root, not mixed into it.
    """
    hashes = _kb_chain_hashes()
    provider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    signer = MerkleSigner(kms=provider, key_id=_KB_KEY_ID)
    bundle = signer.sign_day(day=date(2026, 6, 25), hashes=hashes)
    assert bundle.root_hex == MerkleSigner.build_root(hashes)


def test_det_chain_hash_invariant_pinned() -> None:
    """Pin the KB fixture chain-hash tail + Merkle root to literal values.

    This is the concrete ``det 9b99932311ebcc94`` regression gate for S4: the
    audit-chain determinism primitives are anchored so any drift (incl. a
    signature leaking into the chain input) trips here, not silently downstream.
    """
    hashes = _kb_chain_hashes()
    assert hashes[-1] == _KB_CHAIN_TAIL
    assert MerkleSigner.build_root(hashes) == _KB_MERKLE_ROOT


def test_determinism_100x_root_and_signature() -> None:
    """Same fixture, signed 100× ⇒ exactly one root and one signature (I2)."""
    hashes = _kb_chain_hashes()
    provider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    signer = MerkleSigner(kms=provider, key_id=_KB_KEY_ID)
    bundles = [signer.sign_day(day=date(2026, 6, 25), hashes=hashes) for _ in range(100)]
    roots = {b.root_hex for b in bundles}
    sigs = {b.signature_hex for b in bundles}
    assert roots == {_KB_MERKLE_ROOT}
    assert len(sigs) == 1


def test_signed_root_tamper_detected() -> None:
    """A tampered root no longer verifies under the same signature (I4)."""
    hashes = _kb_chain_hashes()
    provider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    signer = MerkleSigner(kms=provider, key_id=_KB_KEY_ID)
    bundle = signer.sign_day(day=date(2026, 6, 25), hashes=hashes)
    tampered = SignedMerkleRoot(
        day=bundle.day,
        root_hex="e" * 64,
        signature_hex=bundle.signature_hex,
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
    )
    assert tampered.verify_against(provider) is False


def test_provider_satisfies_protocol() -> None:
    provider: KmsProvider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    sig = provider.sign(root_bytes=b"z" * 32, key_id=_KB_KEY_ID)
    assert provider.verify(root_bytes=b"z" * 32, signature_bytes=sig, key_id=_KB_KEY_ID) is True


def test_local_provider_sign_unknown_key_raises() -> None:
    # Signing with a key_id the factory never registered must fail loud (a missing
    # signing key is a config error, never a blank signature).
    provider = build_kms_provider(KmsSettings(key_id=_KB_KEY_ID))
    with pytest.raises(KeyError):
        provider.sign(root_bytes=b"x" * 32, key_id="unregistered-key")


def test_local_provider_custom_hmac_key_signs() -> None:
    # An operator-supplied dev HMAC key is honoured (not the built-in default).
    provider = build_kms_provider(
        KmsSettings(key_id=_KB_KEY_ID, local_hmac_key=SecretStr("operator-dev-key"))
    )
    root = bytes.fromhex("ab" * 32)
    sig = provider.sign(root_bytes=root, key_id=_KB_KEY_ID)
    assert provider.verify(root_bytes=root, signature_bytes=sig, key_id=_KB_KEY_ID) is True
