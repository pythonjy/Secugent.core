# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — daily Merkle root with mock KMS signature.

Core tier (Apache-2.0). This module holds the :class:`KmsProvider` Protocol
(the abstraction Core depends on) and the dev-only :class:`LocalHmacKmsProvider`.
The production external-KMS *implementations* (``AwsKmsProvider`` /
``VaultTransitProvider``) are Enterprise (BSL-1.1) and live in
``secugent.enterprise.kms`` so Core/audit never ships BSL-licensed code
(open-core boundary, BDP_01 item 1). Core depends only on the Protocol, never
on the Enterprise impls (dependency-inversion at the boundary).

The runtime path:

1. ``MerkleSigner.build_root(hashes)`` produces a deterministic SHA-256
   Merkle root from the day's event-chain hashes.
2. ``KmsProvider.sign(root_bytes)`` produces a signature blob — the default
   :class:`LocalHmacKmsProvider` uses HMAC-SHA256 keyed by ``key_id``.
   Production swaps in AWS KMS / Vault Transit (``secugent.enterprise.kms``).
3. The signed bundle :class:`SignedMerkleRoot` is what gets pushed to the
   external object-lock S3 store (out of scope for PHASE 12 — we only need
   to verify the cryptography).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from typing import Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, SecretStr

__all__ = [
    "KmsProvider",
    "KmsProviderName",
    "KmsSettings",
    "LocalHmacKmsProvider",
    "MerkleSigner",
    "SignedMerkleRoot",
    "build_kms_provider",
]


@dataclass(frozen=True)
class SignedMerkleRoot:
    day: date
    root_hex: str
    signature_hex: str
    key_id: str
    algorithm: str

    def verify_against(self, provider: KmsProvider) -> bool:
        return provider.verify(
            root_bytes=bytes.fromhex(self.root_hex),
            signature_bytes=bytes.fromhex(self.signature_hex),
            key_id=self.key_id,
        )


class KmsProvider(Protocol):
    algorithm: str

    def sign(self, *, root_bytes: bytes, key_id: str) -> bytes: ...
    def verify(self, *, root_bytes: bytes, signature_bytes: bytes, key_id: str) -> bool: ...


# ---------------------------------------------------------------------------
# Local HMAC provider — default for tests and dev
# ---------------------------------------------------------------------------


class LocalHmacKmsProvider:
    """HMAC-SHA256 provider keyed by ``key_id`` registered in-memory.

    A poor substitute for a real KMS but sufficient to exercise the signing
    and verification flow during unit tests.
    """

    algorithm = "HMAC-SHA256"

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register_key(self, key_id: str, key_bytes: bytes) -> None:
        self._keys[key_id] = key_bytes

    def sign(self, *, root_bytes: bytes, key_id: str) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyError(f"unknown key_id {key_id!r}")
        return hmac.new(key, root_bytes, hashlib.sha256).digest()

    def verify(self, *, root_bytes: bytes, signature_bytes: bytes, key_id: str) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        expected = hmac.new(key, root_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature_bytes)


# NOTE: The production external-KMS implementations (AwsKmsProvider /
# VaultTransitProvider) were moved to ``secugent.enterprise.kms`` (BSL-1.1) so
# the Apache-2.0 Core never ships Enterprise-licensed code. Core depends only on
# the ``KmsProvider`` Protocol above (dependency inversion at the boundary).


# ---------------------------------------------------------------------------
# Merkle root builder
# ---------------------------------------------------------------------------


class MerkleSigner:
    """Build + sign a Merkle root over a list of event hashes."""

    def __init__(self, *, kms: KmsProvider, key_id: str) -> None:
        self._kms = kms
        self._key_id = key_id

    # Domain-separation prefixes (RFC 6962 style) — distinguish leaf hashes
    # from internal-node hashes so a crafted set of leaves cannot reproduce an
    # internal node and forge an equal root (CVE-2012-2459 second-preimage).
    _LEAF_PREFIX = b"\x00"
    _NODE_PREFIX = b"\x01"

    @staticmethod
    def build_root(hashes: list[str]) -> str:
        if not hashes:
            return hashlib.sha256(b"\x00").hexdigest()  # empty-tree sentinel
        leaf, node = MerkleSigner._LEAF_PREFIX, MerkleSigner._NODE_PREFIX
        layer = [hashlib.sha256(leaf + bytes.fromhex(h)).digest() for h in hashes]
        while len(layer) > 1:
            paired: list[bytes] = []
            for i in range(0, len(layer), 2):
                if i + 1 < len(layer):
                    paired.append(hashlib.sha256(node + layer[i] + layer[i + 1]).digest())
                else:
                    # Odd node carries up unchanged — no self-duplication, which
                    # is the other half of the CVE-2012-2459 weakness.
                    paired.append(layer[i])
            layer = paired
        return layer[0].hex()

    def sign_day(self, *, day: date, hashes: list[str]) -> SignedMerkleRoot:
        # The signature is computed OVER the Merkle root via the INJECTED
        # provider (``self._kms``) — it is never mixed back into the chain-hash
        # input (``compute_chain_hash`` over prev_hash||canonical_body). Swapping
        # the provider changes only ``signature_hex``; ``root_hex`` is a pure
        # function of ``hashes`` (det 9b99792311ebcc94 invariant).
        root_hex = self.build_root(hashes)
        signature = self._kms.sign(root_bytes=bytes.fromhex(root_hex), key_id=self._key_id)
        return SignedMerkleRoot(
            day=day,
            root_hex=root_hex,
            signature_hex=signature.hex(),
            key_id=self._key_id,
            algorithm=self._kms.algorithm,
        )


# ---------------------------------------------------------------------------
# G-H3 — boot settings + factory (selects Local HMAC vs external Vault Transit)
# ---------------------------------------------------------------------------


KmsProviderName = Literal["local", "vault_transit", "aws_kms", "gcp_kms"]

# Dev signing key material for the LocalHmacKmsProvider default. Used only when
# no operator-supplied HMAC key is configured; production must select an external
# KMS provider for tamper-evident evidence (warned about at the call site in the
# create_app integration step).
_DEV_HMAC_KEY: Final[bytes] = b"secugent-dev-merkle-signing-key-0001"


class KmsSettings(BaseModel):
    """Operator-facing KMS configuration for the daily Merkle signer (G-H3 + B5).

    ``provider="vault_transit"`` selects the Enterprise
    :class:`secugent.enterprise.kms.VaultTransitProvider` (BSL-1.1, lazily
    imported only on that path so Core stays importable on a slim install).
    ``provider="aws_kms"`` selects :class:`~secugent.enterprise.kms.AwsKmsProvider`
    (requires ``kms_region``). ``provider="gcp_kms"`` selects
    :class:`~secugent.enterprise.kms.GcpKmsProvider` (key_id is the full
    CryptoKeyVersion resource name). Any unrecognised value selects the dev-only
    :class:`LocalHmacKmsProvider`.

    ``require_external=True`` (B5 prod guard): refuses provider='local' (the dev
    HMAC key) at build time — production must use an external KMS.
    """

    model_config = ConfigDict(extra="forbid")

    provider: KmsProviderName = "local"
    key_id: str = "merkle-dev"
    vault_addr: str | None = None
    vault_token: SecretStr | None = None
    # Dev-only override for the local HMAC key; SecretStr so it redacts on repr.
    local_hmac_key: SecretStr | None = None
    # AWS KMS region (required when provider='aws_kms').
    kms_region: str | None = None
    # B5 prod guard: refuse the dev HMAC (provider='local') when True.
    # Set SECUGENT_KMS_REQUIRE_EXTERNAL=true in production to enforce this.
    require_external: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> KmsSettings:
        """Build from ``SECUGENT_KMS_*`` (+ ``VAULT_*`` for the transit path).

        Recognised ``SECUGENT_KMS_PROVIDER`` values:
        ``local`` (dev default), ``vault_transit``, ``aws_kms``, ``gcp_kms``.
        Unset / unrecognised ⇒ ``local``.

        ``SECUGENT_KMS_REQUIRE_EXTERNAL=true`` (case-insensitive) activates the
        B5 prod guard: building with provider='local' will raise ``ValueError``.
        """
        env = os.environ if environ is None else environ
        raw_provider = env.get("SECUGENT_KMS_PROVIDER", "").strip().lower()
        _known: frozenset[KmsProviderName] = frozenset({"local", "vault_transit", "aws_kms", "gcp_kms"})
        provider: KmsProviderName = raw_provider if raw_provider in _known else "local"
        token = env.get("VAULT_TOKEN")
        local_key = env.get("SECUGENT_KMS_LOCAL_HMAC_KEY")
        raw_ext = env.get("SECUGENT_KMS_REQUIRE_EXTERNAL", "").strip().lower()
        allow_dev_hmac = env.get("SECUGENT_KMS_ALLOW_DEV_HMAC", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        # C3-② (W8) drift note: this keys on the EXPLICIT "production" string, which
        # is intentionally NARROWER than the canonical dev predicate
        # ``secugent.api.env.is_dev_env`` (whose inverse ``not is_dev_env`` treats any
        # non-"dev" value — incl. unset/"staging" — as production). Auto-enforcing the
        # external-KMS guard ONLY on an explicit "production" avoids surprising CI /
        # prod-mirror boxes (named neither "dev" nor "production") with a fail-closed
        # signer build. Explicit SECUGENT_KMS_REQUIRE_EXTERNAL always overrides. A
        # future security pass may tighten this to deny-by-default (not is_dev_env).
        is_production = env.get("SECUGENT_ENV", "").strip().lower() == "production"
        # B5 prod guard (defense in depth): auto-enforce require_external when
        # SECUGENT_ENV=production so that a deployment with provider=local fails
        # at boot rather than silently signing Merkle roots with the hardcoded
        # dev HMAC key. Priority: explicit SECUGENT_KMS_REQUIRE_EXTERNAL > auto-
        # production detection. Escape hatch: SECUGENT_KMS_ALLOW_DEV_HMAC=1
        # disables auto-enforcement for dev/CI environments that are named
        # "production" locally (e.g. prod-mirror smoke tests).
        if raw_ext:
            require_external = raw_ext in {"1", "true", "yes", "on"}
        elif is_production and not allow_dev_hmac:
            require_external = True
        else:
            require_external = False
        return cls(
            provider=provider,
            key_id=env.get("SECUGENT_KMS_KEY_ID") or "merkle-dev",
            vault_addr=env.get("VAULT_ADDR") or None,
            vault_token=SecretStr(token) if token else None,
            local_hmac_key=SecretStr(local_key) if local_key else None,
            kms_region=env.get("SECUGENT_KMS_REGION") or None,
            require_external=require_external,
        )


def build_kms_provider(settings: KmsSettings) -> KmsProvider:
    """Select the KMS provider for the Merkle signer (G-H3 + B5).

    * ``provider="vault_transit"`` → Enterprise
      :class:`~secugent.enterprise.kms.VaultTransitProvider` (lazy import; the
      open-core boundary forbids only *load-time* Enterprise imports from Core).
      ``vault_addr`` is required — its absence is a misconfiguration → ``ValueError``.
    * ``provider="aws_kms"`` → Enterprise
      :class:`~secugent.enterprise.kms.AwsKmsProvider` (lazy import).
      ``kms_region`` is required — its absence → ``ValueError`` (fail-closed).
    * ``provider="gcp_kms"`` → Enterprise
      :class:`~secugent.enterprise.kms.GcpKmsProvider` (lazy import). The
      ``key_id`` must be the full GCP CryptoKeyVersion resource name.
    * ``provider="local"`` → :class:`LocalHmacKmsProvider` with ``key_id``
      registered. This is the dev-only HMAC signer — **refused when
      ``settings.require_external=True``** (B5 prod guard).

    **B5 prod guard**: when ``settings.require_external`` is ``True``, this
    function raises ``ValueError`` on ``provider='local'`` — the dev HMAC key
    must never be used in production. Allowed external providers:
    vault_transit / aws_kms / gcp_kms.

    All returns conform to the :class:`KmsProvider` Protocol; the integration
    step can build ``MerkleSigner(kms=provider, key_id=...)`` directly.
    """
    # B5 prod guard: refuse the dev HMAC in production (fail-closed).
    if settings.require_external and settings.provider == "local":
        raise ValueError(
            "KmsSettings.require_external=True forbids provider='local' (the dev HMAC key). "
            "Select an external KMS provider for production: vault_transit / aws_kms / gcp_kms. "
            "Set SECUGENT_KMS_PROVIDER to one of those and configure the corresponding credentials."
        )

    if settings.provider == "vault_transit":
        if not settings.vault_addr:
            raise ValueError(
                "KmsSettings.vault_addr is required when provider='vault_transit' "
                "(fail-closed: refusing to build a Transit signer without an address)"
            )
        # Lazy, call-time import: Core must never import Enterprise at load time
        # (open-core boundary I2). Only the vault_transit path touches it.
        from secugent.enterprise.kms import VaultTransitProvider

        token = settings.vault_token.get_secret_value() if settings.vault_token is not None else None
        return VaultTransitProvider(url=settings.vault_addr, token=token)

    if settings.provider == "aws_kms":
        if not settings.kms_region:
            raise ValueError(
                "KmsSettings.kms_region is required when provider='aws_kms' "
                "(fail-closed: refusing to build an AWS KMS signer without a region). "
                "Set SECUGENT_KMS_REGION to the AWS region, e.g. ap-northeast-2."
            )
        # Lazy, call-time import (open-core boundary I2).
        from secugent.enterprise.kms import AwsKmsProvider

        return AwsKmsProvider(region=settings.kms_region)

    if settings.provider == "gcp_kms":
        # Lazy, call-time import (open-core boundary I2).
        # key_id carries the full GCP CryptoKeyVersion resource name.
        from secugent.enterprise.kms import GcpKmsProvider

        return GcpKmsProvider()

    local = LocalHmacKmsProvider()
    key_bytes = (
        settings.local_hmac_key.get_secret_value().encode("utf-8")
        if settings.local_hmac_key is not None
        else _DEV_HMAC_KEY
    )
    local.register_key(settings.key_id, key_bytes)
    return local
