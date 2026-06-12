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
from dataclasses import dataclass
from datetime import date
from typing import Protocol

__all__ = [
    "KmsProvider",
    "LocalHmacKmsProvider",
    "MerkleSigner",
    "SignedMerkleRoot",
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
        root_hex = self.build_root(hashes)
        signature = self._kms.sign(root_bytes=bytes.fromhex(root_hex), key_id=self._key_id)
        return SignedMerkleRoot(
            day=day,
            root_hex=root_hex,
            signature_hex=signature.hex(),
            key_id=self._key_id,
            algorithm=self._kms.algorithm,
        )
