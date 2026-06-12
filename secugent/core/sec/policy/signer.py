# SPDX-License-Identifier: Apache-2.0
"""Sign / verify a compiled policy document (EM-03, invariant I-D).

Mechanical Oversight must only ever load a policy whose bytes a human signed.
Signing reuses the audit subsystem's :class:`KmsProvider` (HMAC in dev, AWS
KMS / Vault Transit in prod) — no ad-hoc crypto. Any hash or signature mismatch
raises :class:`PolicySignatureError` (no partial acceptance).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Set as AbstractSet
from dataclasses import dataclass

from pydantic import ValidationError

from secugent.audit.merkle import KmsProvider
from secugent.core.sec.policy._jcs import canonical_json
from secugent.core.sec.policy.schema import PolicyDoc

__all__ = ["SignedBundle", "PolicySignatureError", "sign_bundle", "verify_bundle"]

# Domain-separation prefix: the signed bytes are H(domain || doc_json), so a
# policy signature can never be confused with a Merkle-root signature (which the
# same KMS produces over a bare 32-byte hash), and the signature binds the whole
# document body — not merely its 32-byte digest.
_POLICY_SIG_DOMAIN = b"secugent.policy.bundle.v1\x00"


class PolicySignatureError(Exception):
    """Raised when a signed bundle's key, algorithm, hash, or signature is invalid."""


@dataclass(frozen=True)
class SignedBundle:
    doc_json: str  # canonical JSON of the PolicyDoc (the signed bytes)
    doc_hash: str  # sha256(doc_json) — the policy identity
    signature_hex: str
    key_id: str
    algorithm: str


def _signed_digest(doc_json: str) -> bytes:
    return hashlib.sha256(_POLICY_SIG_DOMAIN + doc_json.encode("utf-8")).digest()


def sign_bundle(doc: PolicyDoc, *, kms: KmsProvider, key_id: str) -> SignedBundle:
    doc_json = canonical_json(doc.model_dump(mode="json"))
    doc_hash = hashlib.sha256(doc_json.encode("utf-8")).hexdigest()
    signature = kms.sign(root_bytes=_signed_digest(doc_json), key_id=key_id)
    return SignedBundle(
        doc_json=doc_json,
        doc_hash=doc_hash,
        signature_hex=signature.hex(),
        key_id=key_id,
        algorithm=kms.algorithm,
    )


def verify_bundle(bundle: SignedBundle, *, kms: KmsProvider, allowed_key_ids: AbstractSet[str]) -> PolicyDoc:
    """Return the :class:`PolicyDoc` iff the bundle fully verifies, else raise.

    Checks, fail-closed, in order: the signing ``key_id`` must be in
    ``allowed_key_ids`` (no trusting the bundle's own key claim — defeats
    key-substitution), the ``algorithm`` must match the verifying KMS, the body
    must hash to ``doc_hash``, the signature must verify, and the body must be a
    valid :class:`PolicyDoc`. Any failure raises :class:`PolicySignatureError`.
    """
    if bundle.key_id not in allowed_key_ids:
        raise PolicySignatureError(f"signing key_id {bundle.key_id!r} is not an authorized signer")
    if bundle.algorithm != kms.algorithm:
        raise PolicySignatureError(
            f"algorithm mismatch: bundle={bundle.algorithm!r} verifier={kms.algorithm!r}"
        )
    recomputed = hashlib.sha256(bundle.doc_json.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(recomputed, bundle.doc_hash):
        raise PolicySignatureError("doc_hash does not match doc_json (body tampered)")
    try:
        signature_bytes = bytes.fromhex(bundle.signature_hex)
    except ValueError as exc:
        raise PolicySignatureError(f"malformed signature hex: {exc}") from exc
    if not kms.verify(
        root_bytes=_signed_digest(bundle.doc_json), signature_bytes=signature_bytes, key_id=bundle.key_id
    ):
        raise PolicySignatureError("signature verification failed")
    try:
        return PolicyDoc.model_validate_json(bundle.doc_json)
    except ValidationError as exc:
        raise PolicySignatureError(f"signed body is not a valid PolicyDoc: {exc}") from exc
