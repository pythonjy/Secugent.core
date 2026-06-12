# SPDX-License-Identifier: Apache-2.0
"""EM-03 — policy bundle signing / verification / tamper + key-pinning."""

from __future__ import annotations

import pytest

from secugent.audit.merkle import LocalHmacKmsProvider
from secugent.core.sec.policy import (
    Match,
    PolicyDoc,
    PolicySignatureError,
    Rule,
    SignedBundle,
    sign_bundle,
    verify_bundle,
)

_KEY_ID = "policy-key-1"
_ALLOWED = frozenset({_KEY_ID})


def _kms() -> LocalHmacKmsProvider:
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY_ID, b"a-32-byte-or-longer-secret-key!!!")
    return kms


def _doc(rationale: str = "no secrets") -> PolicyDoc:
    return PolicyDoc(
        version="1",
        tenant_id="acme",
        rules=[Rule(id="r1", effect="deny", match=Match(target_glob="c:/secret/*"), rationale=rationale)],
    )


def test_sign_verify_roundtrip() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    restored = verify_bundle(bundle, kms=kms, allowed_key_ids=_ALLOWED)
    assert restored.version == "1"
    assert restored.rules[0].id == "r1"
    assert bundle.algorithm == "HMAC-SHA256"


def test_korean_rationale_roundtrip() -> None:
    # Non-ASCII (Korean) body must canonicalize + sign + verify stably.
    kms = _kms()
    bundle = sign_bundle(_doc(rationale="대외비 외부 반출 금지"), kms=kms, key_id=_KEY_ID)
    restored = verify_bundle(bundle, kms=kms, allowed_key_ids=_ALLOWED)
    assert restored.rules[0].rationale == "대외비 외부 반출 금지"


def test_tampered_doc_json_rejected() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    tampered = SignedBundle(
        doc_json=bundle.doc_json.replace("no secrets", "no secretz", 1),
        doc_hash=bundle.doc_hash,
        signature_hex=bundle.signature_hex,
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(tampered, kms=kms, allowed_key_ids=_ALLOWED)


def test_tampered_signature_rejected() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    flipped = "0" if bundle.signature_hex[0] != "0" else "1"
    tampered = SignedBundle(
        doc_json=bundle.doc_json,
        doc_hash=bundle.doc_hash,
        signature_hex=flipped + bundle.signature_hex[1:],
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(tampered, kms=kms, allowed_key_ids=_ALLOWED)


def test_doc_hash_mismatch_rejected() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    bad = SignedBundle(
        doc_json=bundle.doc_json,
        doc_hash="0" * 64,
        signature_hex=bundle.signature_hex,
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(bad, kms=kms, allowed_key_ids=_ALLOWED)


def test_wrong_key_rejected() -> None:
    # Same key_id name, but the verifier's KMS holds a DIFFERENT secret.
    bundle = sign_bundle(_doc(), kms=_kms(), key_id=_KEY_ID)
    other = LocalHmacKmsProvider()
    other.register_key(_KEY_ID, b"a-different-32-byte-secret-key!!!")
    with pytest.raises(PolicySignatureError):
        verify_bundle(bundle, kms=other, allowed_key_ids=_ALLOWED)


def test_key_substitution_attack_rejected() -> None:
    # The crux of I-D: an attacker signs a WEAKENED policy with a different key
    # the KMS happens to know, and sets the bundle's key_id to it. Pinning the
    # authorized signer (allowed_key_ids) must reject it even though the signature
    # is internally valid for that key.
    kms = _kms()
    kms.register_key("attacker-key", b"attacker-controlled-32-byte-key!!")
    weakened = PolicyDoc(
        version="1",
        tenant_id="acme",
        rules=[Rule(id="a1", effect="allow", match=Match(target_glob="c:/secret/*"), rationale="oops")],
    )
    forged = sign_bundle(weakened, kms=kms, key_id="attacker-key")
    # signature is valid for 'attacker-key', but it is not an authorized signer
    with pytest.raises(PolicySignatureError):
        verify_bundle(forged, kms=kms, allowed_key_ids=_ALLOWED)


def test_algorithm_mismatch_rejected() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    bad = SignedBundle(
        doc_json=bundle.doc_json,
        doc_hash=bundle.doc_hash,
        signature_hex=bundle.signature_hex,
        key_id=bundle.key_id,
        algorithm="EdDSA",  # claims a different algorithm than the verifier
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(bad, kms=kms, allowed_key_ids=_ALLOWED)


def test_malformed_signature_hex_rejected() -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    bad = SignedBundle(
        doc_json=bundle.doc_json,
        doc_hash=bundle.doc_hash,
        signature_hex="zz",
        key_id=bundle.key_id,
        algorithm=bundle.algorithm,
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(bad, kms=kms, allowed_key_ids=_ALLOWED)


def test_signed_body_invalid_policydoc_raises_signature_error() -> None:
    # A bundle correctly signed over a body that is NOT a valid PolicyDoc must
    # raise PolicySignatureError (not a raw ValidationError) for direct callers.
    kms = _kms()
    bad_json = '{"version":"1","tenant_id":"BAD TENANT!!","rules":[]}'
    import hashlib

    from secugent.core.sec.policy.signer import _signed_digest

    doc_hash = hashlib.sha256(bad_json.encode("utf-8")).hexdigest()
    sig = kms.sign(root_bytes=_signed_digest(bad_json), key_id=_KEY_ID)
    bundle = SignedBundle(
        doc_json=bad_json,
        doc_hash=doc_hash,
        signature_hex=sig.hex(),
        key_id=_KEY_ID,
        algorithm=kms.algorithm,
    )
    with pytest.raises(PolicySignatureError):
        verify_bundle(bundle, kms=kms, allowed_key_ids=_ALLOWED)


def test_signature_deterministic_100x() -> None:
    kms = _kms()
    doc = _doc()
    sigs = {sign_bundle(doc, kms=kms, key_id=_KEY_ID).signature_hex for _ in range(100)}
    assert len(sigs) == 1
