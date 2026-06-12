# SPDX-License-Identifier: Apache-2.0
"""EM-03 — loader is signed-only and fail-closed (invariant I-D)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.audit.merkle import LocalHmacKmsProvider
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import (
    Match,
    PolicyDoc,
    PolicyLoadError,
    Rule,
    empty_deny_policy,
    load_active_policy,
    sign_bundle,
    write_signed_bundle,
)

_KEY_ID = "policy-key-1"
_ALLOWED = frozenset({_KEY_ID})


def _kms() -> LocalHmacKmsProvider:
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY_ID, b"a-32-byte-or-longer-secret-key!!!")
    return kms


def _doc() -> PolicyDoc:
    return PolicyDoc(
        version="1",
        tenant_id="acme",
        rules=[Rule(id="d1", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="x")],
    )


def _eff(target: str = "c:/secret/a.txt") -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target=target, sink_class=SinkClass.LOCAL_SANDBOX)


def test_valid_signed_bundle_loads(tmp_path: Path) -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(bundle, path)
    policy = load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)
    assert policy.evaluate(_eff(), DataLabel.PUBLIC).outcome == "deny"


def test_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError):
        load_active_policy(tmp_path / "nope.json", kms=_kms(), allowed_key_ids=_ALLOWED)


def test_unsigned_plain_policy_doc_rejected(tmp_path: Path) -> None:
    # A bare PolicyDoc (no signature envelope) must NOT load.
    path = tmp_path / "plain.json"
    path.write_text(_doc().model_dump_json(), encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=_kms(), allowed_key_ids=_ALLOWED)


def test_tampered_bundle_file_fails_closed(tmp_path: Path) -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(bundle, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["doc_json"] = data["doc_json"].replace("c:/secret/*", "c:/public/*", 1)  # tamper rule
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=_kms(), allowed_key_ids=_ALLOWED)


def test_non_object_json_fails_closed(tmp_path: Path) -> None:
    # A JSON array (not an object) is not a bundle → fail closed.
    path = tmp_path / "arr.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=_kms(), allowed_key_ids=_ALLOWED)


def test_unauthorized_signer_fails_closed(tmp_path: Path) -> None:
    # A bundle signed by a KMS-known key that is NOT in allowed_key_ids must
    # be refused at load (key-substitution defense, fail-closed).
    kms = _kms()
    kms.register_key("rogue", b"rogue-controlled-32-byte-secret!!")
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(sign_bundle(_doc(), kms=kms, key_id="rogue"), path)
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)


def test_wrong_field_type_fails_closed(tmp_path: Path) -> None:
    """SG-20260602-04: a bundle whose doc_json is an object (not a string) must
    raise PolicyLoadError, not leak an AttributeError from verify_bundle."""
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(bundle, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["doc_json"] = {"a": 1}  # object instead of a JSON string
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)


def test_missing_bundle_field_fails_closed(tmp_path: Path) -> None:
    kms = _kms()
    bundle = sign_bundle(_doc(), kms=kms, key_id=_KEY_ID)
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(bundle, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["signature_hex"]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)


def test_empty_deny_policy_denies_everything() -> None:
    policy = empty_deny_policy()
    assert policy.evaluate(_eff(target="c:/anything/x"), DataLabel.PUBLIC).outcome == "deny"
