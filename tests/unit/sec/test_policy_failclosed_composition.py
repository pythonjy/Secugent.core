# SPDX-License-Identifier: Apache-2.0
"""EM-03 — I-D composition: only a signed, verified policy reaches enforcement.

Demonstrates the load → verify → compile → OversightEngine.evaluate_effect chain
without touching the live boot path (api/main.py). A tampered bundle is refused
at load (PolicyLoadError) — i.e. boot would refuse — so it never enforces.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.audit.merkle import LocalHmacKmsProvider
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import (
    Match,
    PolicyDoc,
    PolicyLoadError,
    Rule,
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
        tenant_id="_base",
        rules=[Rule(id="d1", effect="hard_block", match=Match(target_glob="c:/secret/*"), rationale="no")],
    )


def _eff() -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target="c:/secret/a.txt", sink_class=SinkClass.LOCAL_SANDBOX)


def test_verified_policy_drives_oversight(tmp_path: Path) -> None:
    kms = _kms()
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(sign_bundle(_doc(), kms=kms, key_id=_KEY_ID), path)
    compiled = load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)  # verify + compile
    engine = OversightEngine(Regulations(version="t"), compiled_policy=compiled)
    assert engine.evaluate_effect(_eff(), DataLabel.PUBLIC).outcome == "hard_block"


def test_tampered_bundle_refused_before_enforcement(tmp_path: Path) -> None:
    kms = _kms()
    path = tmp_path / "policy.signed.json"
    write_signed_bundle(sign_bundle(_doc(), kms=kms, key_id=_KEY_ID), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["doc_json"] = data["doc_json"].replace("hard_block", "allow", 1)  # weaken the rule
    path.write_text(json.dumps(data), encoding="utf-8")
    # boot would refuse: the tampered artifact never compiles into an enforcer.
    with pytest.raises(PolicyLoadError):
        load_active_policy(path, kms=kms, allowed_key_ids=_ALLOWED)
