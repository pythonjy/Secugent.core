# SPDX-License-Identifier: Apache-2.0
"""B6 — the checked-in closed-net egress bundle template (§B-4a triple test).

``secugent/core/sec/policy/bundles/closed_net.json`` is the *unsigned* PolicyDoc
template an operator signs (4-eyes/MFA via ``authoring.sign_off``) before
mounting it as ``SECUGENT_POLICY_BUNDLE_PATH``. These tests pin its enforced
behaviour after the full operator flow (sign-off → write → ``load_active_policy``
→ compile):

  * internal-only bank sink (``*.kr-bank.internal``) → ALLOW
  * any EXTERNAL sink                                → HARD_BLOCK (§C-1)
  * everything else                                  → DENY (deny-by-default)

Per §B-4a (deterministic security module) this carries unit + property-based
(hypothesis) + scenario-regression layers AND a 100× determinism proof. §C-3
fixtures are Korean financial (KB국민은행 / 폐쇄망) domains.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secugent.audit.merkle import LocalHmacKmsProvider
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import (
    CompiledPolicy,
    Decision,
    PolicyDoc,
    load_active_policy,
    write_signed_bundle,
)
from secugent.core.sec.policy.authoring import sign_off
from secugent.core.sec.policy.fixtures import Fixture
from secugent.core.tenancy import Principal, TenantId

_BUNDLE_TEMPLATE = (
    Path(__file__).resolve().parents[4]
    / "secugent"
    / "core"
    / "sec"
    / "policy"
    / "bundles"
    / "closed_net.json"
)
_KEY_ID = "policy-prod-krbank"


# --------------------------------------------------------------------------- #
# helpers — load the template and run it through the real operator sign-off path
# --------------------------------------------------------------------------- #


def _load_template() -> PolicyDoc:
    return PolicyDoc.model_validate_json(_BUNDLE_TEMPLATE.read_text(encoding="utf-8"))


def _kms() -> LocalHmacKmsProvider:
    kms = LocalHmacKmsProvider()
    kms.register_key(_KEY_ID, b"secugent-closed-net-krbank-signing-key-0001")
    return kms


def _internal_effect(target: str = "https://core.kr-bank.internal/v1/accounts") -> Effect:
    return Effect(kind=EffectKind.NET_SEND, target=target, sink_class=SinkClass.INTERNAL)


def _external_effect(target: str = "https://api.vendor.example/v1/x") -> Effect:
    return Effect(kind=EffectKind.NET_SEND, target=target, sink_class=SinkClass.EXTERNAL)


# §C-3: Korean financial closed-net fixtures (used as the sign-off behavior gate).
_SIGNOFF_FIXTURES: list[Fixture] = [
    Fixture(effect=_internal_effect(), label=DataLabel.CONFIDENTIAL, expected="allow"),
    Fixture(effect=_external_effect(), label=DataLabel.PUBLIC, expected="hard_block"),
]


def _admin() -> Principal:
    return Principal(
        user_id="보안담당관",
        tenant_id=TenantId("financial-kr"),
        role="admin",
        mfa_satisfied=True,
    )


def _compile_via_signoff(tmp_path: Path) -> CompiledPolicy:
    """Sign the template (admin+MFA+fixtures) and load it back, fail-closed."""
    draft = _load_template()
    kms = _kms()
    bundle = sign_off(draft, _SIGNOFF_FIXTURES, approver=_admin(), kms=kms, key_id=_KEY_ID)
    out = tmp_path / "active.bundle.json"
    write_signed_bundle(bundle, out)
    return load_active_policy(out, kms=kms, allowed_key_ids={_KEY_ID})


# --------------------------------------------------------------------------- #
# template integrity
# --------------------------------------------------------------------------- #


def test_template_is_unsigned_policydoc_with_deny_default() -> None:
    raw = json.loads(_BUNDLE_TEMPLATE.read_text(encoding="utf-8"))
    # An unsigned PolicyDoc (NOT a SignedBundle): no signature fields present.
    assert "signature_hex" not in raw
    assert "doc_hash" not in raw
    doc = _load_template()
    assert doc.default == "deny"  # deny-by-default is structural
    assert {r.id for r in doc.rules} == {
        "allow-internal-krbank-net-send",
        "allow-internal-krbank-net-recv",
        "hard-block-external-egress",
    }


# --------------------------------------------------------------------------- #
# 1) unit — the three decisions
# --------------------------------------------------------------------------- #


def test_internal_krbank_sink_is_allowed(tmp_path: Path) -> None:
    compiled = _compile_via_signoff(tmp_path)
    decision = compiled.evaluate(_internal_effect(), DataLabel.CONFIDENTIAL)
    assert decision.outcome == "allow"
    assert decision.rule_id == "allow-internal-krbank-net-send"


def test_external_sink_is_hard_blocked(tmp_path: Path) -> None:
    compiled = _compile_via_signoff(tmp_path)
    decision = compiled.evaluate(_external_effect(), DataLabel.PUBLIC)
    # §C-1: external egress is HARD BLOCK regardless of risk/label.
    assert decision.outcome == "hard_block"
    assert decision.rule_id == "hard-block-external-egress"


def test_internal_but_non_krbank_host_is_denied(tmp_path: Path) -> None:
    compiled = _compile_via_signoff(tmp_path)
    # Internal sink but a host the allow-glob does not cover → deny-by-default.
    decision = compiled.evaluate(_internal_effect("https://intranet.other-corp.internal/x"), DataLabel.PUBLIC)
    assert decision.outcome == "deny"
    assert decision.rule_id is None


# --------------------------------------------------------------------------- #
# 2) scenario regression — table of (effect, label, expected)
# --------------------------------------------------------------------------- #


_SCENARIOS: list[tuple[Effect, DataLabel, str]] = [
    (_internal_effect("https://core.kr-bank.internal/v1/accounts"), DataLabel.SECRET, "allow"),
    (
        Effect(
            kind=EffectKind.NET_RECV,
            target="https://feed.kr-bank.internal/quotes",
            sink_class=SinkClass.INTERNAL,
        ),
        DataLabel.INTERNAL_USE,
        "allow",
    ),
    (_external_effect("https://www.naver.com/"), DataLabel.PUBLIC, "hard_block"),
    (
        # external sink wins hard_block even if the host *looks* internal.
        Effect(
            kind=EffectKind.NET_SEND,
            target="https://core.kr-bank.internal/x",
            sink_class=SinkClass.EXTERNAL,
        ),
        DataLabel.PUBLIC,
        "hard_block",
    ),
    (
        Effect(
            kind=EffectKind.FILE_WRITE,
            target="sandbox://tmp/report.txt",
            sink_class=SinkClass.LOCAL_SANDBOX,
        ),
        DataLabel.PUBLIC,
        "deny",
    ),
]


@pytest.mark.parametrize("effect,label,expected", _SCENARIOS)
def test_scenario_regression(tmp_path: Path, effect: Effect, label: DataLabel, expected: str) -> None:
    compiled = _compile_via_signoff(tmp_path)
    assert compiled.evaluate(effect, label).outcome == expected


# --------------------------------------------------------------------------- #
# 3) property-based (hypothesis)
# --------------------------------------------------------------------------- #

# Lower-case, no NUL/backslash/whitespace, no bare ".." segment, non-empty host.
_host = st.from_regex(r"[a-z][a-z0-9.-]{0,30}", fullmatch=True).filter(lambda h: ".." not in h.split("/"))
_path = st.from_regex(r"[a-z0-9/]{0,20}", fullmatch=True)


def _net_target(host: str, path: str) -> str:
    return f"https://{host}/{path}"


@given(host=_host, path=_path, label=st.sampled_from(list(DataLabel)))
def test_property_external_sink_always_hard_block(host: str, path: str, label: DataLabel) -> None:
    """Any EXTERNAL-sink effect is HARD_BLOCK — never allow/deny (§C-1)."""
    effect = Effect(kind=EffectKind.NET_SEND, target=_net_target(host, path), sink_class=SinkClass.EXTERNAL)
    # Compile straight from the template doc (no disk round-trip) — the signature
    # path is exercised by the unit tests; here we hammer evaluate's determinism.
    from secugent.core.sec.policy import compile_policy

    compiled = compile_policy(_load_template())
    assert compiled.evaluate(effect, label).outcome == "hard_block"


@given(host=_host, path=_path, label=st.sampled_from(list(DataLabel)))
def test_property_internal_non_krbank_never_allowed(host: str, path: str, label: DataLabel) -> None:
    """An INTERNAL sink that is NOT a *.kr-bank.internal host is never allowed."""
    from secugent.core.sec.policy import compile_policy

    target = _net_target(host, path)
    # Skip hosts the allow-glob would legitimately cover.
    if Effect(kind=EffectKind.NET_SEND, target=target, sink_class=SinkClass.INTERNAL).target.startswith(
        "https://"
    ) and target.split("/")[2].endswith(".kr-bank.internal"):
        return
    effect = Effect(kind=EffectKind.NET_SEND, target=target, sink_class=SinkClass.INTERNAL)
    assert compile_policy(_load_template()).evaluate(effect, label).outcome != "allow"


# --------------------------------------------------------------------------- #
# 4) §B-4a — 100× determinism (same input → byte-identical Decision)
# --------------------------------------------------------------------------- #


def test_determinism_100x(tmp_path: Path) -> None:
    compiled = _compile_via_signoff(tmp_path)
    internal = _internal_effect()
    external = _external_effect()

    first_internal: Decision = compiled.evaluate(internal, DataLabel.CONFIDENTIAL)
    first_external: Decision = compiled.evaluate(external, DataLabel.PUBLIC)
    for _ in range(100):
        assert compiled.evaluate(internal, DataLabel.CONFIDENTIAL) == first_internal
        assert compiled.evaluate(external, DataLabel.PUBLIC) == first_external
    assert first_internal.outcome == "allow"
    assert first_external.outcome == "hard_block"


def test_signoff_doc_hash_is_stable() -> None:
    """Signing the same template with the same key is deterministic (HMAC)."""
    draft = _load_template()
    kms = _kms()
    b1 = sign_off(draft, _SIGNOFF_FIXTURES, approver=_admin(), kms=kms, key_id=_KEY_ID)
    b2 = sign_off(draft, _SIGNOFF_FIXTURES, approver=_admin(), kms=kms, key_id=_KEY_ID)
    assert b1.doc_hash == b2.doc_hash
    assert b1.signature_hex == b2.signature_hex
