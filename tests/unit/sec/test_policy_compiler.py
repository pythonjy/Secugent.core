# SPDX-License-Identifier: Apache-2.0
"""EM-03 — policy DSL schema, compile, and deterministic evaluation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import (
    CompiledPolicy,
    Decision,
    Match,
    PolicyDoc,
    Rule,
    compile_policy,
)


def _eff(
    kind: EffectKind = EffectKind.FILE_WRITE,
    target: str = "c:/data/out.txt",
    sink: SinkClass = SinkClass.LOCAL_SANDBOX,
) -> Effect:
    return Effect(kind=kind, target=target, sink_class=sink)


def _doc(*rules: Rule) -> PolicyDoc:
    return PolicyDoc(version="1", tenant_id="_base", rules=list(rules))


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #


def test_schema_rejects_extra_field() -> None:
    with pytest.raises(ValidationError):
        Rule(id="r", effect="allow", match=Match(), rationale="x", bogus=1)  # type: ignore[call-arg]


def test_schema_rejects_bad_effect() -> None:
    with pytest.raises(ValidationError):
        Rule(id="r", effect="permit", match=Match(), rationale="x")  # type: ignore[arg-type]


def test_policy_default_is_deny() -> None:
    assert _doc().default == "deny"


# --------------------------------------------------------------------------- #
# evaluate — deny-by-default + precedence
# --------------------------------------------------------------------------- #


def test_empty_policy_denies() -> None:
    policy = compile_policy(_doc())
    d = policy.evaluate(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "deny"
    assert d.rule_id is None
    assert d.rationale == "default_deny"


def test_matching_allow() -> None:
    policy = compile_policy(
        _doc(Rule(id="a1", effect="allow", match=Match(kind=EffectKind.FILE_WRITE), rationale="writes ok"))
    )
    d = policy.evaluate(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "allow"
    assert d.rule_id == "a1"


def test_hard_block_beats_allow() -> None:
    policy = compile_policy(
        _doc(
            Rule(id="a1", effect="allow", match=Match(kind=EffectKind.FILE_WRITE), rationale="allow"),
            Rule(id="h1", effect="hard_block", match=Match(kind=EffectKind.FILE_WRITE), rationale="blocked"),
        )
    )
    d = policy.evaluate(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "hard_block"
    assert d.rule_id == "h1"


def test_deny_beats_allow() -> None:
    policy = compile_policy(
        _doc(
            Rule(id="a1", effect="allow", match=Match(kind=EffectKind.FILE_WRITE), rationale="allow"),
            Rule(id="d1", effect="deny", match=Match(kind=EffectKind.FILE_WRITE), rationale="deny"),
        )
    )
    d = policy.evaluate(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "deny"
    assert d.rule_id == "d1"


# --------------------------------------------------------------------------- #
# match conditions
# --------------------------------------------------------------------------- #


def test_min_label_gates_rule() -> None:
    policy = compile_policy(
        _doc(
            Rule(id="d1", effect="deny", match=Match(min_label=DataLabel.CONFIDENTIAL), rationale="sensitive")
        )
    )
    # below min_label → rule not applied → default deny (rule_id None)
    assert policy.evaluate(_eff(), DataLabel.PUBLIC).rule_id is None
    # at/above min_label → rule applies
    assert policy.evaluate(_eff(), DataLabel.SECRET).rule_id == "d1"


def test_target_glob_matches_canonical_target() -> None:
    policy = compile_policy(
        _doc(Rule(id="d1", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="secret dir"))
    )
    assert policy.evaluate(_eff(target="c:/secret/a.txt"), DataLabel.PUBLIC).outcome == "deny"
    assert policy.evaluate(_eff(target="c:/public/a.txt"), DataLabel.PUBLIC).outcome == "deny"  # default
    assert policy.evaluate(_eff(target="c:/public/a.txt"), DataLabel.PUBLIC).rule_id is None


def test_sink_class_match() -> None:
    policy = compile_policy(
        _doc(Rule(id="x1", effect="allow", match=Match(sink_class=SinkClass.EXTERNAL), rationale="ext ok"))
    )
    assert (
        policy.evaluate(
            _eff(kind=EffectKind.NET_SEND, target="https://a.com/x", sink=SinkClass.EXTERNAL),
            DataLabel.PUBLIC,
        ).outcome
        == "allow"
    )
    assert policy.evaluate(_eff(sink=SinkClass.LOCAL_SANDBOX), DataLabel.PUBLIC).outcome == "deny"


def test_all_conditions_must_match() -> None:
    policy = compile_policy(
        _doc(
            Rule(
                id="combo",
                effect="allow",
                match=Match(
                    kind=EffectKind.FILE_WRITE, sink_class=SinkClass.LOCAL_SANDBOX, target_glob="c:/data/*"
                ),
                rationale="narrow",
            )
        )
    )
    assert policy.evaluate(_eff(), DataLabel.PUBLIC).outcome == "allow"
    # wrong kind → no match → default deny
    assert policy.evaluate(_eff(kind=EffectKind.FILE_READ), DataLabel.PUBLIC).outcome == "deny"


# --------------------------------------------------------------------------- #
# determinism
# --------------------------------------------------------------------------- #


def test_evaluate_deterministic_100x() -> None:
    policy = compile_policy(
        _doc(
            Rule(id="a1", effect="allow", match=Match(kind=EffectKind.FILE_WRITE), rationale="a"),
            Rule(id="d1", effect="deny", match=Match(target_glob="c:/data/*"), rationale="d"),
        )
    )
    outs = {policy.evaluate(_eff(), DataLabel.PUBLIC).model_dump_json() for _ in range(100)}
    assert len(outs) == 1


def test_compiled_policy_has_doc_hash() -> None:
    policy = compile_policy(_doc())
    assert isinstance(policy, CompiledPolicy)
    assert len(policy.doc_hash) == 64  # sha256 hex


def test_decision_is_deterministic_flag() -> None:
    d = compile_policy(_doc()).evaluate(_eff(), DataLabel.PUBLIC)
    assert isinstance(d, Decision)
    assert d.is_deterministic is True


def test_doc_hash_golden_value() -> None:
    # Hard-coded hash guards canonical-JSON stability across pydantic/Python
    # versions: a serialization drift (enum repr, key order) would break every
    # previously-signed bundle, and this test would catch it first.
    doc = PolicyDoc(
        version="1",
        tenant_id="_base",
        rules=[
            Rule(
                id="d1",
                effect="deny",
                match=Match(target_glob="c:/secret/*", min_label=DataLabel.CONFIDENTIAL),
                rationale="no secrets",
            )
        ],
    )
    assert compile_policy(doc).doc_hash == "6d66fff4641ed3dfad268b813158bc6aea1cee217eac30200167f4efc0979347"


# --------------------------------------------------------------------------- #
# matching edge cases + precedence among same-outcome rules
# --------------------------------------------------------------------------- #


def test_glob_star_crosses_slash() -> None:
    # Documented footgun: fnmatch '*' is NOT segment-anchored — it spans '/'.
    policy = compile_policy(
        _doc(Rule(id="d", effect="deny", match=Match(target_glob="c:/data/*"), rationale="x"))
    )
    assert policy.evaluate(_eff(target="c:/data/sub/deep.txt"), DataLabel.PUBLIC).outcome == "deny"


def test_same_outcome_first_rule_in_document_order_wins() -> None:
    policy = compile_policy(
        _doc(
            Rule(id="d1", effect="deny", match=Match(kind=EffectKind.FILE_WRITE), rationale="first"),
            Rule(id="d2", effect="deny", match=Match(target_glob="c:/data/*"), rationale="second"),
        )
    )
    d = policy.evaluate(_eff(), DataLabel.PUBLIC)  # both rules match
    assert d.outcome == "deny"
    assert d.rule_id == "d1"  # document-order first match wins (deterministic)


def test_blank_rule_id_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule(id="   ", effect="allow", match=Match(), rationale="x")


def test_blank_rationale_rejected() -> None:
    with pytest.raises(ValidationError):
        Rule(id="r", effect="allow", match=Match(), rationale="   ")
