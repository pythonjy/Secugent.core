# SPDX-License-Identifier: Apache-2.0
"""EM-03 — additive OversightEngine.evaluate_effect surface (no regression to evaluate(step))."""

from __future__ import annotations

from secugent.core.contracts import Step
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import TenantId


def _eff(target: str = "c:/secret/a.txt") -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target=target, sink_class=SinkClass.LOCAL_SANDBOX)


def _compiled() -> object:
    doc = PolicyDoc(
        version="1",
        tenant_id="_base",
        rules=[Rule(id="d1", effect="hard_block", match=Match(target_glob="c:/secret/*"), rationale="no")],
    )
    return compile_policy(doc)


def test_evaluate_effect_uses_compiled_policy() -> None:
    engine = OversightEngine(Regulations(version="t"), compiled_policy=_compiled())
    d = engine.evaluate_effect(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "hard_block"
    assert d.rule_id == "d1"


def test_evaluate_effect_deny_by_default_without_policy() -> None:
    engine = OversightEngine(Regulations(version="t"))  # no compiled_policy
    d = engine.evaluate_effect(_eff(), DataLabel.PUBLIC)
    assert d.outcome == "deny"
    assert d.rule_id is None


def test_existing_evaluate_step_unaffected_by_compiled_policy() -> None:
    # Attaching a compiled policy must NOT change the legacy Step-based path.
    engine = OversightEngine(Regulations(version="t"), compiled_policy=_compiled())
    step = Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:researcher",
        action_type="file_read",
        target="c:/data/report.csv",
    )
    result = engine.evaluate(step)
    assert result.allowed is True  # empty regulations → allowed, policy irrelevant here
