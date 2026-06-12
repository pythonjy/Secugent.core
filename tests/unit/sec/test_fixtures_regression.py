# SPDX-License-Identifier: Apache-2.0
"""EM-04 — fixture regression runner (deterministic)."""

from __future__ import annotations

from typing import Any

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Fixture, Match, PolicyDoc, Rule, compile_policy, run_fixtures


def _policy(*rules: Rule) -> Any:
    return compile_policy(PolicyDoc(version="1", tenant_id="_base", rules=list(rules)))


def _eff(target: str = "c:/secret/a.txt") -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target=target, sink_class=SinkClass.LOCAL_SANDBOX)


def test_all_fixtures_pass() -> None:
    policy = _policy(Rule(id="d", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="no"))
    fixtures = [
        Fixture(_eff("c:/secret/a.txt"), DataLabel.PUBLIC, "deny"),  # matches rule
        Fixture(_eff("c:/public/a.txt"), DataLabel.PUBLIC, "deny"),  # default_deny
    ]
    report = run_fixtures(policy, fixtures)
    assert report.all_passed
    assert report.failures == ()


def test_fixture_mismatch_fails() -> None:
    policy = _policy(Rule(id="a", effect="allow", match=Match(), rationale="allow all"))
    fixtures = [Fixture(_eff(), DataLabel.PUBLIC, "deny")]  # policy allows, fixture expects deny
    report = run_fixtures(policy, fixtures)
    assert not report.all_passed
    assert len(report.failures) == 1
    assert report.failures[0].actual == "allow"


def test_hard_block_fixture() -> None:
    policy = _policy(
        Rule(id="h", effect="hard_block", match=Match(kind=EffectKind.FILE_WRITE), rationale="blocked")
    )
    report = run_fixtures(policy, [Fixture(_eff(), DataLabel.PUBLIC, "hard_block")])
    assert report.all_passed


def test_run_fixtures_deterministic_100x() -> None:
    # The fixture runner is a pure decision function — identical input must yield
    # identical outcomes every time (§B-4a determinism proof).
    policy = _policy(Rule(id="d", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="no"))
    fixtures = [
        Fixture(_eff("c:/secret/a.txt"), DataLabel.PUBLIC, "deny"),
        Fixture(_eff("c:/public/a.txt"), DataLabel.PUBLIC, "deny"),
    ]
    outcomes = {tuple(r.actual for r in run_fixtures(policy, fixtures).results) for _ in range(100)}
    assert len(outcomes) == 1
