# SPDX-License-Identifier: Apache-2.0
"""EM-03 — Hypothesis properties: evaluation is total + deny-priority holds."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy

_KINDS = st.sampled_from(list(EffectKind))
_SINKS = st.sampled_from(list(SinkClass))
_LABELS = st.sampled_from(list(DataLabel))


def _eff(kind: EffectKind, sink: SinkClass) -> Effect:
    targets = {
        EffectKind.FILE_READ: "c:/data/x",
        EffectKind.FILE_WRITE: "c:/data/x",
        EffectKind.NET_SEND: "https://a.com/x",
        EffectKind.NET_RECV: "https://a.com/x",
        EffectKind.CONNECTOR_ACTION: "chan-1",
        EffectKind.PROCESS_EXEC: "run-x",
    }
    return Effect(kind=kind, target=targets[kind], sink_class=sink)


def _policy(*rules: Rule) -> object:
    return compile_policy(PolicyDoc(version="1", tenant_id="_base", rules=list(rules)))


@given(kind=_KINDS, sink=_SINKS, label=_LABELS)
def test_evaluation_is_total(kind: EffectKind, sink: SinkClass, label: DataLabel) -> None:
    d = _policy().evaluate(_eff(kind, sink), label)  # empty policy
    assert d.outcome in {"allow", "deny", "hard_block"}
    assert d.outcome == "deny"  # deny-by-default


@given(kind=_KINDS, sink=_SINKS, label=_LABELS)
def test_allow_never_overrides_deny(kind: EffectKind, sink: SinkClass, label: DataLabel) -> None:
    policy = _policy(
        Rule(id="a", effect="allow", match=Match(), rationale="a"),
        Rule(id="d", effect="deny", match=Match(), rationale="d"),
    )
    assert policy.evaluate(_eff(kind, sink), label).outcome == "deny"


@given(kind=_KINDS, sink=_SINKS, label=_LABELS)
def test_hard_block_always_wins(kind: EffectKind, sink: SinkClass, label: DataLabel) -> None:
    policy = _policy(
        Rule(id="a", effect="allow", match=Match(), rationale="a"),
        Rule(id="d", effect="deny", match=Match(), rationale="d"),
        Rule(id="h", effect="hard_block", match=Match(), rationale="h"),
    )
    assert policy.evaluate(_eff(kind, sink), label).outcome == "hard_block"
