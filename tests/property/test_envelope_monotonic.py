# SPDX-License-Identifier: Apache-2.0
"""EM-07 — Hypothesis: cumulative usage can never exceed envelope caps.

No matter the order or count of effects flowed through ``check`` (recording usage
only on allow), the running totals stay within the envelope's caps.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.envelope import AuthorizationEnvelope, EnvelopeUsage, check
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass

_REVS = st.sampled_from(list(ReversibilityClass))


def _connector() -> Effect:
    return Effect(kind=EffectKind.CONNECTOR_ACTION, target="c", sink_class=SinkClass.EXTERNAL, action="x")


@given(sequence=st.lists(_REVS, max_size=15))
def test_irreversible_use_never_exceeds_budget(sequence: list[ReversibilityClass]) -> None:
    env = AuthorizationEnvelope(
        max_data_label=DataLabel.SECRET,
        allowed_sinks=frozenset({SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"x"}),
        max_irreversible=2,
        egress_byte_cap=10**9,
    )
    usage = EnvelopeUsage()
    eff = _connector()
    for rev in sequence:
        if check(eff, DataLabel.PUBLIC, env, usage, rev).outcome == "allow":
            usage.record(eff, rev)
    assert usage.irreversible_used <= env.max_irreversible


@given(estimates=st.lists(st.integers(min_value=0, max_value=60), max_size=20))
def test_egress_bytes_never_exceed_cap(estimates: list[int]) -> None:
    cap = 100
    env = AuthorizationEnvelope(
        max_data_label=DataLabel.SECRET,
        allowed_sinks=frozenset({SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"net_recv"}),
        egress_byte_cap=cap,
    )
    usage = EnvelopeUsage()
    for est in estimates:
        eff = Effect(
            kind=EffectKind.NET_RECV,
            target="https://x.example/a",
            sink_class=SinkClass.EXTERNAL,
            byte_estimate=est,
        )
        if check(eff, DataLabel.PUBLIC, env, usage, ReversibilityClass.REVERSIBLE).outcome == "allow":
            usage.record(eff, ReversibilityClass.REVERSIBLE)
    assert usage.egress_bytes <= cap
