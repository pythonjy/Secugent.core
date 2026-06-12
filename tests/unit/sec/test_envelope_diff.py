# SPDX-License-Identifier: Apache-2.0
"""EM-08 — envelope delta surfacing + canonical fingerprint (deterministic)."""

from __future__ import annotations

import string
from datetime import UTC, datetime
from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from secugent.core.sec.effects import SinkClass
from secugent.core.sec.envelope import AuthorizationEnvelope
from secugent.core.sec.envelope_diff import diff, envelope_fingerprint, is_low_risk
from secugent.core.sec.labels import DataLabel

_T2026 = datetime(2026, 1, 1, tzinfo=UTC)
_T2030 = datetime(2030, 1, 1, tzinfo=UTC)


def test_diff_detects_new_capability_surface() -> None:
    base = AuthorizationEnvelope(
        max_data_label=DataLabel.PUBLIC,
        allowed_sinks=frozenset({SinkClass.LOCAL_SANDBOX}),
        allowed_actions=frozenset({"file_read"}),
    )
    proposed = AuthorizationEnvelope(
        max_data_label=DataLabel.CONFIDENTIAL,
        allowed_sinks=frozenset({SinkClass.LOCAL_SANDBOX, SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"file_read", "net_send"}),
        max_irreversible=2,
        egress_byte_cap=1000,
    )
    delta = diff(base, proposed)
    assert delta.label_raised
    assert SinkClass.EXTERNAL in delta.added_sinks
    assert "net_send" in delta.added_actions
    assert delta.irreversible_increase == 2
    assert delta.egress_increase == 1000
    assert not delta.is_empty
    assert not is_low_risk(delta)


def test_diff_of_identical_envelopes_is_empty() -> None:
    env = AuthorizationEnvelope(
        allowed_sinks=frozenset({SinkClass.EXTERNAL}), allowed_actions=frozenset({"net_send"})
    )
    delta = diff(env, env)
    assert delta.is_empty
    assert is_low_risk(delta)


def test_quantitative_only_increase_is_low_risk_but_not_empty() -> None:
    base = AuthorizationEnvelope(
        allowed_sinks=frozenset({SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"net_send"}),
        egress_byte_cap=100,
        spend_cap_usd=Decimal("1"),
    )
    proposed = base.model_copy(update={"egress_byte_cap": 5000, "spend_cap_usd": Decimal("9")})
    delta = diff(base, proposed)
    assert delta.egress_increase == 4900
    assert delta.spend_increase == Decimal("8")
    assert not delta.label_raised and not delta.added_sinks and not delta.added_actions
    assert is_low_risk(delta)  # no NEW capability surface — just bigger caps
    assert not delta.is_empty  # but it is still a change


def test_lowered_caps_do_not_register_as_increase() -> None:
    base = AuthorizationEnvelope(egress_byte_cap=5000, spend_cap_usd=Decimal("9"), max_irreversible=5)
    proposed = base.model_copy(
        update={"egress_byte_cap": 10, "spend_cap_usd": Decimal("1"), "max_irreversible": 1}
    )
    delta = diff(base, proposed)
    assert delta.egress_increase == 0
    assert delta.spend_increase == Decimal("0")
    assert delta.irreversible_increase == 0
    assert is_low_risk(delta)


def test_extending_not_after_is_surfaced_as_risk() -> None:
    base = AuthorizationEnvelope(not_after=_T2026)
    proposed = base.model_copy(update={"not_after": _T2030})
    delta = diff(base, proposed)
    assert delta.validity_extended
    assert not delta.is_empty
    assert not is_low_risk(delta)  # a longer autonomous window IS new risk


def test_removing_not_after_is_surfaced_as_risk() -> None:
    base = AuthorizationEnvelope(not_after=_T2026)
    proposed = base.model_copy(update={"not_after": None})  # bounded → unlimited
    delta = diff(base, proposed)
    assert delta.validity_extended
    assert not is_low_risk(delta)


def test_narrowing_not_after_is_low_risk() -> None:
    base = AuthorizationEnvelope(not_after=None)  # unlimited baseline
    proposed = base.model_copy(update={"not_after": _T2026})  # now bounded = narrower
    delta = diff(base, proposed)
    assert not delta.validity_extended
    assert is_low_risk(delta)
    assert delta.is_empty  # tightening is no escalation at all


def test_fingerprint_decimal_scale_is_canonical() -> None:
    e1 = AuthorizationEnvelope(spend_cap_usd=Decimal("1.0"))
    e2 = AuthorizationEnvelope(spend_cap_usd=Decimal("1.00"))
    assert e1 == e2  # pydantic/Decimal treat these as equal envelopes
    assert envelope_fingerprint(e1) == envelope_fingerprint(e2)  # ...so must their hashes


def test_fingerprint_negative_zero_equals_zero() -> None:
    assert envelope_fingerprint(AuthorizationEnvelope(spend_cap_usd=Decimal("-0"))) == envelope_fingerprint(
        AuthorizationEnvelope(spend_cap_usd=Decimal("0"))
    )


def test_fingerprint_distinguishes_high_precision_spend_caps() -> None:
    # distinct caps must NEVER collide (a collision would fail-OPEN: an approval
    # bound to one cap would authorize the other). 31 sig digits — beyond the
    # 28-digit default context that a normalize()-based hash would round away.
    e1 = AuthorizationEnvelope(spend_cap_usd=Decimal("123456789012345678901234567890.5"))
    e2 = AuthorizationEnvelope(spend_cap_usd=Decimal("123456789012345678901234567899.5"))
    assert e1 != e2
    assert envelope_fingerprint(e1) != envelope_fingerprint(e2)


def test_fingerprint_deterministic_100x() -> None:
    env = AuthorizationEnvelope(
        allowed_sinks=frozenset({SinkClass.EXTERNAL, SinkClass.LOCAL_SANDBOX}),
        allowed_actions=frozenset({"a", "b", "c"}),
    )
    fingerprints = {envelope_fingerprint(env) for _ in range(100)}
    assert len(fingerprints) == 1


def test_fingerprint_is_order_independent() -> None:
    e1 = AuthorizationEnvelope(
        allowed_sinks=frozenset({SinkClass.EXTERNAL, SinkClass.INTERNAL}),
        allowed_actions=frozenset({"x", "y"}),
    )
    e2 = AuthorizationEnvelope(
        allowed_sinks=frozenset({SinkClass.INTERNAL, SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"y", "x"}),
    )
    assert envelope_fingerprint(e1) == envelope_fingerprint(e2)


def test_fingerprint_changes_with_content() -> None:
    e1 = AuthorizationEnvelope(allowed_actions=frozenset({"a"}))
    e2 = AuthorizationEnvelope(allowed_actions=frozenset({"a", "b"}))
    assert envelope_fingerprint(e1) != envelope_fingerprint(e2)


@given(
    label=st.sampled_from(list(DataLabel)),
    sinks=st.sets(st.sampled_from(list(SinkClass))),
    actions=st.sets(st.text(alphabet=string.ascii_lowercase + "._", min_size=1, max_size=10), max_size=5),
    irreversible=st.integers(min_value=0, max_value=10),
    egress=st.integers(min_value=0, max_value=10**9),
)
def test_property_self_diff_empty_and_fingerprint_stable(
    label: DataLabel, sinks: set[SinkClass], actions: set[str], irreversible: int, egress: int
) -> None:
    env = AuthorizationEnvelope(
        max_data_label=label,
        allowed_sinks=frozenset(sinks),
        allowed_actions=frozenset(actions),
        max_irreversible=irreversible,
        egress_byte_cap=egress,
    )
    delta = diff(env, env)
    assert delta.is_empty
    assert is_low_risk(delta)
    assert envelope_fingerprint(env) == envelope_fingerprint(env.model_copy())
