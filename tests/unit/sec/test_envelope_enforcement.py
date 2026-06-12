# SPDX-License-Identifier: Apache-2.0
"""EM-07 — AuthorizationEnvelope.check enforcement + contextvar binding."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.envelope import (
    AuthorizationEnvelope,
    EnvelopeUsage,
    bind_envelope,
    check,
    current_envelope,
    current_envelope_usage,
)
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass

_REV = ReversibilityClass.REVERSIBLE
_IRR = ReversibilityClass.IRREVERSIBLE


def _sandbox_write() -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target="c:/sandbox/out.txt", sink_class=SinkClass.LOCAL_SANDBOX)


def _connector(action: str = "smtp.send", byte_estimate: int = 0) -> Effect:
    return Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target="channel-1",
        sink_class=SinkClass.EXTERNAL,
        action=action,
        byte_estimate=byte_estimate,
    )


def _full_env(**over: object) -> AuthorizationEnvelope:
    base: dict[str, object] = dict(
        max_data_label=DataLabel.CONFIDENTIAL,
        allowed_sinks=frozenset({SinkClass.LOCAL_SANDBOX, SinkClass.EXTERNAL}),
        allowed_actions=frozenset({"file_write", "smtp.send", "net_recv"}),
    )
    base.update(over)
    return AuthorizationEnvelope(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# deny-by-default + happy path
# --------------------------------------------------------------------------- #


def test_empty_envelope_suspends_everything() -> None:
    d = check(_sandbox_write(), DataLabel.PUBLIC, AuthorizationEnvelope(), EnvelopeUsage(), _REV)
    assert d.outcome == "suspend"


def test_within_envelope_allows() -> None:
    d = check(_sandbox_write(), DataLabel.INTERNAL_USE, _full_env(), EnvelopeUsage(), _REV)
    assert d.outcome == "allow"
    assert d.reason == "within_envelope"


def test_label_above_ceiling_suspends() -> None:
    d = check(
        _sandbox_write(),
        DataLabel.SECRET,
        _full_env(max_data_label=DataLabel.INTERNAL_USE),
        EnvelopeUsage(),
        _REV,
    )
    assert d.outcome == "suspend"
    assert d.reason == "label_exceeds_envelope"


def test_sink_not_allowed_suspends() -> None:
    env = _full_env(allowed_sinks=frozenset({SinkClass.LOCAL_SANDBOX}))
    d = check(_connector(), DataLabel.PUBLIC, env, EnvelopeUsage(), _REV)
    assert d.outcome == "suspend"
    assert d.reason == "sink_not_in_envelope"


def test_action_not_allowed_suspends() -> None:
    env = _full_env(allowed_actions=frozenset({"file_write"}))
    d = check(_connector(action="smtp.send"), DataLabel.PUBLIC, env, EnvelopeUsage(), _REV)
    assert d.outcome == "suspend"
    assert d.reason == "action_not_in_envelope"


# --------------------------------------------------------------------------- #
# irreversible budget (default 0)
# --------------------------------------------------------------------------- #


def test_irreversible_default_zero_suspends() -> None:
    d = check(_connector(), DataLabel.PUBLIC, _full_env(), EnvelopeUsage(), _IRR)
    assert d.outcome == "suspend"
    assert d.reason == "irreversible_budget_exhausted"


def test_irreversible_budget_one_allows_then_exhausts() -> None:
    env = _full_env(max_irreversible=1)
    eff = _connector()
    usage = EnvelopeUsage()
    assert check(eff, DataLabel.PUBLIC, env, usage, _IRR).outcome == "allow"
    usage.record(eff, _IRR)
    assert usage.irreversible_used == 1
    second = check(eff, DataLabel.PUBLIC, env, usage, _IRR)
    assert second.outcome == "suspend"  # budget exhausted


# --------------------------------------------------------------------------- #
# spend / egress / time
# --------------------------------------------------------------------------- #


def test_spend_cap_exceeded_suspends() -> None:
    env = _full_env(spend_cap_usd=Decimal("1.00"))
    usage = EnvelopeUsage(spent_usd=Decimal("2.50"))
    d = check(_sandbox_write(), DataLabel.PUBLIC, env, usage, _REV)
    assert d.outcome == "suspend"
    assert d.reason == "spend_cap_exceeded"


def test_egress_cap_exceeded_suspends() -> None:
    env = _full_env(egress_byte_cap=100)
    d = check(_connector(byte_estimate=200), DataLabel.PUBLIC, env, EnvelopeUsage(), _REV)
    assert d.outcome == "suspend"
    assert d.reason == "egress_cap_exceeded"


def test_expired_envelope_suspends() -> None:
    env = _full_env(not_after=datetime(2020, 1, 1, tzinfo=UTC))
    now = datetime(2026, 6, 2, tzinfo=UTC)
    d = check(_sandbox_write(), DataLabel.PUBLIC, env, EnvelopeUsage(), _REV, now=now)
    assert d.outcome == "suspend"
    assert d.reason == "envelope_expired"


def test_no_now_skips_time_gate() -> None:
    env = _full_env(not_after=datetime(2020, 1, 1, tzinfo=UTC))
    d = check(_sandbox_write(), DataLabel.PUBLIC, env, EnvelopeUsage(), _REV)  # now omitted
    assert d.outcome == "allow"


# --------------------------------------------------------------------------- #
# determinism + contextvar binding
# --------------------------------------------------------------------------- #


def test_check_deterministic_100x() -> None:
    env = _full_env()
    outs = {
        check(_sandbox_write(), DataLabel.INTERNAL_USE, env, EnvelopeUsage(), _REV).model_dump_json()
        for _ in range(100)
    }
    assert len(outs) == 1


def test_bind_envelope_contextvar() -> None:
    env = _full_env()
    usage = EnvelopeUsage()
    with bind_envelope(env, usage):
        assert current_envelope() is env
        assert current_envelope_usage() is usage
    with pytest.raises(LookupError):
        current_envelope()
