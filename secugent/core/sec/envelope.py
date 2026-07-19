# SPDX-License-Identifier: Apache-2.0
"""Authorization envelope — a per-task, machine-enforced effect budget (EM-07).

Plan Review approves an *envelope* (data-label ceiling, allowed sinks/actions,
irreversible count, spend/egress/time caps); the agent then runs autonomously
*inside* it, and the boundary is enforced deterministically — not by per-step
human approval. An empty envelope authorizes nothing (deny-by-default); the
irreversible budget defaults to 0 (irreversible effects need explicit approval).

``check`` is pure (no mutation): the caller records usage after a successful,
gated execution. ``EnvelopeUsage`` only ever increases (monotonic), so cumulative
usage can never exceed the caps regardless of effect ordering.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from secugent.core.sec.effects import Effect, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass

__all__ = [
    "AuthorizationEnvelope",
    "EnvelopeUsage",
    "EnvelopeDecision",
    "check",
    "current_envelope",
    "current_envelope_usage",
    "bind_envelope",
]


class AuthorizationEnvelope(BaseModel):
    """Immutable pre-approved effect budget. Defaults = deny-everything."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_data_label: DataLabel = DataLabel.PUBLIC  # ceiling: only this label or below
    allowed_sinks: frozenset[SinkClass] = Field(default_factory=frozenset)
    allowed_actions: frozenset[str] = Field(default_factory=frozenset)  # empty ⇒ nothing allowed
    max_irreversible: int = 0  # default 0 — irreversible effects need explicit approval
    spend_cap_usd: Decimal = Decimal("0")
    egress_byte_cap: int = 0
    not_after: datetime | None = None  # time-boxed


class EnvelopeUsage(BaseModel):
    """Monotonic running usage against an envelope (only ever increases)."""

    model_config = ConfigDict(extra="forbid")

    irreversible_used: int = 0
    spent_usd: Decimal = Decimal("0")
    egress_bytes: int = 0

    def record(self, effect: Effect, reversibility: ReversibilityClass) -> None:
        """Accrue ``effect`` into usage (monotonic; spend is accrued externally)."""
        if reversibility is ReversibilityClass.IRREVERSIBLE:
            self.irreversible_used += 1
        self.egress_bytes += effect.byte_estimate


class EnvelopeDecision(BaseModel):
    """Deterministic verdict: allow, or suspend → HITL (with an auditable reason)."""

    model_config = ConfigDict(extra="forbid")

    outcome: Literal["allow", "suspend"]
    reason: str


def _action_of(effect: Effect) -> str:
    """The action key checked against ``allowed_actions``: a connector action
    (e.g. 'slack.post_message') or the effect kind (e.g. 'file_write')."""
    return effect.action or str(effect.kind)


def check(
    effect: Effect,
    label: DataLabel,
    env: AuthorizationEnvelope,
    usage: EnvelopeUsage,
    reversibility: ReversibilityClass,
    *,
    now: datetime | None = None,
) -> EnvelopeDecision:
    """Decide whether ``effect`` is inside ``env`` given current ``usage``.

    Pure: the caller updates ``usage`` after a successful execution. ``now`` (if
    given) is checked against ``env.not_after``; omit it to skip the time gate.
    """
    if label > env.max_data_label:
        return EnvelopeDecision(outcome="suspend", reason="label_exceeds_envelope")
    if effect.sink_class not in env.allowed_sinks:
        return EnvelopeDecision(outcome="suspend", reason="sink_not_in_envelope")
    if _action_of(effect) not in env.allowed_actions:
        return EnvelopeDecision(outcome="suspend", reason="action_not_in_envelope")
    if reversibility is ReversibilityClass.IRREVERSIBLE and usage.irreversible_used >= env.max_irreversible:
        return EnvelopeDecision(outcome="suspend", reason="irreversible_budget_exhausted")
    if usage.spent_usd > env.spend_cap_usd:
        return EnvelopeDecision(outcome="suspend", reason="spend_cap_exceeded")
    if usage.egress_bytes + effect.byte_estimate > env.egress_byte_cap:
        return EnvelopeDecision(outcome="suspend", reason="egress_cap_exceeded")
    if now is not None and env.not_after is not None and now > env.not_after:
        return EnvelopeDecision(outcome="suspend", reason="envelope_expired")
    return EnvelopeDecision(outcome="allow", reason="within_envelope")


# --------------------------------------------------------------------------- #
# Run-scoped binding (mirrors tenancy.set_current_tenant)
# --------------------------------------------------------------------------- #

_CURRENT_ENVELOPE: ContextVar[AuthorizationEnvelope] = ContextVar("secugent.current_envelope")
_CURRENT_USAGE: ContextVar[EnvelopeUsage] = ContextVar("secugent.current_envelope_usage")


def current_envelope() -> AuthorizationEnvelope:
    """The envelope bound to the current run context (raises if unbound)."""
    return _CURRENT_ENVELOPE.get()


def current_envelope_usage() -> EnvelopeUsage:
    """The usage bound to the current run context (raises if unbound)."""
    return _CURRENT_USAGE.get()


@contextmanager
def bind_envelope(
    envelope: AuthorizationEnvelope, usage: EnvelopeUsage
) -> Iterator[tuple[AuthorizationEnvelope, EnvelopeUsage]]:
    """Bind ``envelope`` + ``usage`` to the current context for the block."""
    env_token: Token[AuthorizationEnvelope] = _CURRENT_ENVELOPE.set(envelope)
    usage_token: Token[EnvelopeUsage] = _CURRENT_USAGE.set(usage)
    try:
        yield envelope, usage
    finally:
        _CURRENT_USAGE.reset(usage_token)
        _CURRENT_ENVELOPE.reset(env_token)
