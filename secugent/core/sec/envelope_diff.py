# SPDX-License-Identifier: Apache-2.0
"""Envelope delta + canonical fingerprint (EM-08).

Plan Review must be *envelope approval*, not "does the plan look plausible". Two
deterministic helpers support that:

* ``diff`` / ``is_low_risk`` — surface only what the proposed envelope adds over
  the tenant baseline, so a human reviews the **new capability surface** (new
  sinks/actions, raised data-label ceiling, new irreversible budget) instead of
  re-reading the whole envelope. Pure quantitative cap bumps are low-risk.
* ``envelope_fingerprint`` — a stable sha256 over the canonical envelope, bound
  into the approval token (``ApprovalScope.envelope_hash``). Re-verified at
  execution so an approval for envelope A cannot authorize envelope B.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal

from secugent.core.sec.effects import SinkClass
from secugent.core.sec.envelope import AuthorizationEnvelope

__all__ = ["EnvelopeDelta", "diff", "is_low_risk", "envelope_fingerprint"]


@dataclass(frozen=True)
class EnvelopeDelta:
    """What ``proposed`` adds over ``baseline`` (increases only; never negative)."""

    label_raised: bool
    added_sinks: frozenset[SinkClass]
    added_actions: frozenset[str]
    irreversible_increase: int
    spend_increase: Decimal
    egress_increase: int
    validity_extended: bool  # proposed grants a later/unbounded expiry than baseline

    @property
    def is_empty(self) -> bool:
        """True when nothing escalated *and* no cap grew — an identical budget."""
        return (
            not self.label_raised
            and not self.added_sinks
            and not self.added_actions
            and self.irreversible_increase == 0
            and self.spend_increase == 0
            and self.egress_increase == 0
            and not self.validity_extended
        )


def _validity_extended(baseline: AuthorizationEnvelope, proposed: AuthorizationEnvelope) -> bool:
    """True when ``proposed`` lengthens the autonomous window: a bounded baseline
    becoming unbounded (``None`` = unlimited), or a strictly later deadline. A
    narrower (earlier/now-bounded) deadline is not an escalation."""
    if proposed.not_after is None:
        return baseline.not_after is not None  # bounded → unbounded = more authority
    if baseline.not_after is None:
        return False  # unbounded → bounded = narrower
    return proposed.not_after > baseline.not_after


def diff(baseline: AuthorizationEnvelope, proposed: AuthorizationEnvelope) -> EnvelopeDelta:
    """Compute what ``proposed`` adds over ``baseline``. Reductions are ignored
    (a narrower envelope is never *more* dangerous than the baseline)."""
    return EnvelopeDelta(
        label_raised=proposed.max_data_label > baseline.max_data_label,
        added_sinks=frozenset(proposed.allowed_sinks - baseline.allowed_sinks),
        added_actions=frozenset(proposed.allowed_actions - baseline.allowed_actions),
        irreversible_increase=max(0, proposed.max_irreversible - baseline.max_irreversible),
        spend_increase=max(Decimal("0"), proposed.spend_cap_usd - baseline.spend_cap_usd),
        egress_increase=max(0, proposed.egress_byte_cap - baseline.egress_byte_cap),
        validity_extended=_validity_extended(baseline, proposed),
    )


def is_low_risk(delta: EnvelopeDelta) -> bool:
    """Low-risk = adds NO new capability surface: no new sinks, no new actions,
    no raised data-label ceiling, no new irreversible budget, and no longer
    autonomous window. Quantitative cap bumps (spend/egress) alone are not
    capability escalations."""
    return (
        not delta.label_raised
        and not delta.added_sinks
        and not delta.added_actions
        and delta.irreversible_increase == 0
        and not delta.validity_extended
    )


def envelope_fingerprint(env: AuthorizationEnvelope) -> str:
    """Stable sha256 over the canonical envelope (frozenset fields are sorted, so
    the hash is order-independent). Bound into the approval token."""
    payload: dict[str, object] = {
        "max_data_label": int(env.max_data_label),
        "allowed_sinks": sorted(str(sink) for sink in env.allowed_sinks),
        "allowed_actions": sorted(env.allowed_actions),
        "max_irreversible": env.max_irreversible,
        # Exact canonical Decimal key: equal amounts of differing scale (1.0 vs
        # 1.00, 0 vs -0) share one fingerprint, while DISTINCT amounts never
        # collide. ``as_integer_ratio`` is exact (no precision rounding) — unlike
        # ``normalize()``, which would round at 28 digits and could fail-OPEN by
        # collapsing two different high-precision caps onto one hash.
        "spend_cap_usd": list(env.spend_cap_usd.as_integer_ratio()),
        "egress_byte_cap": env.egress_byte_cap,
        "not_after": env.not_after.isoformat() if env.not_after is not None else None,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
