# SPDX-License-Identifier: Apache-2.0
"""Derive a *minimal* authorization envelope from a HEAD plan (EM-07).

The builder only **proposes** the least-privilege envelope the plan's steps would
need (which sinks/actions). The data-label ceiling, irreversible count, and caps
are conservative defaults a human raises/confirms at Plan Review (EM-08). The
builder never *confirms* an envelope — that is a human decision.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from secugent.core.contracts import Plan
from secugent.core.sec.effects import EffectKind, SinkClass
from secugent.core.sec.envelope import AuthorizationEnvelope
from secugent.core.sec.labels import DataLabel

__all__ = ["build_minimal_envelope"]

# action_type → (effect kind, sink). Unmapped actions are NOT pre-authorized.
_MAP: dict[str, tuple[EffectKind, SinkClass]] = {
    "file_read": (EffectKind.FILE_READ, SinkClass.LOCAL_SANDBOX),
    "file_write": (EffectKind.FILE_WRITE, SinkClass.LOCAL_SANDBOX),
    "http_get": (EffectKind.NET_RECV, SinkClass.EXTERNAL),
    "compute": (EffectKind.PROCESS_EXEC, SinkClass.LOCAL_SANDBOX),
    "desktop": (EffectKind.PROCESS_EXEC, SinkClass.LOCAL_SANDBOX),
}


def build_minimal_envelope(
    plan: Plan,
    *,
    max_data_label: DataLabel = DataLabel.INTERNAL_USE,
    max_irreversible: int = 0,
    spend_cap_usd: Decimal = Decimal("0"),
    egress_byte_cap: int = 0,
    not_after: datetime | None = None,
) -> AuthorizationEnvelope:
    """Propose the minimal envelope covering ``plan``'s steps (deny-by-default).

    An empty plan (or one with only unmapped actions) yields an envelope that
    authorizes nothing.
    """
    sinks: set[SinkClass] = set()
    actions: set[str] = set()
    for step in plan.steps:
        mapped = _MAP.get(step.action_type)
        if mapped is None:
            continue  # unknown/unmapped action is never pre-authorized
        kind, sink = mapped
        sinks.add(sink)
        actions.add(str(kind))
    return AuthorizationEnvelope(
        max_data_label=max_data_label,
        allowed_sinks=frozenset(sinks),
        allowed_actions=frozenset(actions),
        max_irreversible=max_irreversible,
        spend_cap_usd=spend_cap_usd,
        egress_byte_cap=egress_byte_cap,
        not_after=not_after,
    )
