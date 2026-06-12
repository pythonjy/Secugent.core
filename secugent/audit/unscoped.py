# SPDX-License-Identifier: Apache-2.0
"""Unscoped-effect telemetry (EM-04).

"What rule did I forget?" is invisible to review. So every effect that matched
**no explicit rule** (fell to ``default_deny``, i.e. ``Decision.rule_id is None``)
is recorded as a ``policy.unscoped`` event on the durable hash chain and can be
clustered into a review queue. This turns unknown-unknowns into a reviewable
stream. Recording is audit-only — it never changes enforcement (the effect is
still denied by default).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect
from secugent.core.tenancy import TenantId

__all__ = ["UnscopedRecorder", "UnscopedCluster", "cluster_unscoped"]


class _AuditSink(Protocol):
    def append_event(self, event: Event) -> Any: ...


@dataclass(frozen=True)
class UnscopedCluster:
    fingerprint: str
    count: int
    kind: str
    sample_target: str


class UnscopedRecorder:
    """Records ``policy.unscoped`` events for effects no rule covered."""

    def __init__(self, audit_store: _AuditSink) -> None:
        self._audit = audit_store

    def record(self, *, tenant_id: TenantId, effect: Effect, run_id: str | None = None) -> Event:
        event = Event(
            tenant_id=tenant_id,
            actor="policy.evaluator",
            type="policy.unscoped",
            run_id=run_id,
            payload={
                "effect_fingerprint": effect.fingerprint(),
                "kind": str(effect.kind),
                "sink": str(effect.sink_class),
                "target": effect.target,
            },
            severity="warn",
        )
        self._audit.append_event(event)
        return event


def cluster_unscoped(events: list[Event]) -> list[UnscopedCluster]:
    """Cluster ``policy.unscoped`` events by effect fingerprint (review queue)."""
    by_fingerprint: dict[str, list[Event]] = {}
    for event in events:
        if event.type != "policy.unscoped":
            continue
        fingerprint = str(event.payload.get("effect_fingerprint", ""))
        by_fingerprint.setdefault(fingerprint, []).append(event)
    clusters = [
        UnscopedCluster(
            fingerprint=fingerprint,
            count=len(group),
            kind=str(group[0].payload.get("kind", "")),
            sample_target=str(group[0].payload.get("target", "")),
        )
        for fingerprint, group in by_fingerprint.items()
    ]
    return sorted(clusters, key=lambda c: (-c.count, c.fingerprint))
