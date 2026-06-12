# SPDX-License-Identifier: Apache-2.0
"""STEER pre-commit intervention (EM-09).

Redefines STEER's "rollback" honestly, per the EM-01 reversibility class:
- **irreversible** → ``intervene`` *aborts* the staged effect (recall before send);
- **compensatable** → ``compensate`` issues the registered compensating action;
- **reversible** → ``rollback_reversible`` restores a file snapshot.

Every intervention is recorded on the durable hash chain (append-only).
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect
from secugent.core.tenancy import Principal
from secugent.io.staging import StagedEffectStore
from secugent.steer.snapshots import FileSnapshotStore

__all__ = ["classify_intervention", "intervene", "compensate", "rollback_reversible"]

InterventionKind = Literal["abort", "resume"]

_ABORT_KEYWORDS = ("abort", "stop", "cancel", "recall", "halt", "회수", "중단", "취소", "정지")


class PrecommitAuditSink(Protocol):
    def append_event(self, event: Event) -> Any: ...


def classify_intervention(instruction: str) -> InterventionKind:
    """Classify a STEER directive: abort (recall staged) vs resume."""
    lowered = instruction.lower()
    if any(keyword in lowered for keyword in _ABORT_KEYWORDS):
        return "abort"
    return "resume"


def intervene(
    run_id: str,
    instruction: str,
    *,
    principal: Principal,
    store: StagedEffectStore,
    audit: PrecommitAuditSink,
) -> list[str]:
    """Apply a STEER directive to a run's staged (irreversible) effects.

    On 'abort', every staged effect for the run is recalled (transport never
    runs). Returns the aborted staged ids. All steps are audited.
    """
    kind = classify_intervention(instruction)
    audit.append_event(
        Event(
            tenant_id=principal.tenant_id,
            actor=f"steer:{principal.user_id}",
            type="precommit.received",
            run_id=run_id,
            payload={"instruction": instruction[:200], "classified": kind},
            severity="warn",
        )
    )
    if kind != "abort":
        return []
    aborted: list[str] = []
    for staged in store.list_staged(run_id):
        if staged.req.principal.tenant_id != principal.tenant_id:
            continue  # never recall another tenant's staged effect
        store.abort(staged.id, principal=principal, reason=f"STEER: {instruction[:120]}", audit=audit)
        aborted.append(staged.id)
    audit.append_event(
        Event(
            tenant_id=principal.tenant_id,
            actor=f"steer:{principal.user_id}",
            type="precommit.aborted",
            run_id=run_id,
            payload={"count": len(aborted), "staged_ids": aborted},
            severity="warn",
        )
    )
    return aborted


def compensate(
    effect: Effect,
    compensating_action: str,
    *,
    principal: Principal,
    run_id: str,
    audit: PrecommitAuditSink,
) -> str:
    """Issue the compensating action for an already-executed compensatable effect."""
    audit.append_event(
        Event(
            tenant_id=principal.tenant_id,
            actor=f"steer:{principal.user_id}",
            type="precommit.compensated",
            run_id=run_id,
            payload={
                "effect_fingerprint": effect.fingerprint(),
                "compensating_action": compensating_action,
            },
            severity="warn",
        )
    )
    return compensating_action


def rollback_reversible(
    effect: Effect,
    *,
    snapshots: FileSnapshotStore,
    principal: Principal,
    run_id: str,
    audit: PrecommitAuditSink,
) -> None:
    """Roll back a reversible file effect to its captured snapshot."""
    snapshots.rollback(effect.target)
    audit.append_event(
        Event(
            tenant_id=principal.tenant_id,
            actor=f"steer:{principal.user_id}",
            type="precommit.rolled_back",
            run_id=run_id,
            payload={"effect_fingerprint": effect.fingerprint(), "target": effect.target},
            severity="warn",
        )
    )
