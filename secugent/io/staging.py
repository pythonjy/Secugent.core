# SPDX-License-Identifier: Apache-2.0
"""Two-phase staging commit for irreversible effects (EM-09, invariant I-C).

An irreversible effect cannot be undone, so it is never executed directly. The
broker *stages* it (holding/outbox) and it only reaches the transport on an
explicit commit that requires BOTH (a) envelope irreversible-budget remaining or
a synchronous HITL approval, AND (b) the hold window having elapsed. During the
hold window STEER can recall it (abort) — "catch it before it is sent". Every
state change is recorded on the durable hash chain.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from secugent.core.contracts import Event, EventSeverity
from secugent.core.sec.policy import Decision
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal
from secugent.io.broker.request import EgressRequest, EgressResult
from secugent.io.broker.transport import Transport

__all__ = [
    "StageState",
    "StagedEffect",
    "CommitGate",
    "CommitRefusedError",
    "StagedEffectStore",
    "StagingAuditSink",
]


class StageState(StrEnum):
    STAGED = "staged"
    COMMITTED = "committed"
    ABORTED = "aborted"


class StagingAuditSink(Protocol):
    def append_event(self, event: Event) -> Any: ...


class CommitRefusedError(Exception):
    """Raised when a staged effect may not be committed yet (gate or hold window)."""


@dataclass(frozen=True)
class CommitGate:
    """Authority to commit an irreversible effect (besides the hold window)."""

    hitl_approved: bool = False
    envelope_budget_remaining: bool = False

    def permits(self) -> bool:
        return self.hitl_approved or self.envelope_budget_remaining


@dataclass
class StagedEffect:
    id: str
    req: EgressRequest
    reversibility: ReversibilityClass
    hold_until: datetime
    compensating_action: str | None = None
    state: StageState = StageState.STAGED


class StagedEffectStore:
    """Holds staged irreversible effects until committed or aborted."""

    def __init__(self) -> None:
        self._by_id: dict[str, StagedEffect] = {}

    def stage(
        self,
        req: EgressRequest,
        *,
        reversibility: ReversibilityClass,
        hold_sec: int,
        now: datetime,
        compensating_action: str | None = None,
        audit: StagingAuditSink | None = None,
    ) -> StagedEffect:
        if hold_sec < 0:
            raise ValueError("hold_sec must be non-negative")
        staged = StagedEffect(
            id=f"staged_{uuid.uuid4().hex[:16]}",
            req=req,
            reversibility=reversibility,
            hold_until=now + timedelta(seconds=hold_sec),
            compensating_action=compensating_action,
        )
        self._by_id[staged.id] = staged
        if audit is not None:
            audit.append_event(self._event(staged, "egress.staged", "warn"))
        return staged

    def get(self, staged_id: str) -> StagedEffect | None:
        return self._by_id.get(staged_id)

    def list_staged(self, run_id: str) -> list[StagedEffect]:
        return [s for s in self._by_id.values() if s.req.run_id == run_id and s.state is StageState.STAGED]

    def commit(
        self,
        staged_id: str,
        *,
        principal: Principal,
        gate: CommitGate,
        now: datetime,
        transport: Transport,
        audit: StagingAuditSink | None = None,
    ) -> EgressResult:
        staged = self._require_staged(staged_id)
        self._require_same_tenant(principal, staged)
        if now < staged.hold_until:
            raise CommitRefusedError(f"hold window active until {staged.hold_until.isoformat()}")
        if not gate.permits():
            raise CommitRefusedError("commit gate denied (no envelope budget and no HITL approval)")
        payload = transport.execute(staged.req)
        staged.state = StageState.COMMITTED
        if audit is not None:
            audit.append_event(self._event(staged, "egress.committed", "info"))
        return EgressResult(
            ok=True,
            decision=Decision(outcome="allow", rule_id=None, rationale="staged_commit"),
            payload=payload,
            audit_event_id="",
        )

    def abort(
        self,
        staged_id: str,
        *,
        principal: Principal,
        reason: str,
        audit: StagingAuditSink | None = None,
    ) -> None:
        staged = self._require_staged(staged_id)
        self._require_same_tenant(principal, staged)
        staged.state = StageState.ABORTED
        if audit is not None:
            event = self._event(staged, "egress.aborted", "warn")
            event.payload["reason"] = reason
            event.payload["aborted_by"] = principal.user_id
            audit.append_event(event)

    def _require_staged(self, staged_id: str) -> StagedEffect:
        staged = self._by_id.get(staged_id)
        if staged is None:
            raise CommitRefusedError(f"no staged effect {staged_id!r}")
        if staged.state is not StageState.STAGED:
            raise CommitRefusedError(f"staged effect {staged_id!r} is already {staged.state}")
        return staged

    @staticmethod
    def _require_same_tenant(principal: Principal, staged: StagedEffect) -> None:
        # Fail-closed cross-tenant guard: a principal may only commit/abort a
        # staged effect belonging to its own tenant (confused-deputy defense).
        if principal.tenant_id != staged.req.principal.tenant_id:
            raise CommitRefusedError("cross-tenant staging access denied")

    def _event(self, staged: StagedEffect, event_type: str, severity: EventSeverity) -> Event:
        req = staged.req
        return Event(
            tenant_id=req.principal.tenant_id,
            actor="staging",
            type=event_type,
            run_id=req.run_id,
            payload={
                "staged_id": staged.id,
                "effect_fingerprint": req.effect.fingerprint(),
                "target": req.effect.target,
                "reversibility": str(staged.reversibility),
            },
            severity=severity,
        )
