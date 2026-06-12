# SPDX-License-Identifier: Apache-2.0
"""Approval token issuance, verification, expiry, and nonce-reuse defenses.

Per SECURITY_CONTRACT §4, every approval token carries a strict
:class:`secugent.core.contracts.ApprovalScope`. The token is single-use
(consumed on first successful execution), bound to a fixed nonce that cannot
be reused, and re-verified at step execution time — never trusted on the
basis of "the human clicked approve once".
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from secugent.core.contracts import (
    ActionType,
    Approval,
    ApprovalError,
    ApprovalScope,
    Step,
)
from secugent.core.event_store import EventStore
from secugent.core.rule_of_two import (
    RuleOfTwoContext,
    classify_axes,
    requires_hitl,
)
from secugent.observability.metrics import APPROVAL_WAIT

__all__ = ["ApprovalService", "DEFAULT_TTL_SECONDS"]

DEFAULT_TTL_SECONDS = 15 * 60  # 15 minutes


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _new_nonce() -> str:
    """Generate a cryptographically random nonce (URL-safe, 32 bytes)."""
    return secrets.token_urlsafe(32)


def _observe_approval_wait(approval: Approval) -> None:
    """Record approval wait time in the APPROVAL_WAIT histogram (S8E).

    ``wait_seconds`` is the elapsed time from ``approval.created_at`` to now.
    We use ``risk_band="unknown"`` because :class:`ApprovalService` does not
    have direct access to the risk score at decision time; a future stage can
    pass the risk band explicitly when the risk analyzer is wired in.
    """
    wait_seconds = max(0.0, (_utcnow() - approval.created_at).total_seconds())
    tenant_id = str(approval.scope.tenant_id)
    APPROVAL_WAIT.labels(tenant_id=tenant_id, risk_band="unknown").observe(wait_seconds)


class ApprovalService:
    """Issues and verifies approval tokens against the durable event store."""

    def __init__(self, store: EventStore) -> None:
        self._store = store

    # ------------------------------------------------------------------ #
    # Issuance
    # ------------------------------------------------------------------ #

    def request_approval(
        self,
        *,
        actor: str,
        scope: ApprovalScope,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> Approval:
        """Create a pending approval record. Returns the durable record."""
        if ttl_seconds <= 0:
            raise ApprovalError("ttl_seconds must be positive")
        expires_at = _utcnow() + timedelta(seconds=ttl_seconds)
        # Scope's own expires_at must not outlive the approval ttl.
        if scope.expires_at > expires_at:
            scope = scope.model_copy(update={"expires_at": expires_at})
        approval = Approval(
            actor=actor,
            scope=scope,
            expires_at=expires_at,
            nonce=_new_nonce(),
            status="pending",
        )
        self._store.save_approval(approval)
        return approval

    def grant(self, approval_id: str, *, reason: str | None = None) -> Approval:
        approval = self._must_load(approval_id)
        if approval.status != "pending":
            raise ApprovalError(f"approval {approval_id} is not pending (status={approval.status})")
        if approval.expires_at <= _utcnow():
            self._store.update_approval_status(approval_id, "expired", reason="ttl-exceeded")
            raise ApprovalError(f"approval {approval_id} already expired")
        # S8E: record how long this approval waited before being granted.
        _observe_approval_wait(approval)
        self._store.update_approval_status(approval_id, "approved", reason=reason)
        return self._must_load(approval_id)

    def reject(self, approval_id: str, *, reason: str | None = None) -> Approval:
        approval = self._must_load(approval_id)
        if approval.status not in ("pending",):
            raise ApprovalError(f"cannot reject approval {approval_id} (status={approval.status})")
        # S8E: record how long this approval waited before being rejected.
        _observe_approval_wait(approval)
        self._store.update_approval_status(approval_id, "rejected", reason=reason)
        return self._must_load(approval_id)

    def revoke(self, approval_id: str, *, reason: str | None = None) -> Approval:
        approval = self._must_load(approval_id)
        if approval.status in ("consumed", "expired", "revoked"):
            raise ApprovalError(f"cannot revoke approval {approval_id} (status={approval.status})")
        self._store.update_approval_status(approval_id, "revoked", reason=reason)
        return self._must_load(approval_id)

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #

    def verify_for_step(
        self,
        approval_id: str,
        step: Step,
        *,
        observed_risk: int | None = None,
        observed_nonce: str | None = None,
        observed_envelope_hash: str | None = None,
    ) -> Approval:
        """Re-verify scope/expiry/nonce *immediately before* executing a step.

        Raises :class:`ApprovalError` on any mismatch — caller MUST treat as
        fail-closed. ``observed_envelope_hash`` is the fingerprint of the
        envelope actually about to be enforced (EM-08); if the scope is bound to
        an envelope it must match exactly.
        """
        approval = self._must_load(approval_id)

        if approval.status == "consumed":
            raise ApprovalError("approval already consumed (nonce reuse attempt)")
        if approval.status == "rejected":
            raise ApprovalError("approval was rejected")
        if approval.status in ("expired", "revoked"):
            raise ApprovalError(f"approval is {approval.status}")
        if approval.status == "pending":
            raise ApprovalError("approval not granted yet")
        if approval.status != "approved":
            raise ApprovalError(f"approval status invalid: {approval.status}")

        if approval.expires_at <= _utcnow():
            self._store.update_approval_status(approval_id, "expired", reason="ttl-exceeded")
            raise ApprovalError("approval expired")

        if observed_nonce is not None and observed_nonce != approval.nonce:
            raise ApprovalError("nonce mismatch")

        self._enforce_scope(approval.scope, step)

        # EM-08: an envelope-bound approval must execute under the SAME envelope.
        if approval.scope.envelope_hash is not None:
            if observed_envelope_hash is None:
                raise ApprovalError("envelope-bound approval requires observed_envelope_hash (fail-closed)")
            if observed_envelope_hash != approval.scope.envelope_hash:
                raise ApprovalError(
                    "envelope_hash mismatch: execution envelope differs from the approved envelope"
                )

        if observed_risk is not None and observed_risk > approval.scope.max_risk:
            raise ApprovalError(
                f"observed risk {observed_risk} exceeds scope.max_risk {approval.scope.max_risk}"
            )

        return approval

    def consume(
        self,
        approval_id: str,
        step: Step,
        *,
        observed_risk: int | None = None,
        observed_nonce: str | None = None,
        observed_envelope_hash: str | None = None,
    ) -> Approval:
        """Verify and immediately mark consumed. Single-use guarantee."""
        approval = self.verify_for_step(
            approval_id,
            step,
            observed_risk=observed_risk,
            observed_nonce=observed_nonce,
            observed_envelope_hash=observed_envelope_hash,
        )
        self._store.update_approval_status(approval.id, "consumed", reason="step-executed")
        return self._must_load(approval.id)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _enforce_scope(scope: ApprovalScope, step: Step) -> None:
        # PHASE 9: cross-tenant approval use is fail-closed.
        if scope.tenant_id != step.tenant_id:
            raise ApprovalError(
                f"tenant_mismatch: scope.tenant_id={scope.tenant_id} != step.tenant_id={step.tenant_id}"
            )
        if scope.run_id != step.run_id:
            raise ApprovalError(f"scope.run_id={scope.run_id} != step.run_id={step.run_id}")
        if scope.plan_id is not None and step.plan_id is not None and scope.plan_id != step.plan_id:
            raise ApprovalError(f"scope.plan_id={scope.plan_id} != step.plan_id={step.plan_id}")
        if scope.step_ids and step.id not in scope.step_ids:
            raise ApprovalError(f"step {step.id} not in approved step_ids={scope.step_ids}")
        # A scope is "dedicated" to this step iff its ``step_ids`` is exactly the
        # single element ``[step.id]``. A plan-wide approval (no step_ids) OR a
        # multi-step scope that merely *contains* this step id is NOT dedicated.
        step_dedicated = scope.step_ids == [step.id]

        # G-C2: generalize the single-axis carve-out to the full Rule of Two
        # (§A-2.1). A step that trips all three axes (untrusted input + sensitive
        # access + external comm) can NEVER ride a plan-level pre-approval — it is
        # authorized ONLY by an approval dedicated to this exact step (a fresh,
        # step-scoped HITL). ``connector_action`` is a strict special case of this
        # (it is always axes ②+③ and is additionally forbidden in
        # ``allowed_action_types`` by ``ApprovalScope``). Closing the invariant
        # here in the core means a non-dedicated Rule-of-Two scope can never be
        # smuggled through, independent of the caller graph (SG-20260604-04).
        # Axis ① (untrusted_input) is auto-derived by ``RuleOfTwoContext.from_step``
        # from a ``provenance`` block in ``Step.context``, so a provenance-tainted
        # 3-axis step is forced through a step-dedicated HITL here too — no logic
        # change is needed in this gate (it already routes the decision through the
        # single core classifier). The deterministic *producer* that injects that
        # provenance (``HeadAgent.mark_untrusted_source``) is not yet wired into live
        # planning (BDP_02 항목 5 deferral) — this gate is correct either way, since a
        # provenance block from any source (LLM plan or future producer) routes here.
        rule_of_two_hitl = requires_hitl(classify_axes(step, RuleOfTwoContext.from_step(step)))
        if rule_of_two_hitl and not step_dedicated:
            raise ApprovalError(
                "Rule of Two violation (3 axes) requires a step-dedicated HITL "
                f"approval; scope step_ids={scope.step_ids} is not dedicated to "
                f"step {step.id}"
            )

        if not _action_allowed(step.action_type, scope.allowed_action_types, step_dedicated=step_dedicated):
            raise ApprovalError(f"action_type {step.action_type} not in allowed={scope.allowed_action_types}")

    def _must_load(self, approval_id: str) -> Approval:
        approval = self._store.get_approval(approval_id)
        if approval is None:
            raise ApprovalError(f"approval {approval_id} not found")
        return approval


def _action_allowed(action_type: ActionType, allowed: list[ActionType], *, step_dedicated: bool) -> bool:
    # `unknown` is never pre-authorized.
    if action_type == "unknown":
        return False
    if action_type == "connector_action":
        # Forbidden in ``allowed_action_types`` by construction, so it cannot be
        # bundled into a plan-level pre-approval. It is authorized ONLY by an
        # approval *dedicated to this exact step* — a scope whose ``step_ids`` is
        # exactly ``[step.id]`` (``step_dedicated``). A multi-step scope that
        # merely contains this step id is NOT dedicated and is rejected.
        return step_dedicated
    if not allowed:
        # Empty allowed list means "nothing pre-authorized" — fail-closed.
        return False
    return action_type in allowed
