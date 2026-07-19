# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.approval.ApprovalService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secugent.core.approval import ApprovalService
from secugent.core.contracts import (
    Approval,
    ApprovalError,
    ApprovalScope,
    Step,
)


def _future(seconds: int = 600) -> datetime:
    return datetime.now(tz=UTC) + timedelta(seconds=seconds)


def _past(seconds: int = 60) -> datetime:
    return datetime.now(tz=UTC) - timedelta(seconds=seconds)


@pytest.fixture
def base_step() -> Step:
    return Step(
        tenant_id="legacy-default",
        run_id="run_test",
        plan_id="plan_test",
        actor="sub:r",
        action_type="file_read",
        target="D:/x",
    )


@pytest.fixture
def base_scope(base_step: Step) -> ApprovalScope:
    return ApprovalScope(
        tenant_id="legacy-default",
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        step_ids=[base_step.id],
        allowed_action_types=["file_read"],
        max_risk=70,
        expires_at=_future(),
    )


# -- happy path -----------------------------------------------------------


def test_grant_and_consume(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    assert pending.status == "pending"
    granted = approval_service.grant(pending.id, reason="ok")
    assert granted.status == "approved"

    consumed = approval_service.consume(
        granted.id,
        base_step,
        observed_risk=40,
        observed_nonce=granted.nonce,
    )
    assert consumed.status == "consumed"


def test_consume_twice_blocked(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    approval_service.consume(granted.id, base_step, observed_risk=10, observed_nonce=granted.nonce)
    with pytest.raises(ApprovalError, match="consumed"):
        approval_service.consume(granted.id, base_step, observed_risk=10, observed_nonce=granted.nonce)


# -- scope mismatch -------------------------------------------------------


def test_scope_run_mismatch(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    other_step = base_step.model_copy(update={"run_id": "run_other"})
    with pytest.raises(ApprovalError, match="run_id"):
        approval_service.verify_for_step(granted.id, other_step, observed_nonce=granted.nonce)


def test_scope_plan_mismatch(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    other = base_step.model_copy(update={"plan_id": "plan_other"})
    with pytest.raises(ApprovalError, match="plan_id"):
        approval_service.verify_for_step(granted.id, other, observed_nonce=granted.nonce)


def test_scope_step_not_listed(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    new_step = Step(
        tenant_id="legacy-default",
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        actor="sub:r",
        action_type="file_read",
    )
    with pytest.raises(ApprovalError, match="step .* not in approved"):
        approval_service.verify_for_step(granted.id, new_step, observed_nonce=granted.nonce)


def test_scope_action_type_mismatch(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    other = base_step.model_copy(update={"action_type": "http_get"})
    with pytest.raises(ApprovalError, match="action_type"):
        approval_service.verify_for_step(granted.id, other, observed_nonce=granted.nonce)


def test_scope_max_risk(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="exceeds scope.max_risk"):
        approval_service.verify_for_step(
            granted.id, base_step, observed_risk=99, observed_nonce=granted.nonce
        )


# -- expiry & nonce -------------------------------------------------------


def test_expired_token_grant_blocked(
    approval_service: ApprovalService,
    base_step: Step,
) -> None:
    expired_scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        step_ids=[base_step.id],
        allowed_action_types=["file_read"],
        max_risk=70,
        expires_at=_past(),
    )
    expired = Approval(
        actor="human:a",
        scope=expired_scope,
        expires_at=_past(),
        nonce="test-expired-nonce",
        status="pending",
    )
    approval_service._store.save_approval(expired)  # type: ignore[attr-defined]
    with pytest.raises(ApprovalError, match="expired"):
        approval_service.grant(expired.id)


def test_expired_token_verify_blocked(
    approval_service: ApprovalService,
    base_step: Step,
) -> None:
    expired_scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        step_ids=[base_step.id],
        allowed_action_types=["file_read"],
        max_risk=70,
        expires_at=_past(),
    )
    approved_then_expired = Approval(
        actor="human:a",
        scope=expired_scope,
        expires_at=_past(),
        nonce="test-expired-verify-nonce",
        status="approved",
    )
    approval_service._store.save_approval(approved_then_expired)  # type: ignore[attr-defined]
    with pytest.raises(ApprovalError, match="expired"):
        approval_service.verify_for_step(
            approved_then_expired.id,
            base_step,
            observed_nonce=approved_then_expired.nonce,
        )


def test_nonce_mismatch(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="nonce"):
        approval_service.verify_for_step(granted.id, base_step, observed_nonce="forged-nonce")


# -- status transitions ---------------------------------------------------


def test_rejected_blocks_verify(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    approval_service.reject(pending.id, reason="no")
    with pytest.raises(ApprovalError, match="rejected"):
        approval_service.verify_for_step(pending.id, base_step, observed_nonce=pending.nonce)


def test_pending_blocks_verify(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    with pytest.raises(ApprovalError, match="not granted"):
        approval_service.verify_for_step(pending.id, base_step, observed_nonce=pending.nonce)


def test_revoke(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
    base_step: Step,
) -> None:
    pending = approval_service.request_approval(actor="human:a", scope=base_scope)
    approval_service.grant(pending.id)
    approval_service.revoke(pending.id, reason="op-cancel")
    with pytest.raises(ApprovalError, match="revoked"):
        approval_service.verify_for_step(pending.id, base_step, observed_nonce=pending.nonce)


def test_nonce_uniqueness_across_approvals(
    approval_service: ApprovalService,
    base_scope: ApprovalScope,
) -> None:
    a1 = approval_service.request_approval(actor="human:a", scope=base_scope)
    a2 = approval_service.request_approval(actor="human:a", scope=base_scope)
    assert a1.nonce != a2.nonce


# -- connector_action carve-out (Rule of Two: step-scoped HITL only) ----------


def _connector_step() -> Step:
    return Step(
        tenant_id="legacy-default",
        run_id="run_test",
        plan_id="plan_test",
        actor="sub:m",
        action_type="connector_action",
        target="kakaowork.post_message",
    )


def test_connector_action_consumed_by_step_scoped_approval(
    approval_service: ApprovalService,
) -> None:
    # A step-scoped approval pinned to this exact step authorizes connector_action
    # even though connector_action can never appear in allowed_action_types.
    step = _connector_step()
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=[step.id],
        allowed_action_types=[],  # connector_action is forbidden here by construction
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    consumed = approval_service.consume(granted.id, step, observed_nonce=granted.nonce)
    assert consumed.status == "consumed"


def test_connector_action_rejected_by_plan_wide_approval(
    approval_service: ApprovalService,
) -> None:
    # A plan-wide approval (no step_ids) must NOT smuggle a connector action
    # through — Rule of Two requires a step-scoped HITL approval.
    step = _connector_step()
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=[],  # plan-wide, not pinned to this step
        allowed_action_types=[],
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="action_type"):
        approval_service.verify_for_step(granted.id, step, observed_nonce=granted.nonce)


# -- connector_action carve-out must be DEDICATED, not membership ---


def test_connector_action_rejected_by_multi_step_scope(
    approval_service: ApprovalService,
) -> None:
    # Regression: a connector_action must be authorized ONLY
    # by a scope pinned to this exact step alone (single-element step_ids ==
    # [step.id]). A multi-step scope that merely *contains* the connector step id
    # (e.g. step_ids=[connector_step, other_step]) is NOT dedicated and must be
    # rejected fail-closed — even though connector_action can never appear in
    # allowed_action_types. The core must close this invariant itself rather than
    # relying on the caller graph (head_agent ValidationError / SubAgent single
    # step_ids) to keep a non-dedicated connector scope from ever being built.
    step = _connector_step()
    other_step_id = "step_other_in_same_scope"
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        # Multi-step scope: contains this connector step but is NOT dedicated to it.
        step_ids=[step.id, other_step_id],
        allowed_action_types=[],
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="action_type"):
        approval_service.verify_for_step(granted.id, step, observed_nonce=granted.nonce)


def test_connector_action_rejected_by_multi_step_scope_other_order(
    approval_service: ApprovalService,
) -> None:
    # Same as above but the connector step id is the *second* element — guards
    # against an accidental "is step_ids[0]" style narrowing instead of a true
    # single-element equality check.
    step = _connector_step()
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=["step_other_leading", step.id],
        allowed_action_types=[],
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="action_type"):
        approval_service.verify_for_step(granted.id, step, observed_nonce=granted.nonce)


def test_connector_action_dedicated_single_step_still_consumes(
    approval_service: ApprovalService,
) -> None:
    # The legitimate path must keep working: a dedicated single-step scope
    # (step_ids == [step.id]) still authorizes connector_action and consumes the
    # token once. Narrowing the carve-out must NOT regress this.
    step = _connector_step()
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=[step.id],  # dedicated single-element scope
        allowed_action_types=[],
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    consumed = approval_service.consume(granted.id, step, observed_nonce=granted.nonce)
    assert consumed.status == "consumed"
    # Single-use: a second consume is blocked (nonce/expiry/revoke invariants
    # remain in force on the narrowed connector path).
    with pytest.raises(ApprovalError, match="consumed"):
        approval_service.consume(granted.id, step, observed_nonce=granted.nonce)


def test_connector_action_dedicated_scope_respects_expiry(
    approval_service: ApprovalService,
) -> None:
    # The narrowed carve-out must not bypass expiry: a dedicated connector scope
    # whose token is past-expiry is still rejected fail-closed.
    step = _connector_step()
    expired_scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=[step.id],
        allowed_action_types=[],
        max_risk=70,
        expires_at=_past(),
    )
    approved_then_expired = Approval(
        actor="human:a",
        scope=expired_scope,
        expires_at=_past(),
        nonce="test-connector-expired-nonce",
        status="approved",
    )
    approval_service._store.save_approval(approved_then_expired)  # type: ignore[attr-defined]
    with pytest.raises(ApprovalError, match="expired"):
        approval_service.verify_for_step(
            approved_then_expired.id, step, observed_nonce=approved_then_expired.nonce
        )


# -- non-connector approval logic must NOT regress -----------


def test_non_connector_multi_step_scope_still_authorizes(
    approval_service: ApprovalService,
    base_step: Step,
) -> None:
    # Regression guard: for non-connector actions the existing behavior is
    # membership-based (step.id in step_ids) AND allowed_action_types
    # membership. Narrowing the connector carve-out must leave this path intact —
    # a file_read step in a multi-step scope listing it (plus another id) and
    # allowing file_read must still authorize.
    scope = ApprovalScope(
        tenant_id=base_step.tenant_id,
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        step_ids=[base_step.id, "step_sibling"],  # multi-step
        allowed_action_types=["file_read"],
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    consumed = approval_service.consume(granted.id, base_step, observed_risk=10, observed_nonce=granted.nonce)
    assert consumed.status == "consumed"


def test_non_connector_action_type_not_allowed_still_rejected(
    approval_service: ApprovalService,
    base_step: Step,
) -> None:
    # The non-connector branch still rejects when the action_type is absent from
    # allowed_action_types, regardless of step_ids membership.
    scope = ApprovalScope(
        tenant_id=base_step.tenant_id,
        run_id=base_step.run_id,
        plan_id=base_step.plan_id,
        step_ids=[base_step.id, "step_sibling"],
        allowed_action_types=["http_get"],  # file_read NOT allowed
        max_risk=70,
        expires_at=_future(),
    )
    pending = approval_service.request_approval(actor="human:a", scope=scope)
    granted = approval_service.grant(pending.id)
    with pytest.raises(ApprovalError, match="action_type"):
        approval_service.verify_for_step(granted.id, base_step, observed_nonce=granted.nonce)


# -- determinism of the carve-out decision (§B-4a, 100 runs) --


def test_action_allowed_carve_out_is_deterministic_100x() -> None:
    # Deterministic module (§B-4a): the same inputs must yield the same authorize
    # decision 100 times. Covers the connector_action carve-out (dedicated vs
    # not) and the non-connector membership branch on the pure decision function.
    from secugent.core.approval import _action_allowed

    cases: list[tuple[str, list[str], bool, bool]] = [
        # (action_type, allowed_action_types, step_dedicated, expected)
        ("connector_action", [], True, True),  # dedicated single-step → allow
        ("connector_action", [], False, False),  # multi-step / plan-wide → deny
        ("unknown", [], True, False),  # unknown never authorized
        ("unknown", ["unknown"], True, False),
        ("file_read", ["file_read"], True, True),  # membership → allow
        ("file_read", ["file_read"], False, True),  # dedication irrelevant here
        ("file_read", ["http_get"], True, False),  # not in allowed → deny
        ("file_read", [], True, False),  # empty allowed → fail-closed
    ]
    for _ in range(100):
        for action_type, allowed, dedicated, expected in cases:
            result = _action_allowed(
                action_type,  # type: ignore[arg-type]
                allowed,  # type: ignore[arg-type]
                step_dedicated=dedicated,
            )
            assert result is expected
