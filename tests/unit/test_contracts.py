# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from secugent.core.contracts import (
    Approval,
    ApprovalScope,
    Event,
    HardBlockException,
    Plan,
    Risk,
    RiskScore,
    Run,
    SessionRegulationPatch,
    Step,
    Violation,
)


def _future(seconds: int = 60) -> datetime:
    return datetime.now(tz=UTC) + timedelta(seconds=seconds)


# -- Run / Step / Plan ----------------------------------------------------


def test_run_defaults_and_status() -> None:
    run = Run(tenant_id="legacy-default", goal="hello world")
    assert run.id.startswith("run_")
    assert run.status == "pending"
    assert run.created_at.tzinfo is not None


def test_run_goal_required() -> None:
    with pytest.raises(ValidationError):
        Run(tenant_id="legacy-default", goal="")  # min_length=1


def test_step_defaults() -> None:
    step = Step(
        tenant_id="legacy-default",
        run_id="run_x",
        plan_id=None,
        actor="sub:1",
        action_type="file_read",
        target="D:/a.txt",
    )
    assert step.status == "pending"
    assert step.id.startswith("step_")


def test_step_unknown_action_type_rejected() -> None:
    with pytest.raises(ValidationError):
        Step(tenant_id="legacy-default", run_id="r", actor="a", action_type="email_send")  # type: ignore[arg-type]


def test_plan_holds_steps_and_risks() -> None:
    step = Step(tenant_id="legacy-default", run_id="r", actor="sub:1", action_type="file_read", target="D:/a")
    plan = Plan(
        tenant_id="legacy-default",
        run_id="r",
        goal="g",
        steps=[step],
        risks=[Risk(description="reads sensitive file")],
        assigned_subs={step.id: "sub:1"},
    )
    assert plan.steps[0].id == step.id
    assert plan.risks[0].severity == "medium"


# -- ApprovalScope --------------------------------------------------------


def test_approval_scope_rejects_unknown_action() -> None:
    with pytest.raises(ValidationError):
        ApprovalScope(
            tenant_id="legacy-default",
            run_id="r",
            step_ids=["s1"],
            allowed_action_types=["unknown"],  # type: ignore[list-item]
            max_risk=50,
            expires_at=_future(),
        )


def test_approval_scope_max_risk_bounds() -> None:
    with pytest.raises(ValidationError):
        ApprovalScope(
            tenant_id="legacy-default",
            run_id="r",
            step_ids=["s1"],
            allowed_action_types=["file_read"],
            max_risk=101,
            expires_at=_future(),
        )


# -- Approval -------------------------------------------------------------


def test_approval_nonce_required() -> None:
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id="r",
        step_ids=["s"],
        allowed_action_types=["file_read"],
        max_risk=50,
        expires_at=_future(),
    )
    with pytest.raises(ValidationError):
        Approval(  # type: ignore[call-arg]
            actor="human:a",
            scope=scope,
            expires_at=_future(),
        )


# -- Event ----------------------------------------------------------------


def test_event_defaults() -> None:
    e = Event(tenant_id="legacy-default", actor="head", type="plan.created")
    assert e.severity == "info"
    assert e.id.startswith("evt_")
    assert e.payload == {}


# -- Violation / HardBlockException --------------------------------------


def test_violation_defaults_hard_block_true() -> None:
    v = Violation(rule_id="R1", category="banned_path", message="nope")
    assert v.hard_block is True
    exc = HardBlockException(v)
    assert exc.violation is v
    assert str(exc) == "nope"


# -- RiskScore ------------------------------------------------------------


def _full_breakdown() -> dict[str, int]:
    return {
        "data_sensitivity": 10,
        "external_exposure": 10,
        "irreversibility": 10,
        "privilege_escalation": 10,
        "intent_alignment": 10,
    }


def test_risk_score_requires_all_dims() -> None:
    bad = _full_breakdown()
    del bad["intent_alignment"]
    with pytest.raises(ValidationError):
        RiskScore(total=50, breakdown=bad, rationale="r", confidence=0.8)


def test_risk_score_dim_out_of_range() -> None:
    bad = _full_breakdown()
    bad["data_sensitivity"] = 200
    with pytest.raises(ValidationError):
        RiskScore(total=10, breakdown=bad, rationale="r", confidence=0.8)


def test_risk_score_total_bounds() -> None:
    with pytest.raises(ValidationError):
        RiskScore(total=-1, breakdown=_full_breakdown(), rationale="r", confidence=0.5)
    with pytest.raises(ValidationError):
        RiskScore(total=101, breakdown=_full_breakdown(), rationale="r", confidence=0.5)


def test_risk_score_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        RiskScore(total=10, breakdown=_full_breakdown(), rationale="r", confidence=1.5)


# -- SessionRegulationPatch ----------------------------------------------


def test_session_patch_basic() -> None:
    patch = SessionRegulationPatch(
        tenant_id="legacy-default",
        run_id="r",
        rules=[{"category": "banned_path", "pattern": "D:/x"}],
        expires_at=_future(),
        reason="STEER: do not touch attachments",
    )
    assert patch.id.startswith("patch_")
    assert patch.run_id == "r"


# -- extras forbidden ----------------------------------------------------


def test_unexpected_field_rejected_on_run() -> None:
    with pytest.raises(ValidationError):
        Run(tenant_id="legacy-default", goal="x", note="extra")  # type: ignore[call-arg]
