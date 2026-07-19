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


# -- Plan AI-generated provenance (§C-1) ----------------------------


def test_plan_provenance_defaults() -> None:
    # A bare Plan is still honestly marked AI-generated, with safe model/version
    # defaults the planner overwrites (INV-H2-2: ai_generated is always True).
    plan = Plan(tenant_id="legacy-default", run_id="r", goal="g", risks=[Risk(description="x")])
    assert plan.ai_generated is True
    assert plan.model_id == "unknown"
    assert plan.regulations_version == "0.0.0"


def test_plan_provenance_stampable() -> None:
    plan = Plan(
        tenant_id="legacy-default",
        run_id="r",
        goal="g",
        risks=[Risk(description="x")],
        model_id="claude-opus-4-7",
        regulations_version="1.4.2",
    )
    assert plan.model_id == "claude-opus-4-7"
    assert plan.regulations_version == "1.4.2"


def test_plan_ai_generated_cannot_be_false() -> None:
    # INV-H2-2: a forged ``ai_generated=False`` is unrepresentable (Literal[True]).
    with pytest.raises(ValidationError):
        Plan(
            tenant_id="legacy-default",
            run_id="r",
            goal="g",
            risks=[Risk(description="x")],
            ai_generated=False,  # type: ignore[arg-type]
        )


def test_plan_ai_generated_is_frozen() -> None:
    # INV-H2-2: the provenance flag is immutable once constructed.
    plan = Plan(tenant_id="legacy-default", run_id="r", goal="g", risks=[Risk(description="x")])
    with pytest.raises(ValidationError):
        plan.ai_generated = True  # type: ignore[misc]  # frozen field — even True is rejected


def test_ai_generated_marker_is_korean_constant() -> None:
    # INV-H2-4: the marker is a fixed Korean-default string (§C-3) — deterministic.
    from secugent.core.contracts import AI_GENERATED_MARKER

    assert AI_GENERATED_MARKER == "AI 생성: 본 산출물은 AI가 생성했습니다."


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


# -- ApprovalScope.rule_of_two_axes (§C-2) --------------------------


def _scope(**kw: object) -> ApprovalScope:
    base: dict[str, object] = {
        "tenant_id": "legacy-default",
        "run_id": "r",
        "step_ids": ["s1"],
        "allowed_action_types": ["file_read"],
        "max_risk": 50,
        "expires_at": _future(),
    }
    base.update(kw)
    return ApprovalScope(**base)  # type: ignore[arg-type]


def test_rule_of_two_axes_defaults_empty() -> None:
    # An axis-free scope honestly carries no axes (not a fabricated fill).
    assert _scope().rule_of_two_axes == ()


def test_rule_of_two_axes_normalized_sorted_unique() -> None:
    # Caller order/duplication is normalized so a given axis set has exactly one
    # byte representation (INV-M4-2 uniqueness / INV-M4-3 determinism).
    scope = _scope(
        rule_of_two_axes=("external_comm", "untrusted_input", "external_comm"),
    )
    assert scope.rule_of_two_axes == ("external_comm", "untrusted_input")


def test_rule_of_two_axes_rejects_non_canonical_token() -> None:
    # A typo'd / forged axis token can never enter an audit row (fail-closed).
    with pytest.raises(ValidationError):
        _scope(rule_of_two_axes=("untrusted_input", "not_an_axis"))


def test_rule_of_two_axes_is_frozen() -> None:
    # INV-M4-2: the axis set that justified a HITL approval is fixed at issuance.
    scope = _scope(rule_of_two_axes=("sensitive_access",))
    with pytest.raises(ValidationError):
        scope.rule_of_two_axes = ("external_comm",)  # type: ignore[misc]


def test_rule_of_two_axis_tokens_match_axis_enum() -> None:
    # The literal tokens duplicated in contracts.py (to avoid an import cycle)
    # MUST equal the Axis enum value set, or the §C-2 schema would silently drift.
    from secugent.core.contracts import _RULE_OF_TWO_AXIS_TOKENS
    from secugent.core.rule_of_two import Axis

    assert _RULE_OF_TWO_AXIS_TOKENS == {axis.value for axis in Axis}


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
