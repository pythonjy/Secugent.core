# SPDX-License-Identifier: Apache-2.0
"""HeadAgent stamps immutable AI-generated provenance on every Plan.

§C-1 (AI 산출물 식별표시) + 한국 AI 기본법 워터마크. Proves:

* every Plan returned by ``HeadAgent.plan`` carries ``ai_generated`` /
  ``model_id`` / ``regulations_version`` (INV-H2-1);
* ``model_id`` is the resolved planner model and ``regulations_version`` is the
  injected provider's value (live ``state_.active_regulations_version``);
* the stamping is deterministic — same plan input ⇒ byte-identical provenance
  across 100 runs (INV-H2-4), no wall-clock enters the contract;
* the existing ``MissingRiskSectionError`` re-prompt harness is untouched.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from secugent.agents.head_agent import HeadAgent, HeadPlanRequest
from secugent.core.approval import ApprovalService
from secugent.core.contracts import MissingRiskSectionError
from secugent.core.event_store import EventStore
from secugent.core.llm_client import PLANNER_MODEL_DEFAULT, MockLLMClient

# 한국 금융 도메인 픽스처(§C-3): 계좌 외부 전송 계획.
_KR_FINANCE_PLAN: dict[str, Any] = {
    "steps": [
        {
            "id": "s1",
            "actor": "sub:analyzer",
            "action_type": "file_read",
            "target": "/data/계좌원장.csv",
        }
    ],
    "risks": [
        {"description": "민감 금융 데이터 접근 — 신용정보법 §22", "severity": "high"},
    ],
}


def _plan_json() -> str:
    return json.dumps(_KR_FINANCE_PLAN, ensure_ascii=False)


def _head(
    store: EventStore,
    approvals: ApprovalService,
    *,
    responses: list[str] | None = None,
    model: str | None = None,
    regulations_version_provider: Any = None,
) -> HeadAgent:
    llm = MockLLMClient(responses if responses is not None else [_plan_json()])
    return HeadAgent(
        llm,
        event_store=store,
        approval_service=approvals,
        model=model,
        regulations_version_provider=regulations_version_provider,
    )


def test_plan_carries_provenance_defaults(
    temp_event_store: EventStore, approval_service: ApprovalService
) -> None:
    # No provider wired ⇒ honest 0.0.0 fallback, default planner model.
    head = _head(temp_event_store, approval_service)
    plan = head.plan(HeadPlanRequest(run_id="r1", goal="계좌 점검"))
    assert plan.ai_generated is True
    assert plan.model_id == PLANNER_MODEL_DEFAULT
    assert plan.regulations_version == "0.0.0"


def test_plan_stamps_resolved_model_and_live_version(
    temp_event_store: EventStore, approval_service: ApprovalService
) -> None:
    # The resolved model + the injected live REGULATIONS version are stamped.
    head = _head(
        temp_event_store,
        approval_service,
        model="claude-test-model",
        regulations_version_provider=lambda: "2.1.0",
    )
    plan = head.plan(HeadPlanRequest(run_id="r2", goal="계좌 점검"))
    assert plan.model_id == "claude-test-model"
    assert plan.regulations_version == "2.1.0"


def test_provider_read_at_plan_time_not_construction(
    temp_event_store: EventStore, approval_service: ApprovalService
) -> None:
    # The provider is a late-bound callable (live engine version resolves only at
    # plan() time, after boot wiring sets the OversightEngine).
    box = {"version": "0.0.0"}
    head = _head(
        temp_event_store,
        approval_service,
        responses=[_plan_json(), _plan_json()],
        regulations_version_provider=lambda: box["version"],
    )
    first = head.plan(HeadPlanRequest(run_id="r3a", goal="g"))
    assert first.regulations_version == "0.0.0"
    box["version"] = "9.9.9"
    second = head.plan(HeadPlanRequest(run_id="r3b", goal="g"))
    assert second.regulations_version == "9.9.9"


def test_provenance_is_deterministic_100x(
    temp_event_store: EventStore, approval_service: ApprovalService
) -> None:
    # INV-H2-4: same plan input ⇒ byte-identical provenance every time. The only
    # non-deterministic Plan fields are server-generated ids; provenance is fixed.
    head = _head(
        temp_event_store,
        approval_service,
        responses=[_plan_json() for _ in range(100)],
        model="claude-fixed",
        regulations_version_provider=lambda: "1.0.0",
    )
    seen: set[tuple[bool, str, str]] = set()
    for i in range(100):
        plan = head.plan(HeadPlanRequest(run_id=f"r-{i}", goal="동일 입력"))
        seen.add((plan.ai_generated, plan.model_id, plan.regulations_version))
    assert seen == {(True, "claude-fixed", "1.0.0")}


def test_missing_risk_section_harness_intact(
    temp_event_store: EventStore, approval_service: ApprovalService
) -> None:
    # The provenance stamp must not weaken the risk-section re-prompt harness:
    # a plan with no risks still exhausts attempts and raises (head_agent.py:404).
    no_risks = json.dumps({"steps": [], "risks": []})
    head = _head(
        temp_event_store,
        approval_service,
        responses=[no_risks, no_risks, no_risks],
        regulations_version_provider=lambda: "1.0.0",
    )
    with pytest.raises(MissingRiskSectionError):
        head.plan(HeadPlanRequest(run_id="r-bad", goal="위험 섹션 없음"))
