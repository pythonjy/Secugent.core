# SPDX-License-Identifier: Apache-2.0
"""Producer wiring: run ``context['grounding_evidence']`` → persisted ``plan['evidence']``.

The hotspot integration node (2026-07-13) that activates the dormant grounding
citation path. A retrieval connector / MCP tool result placed on the run context
is bound (fail-closed, §B-8) into the PLANNING-persisted plan so the Plan Review
read/decision paths can cite and (when enabled) enforce it.

SecuGent builds no retrieval engine (§A-1) — the connector/caller supplies the
evidence; this test pins only the *control* wiring: bind → persist, and the
fail-closed behaviour on a malformed payload (INV-RW-2).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from secugent.config import OrchestratorConfig
from secugent.orchestrator.runner import (
    InMemoryRunStateStore,
    PlanLike,
    RunOrchestrator,
)
from secugent.orchestrator.state import RunState

# --------------------------------------------------------------------------- #
# Korean fixtures (§C-3) — a single loan-review evidence citation.
# --------------------------------------------------------------------------- #


def _kr_evidence() -> dict[str, Any]:
    return {
        "source_uri": "s3://loan-review/2026/여신심사_00123.pdf",
        "doc_id": "LR-00123",
        "retrieved_at": "2026-07-13T09:00:00+09:00",  # KST (§C-3)
        "snippet": "담보 평가액은 3.2억원으로 감정되었다.",
        "span": None,
        "score": 0.91,
    }


class _StubPlanner:
    """Returns a minimal 1-risk plan so the run reaches AWAITING_APPROVAL."""

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        return PlanLike(
            id=f"plan-{run_id}",
            summary="여신 심사 요약",
            steps=[],
            risks=[{"description": "고위험", "severity": "high", "mitigation": "HITL"}],
        )


class _NeverCalledDispatcher:
    async def dispatch(
        self, *, run_id: str, plan: PlanLike, approved_step_ids: list[str] | None = None
    ) -> dict[str, Any]:
        raise AssertionError("dispatcher must not run while parked at AWAITING_APPROVAL")


async def _run_until(runner: RunOrchestrator, run_id: str, *, predicate: Any, timeout_s: float = 4.0) -> Any:
    """Poll the run record until ``predicate(record)`` is truthy or timeout."""
    deadline_iters = int(timeout_s / 0.02)
    for _ in range(deadline_iters):
        record = await runner.get_record(run_id)
        if record is not None and predicate(record):
            return record
        await asyncio.sleep(0.02)
    return await runner.get_record(run_id)


async def _drive(tmp_path: Path, context: dict[str, Any], *, predicate: Any) -> Any:
    runner = RunOrchestrator(
        planner=_StubPlanner(),
        dispatcher=_NeverCalledDispatcher(),
        state_store=InMemoryRunStateStore(),
        # Park at the HITL gate so the PLANNING-persisted plan is captured before
        # any execution can rewrite it (auto_approve defaults False already).
        config=OrchestratorConfig(auto_approve=False),
    )
    await runner.start()
    try:
        run_id = "grounding-producer-01"
        await runner.enqueue(run_id, "여신 심사 실행", context)
        return await _run_until(runner, run_id, predicate=predicate)
    finally:
        await runner.stop()


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_context_evidence_is_persisted_onto_plan(tmp_path: Path) -> None:
    """context['grounding_evidence'] → plan['evidence'] citation, order preserved."""
    record = await _drive(
        tmp_path,
        {"tenant_id": "kb-bank", "grounding_evidence": [_kr_evidence()]},
        predicate=lambda r: isinstance(r.plan, dict) and r.plan.get("id"),
    )
    assert record is not None
    evidence = record.plan["evidence"]
    assert isinstance(evidence, list) and len(evidence) == 1
    assert evidence[0]["doc_id"] == "LR-00123"
    assert evidence[0]["source_uri"] == "s3://loan-review/2026/여신심사_00123.pdf"


@pytest.mark.asyncio
async def test_no_context_evidence_persists_empty_list(tmp_path: Path) -> None:
    """A run with no grounding still gets an explicit (backward-compatible) []."""
    record = await _drive(
        tmp_path,
        {"tenant_id": "kb-bank"},
        predicate=lambda r: isinstance(r.plan, dict) and r.plan.get("id"),
    )
    assert record is not None
    assert record.plan["evidence"] == []


@pytest.mark.asyncio
async def test_malformed_context_evidence_fails_run_closed(tmp_path: Path) -> None:
    """INV-RW-2: a malformed grounding payload fails the run before the HITL gate."""
    record = await _drive(
        tmp_path,
        # missing required doc_id → Evidence validation fails at the bind boundary.
        {
            "tenant_id": "kb-bank",
            "grounding_evidence": [{"source_uri": "s3://x", "snippet": "x"}],
        },
        predicate=lambda r: r.state == RunState.FAILED,
    )
    assert record is not None
    assert record.state == RunState.FAILED
    assert record.failure_reason is not None
    assert record.failure_reason.startswith("grounding_evidence_invalid")


@pytest.mark.asyncio
async def test_non_list_context_evidence_fails_run_closed(tmp_path: Path) -> None:
    """A non-list grounding_evidence is a boundary violation → run fails closed."""
    record = await _drive(
        tmp_path,
        {"tenant_id": "kb-bank", "grounding_evidence": {"not": "a list"}},
        predicate=lambda r: r.state == RunState.FAILED,
    )
    assert record is not None
    assert record.state == RunState.FAILED
    assert record.failure_reason is not None
    assert record.failure_reason.startswith("grounding_evidence_invalid")
