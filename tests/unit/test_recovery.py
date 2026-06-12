# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — recovery decision unit tests (deterministic, no IO)."""

from __future__ import annotations

from datetime import UTC, datetime

from secugent.orchestrator.recovery import (
    decide_recovery_action,
    plan_recovery,
)
from secugent.orchestrator.state import RunRecord, RunState


def _record(run_id: str, state: RunState) -> RunRecord:
    return RunRecord(
        run_id=run_id,
        command="g",
        context={},
        state=state,
        started_at=datetime.now(tz=UTC),
        state_history=[(state, datetime.now(tz=UTC))],
    )


def test_resume_for_pending() -> None:
    d = decide_recovery_action(_record("r1", RunState.PENDING))
    assert d.action == "resume"


def test_resume_for_planning() -> None:
    assert decide_recovery_action(_record("r2", RunState.PLANNING)).action == "resume"


def test_resume_for_awaiting_approval() -> None:
    assert decide_recovery_action(_record("r3", RunState.AWAITING_APPROVAL)).action == "resume"


def test_fail_worker_lost_for_approved() -> None:
    assert decide_recovery_action(_record("r4", RunState.APPROVED)).action == "fail_worker_lost"


def test_fail_worker_lost_for_executing() -> None:
    assert decide_recovery_action(_record("r5", RunState.EXECUTING)).action == "fail_worker_lost"


def test_skip_for_terminal_states() -> None:
    for terminal in (RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED):
        assert decide_recovery_action(_record("r", terminal)).action == "skip"


def test_plan_recovery_deterministic_ordering() -> None:
    records = [
        _record("z-3", RunState.PLANNING),
        _record("a-1", RunState.EXECUTING),
        _record("m-2", RunState.PENDING),
    ]
    plan = plan_recovery(records)
    assert [d.run_id for d in plan] == ["a-1", "m-2", "z-3"]
    # Ensure stability — same input, same output
    plan2 = plan_recovery(records)
    assert plan == plan2
