# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-09/20/21 회귀 테스트: 상태기계 정상 생애주기.

iter1 테스트는 INTERRUPT_REQUESTED→RESUMING 불법 전이를 기대값으로 박제했다.
iter2 수정 후에는 정상 생애주기(pause→checkpoint→resume 성공)가 작동해야 한다:

  RUNNING → INTERRUPT_REQUESTED → PAUSING → PAUSED_SNAPSHOTTED → RESUMING → RUNNING

SG-20(중간 전이 구동)과 SG-21(엔진 None 시 전이 없이 raise)도 함께 검증한다.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from secugent.orchestrator.runner import (
    RunNotDispatchingError,
    RunOrchestrator,
)
from secugent.steer.interrupt_state import InterruptState, InterruptStateError
from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_runner_with_engine() -> tuple[RunOrchestrator, MagicMock]:
    """엔진이 있는 RunOrchestrator (엔진이 pause 신호를 받는다)."""
    mock_engine = MagicMock()
    mock_engine.set_paused.return_value = True

    registry = MagicMock()
    registry.resolve_run_engine.return_value = mock_engine

    runner = RunOrchestrator(
        planner=MagicMock(),
        dispatcher=MagicMock(),
        external_engine_registry=registry,
    )
    return runner, mock_engine


def _make_runner_no_engine() -> RunOrchestrator:
    """엔진 None(비디스패칭) RunOrchestrator."""
    registry = MagicMock()
    registry.resolve_run_engine.return_value = None
    return RunOrchestrator(
        planner=MagicMock(),
        dispatcher=MagicMock(),
        external_engine_registry=registry,
    )


def _make_checkpoint(run_id: str, store: SQLiteCheckpointStore) -> object:
    """테스트용 RunCheckpoint를 store에 쓰고 SnapshotRef를 반환한다."""
    ckpt = RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id="t1",
        step_index=1,
        pending_step_ids=["s2"],
        completed_step_ids=["s1"],
        session_patch_set=[],
        patch_remaining_ttl={},
        regulations_version="1.0.0",
        envelope_hash="env-hash",
        rule_of_two_axes=["sensitive_access"],
        approval_scope_ref="",
        staged_effect_disposition=[],
        file_before_images_ref={},
        directive_log_ref=[],
        created_at=datetime.now(tz=UTC).isoformat(),
        actor="op",
    )
    return store.write(ckpt)


# ---------------------------------------------------------------------------
# 정상 생애주기 테스트 (SG-20/21 핵심)
# ---------------------------------------------------------------------------


class TestNormalLifecycle:
    """pause→checkpoint→resume 성공 생애주기 — 이것이 G-C3 P0 계약이다."""

    def test_pause_transitions_to_interrupt_requested(self) -> None:
        """request_pause 성공 → INTERRUPT_REQUESTED 전이."""
        runner, engine = _make_runner_with_engine()
        runner.request_pause("run-lc-1", request_id="req-1", mode="pause", actor="op")
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get("run-lc-1")
        assert rec is not None
        assert rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED

    def test_notify_pause_completed_drives_to_paused_snapshotted(self) -> None:
        """notify_pause_completed → INTERRUPT_REQUESTED→PAUSING→PAUSED_SNAPSHOTTED."""
        runner, engine = _make_runner_with_engine()
        runner.request_pause("run-lc-2", request_id="req-2", mode="pause", actor="op")
        runner.notify_pause_completed("run-lc-2")
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get("run-lc-2")
        assert rec is not None
        assert rec.interrupt_state == InterruptState.PAUSED_SNAPSHOTTED

    def test_full_lifecycle_pause_checkpoint_resume_succeeds(self) -> None:
        """전체 생애주기: pause → notify_pause_completed → resume → RUNNING.

        SG-20: PAUSED_SNAPSHOTTED에서만 resume이 허용됨.
        SG-20: resume 성공 후 RESUMING→RUNNING 전이 완료.
        """
        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-lc-3", store)

        # Step 1: pause
        runner.request_pause("run-lc-3", request_id="req-3", mode="pause", actor="op")
        # Step 2: simulate checkpoint written → drive to PAUSED_SNAPSHOTTED
        runner.notify_pause_completed("run-lc-3")

        # dispatch stub
        async def _noop_dispatch(**kwargs: object) -> None:
            pass

        runner._dispatcher.dispatch = _noop_dispatch

        # Step 3: resume must succeed (no InterruptStateError)
        async def _run() -> None:
            await runner.resume_from_checkpoint("run-lc-3", ref, checkpoint_store=store)

        asyncio.run(_run())  # must not raise

        # After successful resume the state machine must be back to RUNNING
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get("run-lc-3")
        assert rec is not None, "record must exist after full lifecycle"
        assert rec.interrupt_state == InterruptState.RUNNING, (
            f"expected RUNNING after resume, got {rec.interrupt_state}"
        )

    def test_second_pause_after_resume_succeeds(self) -> None:
        """RESUMING→RUNNING 후 2차 pause도 성공한다 (SG-20: RUNNING에서 재시작 가능)."""
        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-lc-4", store)

        runner.request_pause("run-lc-4", request_id="req-4a", mode="pause", actor="op")
        runner.notify_pause_completed("run-lc-4")

        async def _noop_dispatch(**kwargs: object) -> None:
            pass

        runner._dispatcher.dispatch = _noop_dispatch

        asyncio.run(runner.resume_from_checkpoint("run-lc-4", ref, checkpoint_store=store))

        # 2차 pause: 상태가 RUNNING이므로 성공해야 한다
        runner.request_pause("run-lc-4", request_id="req-4b", mode="pause", actor="op")
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get("run-lc-4")
        assert rec is not None
        assert rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED


# ---------------------------------------------------------------------------
# D-K 거부형 상태기계 — 비정지 상태에서 verb 거부
# ---------------------------------------------------------------------------


class TestStateMachineRejections:
    """D-K: 비-quiescent 상태에서 새 verb → InterruptStateError."""

    def test_double_pause_raises(self) -> None:
        """이미 INTERRUPT_REQUESTED → 2차 pause 거부."""
        runner, engine = _make_runner_with_engine()
        runner.request_pause("run-rej-1", request_id="req-a", mode="pause", actor="op")
        with pytest.raises(InterruptStateError):
            runner.request_pause("run-rej-1", request_id="req-b", mode="pause", actor="op")

    def test_resume_from_interrupt_requested_raises(self) -> None:
        """INTERRUPT_REQUESTED → resume 불법 전이 (PAUSED_SNAPSHOTTED 필요)."""
        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-rej-2", store)

        runner.request_pause("run-rej-2", request_id="req-c", mode="pause", actor="op")
        # notify_pause_completed 미호출 → INTERRUPT_REQUESTED 상태
        # INTERRUPT_REQUESTED → RESUMING은 불법 전이

        async def _run() -> None:
            await runner.resume_from_checkpoint("run-rej-2", ref, checkpoint_store=store)

        with pytest.raises(InterruptStateError):
            asyncio.run(_run())

    def test_pause_when_resuming_raises(self) -> None:
        """RESUMING 상태(non-quiescent)에서 pause → InterruptStateError."""
        runner, engine = _make_runner_with_engine()
        # 수동으로 RESUMING 상태 강제
        from secugent.steer.interrupt_state import RunInterruptRecord

        with runner._interrupt_records_lock:
            rec = RunInterruptRecord(run_id="run-rej-3")
            rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
            rec.transition_to(InterruptState.PAUSING)
            rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
            rec.transition_to(InterruptState.RESUMING)
            runner._interrupt_records["run-rej-3"] = rec

        with pytest.raises(InterruptStateError):
            runner.request_pause("run-rej-3", request_id="req-d", mode="pause", actor="op")

    def test_resume_when_resuming_raises(self) -> None:
        """RESUMING 상태에서 resume → InterruptStateError (D-K)."""
        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-rej-4", store)

        from secugent.steer.interrupt_state import RunInterruptRecord

        with runner._interrupt_records_lock:
            rec = RunInterruptRecord(run_id="run-rej-4")
            rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
            rec.transition_to(InterruptState.PAUSING)
            rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
            rec.transition_to(InterruptState.RESUMING)
            runner._interrupt_records["run-rej-4"] = rec

        async def _run() -> None:
            await runner.resume_from_checkpoint("run-rej-4", ref, checkpoint_store=store)

        with pytest.raises(InterruptStateError):
            asyncio.run(_run())


# ---------------------------------------------------------------------------
# SG-20260621-21: 엔진 None 시 상태 전이 없이 raise
# ---------------------------------------------------------------------------


class TestEngineNoneDoesNotTransition:
    """SG-21: 엔진이 None이면 레코드 생성/전이 없이 RunNotDispatchingError."""

    def test_engine_none_raises_and_no_record_created(self) -> None:
        """엔진이 None인 경우 RunNotDispatchingError, 레코드 미생성."""
        runner = _make_runner_no_engine()
        with pytest.raises(RunNotDispatchingError):
            runner.request_pause("run-none-1", request_id="req-n1", mode="pause", actor="op")
        # 레코드가 생성되지 않아야 한다 (SG-21: no stale INTERRUPT_REQUESTED)
        with runner._interrupt_records_lock:
            assert "run-none-1" not in runner._interrupt_records

    def test_engine_none_then_engine_registered_pause_succeeds(self) -> None:
        """엔진 None 후 엔진 등록 → 2차 pause 성공 (SG-21 멱등 보장)."""
        mock_engine = MagicMock()
        mock_engine.set_paused.return_value = True
        registry = MagicMock()
        # 1차: None, 2차: mock_engine
        registry.resolve_run_engine.side_effect = [None, mock_engine]

        runner = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            external_engine_registry=registry,
        )
        # 1차 pause → RunNotDispatchingError, no record
        with pytest.raises(RunNotDispatchingError):
            runner.request_pause("run-none-2", request_id="req-n2a", mode="pause", actor="op")
        # 2차 pause (엔진 등록 후 시뮬레이션) → 성공
        runner.request_pause("run-none-2", request_id="req-n2b", mode="pause", actor="op")
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get("run-none-2")
        assert rec is not None
        assert rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED


# ---------------------------------------------------------------------------
# notify_pause_completed: no-op when no record
# ---------------------------------------------------------------------------


class TestNotifyPauseCompletedEdgeCases:
    def test_no_record_is_noop(self) -> None:
        """레코드 없는 런에 notify_pause_completed → 아무것도 않함 (no-op)."""
        runner, _ = _make_runner_with_engine()
        runner.notify_pause_completed("run-noop-1")  # must not raise
        with runner._interrupt_records_lock:
            assert "run-noop-1" not in runner._interrupt_records

    def test_resume_without_prior_pause_no_state_machine_transition(self) -> None:
        """이전 pause 없이 resume → state machine record 없이 통과."""
        runner = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-npp-1", store)

        async def _noop_dispatch(**kwargs: object) -> None:
            pass

        runner._dispatcher.dispatch = _noop_dispatch

        async def _run() -> None:
            await runner.resume_from_checkpoint("run-npp-1", ref, checkpoint_store=store)

        asyncio.run(_run())  # must not raise
        with runner._interrupt_records_lock:
            assert "run-npp-1" not in runner._interrupt_records
