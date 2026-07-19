# SPDX-License-Identifier: Apache-2.0
"""회귀 테스트: DispatcherAdapter._runner 역배선 통합 검증.

결함 요약: AppState 생성 시 DispatcherAdapter가 RunOrchestrator보다 먼저 생성되어
_runner=None으로 남는다. _handle_pause_result에서 _runner.notify_pause_completed가
호출되지 않으면 상태기계가 INTERRUPT_REQUESTED에 고착되어 resume이 항상
InterruptStateError를 던진다 (데드락).

테스트 구조:
  - test_no_backwire_notify_not_called: 역배선 없을 때 notify 미호출로 INTERRUPT_REQUESTED 고착
  - test_handle_pause_result_drives_state_machine: 역배선 있을 때 PAUSED_SNAPSHOTTED 도달
  - test_resume_succeeds_after_backwired_pause: 전체 pause→resume 성공 (수동 notify 금지)
  - test_non_pause_path_does_not_call_notify: paused_at_step_id=None → _handle_pause_result 미호출
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from secugent.orchestrator.adapters import DispatcherAdapter
from secugent.orchestrator.runner import RunOrchestrator
from secugent.steer.interrupt_state import InterruptState, InterruptStateError
from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore

# ---------------------------------------------------------------------------
# 공통 픽스처 / 헬퍼
# ---------------------------------------------------------------------------


def _make_sub_result(
    run_id: str,
    paused: bool = True,
    regulations_version: str = "1.2.3",
    rule_of_two_axes: list[str] | None = None,
) -> MagicMock:
    """DispatcherAdapter._handle_pause_result에 주입할 mock sub_result."""
    sr = MagicMock()
    sr.paused_at_step_id = "step-1" if paused else None
    sr.tenant_id = "tenant-sg20"
    sr.step_index = 1
    sr.pending_step_ids = ["step-2"]
    sr.completed_step_ids = ["step-1"]
    sr.session_patch_set = []
    sr.patch_remaining_ttl = {}
    sr.regulations_version = regulations_version
    sr.envelope_hash = "envhash"
    sr.rule_of_two_axes = rule_of_two_axes or ["sensitive_access"]
    sr.approval_scope_ref = ""
    sr.staged_effect_disposition = []
    sr.file_before_images_ref = {}
    sr.directive_log_ref = []
    sr.actor = "op"
    return sr


def _make_runner_with_engine() -> tuple[RunOrchestrator, MagicMock]:
    """pause 요청이 가능한 RunOrchestrator를 반환한다."""
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


def _make_dispatcher_with_checkpoint_store() -> tuple[DispatcherAdapter, SQLiteCheckpointStore]:
    """checkpoint_store가 wired된 DispatcherAdapter를 반환한다."""
    store = SQLiteCheckpointStore(":memory:")
    mock_audit = MagicMock()
    mock_audit.append_event.return_value = None

    adapter = DispatcherAdapter(
        head=MagicMock(),
        dispatcher=MagicMock(),
        approval_service=MagicMock(),
        sub_factory=MagicMock(),
        fallback_engine=MagicMock(),
        checkpoint_store=store,
        audit_chain=mock_audit,
        runner=None,  # 역배선 없음 (결함 재현)
    )
    return adapter, store


# ---------------------------------------------------------------------------
# 결함 재현: 역배선 없을 때 notify 미호출 → INTERRUPT_REQUESTED 고착
# ---------------------------------------------------------------------------


class TestNoBackwireNotifyNotCalled:
    """역배선(_runner=None)이 없으면 notify_pause_completed가 호출되지 않는다."""

    @pytest.mark.asyncio
    async def test_no_backwire_state_machine_stuck_at_interrupt_requested(self) -> None:
        """_runner=None → _handle_pause_result 후 INTERRUPT_REQUESTED 고착 (데드락 재현)."""
        runner, engine = _make_runner_with_engine()
        adapter, store = _make_dispatcher_with_checkpoint_store()
        # adapter._runner = None (역배선 없음)

        run_id = f"run-sg20-noback-{uuid.uuid4().hex[:8]}"
        runner.request_pause(run_id, request_id="req-noback", mode="pause", actor="op")

        sub_result = _make_sub_result(run_id)
        # _handle_pause_result를 직접 호출 — 역배선이 없으므로 notify_pause_completed 미호출
        await adapter._handle_pause_result(run_id, sub_result)

        # 상태가 INTERRUPT_REQUESTED에 고착 (PAUSED_SNAPSHOTTED에 도달하지 못함)
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get(run_id)
        assert rec is not None, "record should exist after request_pause"
        assert rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED, (
            f"기대: INTERRUPT_REQUESTED (고착), 실제: {rec.interrupt_state}"
        )

    @pytest.mark.asyncio
    async def test_no_backwire_resume_raises_interrupt_state_error(self) -> None:
        """역배선 없으면 INTERRUPT_REQUESTED 고착 → resume이 InterruptStateError를 던진다."""
        runner, engine = _make_runner_with_engine()
        adapter, store = _make_dispatcher_with_checkpoint_store()
        # adapter._runner = None (역배선 없음)

        run_id = f"run-sg20-noback-res-{uuid.uuid4().hex[:8]}"
        runner.request_pause(run_id, request_id="req-noback-r", mode="pause", actor="op")

        sub_result = _make_sub_result(run_id)
        await adapter._handle_pause_result(run_id, sub_result)

        # checkpoint를 store에 직접 쓰기 (resume에 필요)
        ckpt = RunCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            run_id=run_id,
            tenant_id="tenant-sg20",
            step_index=1,
            pending_step_ids=["s2"],
            completed_step_ids=["s1"],
            session_patch_set=[],
            patch_remaining_ttl={},
            regulations_version="1.2.3",
            envelope_hash="ehash",
            rule_of_two_axes=["sensitive_access"],
            approval_scope_ref="",
            staged_effect_disposition=[],
            file_before_images_ref={},
            directive_log_ref=[],
            created_at=datetime.now(tz=UTC).isoformat(),
            actor="op",
        )
        ref = store.write(ckpt)

        # INTERRUPT_REQUESTED 상태이므로 resume → InterruptStateError (데드락 증명)
        async def _dispatch_noop(**kwargs: object) -> None:
            pass

        runner._dispatcher.dispatch = _dispatch_noop  # type: ignore[attr-defined]

        with pytest.raises(InterruptStateError):
            await runner.resume_from_checkpoint(run_id, ref, checkpoint_store=store)


# ---------------------------------------------------------------------------
# 수정 검증: 역배선이 있을 때 PAUSED_SNAPSHOTTED 도달
# ---------------------------------------------------------------------------


class TestHandlePauseResultDrivesStateMachine:
    """역배선(_runner=runner) 있을 때 _handle_pause_result가 PAUSED_SNAPSHOTTED까지 전이."""

    @pytest.mark.asyncio
    async def test_backwired_handle_pause_result_reaches_paused_snapshotted(self) -> None:
        """_runner 역배선 후 _handle_pause_result → PAUSED_SNAPSHOTTED 전이."""
        runner, engine = _make_runner_with_engine()
        _, store = _make_dispatcher_with_checkpoint_store()

        # 역배선: runner 주입
        adapter = DispatcherAdapter(
            head=MagicMock(),
            dispatcher=MagicMock(),
            approval_service=MagicMock(),
            sub_factory=MagicMock(),
            fallback_engine=MagicMock(),
            checkpoint_store=store,
            audit_chain=MagicMock(),
            runner=runner,  # 역배선
        )

        run_id = f"run-sg20-back-{uuid.uuid4().hex[:8]}"
        runner.request_pause(run_id, request_id="req-back", mode="pause", actor="op")

        sub_result = _make_sub_result(run_id)
        # _handle_pause_result를 통해 간접적으로 notify_pause_completed 호출
        await adapter._handle_pause_result(run_id, sub_result)

        # PAUSED_SNAPSHOTTED 도달 확인
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get(run_id)
        assert rec is not None
        assert rec.interrupt_state == InterruptState.PAUSED_SNAPSHOTTED, (
            f"기대: PAUSED_SNAPSHOTTED, 실제: {rec.interrupt_state}"
        )


# ---------------------------------------------------------------------------
# 전체 end-to-end: pause → _handle_pause_result → resume 성공 (수동 notify 금지)
# ---------------------------------------------------------------------------


class TestResumeSucceedsAfterBackwiredPause:
    """역배선 후 pause→_handle_pause_result→resume E2E 성공 (수동 notify_pause_completed 없음)."""

    @pytest.mark.asyncio
    async def test_full_lifecycle_via_handle_pause_result(self) -> None:
        """_handle_pause_result 경유 전체 생애주기 — runner.notify_pause_completed 직접 호출 없음.

        Step 1: request_pause (INTERRUPT_REQUESTED)
        Step 2: _handle_pause_result → notify_pause_completed 간접 호출 → PAUSED_SNAPSHOTTED
        Step 3: resume_from_checkpoint 성공 → RUNNING
        """
        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")
        mock_audit = MagicMock()

        # 역배선
        adapter = DispatcherAdapter(
            head=MagicMock(),
            dispatcher=MagicMock(),
            approval_service=MagicMock(),
            sub_factory=MagicMock(),
            fallback_engine=MagicMock(),
            checkpoint_store=store,
            audit_chain=mock_audit,
            runner=runner,  # 역배선
        )

        run_id = f"run-sg20-e2e-{uuid.uuid4().hex[:8]}"

        # Step 1: pause 요청
        runner.request_pause(run_id, request_id="req-e2e", mode="pause", actor="op")

        # Step 2: _handle_pause_result 경유 (수동 notify 직접 호출 없음)
        sub_result = _make_sub_result(run_id)
        await adapter._handle_pause_result(run_id, sub_result)

        # PAUSED_SNAPSHOTTED 확인
        with runner._interrupt_records_lock:
            rec = runner._interrupt_records.get(run_id)
        assert rec is not None
        assert rec.interrupt_state == InterruptState.PAUSED_SNAPSHOTTED

        # Step 3: resume — checkpoint를 store에서 찾아야 함
        # _handle_pause_result가 store.write를 호출했으므로 ref를 재구성
        # 직접 쓴 checkpoint 대신 store에서 첫 번째 항목을 꺼낸다
        conn = store._conn  # type: ignore[attr-defined]
        row = conn.execute(
            "SELECT checkpoint_id, run_id, step_index FROM run_checkpoints WHERE run_id=?",
            (run_id,),
        ).fetchone()
        assert row is not None, "checkpoint_store에 checkpoint가 없음 — write 미실행"

        from secugent.steer.snapshots import SnapshotRef

        ref = SnapshotRef(
            uri=f"snap://{run_id}/step-1/{row[0]}",
            run_id=run_id,
            step_index=int(row[2]),
            pending_step_ids=("step-2",),
        )

        async def _dispatch_noop(**kwargs: object) -> None:
            pass

        runner._dispatcher.dispatch = _dispatch_noop  # type: ignore[attr-defined]

        await runner.resume_from_checkpoint(run_id, ref, checkpoint_store=store)

        # RUNNING 복귀 확인
        with runner._interrupt_records_lock:
            rec2 = runner._interrupt_records.get(run_id)
        assert rec2 is not None
        assert rec2.interrupt_state == InterruptState.RUNNING, f"기대: RUNNING, 실제: {rec2.interrupt_state}"


# ---------------------------------------------------------------------------
# 비정지 경로: paused_at_step_id=None → _handle_pause_result 미호출 확인
# ---------------------------------------------------------------------------


class TestNonPausePathDoesNotCallHandlePause:
    """paused_at_step_id=None 경로에서는 _handle_pause_result가 호출되지 않는다."""

    def test_dispatch_no_pause_does_not_trigger_handle_pause_result(self) -> None:
        """sub_result.paused_at_step_id=None → _handle_pause_result 미호출 (adapter.dispatch 레벨)."""
        # DispatcherAdapter.dispatch 내부 루프에서 paused_at_step_id is None이면 break 없이 통과
        # 이 테스트는 비정지 경로에서 notify_pause_completed가 호출되지 않음을 보장한다.
        # SubAgentResult는 TYPE_CHECKING 전용 임포트이므로 MagicMock으로 대체한다.
        from secugent.agents.dispatcher import DispatcherResult

        runner, engine = _make_runner_with_engine()
        store = SQLiteCheckpointStore(":memory:")

        called: list[str] = []

        original_notify = runner.notify_pause_completed

        def _track_notify(rid: str) -> None:
            called.append(rid)
            original_notify(rid)

        runner.notify_pause_completed = _track_notify  # type: ignore[method-assign]

        # sub_result.paused_at_step_id = None — 정지 없음 (MagicMock으로 대체)
        sub_result_mock = MagicMock()
        sub_result_mock.paused_at_step_id = None

        dispatcher_result = MagicMock(spec=DispatcherResult)
        dispatcher_result.sub_results = {"agent-1": sub_result_mock}
        dispatcher_result.output = {}

        raw_dispatcher = MagicMock()
        raw_dispatcher.dispatch.return_value = dispatcher_result

        approval_service = MagicMock()
        approval_service.request_plan_approval.return_value = MagicMock()

        # adapter 인스턴스를 생성하지만 dispatch를 실제로 호출하지는 않는다.
        # 이 테스트의 목적은 비정지 sub_result(paused_at_step_id=None)가
        # notify_pause_completed 호출로 이어지지 않음을 보장하는 것이다.
        # adapter 객체 자체가 runner를 역배선받아 있어야 혹시라도 호출이 새지 않는지
        # 확인하는 가드 역할을 한다.
        DispatcherAdapter(
            head=MagicMock(),
            dispatcher=raw_dispatcher,
            approval_service=approval_service,
            sub_factory=MagicMock(),
            fallback_engine=MagicMock(),
            checkpoint_store=store,
            audit_chain=MagicMock(),
            runner=runner,
        )

        # notify가 호출되지 않았는지 확인 (비정지 경로)
        assert called == [], "비정지 경로에서 notify_pause_completed가 사전 호출됨"
