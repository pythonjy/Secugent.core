# SPDX-License-Identifier: Apache-2.0
"""회귀 테스트: adapters.py E4 steer.failed §C-2 필수 필드 검증.

결함 요약: DispatcherAdapter._handle_pause_result의 E4 경로(checkpoint_store.write 예외)에서
생성하는 steer.failed 이벤트 payload에 §C-2 필수 필드
(decision, input_hash, regulations_version, rule_of_two_axes, risk_score, actor dict)가
누락되어 있다.

테스트 구조:
  - 직접 DispatcherAdapter._handle_pause_result 호출
  - checkpoint_store.write가 예외를 던지도록 mock 설정
  - audit_chain.append_event가 받은 Event의 payload 필드 단언
  - inline 딕셔너리 시뮬레이션 금지 (실제 구현 코드 경유)
"""

from __future__ import annotations

import hashlib
import uuid
from unittest.mock import MagicMock

import pytest

from secugent.core.contracts import Event
from secugent.orchestrator.adapters import DispatcherAdapter
from secugent.steer.snapshots import SQLiteCheckpointStore

# ---------------------------------------------------------------------------
# 공통 픽스처 / 헬퍼
# ---------------------------------------------------------------------------

_REGULATIONS_VERSION = "2.5.1"
_RULE_OF_TWO_AXES = ["sensitive_access", "external_comm"]


def _make_sub_result(run_id: str) -> MagicMock:
    """_handle_pause_result에 주입할 mock sub_result."""
    sr = MagicMock()
    sr.paused_at_step_id = "step-1"
    sr.tenant_id = "tenant-sg23b"
    sr.step_index = 1
    sr.pending_step_ids = ["step-2"]
    sr.completed_step_ids = ["step-1"]
    sr.session_patch_set = []
    sr.patch_remaining_ttl = {}
    sr.regulations_version = _REGULATIONS_VERSION
    sr.envelope_hash = "envhash-sg23b"
    sr.rule_of_two_axes = _RULE_OF_TWO_AXES
    sr.approval_scope_ref = ""
    sr.staged_effect_disposition = []
    sr.file_before_images_ref = {}
    sr.directive_log_ref = []
    sr.actor = "op"
    return sr


def _make_adapter_with_failing_store() -> tuple[DispatcherAdapter, MagicMock, MagicMock]:
    """checkpoint_store.write가 예외를 던지는 DispatcherAdapter를 반환한다.

    Returns:
        adapter: 검사 대상 DispatcherAdapter
        failing_store: write가 RuntimeError를 던지는 mock checkpoint store
        mock_audit: append_event 호출을 캡처하는 mock audit chain
    """
    failing_store = MagicMock()
    failing_store.write.side_effect = RuntimeError("disk full — test-induced failure")

    mock_audit = MagicMock()
    mock_audit.append_event.return_value = None

    adapter = DispatcherAdapter(
        head=MagicMock(),
        dispatcher=MagicMock(),
        approval_service=MagicMock(),
        sub_factory=MagicMock(),
        fallback_engine=MagicMock(),
        checkpoint_store=failing_store,
        audit_chain=mock_audit,
        runner=None,
    )
    return adapter, failing_store, mock_audit


# ---------------------------------------------------------------------------
# E4 경로 steer.failed §C-2 필드 검증 (핵심)
# ---------------------------------------------------------------------------


class TestE4SteerFailedC2Fields:
    """E4 체크포인트 write 실패 → steer.failed payload §C-2 필수 필드 포함."""

    @pytest.mark.asyncio
    async def test_steer_failed_has_decision_reject(self) -> None:
        """E4 steer.failed payload에 decision='reject'가 있어야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        mock_audit.append_event.assert_called_once()
        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        assert event.payload["decision"] == "reject"

    @pytest.mark.asyncio
    async def test_steer_failed_has_input_hash(self) -> None:
        """E4 steer.failed payload에 input_hash가 sha256('checkpoint_write_failed') 값이어야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-ih-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        expected_hash = hashlib.sha256(b"checkpoint_write_failed").hexdigest()
        assert event.payload["input_hash"] == expected_hash, (
            f"input_hash 불일치: {event.payload.get('input_hash')!r} != {expected_hash!r}"
        )

    @pytest.mark.asyncio
    async def test_steer_failed_has_regulations_version(self) -> None:
        """E4 steer.failed payload에 regulations_version이 checkpoint 값과 일치해야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-rv-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        assert event.payload["regulations_version"] == _REGULATIONS_VERSION, (
            f"regulations_version 불일치: {event.payload.get('regulations_version')!r}"
        )

    @pytest.mark.asyncio
    async def test_steer_failed_has_rule_of_two_axes(self) -> None:
        """E4 steer.failed payload에 rule_of_two_axes가 checkpoint 값과 일치해야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-ro2-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        assert event.payload["rule_of_two_axes"] == _RULE_OF_TWO_AXES, (
            f"rule_of_two_axes 불일치: {event.payload.get('rule_of_two_axes')!r}"
        )

    @pytest.mark.asyncio
    async def test_steer_failed_has_risk_score_none(self) -> None:
        """E4 steer.failed payload에 risk_score=None이 있어야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-rs-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        assert "risk_score" in event.payload, "risk_score 필드 누락"
        assert event.payload["risk_score"] is None

    @pytest.mark.asyncio
    async def test_steer_failed_actor_is_structured_dict_in_payload(self) -> None:
        """E4 steer.failed payload에 actor가 {'type': 'sec', 'id': 'system'} 구조여야 한다."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-act-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"
        actor = event.payload.get("actor")
        assert isinstance(actor, dict), f"actor는 dict여야 함, 실제: {type(actor)!r} = {actor!r}"
        assert actor.get("type") == "sec", f"actor.type 불일치: {actor.get('type')!r}"
        assert actor.get("id") == "system", f"actor.id 불일치: {actor.get('id')!r}"

    @pytest.mark.asyncio
    async def test_steer_failed_all_c2_fields_present(self) -> None:
        """E4 steer.failed payload에 §C-2 필수 필드 전체가 있어야 한다 (통합 단언)."""
        adapter, _, mock_audit = _make_adapter_with_failing_store()
        run_id = f"run-sg23b-all-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        event: Event = mock_audit.append_event.call_args[0][0]
        assert event.type == "steer.failed"

        required = {
            "decision",
            "input_hash",
            "regulations_version",
            "rule_of_two_axes",
            "risk_score",
            "actor",
            "gate",
            "rationale",
            "error",
        }
        missing = required - set(event.payload.keys())
        assert not missing, f"§C-2 필수 필드 누락: {missing}"


# ---------------------------------------------------------------------------
# steer.paused actor 구조화 검증 (NEW-2/NEW-3 정렬)
# ---------------------------------------------------------------------------


class TestSteerPausedActorStructured:
    """steer.paused 이벤트의 actor도 구조화 dict여야 한다 (NEW-2/NEW-3 정렬)."""

    @pytest.mark.asyncio
    async def test_steer_paused_actor_is_structured(self) -> None:
        """정상 경로(write 성공)에서 steer.paused payload의 actor가 구조화 dict여야 한다."""
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
            runner=None,
        )

        run_id = f"run-sg23b-paused-{uuid.uuid4().hex[:8]}"
        sub_result = _make_sub_result(run_id)

        await adapter._handle_pause_result(run_id, sub_result)

        # steer.paused 이벤트 찾기
        events = [call[0][0] for call in mock_audit.append_event.call_args_list]
        paused_events = [e for e in events if e.type == "steer.paused"]
        assert len(paused_events) >= 1, "steer.paused 이벤트가 없음"

        paused_payload = paused_events[0].payload
        actor = paused_payload.get("actor")
        assert isinstance(actor, dict), (
            f"steer.paused payload.actor는 dict여야 함, 실제: {type(actor)!r} = {actor!r}"
        )
        assert "type" in actor, "actor.type 누락"
        assert "id" in actor, "actor.id 누락"
