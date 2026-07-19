# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-16 회귀 테스트: runner.py 협력자 Any 타입 → Protocol 도입.

mypy --strict 하에 engine/checkpoint_store/steer_handler 협력자가
구체 Protocol 타입으로 좁혀졌는지 확인한다.
런타임에서는 Protocol을 직접 인스턴스화할 수 없으므로,
runner의 시그니처가 Protocol을 받는지·올바른 메서드를 호출할 수 있는지를
stub으로 단언한다.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from secugent.orchestrator.runner import (
    CheckpointStoreProtocol,
    OversightEngineProtocol,
    RunOrchestrator,
    SteerHandlerProtocol,
)

# ---------------------------------------------------------------------------
# Protocol 존재 및 메서드 구조 단언
# ---------------------------------------------------------------------------


class TestOversightEngineProtocol:
    """OversightEngineProtocol: set_paused / is_paused 시그니처 존재."""

    def test_protocol_has_set_paused(self) -> None:
        assert hasattr(OversightEngineProtocol, "set_paused"), (
            "OversightEngineProtocol에 set_paused 없음 (SG-20260621-16)"
        )

    def test_protocol_has_is_paused(self) -> None:
        assert hasattr(OversightEngineProtocol, "is_paused"), (
            "OversightEngineProtocol에 is_paused 없음 (SG-20260621-16)"
        )

    def test_concrete_engine_satisfies_protocol(self) -> None:
        """OversightEngine이 Protocol을 만족함."""
        from secugent.core.mechanical_oversight import OversightEngine
        from secugent.core.regulations import Regulations

        engine = OversightEngine(Regulations(version="0.1.0"))
        assert isinstance(engine, OversightEngineProtocol), (
            "OversightEngine이 OversightEngineProtocol을 만족하지 않음"
        )


class TestCheckpointStoreProtocol:
    """CheckpointStoreProtocol: write / resolve 시그니처 존재."""

    def test_protocol_has_write(self) -> None:
        assert hasattr(CheckpointStoreProtocol, "write"), (
            "CheckpointStoreProtocol에 write 없음 (SG-20260621-16)"
        )

    def test_protocol_has_resolve(self) -> None:
        assert hasattr(CheckpointStoreProtocol, "resolve"), (
            "CheckpointStoreProtocol에 resolve 없음 (SG-20260621-16)"
        )

    def test_sqlite_store_satisfies_protocol(self, tmp_path: Any) -> None:
        """SQLiteCheckpointStore가 Protocol을 만족함."""
        from secugent.steer.snapshots import SQLiteCheckpointStore

        store = SQLiteCheckpointStore(str(tmp_path / "ckpt.db"))
        try:
            assert isinstance(store, CheckpointStoreProtocol), (
                "SQLiteCheckpointStore가 CheckpointStoreProtocol을 만족하지 않음"
            )
        finally:
            store.close()


class TestSteerHandlerProtocol:
    """SteerHandlerProtocol: emit_resume_from_checkpoint 시그니처 존재."""

    def test_protocol_has_emit_resume_from_checkpoint(self) -> None:
        assert hasattr(SteerHandlerProtocol, "emit_resume_from_checkpoint"), (
            "SteerHandlerProtocol에 emit_resume_from_checkpoint 없음 (SG-20260621-16)"
        )

    def test_concrete_handler_satisfies_protocol(self) -> None:
        """SteerHandler가 Protocol을 만족함."""
        from secugent.core.event_store import EventStore
        from secugent.core.mechanical_oversight import OversightEngine
        from secugent.core.regulations import Regulations
        from secugent.steer.steer import SteerHandler

        engine = OversightEngine(Regulations(version="0.1.0"))
        store = EventStore(":memory:")
        handler = SteerHandler(oversight=engine, event_store=store)
        assert isinstance(handler, SteerHandlerProtocol), (
            "SteerHandler가 SteerHandlerProtocol을 만족하지 않음"
        )


# ---------------------------------------------------------------------------
# runner의 resume_from_checkpoint가 Protocol 타입으로 협력자를 받는지 확인
# (런타임 stub이 올바른 메서드를 호출받는지 단언)
# ---------------------------------------------------------------------------


class TestRunnerUsesProtocols:
    """runner.resume_from_checkpoint가 Protocol 메서드만 호출함."""

    @pytest.mark.asyncio
    async def test_resume_calls_checkpoint_store_resolve(self) -> None:
        """checkpoint_store.resolve()가 호출됨 (Any가 아닌 Protocol 메서드)."""
        from secugent.steer.snapshots import RunCheckpoint, SnapshotRef

        checkpoint = RunCheckpoint(
            checkpoint_id="ckpt-proto-test",
            run_id="run-proto",
            tenant_id="legacy-default",
            step_index=1,
            pending_step_ids=["s2"],
            completed_step_ids=["s1"],
            session_patch_set=[],
            patch_remaining_ttl={},
            regulations_version="0.1.0",
            envelope_hash="eh-test",
            rule_of_two_axes=["untrusted_input"],
            approval_scope_ref="scope-ref",
            staged_effect_disposition=[],
            file_before_images_ref={},
            directive_log_ref=[],
            created_at="2026-06-21T09:00:00+09:00",
            actor="role:operator:u1",
        )
        store_mock = MagicMock()
        store_mock.resolve.return_value = checkpoint

        dispatcher_mock = MagicMock()
        dispatcher_mock.dispatch = MagicMock(return_value=__import__("asyncio").sleep(0))

        planner_mock = MagicMock()

        from secugent.orchestrator.state import InMemoryRunStateStore

        runner = RunOrchestrator(
            planner=planner_mock,
            dispatcher=dispatcher_mock,
            state_store=InMemoryRunStateStore(),
        )
        # 런 상태 만들기
        await runner._store.create("run-proto", "cmd", {})

        ref = SnapshotRef(
            uri="snap://run-proto/step-1/ckpt-proto-test",
            run_id="run-proto",
            step_index=1,
            pending_step_ids=("s2",),
        )
        await runner.resume_from_checkpoint(
            "run-proto",
            ref,
            checkpoint_store=store_mock,
        )
        # Protocol 메서드 resolve()가 호출됐어야 한다
        store_mock.resolve.assert_called_once_with(ref)
