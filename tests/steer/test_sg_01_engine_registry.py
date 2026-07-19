# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-01 회귀 테스트: runner._engine_registry vs AppState._run_engines 분리 문제.

external_engine_registry가 설정되면 request_pause가 AppState의 엔진을 찾는다.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from secugent.orchestrator.runner import RunNotDispatchingError, RunOrchestrator


class _FakeRegistry:
    """AppState처럼 동작하는 최소 엔진 레지스트리."""

    def __init__(self) -> None:
        self._engines: dict[str, object] = {}

    def register_run_engine(self, run_id: str, engine: object) -> None:
        self._engines[run_id] = engine

    def unregister_run_engine(self, run_id: str) -> None:
        self._engines.pop(run_id, None)

    def resolve_run_engine(self, run_id: str) -> object | None:
        return self._engines.get(run_id)


class TestEngineRegistryDelegation:
    """SG-01: external_engine_registry 위임 검증."""

    def test_request_pause_finds_engine_via_external_registry(self) -> None:
        """external_engine_registry에 등록된 엔진으로 request_pause가 성공함."""
        planner = MagicMock()
        dispatcher = MagicMock()
        registry = _FakeRegistry()

        orchestrator = RunOrchestrator(
            planner=planner,
            dispatcher=dispatcher,
            external_engine_registry=registry,
        )

        # 엔진을 external registry에 직접 등록 (DispatcherAdapter가 하는 것처럼)
        mock_engine = MagicMock()
        registry.register_run_engine("run-001", mock_engine)

        # request_pause가 external registry에서 엔진을 찾아야 함
        orchestrator.request_pause(
            "run-001",
            request_id="req-001",
            mode="pause",
            actor="operator:test",
        )
        mock_engine.set_paused.assert_called_once_with(
            paused=True,
            request_id="req-001",
            actor="operator:test",
            stop_mode=False,
        )

    def test_request_pause_raises_when_engine_not_in_external_registry(self) -> None:
        """external registry에 없는 run_id → RunNotDispatchingError."""
        registry = _FakeRegistry()
        orchestrator = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            external_engine_registry=registry,
        )
        with pytest.raises(RunNotDispatchingError):
            orchestrator.request_pause(
                "nonexistent-run",
                request_id="req-x",
                mode="pause",
                actor="op",
            )

    def test_internal_registry_used_when_no_external(self) -> None:
        """external_engine_registry=None이면 내부 registry 사용."""
        orchestrator = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        mock_engine = MagicMock()
        orchestrator.register_run_engine("run-internal", mock_engine)

        orchestrator.request_pause(
            "run-internal",
            request_id="req-int",
            mode="stop",
            actor="op",
        )
        mock_engine.set_paused.assert_called_once_with(
            paused=True,
            request_id="req-int",
            actor="op",
            stop_mode=True,
        )

    def test_register_delegates_to_external_registry(self) -> None:
        """register_run_engine이 external registry에 위임한다."""
        registry = _FakeRegistry()
        orchestrator = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            external_engine_registry=registry,
        )
        mock_engine = MagicMock()
        orchestrator.register_run_engine("run-ext", mock_engine)

        # 내부 레지스트리에는 없고 외부에만 있어야 함
        assert orchestrator._engine_registry == {}
        assert registry.resolve_run_engine("run-ext") is mock_engine

    def test_deregister_delegates_to_external_registry(self) -> None:
        """deregister_run_engine이 external registry의 unregister_run_engine을 호출한다."""
        registry = _FakeRegistry()
        orchestrator = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            external_engine_registry=registry,
        )
        mock_engine = MagicMock()
        registry.register_run_engine("run-ext2", mock_engine)

        orchestrator.deregister_run_engine("run-ext2")
        assert registry.resolve_run_engine("run-ext2") is None
