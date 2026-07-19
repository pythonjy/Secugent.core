# SPDX-License-Identifier: Apache-2.0
"""회귀 테스트: dedup 프로브가 다른 request_id 도착 시 엔진 상태를 오염시키지 않음.

dedup 판정에서 set_paused(mutate)를 호출하던 코드가
다른 request_id를 가진 두 번째 요청의 stop_mode/_pause_request_id/_pause_actor를
덮어쓰는 버그를 재현하고 고정한다.

시나리오:
  1. req-A mode="pause" (stop_mode=False) 로 INTERRUPT_REQUESTED 상태 진입.
  2. req-B mode="stop"  (stop_mode=True)  로 재진입 — InterruptStateError 기대.
  3. 에러 발생 전·후에 엔진 pause_snapshot == (True, False) 불변,
     current_pause_request_id() == "req-A" 불변이어야 한다.
"""

from __future__ import annotations

import pytest

from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.orchestrator.runner import RunOrchestrator
from secugent.orchestrator.state import InMemoryRunStateStore


def _make_runner() -> RunOrchestrator:
    from unittest.mock import MagicMock

    return RunOrchestrator(
        planner=MagicMock(),
        dispatcher=MagicMock(),
        state_store=InMemoryRunStateStore(),
    )


class TestDedupProbeDoesNotMutateEngine:
    """dedup 판정 프로브는 엔진 상태를 절대 변경하지 않는다."""

    def test_different_request_id_raises_without_mutating_engine(self) -> None:
        """IR 상태(req-A pause)에서 req-B stop → InterruptStateError 발생 AND 엔진 불변.

        BLOCKING-1 핵심 불변조건:
          1. InterruptStateError가 raise돼야 한다.
          2. engine.pause_snapshot() == (True, False) — stop_mode가 True로 뒤집혀선 안 됨.
          3. engine.current_pause_request_id() == "req-A" — _pause_request_id가 변경돼선 안 됨.
        """
        from secugent.orchestrator.runner import InterruptStateError

        runner = _make_runner()
        engine = OversightEngine(Regulations(version="0.1.0"))
        run_id = "run-b1-immutable"
        runner.register_run_engine(run_id, engine)

        # 1단계: req-A mode=pause → INTERRUPT_REQUESTED 상태, stop_mode=False
        result_a = runner.request_pause(run_id, request_id="req-A", mode="pause", actor="op:alice")
        assert result_a is True
        # 엔진 초기 상태 확인
        assert engine.pause_snapshot() == (True, False), "첫 pause 후 stop_mode는 False이어야 함"
        assert engine.current_pause_request_id() == "req-A"

        # 2단계: req-B mode=stop → InterruptStateError, 엔진 상태 불변이어야 함
        with pytest.raises(InterruptStateError):
            runner.request_pause(run_id, request_id="req-B", mode="stop", actor="op:bob")

        # 핵심 불변: 엔진 상태가 오염되지 않았어야 한다
        assert engine.pause_snapshot() == (True, False), (
            "req-B stop 거부 후에도 stop_mode는 False이어야 함 "
            "(BLOCKING-1: dedup 프로브가 엔진 상태를 오염시킴)"
        )
        assert engine.current_pause_request_id() == "req-A", (
            "_pause_request_id가 req-B로 덮어써져선 안 됨 (BLOCKING-1: §9.1 귀속 오염)"
        )

    def test_same_request_id_still_returns_false(self) -> None:
        """동일 request_id 재요청: False 반환 AND 엔진 불변 (회귀 방지)."""
        runner = _make_runner()
        engine = OversightEngine(Regulations(version="0.1.0"))
        run_id = "run-b1-dup-same"
        runner.register_run_engine(run_id, engine)

        runner.request_pause(run_id, request_id="req-same", mode="pause", actor="op:alice")
        assert engine.current_pause_request_id() == "req-same"

        result2 = runner.request_pause(run_id, request_id="req-same", mode="pause", actor="op:alice")
        assert result2 is False
        # 엔진 상태 여전히 동일
        assert engine.pause_snapshot() == (True, False)
        assert engine.current_pause_request_id() == "req-same"

    def test_stop_then_pause_different_id_raises_without_mutating(self) -> None:
        """mode=stop으로 IR 진입 후 pause 요청(다른 req) → raise AND stop_mode 불변."""
        from secugent.orchestrator.runner import InterruptStateError

        runner = _make_runner()
        engine = OversightEngine(Regulations(version="0.1.0"))
        run_id = "run-b1-stop-then-pause"
        runner.register_run_engine(run_id, engine)

        runner.request_pause(run_id, request_id="req-stop", mode="stop", actor="op:alice")
        # stop_mode=True 설정됨
        assert engine.pause_snapshot() == (True, True)
        assert engine.current_pause_request_id() == "req-stop"

        # 다른 req로 pause → raise, stop_mode는 여전히 True이어야 함
        with pytest.raises(InterruptStateError):
            runner.request_pause(run_id, request_id="req-pause", mode="pause", actor="op:bob")

        assert engine.pause_snapshot() == (True, True), "req-pause 거부 후에도 stop_mode는 True이어야 함"
        assert engine.current_pause_request_id() == "req-stop"
