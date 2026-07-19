# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-14 회귀 테스트: pause_snapshot() 원자적 읽기 + SubAgent 외부 락 미사용."""

from __future__ import annotations

from unittest.mock import MagicMock

from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations


def _make_engine() -> OversightEngine:
    regs = MagicMock(spec=Regulations)
    regs.version = "1.0.0"
    return OversightEngine(regulations=regs)


class TestPauseSnapshot:
    """pause_snapshot()이 원자적으로 두 필드를 반환한다."""

    def test_initial_state(self) -> None:
        engine = _make_engine()
        is_paused, is_stop = engine.pause_snapshot()
        assert is_paused is False
        assert is_stop is False

    def test_after_set_paused(self) -> None:
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-1", actor="op", stop_mode=False)
        is_paused, is_stop = engine.pause_snapshot()
        assert is_paused is True
        assert is_stop is False

    def test_after_set_stop_mode(self) -> None:
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-2", actor="op", stop_mode=True)
        is_paused, is_stop = engine.pause_snapshot()
        assert is_paused is True
        assert is_stop is True

    def test_consistent_with_individual_methods(self) -> None:
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-3", actor="op", stop_mode=True)
        is_paused, is_stop = engine.pause_snapshot()
        assert is_paused == engine.is_paused()
        assert is_stop == engine.is_stop_mode()

    def test_sub_agent_uses_pause_snapshot_not_private_lock(self) -> None:
        """SubAgent가 _patches_lock 내부락을 직접 획득(with)하지 않음."""
        import inspect

        from secugent.agents.sub_agent import SubAgent

        source = inspect.getsource(SubAgent.run)
        # The comment may mention _patches_lock for documentation, but the code
        # must not acquire it via `with self._oversight._patches_lock`.
        assert "with" not in source or "self._oversight._patches_lock" not in source, (
            "SubAgent.run이 여전히 _patches_lock을 직접 획득하고 있습니다 (SG-14)"
        )
        # Positive check: pause_snapshot() public API must be used instead.
        assert "pause_snapshot()" in source, (
            "SubAgent.run이 pause_snapshot() 공개 API를 사용하지 않습니다 (SG-14)"
        )
