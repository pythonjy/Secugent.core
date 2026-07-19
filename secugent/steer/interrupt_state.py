# SPDX-License-Identifier: Apache-2.0
"""STEER 인터럽트 상태기계.

설계 결정: umbrella RunState는 항상 EXECUTING을 유지한다.
interrupt_state는 RunRecord에 additive 필드로 붙는 별도 enum이다.

상태 전이 (합법 전이만 허용; 그 외는 InterruptStateError — INV-SM-1):

  RUNNING → INTERRUPT_REQUESTED → PAUSING → PAUSED_SNAPSHOTTED → RESUMING → RUNNING
                                           → REINSTRUCTING
                                           → ABORTED (mode:stop)
                                           → FAILED (스냅샷 오류 E4)

비합법 전이는 조용히 흡수하지 않고 반드시 raise한다 (INV-SM-1).
D-K: PAUSING 또는 RESUMING 중에 도착하는 반대 verb도 raise한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from secugent.orchestrator.state import RunState

__all__ = [
    "InterruptState",
    "InterruptStateError",
    "RunInterruptRecord",
]


class InterruptState(StrEnum):
    """인터럽트 세부 상태.

    umbrella RunState(EXECUTING)와 별도로 관리된다 (D-A).
    """

    RUNNING = "RUNNING"
    """정상 실행 중 (기본값)."""

    INTERRUPT_REQUESTED = "INTERRUPT_REQUESTED"
    """pause/stop 요청 수신, 스텝 경계 대기 중."""

    PAUSING = "PAUSING"
    """현재 스텝 완료 대기 중 (INV-R1: cooperative step-boundary)."""

    PAUSED_SNAPSHOTTED = "PAUSED_SNAPSHOTTED"
    """스냅샷 기록 완료, HITL/재지시 대기 중."""

    REINSTRUCTING = "REINSTRUCTING"
    """자연어 재지시 처리 중."""

    RESUMING = "RESUMING"
    """재개 신호 수신, 체크포인트에서 재디스패치 중."""

    ABORTED = "ABORTED"
    """mode:stop → 정지 완료 (terminal, D-J).
    umbrella RunState는 CANCELLED로 전환된다."""

    FAILED = "FAILED"
    """스냅샷 오류 등으로 인한 인터럽트 실패 (E4).
    umbrella RunState는 FAILED로 전환된다."""


# ---------------------------------------------------------------------------
# 합법 전이 테이블 (INV-SM-1)
# ---------------------------------------------------------------------------

# 각 상태에서 허용되는 다음 상태 집합.
# 이 테이블에 없는 전이는 모두 InterruptStateError.
_LEGAL_TRANSITIONS: dict[InterruptState, frozenset[InterruptState]] = {
    InterruptState.RUNNING: frozenset({InterruptState.INTERRUPT_REQUESTED}),
    InterruptState.INTERRUPT_REQUESTED: frozenset({InterruptState.PAUSING}),
    InterruptState.PAUSING: frozenset(
        {
            InterruptState.PAUSED_SNAPSHOTTED,
            InterruptState.ABORTED,  # mode:stop (D-J)
            InterruptState.FAILED,  # 스냅샷 오류 (E4)
        }
    ),
    InterruptState.PAUSED_SNAPSHOTTED: frozenset(
        {
            InterruptState.REINSTRUCTING,
            InterruptState.RESUMING,
        }
    ),
    InterruptState.REINSTRUCTING: frozenset(
        {
            InterruptState.RESUMING,
            InterruptState.PAUSED_SNAPSHOTTED,  # 재지시 처리 후 재대기
        }
    ),
    InterruptState.RESUMING: frozenset({InterruptState.RUNNING}),
    # Terminal states — 전이 없음
    InterruptState.ABORTED: frozenset(),
    InterruptState.FAILED: frozenset(),
}

# 비정지 상태 (D-K): 이 상태에서 새 인터럽트/재개 verb 도착 시 raise
_NON_QUIESCENT: frozenset[InterruptState] = frozenset({InterruptState.PAUSING, InterruptState.RESUMING})


class InterruptStateError(RuntimeError):
    """불법 인터럽트 상태 전이 (INV-SM-1).

    조용히 흡수하지 않음 — 항상 raise.
    """

    def __init__(self, from_state: InterruptState, to_state: InterruptState) -> None:
        super().__init__(
            f"불법 인터럽트 전이: {from_state!r} → {to_state!r}. "
            f"합법 전이: {sorted(_LEGAL_TRANSITIONS.get(from_state, frozenset()))}"
        )
        self.from_state = from_state
        self.to_state = to_state


@dataclass
class RunInterruptRecord:
    """단일 런의 인터럽트 상태를 추적하는 레코드.

    RunRecord의 additive 필드로 포함되거나 (D-A), 독립 캐시로 runner에 보관된다.
    """

    run_id: str
    interrupt_state: InterruptState = field(default=InterruptState.RUNNING)

    @property
    def umbrella_state(self) -> RunState:
        """D-A: umbrella RunState는 항상 EXECUTING — interrupt_state와 무관."""
        return RunState.EXECUTING

    def is_quiescent(self) -> bool:
        """D-K: PAUSING/RESUMING은 비정지(non-quiescent) — 새 verb 거부 대상."""
        return self.interrupt_state not in _NON_QUIESCENT

    def transition_to(self, new_state: InterruptState) -> None:
        """상태 전이. 불법 전이 → InterruptStateError (INV-SM-1).

        INV-SM-1: 모든 불법 전이는 raise (절대 조용히 흡수하지 않음).
        """
        allowed = _LEGAL_TRANSITIONS.get(self.interrupt_state, frozenset())
        if new_state not in allowed:
            raise InterruptStateError(self.interrupt_state, new_state)
        self.interrupt_state = new_state
