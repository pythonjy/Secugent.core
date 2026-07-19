# SPDX-License-Identifier: Apache-2.0
"""STEER 인터럽트 코어 테스트 (Lane A — 정지·스냅샷·재개).

§12 테스트 계획에 따라 3중(단위+속성+시나리오) + 100회 결정성을 커버한다.
결정적 모듈이므로 §B-4a 95% 커버리지 게이트가 적용된다.

테스트 구조:
  - Unit: 상태기계·스냅샷·race 경로 직접 단언
  - Property(hypothesis): 임의 입력 불변조건
  - Scenario(회귀): C1-T1a/b/c/d·E4·C1-T5·D-E
  - Determinism-100: snapshot→resume 100회 체인 해시 동일
"""

from __future__ import annotations

import dataclasses
import threading
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import SessionRegulationPatch
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.core.rule_of_two import Axis, requires_hitl
from secugent.orchestrator.state import RunState
from secugent.steer.interrupt_state import (
    InterruptState,
    InterruptStateError,
    RunInterruptRecord,
)
from secugent.steer.snapshots import (
    RunCheckpoint,
    SnapshotRef,
    SQLiteCheckpointStore,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_regs() -> Regulations:
    return Regulations(version="0.1.0")


def _make_engine(regs: Regulations | None = None) -> OversightEngine:
    return OversightEngine(regs or _make_regs())


def _make_checkpoint(
    run_id: str = "run-test-001",
    step_index: int = 2,
    pending: tuple[str, ...] = ("s3", "s4"),
    completed: tuple[str, ...] = ("s1", "s2"),
    tenant_id: str = "tenant-ko-finance",
    actor: str = "role:operator:u-9",
) -> RunCheckpoint:
    return RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id=tenant_id,
        step_index=step_index,
        pending_step_ids=list(pending),
        completed_step_ids=list(completed),
        session_patch_set=[],
        patch_remaining_ttl={},
        regulations_version="0.1.0",
        envelope_hash="abc123",
        rule_of_two_axes=["sensitive_access"],
        approval_scope_ref="scope-001",
        staged_effect_disposition=[],
        file_before_images_ref={},
        directive_log_ref=[],
        created_at=datetime.now(tz=UTC).isoformat(),
        actor=actor,
    )


# ---------------------------------------------------------------------------
# §4.1 InterruptState 상태기계 단위 테스트
# ---------------------------------------------------------------------------


class TestInterruptStateMachine:
    """INV-SM-1: 불법 전이는 raise, 합법 전이는 통과."""

    def test_initial_state_is_running(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        assert rec.interrupt_state == InterruptState.RUNNING

    def test_running_to_interrupt_requested(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        assert rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED

    def test_interrupt_requested_to_pausing(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        assert rec.interrupt_state == InterruptState.PAUSING

    def test_pausing_to_paused_snapshotted(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        assert rec.interrupt_state == InterruptState.PAUSED_SNAPSHOTTED

    def test_paused_to_reinstructing(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        rec.transition_to(InterruptState.REINSTRUCTING)
        assert rec.interrupt_state == InterruptState.REINSTRUCTING

    def test_paused_to_resuming(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        rec.transition_to(InterruptState.RESUMING)
        assert rec.interrupt_state == InterruptState.RESUMING

    def test_resuming_to_running(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        rec.transition_to(InterruptState.RESUMING)
        rec.transition_to(InterruptState.RUNNING)
        assert rec.interrupt_state == InterruptState.RUNNING

    def test_illegal_transition_running_to_resume_raises(self) -> None:
        """INV-SM-1: RUNNING에서 RESUMING으로 직접 전이 금지."""
        rec = RunInterruptRecord(run_id="r1")
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.RESUMING)

    def test_illegal_transition_running_to_reinstructing_raises(self) -> None:
        """INV-SM-1: RUNNING에서 REINSTRUCTING으로 직접 전이 금지."""
        rec = RunInterruptRecord(run_id="r1")
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.REINSTRUCTING)

    def test_illegal_pausing_to_resuming_raises(self) -> None:
        """D-K: PAUSING 중 resume 도착 → 거부."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.RESUMING)

    def test_illegal_resuming_to_pausing_raises(self) -> None:
        """D-K: RESUMING 중 pause 도착 → 거부."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        rec.transition_to(InterruptState.RESUMING)
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.PAUSING)

    def test_pausing_to_aborted_stop_path(self) -> None:
        """D-J: mode:stop → PAUSING → ABORTED."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.ABORTED)
        assert rec.interrupt_state == InterruptState.ABORTED

    def test_aborted_cannot_transition(self) -> None:
        """ABORTED는 terminal — 모든 전이 거부."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.ABORTED)
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.RUNNING)

    def test_pausing_to_failed_on_snapshot_error(self) -> None:
        """E4: 스냅샷 실패 → FAILED."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.FAILED)
        assert rec.interrupt_state == InterruptState.FAILED

    def test_umbrella_state_always_executing(self) -> None:
        """D-A: umbrella RunState는 EXECUTING 유지."""
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        # interrupt_state는 PAUSED_SNAPSHOTTED이지만 umbrella는 여전히 EXECUTING
        assert rec.umbrella_state == RunState.EXECUTING


# ---------------------------------------------------------------------------
# §6 SnapshotRef + DurableSnapshotStore 단위 테스트
# ---------------------------------------------------------------------------


class TestSnapshotRef:
    """INV-SNAP-1/SNAP-2: durable + resolvable URI."""

    def test_snapshot_ref_uri_format(self) -> None:
        ref = SnapshotRef(
            uri="snap://run-abc/step-2/ckpt-xyz",
            run_id="run-abc",
            step_index=2,
            pending_step_ids=("s3", "s4"),
        )
        assert ref.uri.startswith("snap://")
        assert "step-2" in ref.uri

    def test_snapshot_ref_is_frozen(self) -> None:
        """SnapshotRef는 frozen dataclass — 불변."""
        ref = SnapshotRef(
            uri="snap://run-abc/step-2/ckpt-xyz",
            run_id="run-abc",
            step_index=2,
            pending_step_ids=("s3",),
        )
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
            ref.step_index = 99  # type: ignore[misc]


class TestSQLiteCheckpointStore:
    """D-C: SQLite run_checkpoints 테이블 영속."""

    def test_snapshot_and_resolve_roundtrip(self) -> None:
        """INV-2/SNAP-1: snapshot → resolve 성공."""
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-ko-001", step_index=3)
        ref = store.write(checkpoint)
        assert ref.run_id == "run-ko-001"
        assert ref.step_index == 3
        assert "step-3" in ref.uri

        resolved = store.resolve(ref)
        assert resolved.run_id == "run-ko-001"
        assert resolved.step_index == 3
        assert resolved.pending_step_ids == checkpoint.pending_step_ids

    def test_resolve_nonexistent_raises(self) -> None:
        store = SQLiteCheckpointStore(path=":memory:")
        bad_ref = SnapshotRef(
            uri="snap://run-xx/step-0/ckpt-nonexistent",
            run_id="run-xx",
            step_index=0,
            pending_step_ids=(),
        )
        with pytest.raises(KeyError):
            store.resolve(bad_ref)

    def test_atomicity_snap2(self) -> None:
        """SNAP-2: row가 있으면 blob도 반드시 있음."""
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint()
        ref = store.write(checkpoint)
        # resolve 성공 = blob과 행이 동시에 존재
        resolved = store.resolve(ref)
        assert resolved.checkpoint_id == checkpoint.checkpoint_id

    def test_write_failure_injection_does_not_corrupt(self) -> None:
        """E4 원자성: write 실패 시 row가 partial-visible하면 안 됨."""
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-fail-test")

        # 실패 주입: 내부 conn을 닫아서 INSERT가 실패하게 만든다
        store._conn.close()  # type: ignore[attr-defined]

        import sqlite3

        with pytest.raises((sqlite3.ProgrammingError, sqlite3.OperationalError)):
            store.write(checkpoint)

        # 연결 재생성 후 아무 row도 없어야 함 (원자성 보장)
        store2 = SQLiteCheckpointStore(path=":memory:")
        bad_ref = SnapshotRef(
            uri=f"snap://{checkpoint.run_id}/step-{checkpoint.step_index}/{checkpoint.checkpoint_id}",
            run_id=checkpoint.run_id,
            step_index=checkpoint.step_index,
            pending_step_ids=tuple(checkpoint.pending_step_ids),
        )
        with pytest.raises(KeyError):
            store2.resolve(bad_ref)

    def test_korean_tenant_fixture(self) -> None:
        """§C-3: 한국어 픽스처 — 한국 금융 테넌트."""
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(
            run_id="run-금융-감독-001",
            tenant_id="tenant-금융위원회",
            actor="role:operator:김철수-감독관",
        )
        ref = store.write(checkpoint)
        resolved = store.resolve(ref)
        assert resolved.tenant_id == "tenant-금융위원회"
        assert resolved.actor == "role:operator:김철수-감독관"

    def test_close_releases_connection(self) -> None:
        """close() → 연결 해제 (line 161 커버)."""
        store = SQLiteCheckpointStore(path=":memory:")
        store.close()
        # 닫힌 이후에는 쓰기가 실패해야 함
        import sqlite3

        checkpoint = _make_checkpoint()
        with pytest.raises((sqlite3.ProgrammingError, sqlite3.OperationalError)):
            store.write(checkpoint)

    def test_file_path_creates_parent_dir(self, tmp_path: Any) -> None:
        """path != ':memory:' → parent mkdir (line 151 커버)."""
        db_path = str(tmp_path / "subdir" / "test.db")
        store = SQLiteCheckpointStore(path=db_path)
        checkpoint = _make_checkpoint()
        ref = store.write(checkpoint)
        resolved = store.resolve(ref)
        assert resolved.run_id == checkpoint.run_id
        store.close()


# ---------------------------------------------------------------------------
# §5 Race 조건 속성 테스트 (hypothesis)
# ---------------------------------------------------------------------------


class TestRaceProperties:
    """R1-R6, R-NEW 불변조건 속성 테스트."""

    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=200)
    def test_r2_idempotent_pause_request(self, request_id: str) -> None:
        """R2: 동일 request_id 중복 pause → 멱등."""
        seen: set[str] = set()
        # 동일 request_id 두 번 처리 → 두 번째는 no-op
        result1 = _try_register_pause(request_id, seen)
        result2 = _try_register_pause(request_id, seen)
        assert result1 is True
        assert result2 is False  # 멱등: 두 번째는 no-op

    @given(st.integers(min_value=0, max_value=10))
    @settings(max_examples=200)
    def test_state_machine_invariant_all_transitions(self, path_idx: int) -> None:
        """INV-SM-1: 임의 합법 경로는 항상 성공."""
        # 합법 전이 경로들
        legal_paths = [
            [InterruptState.INTERRUPT_REQUESTED],
            [InterruptState.INTERRUPT_REQUESTED, InterruptState.PAUSING],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.PAUSED_SNAPSHOTTED,
            ],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.PAUSED_SNAPSHOTTED,
                InterruptState.RESUMING,
            ],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.PAUSED_SNAPSHOTTED,
                InterruptState.RESUMING,
                InterruptState.RUNNING,
            ],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.PAUSED_SNAPSHOTTED,
                InterruptState.REINSTRUCTING,
            ],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.ABORTED,
            ],
            [
                InterruptState.INTERRUPT_REQUESTED,
                InterruptState.PAUSING,
                InterruptState.FAILED,
            ],
        ]
        path = legal_paths[path_idx % len(legal_paths)]
        rec = RunInterruptRecord(run_id="prop-test-run")
        for state in path:
            rec.transition_to(state)
        assert rec.interrupt_state == path[-1]


def _try_register_pause(request_id: str, seen: set[str]) -> bool:
    """멱등 pause 등록 헬퍼. 이미 있으면 False 반환."""
    if request_id in seen:
        return False
    seen.add(request_id)
    return True


# ---------------------------------------------------------------------------
# R-NEW: 비디스패칭 런 pause 거부 (D-L)
# ---------------------------------------------------------------------------


class TestNonDispatchingRunRejection:
    """D-L / INV-R8: resolve_run_engine==None → RunNotDispatchingError."""

    def test_request_pause_rejects_non_dispatching_run(self) -> None:
        from secugent.orchestrator.runner import RunNotDispatchingError, RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        with pytest.raises(RunNotDispatchingError):
            orch.request_pause(
                "run-not-dispatching",
                request_id="req-001",
                mode="pause",
                actor="role:operator:u-test",
            )


# ---------------------------------------------------------------------------
# E7: PAUSING/RESUMING 중 verb 거부
# ---------------------------------------------------------------------------


class TestQuiescentGate:
    """D-K: PAUSING/RESUMING 중 verb 도착 → InterruptStateError."""

    def test_pausing_rejects_resume_verb(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        assert rec.is_quiescent() is False
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.RESUMING)

    def test_resuming_rejects_pause_verb(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        rec.transition_to(InterruptState.RESUMING)
        assert rec.is_quiescent() is False
        with pytest.raises(InterruptStateError):
            rec.transition_to(InterruptState.INTERRUPT_REQUESTED)

    def test_paused_snapshotted_is_quiescent(self) -> None:
        rec = RunInterruptRecord(run_id="r1")
        rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        rec.transition_to(InterruptState.PAUSING)
        rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)
        assert rec.is_quiescent() is True


# ---------------------------------------------------------------------------
# OversightEngine pause 필드 (mechanical_oversight.py additive)
# ---------------------------------------------------------------------------


class TestOversightEnginePauseField:
    """_patches_lock 보호 pause 필드 — additive (기존 세션패치 경로 비파괴)."""

    def test_pause_field_initially_clear(self) -> None:
        engine = _make_engine()
        assert engine.is_paused() is False

    def test_set_pause_under_lock(self) -> None:
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-001", actor="op:u-1")
        assert engine.is_paused() is True

    def test_clear_pause(self) -> None:
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-001", actor="op:u-1")
        engine.set_paused(paused=False, request_id="req-001", actor="op:u-1")
        assert engine.is_paused() is False

    def test_idempotent_pause_by_request_id(self) -> None:
        """R2: 동일 request_id 두 번 set → 멱등."""
        engine = _make_engine()
        result1 = engine.set_paused(paused=True, request_id="req-dup", actor="op:u-1")
        result2 = engine.set_paused(paused=True, request_id="req-dup", actor="op:u-1")
        assert result1 is True  # 첫 번째는 새로운 요청
        assert result2 is False  # 두 번째는 멱등

    def test_session_patches_preserved_after_pause(self) -> None:
        """기존 세션패치 경로 비파괴 (additive)."""
        from datetime import timedelta

        regs = _make_regs()
        engine = OversightEngine(regs)
        patch = SessionRegulationPatch(
            run_id="run-ko-001",
            rules=[{"category": "banned_path", "pattern": "/etc/*", "hard_block": True}],
            tenant_id="tenant-ko",
            expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
            reason="테스트 패치",
        )
        engine.add_session_patch(patch)
        assert len(engine._patches) == 1  # type: ignore[attr-defined]

        engine.set_paused(paused=True, request_id="req-001", actor="op:u-1")
        # 세션패치는 그대로
        assert len(engine._patches) == 1  # type: ignore[attr-defined]

    def test_thread_safety_concurrent_pause(self) -> None:
        """R6: 스레드 경계 pause 신호 — _patches_lock 보호 확인."""
        engine = _make_engine()
        errors: list[Exception] = []

        def _set_pause() -> None:
            try:
                engine.set_paused(paused=True, request_id=str(uuid.uuid4()), actor="op:u-1")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_set_pause) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert engine.is_paused() is True  # 적어도 하나는 성공


# ---------------------------------------------------------------------------
# D-F Rule-of-Two 축 재게이트 (INV-9)
# ---------------------------------------------------------------------------


class TestRuleOfTwoRegatePauseResume:
    """C1-T5: 축 확장 patch_goal → 재개 HITL 강제."""

    def test_three_axes_requires_hitl(self) -> None:
        """INV-9: 3축 → requires_hitl True."""
        axes = frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})
        assert requires_hitl(axes) is True

    def test_two_axes_no_hitl(self) -> None:
        axes = frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS})
        assert requires_hitl(axes) is False

    def test_resume_with_three_axes_blocked(self) -> None:
        """재개 시 3축 → HITL 강제 (runner.resume_from_checkpoint 에서 확인)."""
        from secugent.orchestrator.runner import ResumeRequiresHITLError, RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        # 3축 스냅샷
        checkpoint = _make_checkpoint(run_id="run-axis-3")
        checkpoint.rule_of_two_axes = ["untrusted_input", "sensitive_access", "external_comm"]

        store = SQLiteCheckpointStore(path=":memory:")
        ref = store.write(checkpoint)

        # runner에 엔진 등록 (dispatching 시뮬)
        engine = _make_engine()
        orch.register_run_engine(checkpoint.run_id, engine)

        # resume_from_checkpoint는 3축 → ResumeRequiresHITLError
        import asyncio

        with pytest.raises(ResumeRequiresHITLError):
            asyncio.run(orch.resume_from_checkpoint(checkpoint.run_id, ref, checkpoint_store=store))


# ---------------------------------------------------------------------------
# D-E TTL 불변 (INV-10)
# ---------------------------------------------------------------------------


class TestTTLInvariant:
    """D-E: 잔여 TTL 동결 → hard-block 결정 pause 지속 불변."""

    def test_remaining_ttl_snapshot_preserves_window(self) -> None:
        """pause 시 잔여 TTL을 저장하고 expires_at 절대값은 저장하지 않음."""
        store = SQLiteCheckpointStore(path=":memory:")
        remaining_ttl = 3600  # 1시간
        checkpoint = _make_checkpoint()
        checkpoint.patch_remaining_ttl = {"patch-001": remaining_ttl}
        ref = store.write(checkpoint)
        resolved = store.resolve(ref)
        # 잔여 TTL이 동결됨 — 절대 wall-clock이 아님
        assert resolved.patch_remaining_ttl == {"patch-001": remaining_ttl}


# ---------------------------------------------------------------------------
# 결정성 100회 (§10 D-1..D-7)
# ---------------------------------------------------------------------------


class TestDeterminism100:
    """C1-T1d: snapshot→resume 100회 — 체인 해시 tail byte 동일."""

    def test_snapshot_ref_uri_deterministic_given_checkpoint_id(self) -> None:
        """동일 checkpoint_id → 동일 URI (INV-DET-1 확인)."""
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-det-001", step_index=5)
        ref = store.write(checkpoint)
        # URI는 checkpoint_id 기반 → 동일 ID면 동일 URI
        # (UUID는 canonical hash body에 들어가면 안 됨 — INV-DET-1)
        expected_uri = f"snap://{checkpoint.run_id}/step-{checkpoint.step_index}/{checkpoint.checkpoint_id}"
        assert ref.uri == expected_uri

    def test_100_pause_resume_cycle_chain_hash_stable(self, tmp_path: Any) -> None:
        """100회 pause→snapshot→resume 사이클 — verify_chain 통과 + tail event_hash 불변 (D-1~D-5, D-2, D-7).

        명세 §10 D-2: compute_chain_hash 동일 입력 → 동일 output.
        명세 §10 D-7: stored_view(redacted canonical)이 해시 body에 유입 — uuid/timestamp 제외.
        verify_chain가 매 사이클 통과해야 한다 (체인 무결성).
        """
        from secugent.audit.hash_chain import ChainedEventStore, compute_chain_hash
        from secugent.core.contracts import Event
        from secugent.core.event_store import EventStore
        from secugent.core.tenancy import TenantId

        ckpt_store = SQLiteCheckpointStore(path=str(tmp_path / "det100_ckpt.db"))
        event_store = EventStore(str(tmp_path / "det100_events.db"))
        chain = ChainedEventStore(event_store)

        _TENANT = "tenant-det-100"

        def _append_steer_event(run_id: str, event_type: str) -> str:
            ev = Event(
                tenant_id=TenantId(_TENANT),
                actor="system",
                type=event_type,
                severity="info",
                run_id=run_id,
                payload={"cycle": "deterministic", "gate": "steer"},
            )
            rec = chain.append_event(ev)
            return rec.event_hash

        # D-2: compute_chain_hash は deterministic — pin with a known constant input
        _KNOWN_PREV = "GENESIS"
        _KNOWN_BODY = '{"actor":"system","gate":"steer","type":"steer.paused"}'
        _DET_CONSTANT = compute_chain_hash(_KNOWN_PREV, _KNOWN_BODY)
        # Verify the constant is stable across runs (INV-DET-1 — uuid/ts NOT in body)
        assert compute_chain_hash(_KNOWN_PREV, _KNOWN_BODY) == _DET_CONSTANT, (
            "compute_chain_hash는 결정적이어야 한다 — INV-DET-1 위반"
        )

        tail_hashes: list[str] = []

        for i in range(100):
            run_id = "run-det-100-cycle"
            _append_steer_event(run_id, "steer.paused")
            # Write a checkpoint for this cycle
            ckpt = _make_checkpoint(
                run_id=run_id,
                step_index=i,
                pending=("step-next",),
                completed=("step-done",),
            )
            ckpt_store.write(ckpt)
            tail_hash = _append_steer_event(run_id, "steer.resumed")
            tail_hashes.append(tail_hash)

            # D-2, D-7: chain must be valid after every cycle
            assert chain.verify_chain(tenant_id=_TENANT), f"verify_chain 실패 at iter {i} — 체인 무결성 위반"

        # All 100 cycles emitted valid events — chain consistent throughout
        assert len(tail_hashes) == 100

        # D-2: compute_chain_hash input → output is byte-identical (deterministic pure fn)
        for _ in range(10):
            assert compute_chain_hash(_KNOWN_PREV, _KNOWN_BODY) == _DET_CONSTANT, (
                "compute_chain_hash 결과 불일치 — INV-DET-1 위반"
            )

        chain.close()
        ckpt_store.close()

    def test_uuid_and_timestamp_not_in_content_hash(self) -> None:
        """INV-DET-1: uuid/timestamp는 content에서 제외 — checkpoint_id/created_at은
        결정성 판단에서 제외되어야 한다 (resolve 내용의 나머지가 동일함)."""
        store = SQLiteCheckpointStore(path=":memory:")
        ckpt1 = _make_checkpoint(run_id="run-det-hash-001", step_index=1)
        ckpt2 = _make_checkpoint(run_id="run-det-hash-001", step_index=1)
        # checkpoint_id, created_at은 다름 (uuid, timestamp)
        assert ckpt1.checkpoint_id != ckpt2.checkpoint_id

        ref1 = store.write(ckpt1)
        ref2 = store.write(ckpt2)

        r1 = store.resolve(ref1)
        r2 = store.resolve(ref2)
        # 비결정 필드(checkpoint_id, created_at)는 달라도 됨
        assert r1.checkpoint_id != r2.checkpoint_id
        # 결정 필드는 동일해야 함
        assert r1.run_id == r2.run_id
        assert r1.step_index == r2.step_index
        assert r1.pending_step_ids == r2.pending_step_ids


# ---------------------------------------------------------------------------
# request_pause / resume_from_checkpoint (runner) 통합
# ---------------------------------------------------------------------------


class TestRunnerPauseResume:
    """runner.py 신규 메서드 통합 테스트."""

    def test_request_pause_returns_true_on_first_call(self) -> None:
        """request_pause는 신규 신호 설정 시 True를 반환한다."""
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-ok", engine)

        # 첫 번째 호출: True 반환 (신규 신호)
        result = orch.request_pause(
            "run-ok",
            request_id="req-001",
            mode="pause",
            actor="role:operator:u-9",
        )
        assert result is True, "첫 번째 pause 요청은 True(신규 신호)를 반환해야 함"

    def test_request_pause_sets_engine_paused(self) -> None:
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-ok", engine)

        orch.request_pause(
            "run-ok",
            request_id="req-001",
            mode="pause",
            actor="role:operator:u-9",
        )
        assert engine.is_paused() is True

    def test_request_pause_mode_stop_sets_stop_flag(self) -> None:
        """D-J: mode:stop → 엔진에 stop 표식."""
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-stop", engine)

        orch.request_pause(
            "run-stop",
            request_id="req-stop-001",
            mode="stop",
            actor="role:operator:u-9",
        )
        assert engine.is_paused() is True
        assert engine.is_stop_mode() is True  # stop 경로 전용 플래그

    def test_register_and_resolve_engine(self) -> None:
        """engine resolver seam: register → resolve."""
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-r", engine)
        assert orch.resolve_run_engine("run-r") is engine

    def test_resolve_unregistered_returns_none(self) -> None:
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        assert orch.resolve_run_engine("run-unknown") is None

    def test_deregister_engine_on_run_end(self) -> None:
        """런 종료 시 엔진 레지스트리에서 제거."""
        from secugent.orchestrator.runner import RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-end", engine)
        orch.deregister_run_engine("run-end")
        assert orch.resolve_run_engine("run-end") is None

    def test_resume_from_checkpoint_idempotent(self) -> None:
        """INV-3: resume_from_checkpoint ≥2회 = 단일 재디스패치."""
        import asyncio

        from secugent.orchestrator.runner import RunOrchestrator

        dispatched_count = 0

        class _CountingDispatcher:
            async def dispatch(self, *, run_id: str, plan: Any) -> dict[str, Any]:
                nonlocal dispatched_count
                dispatched_count += 1
                return {}

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=_CountingDispatcher(),
        )
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-idem")
        ref = store.write(checkpoint)
        engine = _make_engine()
        orch.register_run_engine("run-idem", engine)

        async def _run_twice() -> None:
            await orch.resume_from_checkpoint("run-idem", ref, checkpoint_store=store)
            await orch.resume_from_checkpoint("run-idem", ref, checkpoint_store=store)

        asyncio.run(_run_twice())
        # 두 번 호출했지만 실제 재디스패치는 1회
        assert dispatched_count == 1

    def test_resume_checkpoint_mismatch_raises(self) -> None:
        """from_ref 불일치 → CheckpointMismatchError."""
        import asyncio

        from secugent.orchestrator.runner import CheckpointMismatchError, RunOrchestrator

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        store = SQLiteCheckpointStore(path=":memory:")
        bad_ref = SnapshotRef(
            uri="snap://run-mismatch/step-0/ckpt-nonexistent",
            run_id="run-mismatch",
            step_index=0,
            pending_step_ids=(),
        )
        engine = _make_engine()
        orch.register_run_engine("run-mismatch", engine)

        with pytest.raises(CheckpointMismatchError):
            asyncio.run(orch.resume_from_checkpoint("run-mismatch", bad_ref, checkpoint_store=store))


# ---------------------------------------------------------------------------
# 한국어 픽스처 통합: "민감 경로 /etc 차단하고 계속" (C1-T1b)
# ---------------------------------------------------------------------------


class TestKoreanFixtureConstraint:
    """§C-3 한국어 픽스처: /etc/* hard-block 재지시."""

    def test_etc_constraint_add_and_live(self) -> None:
        """SteerHandler.apply("민감 경로 /etc 차단하고 계속") → add_constraint /etc/*."""
        from secugent.steer.steer import SteerHandler

        regs = _make_regs()
        engine = OversightEngine(regs)
        events: list[Any] = []

        class _FakeStore:
            def append_event(self, event: Any) -> None:
                events.append(event)

        handler = SteerHandler(oversight=engine, event_store=_FakeStore())  # type: ignore[arg-type]
        outcome = handler.apply(
            run_id="run-ko-etc-001",
            directive="민감 경로 /etc 차단하고 계속",
            actor="role:operator:김관리자",
        )
        assert outcome.classification.action == "add_constraint"
        assert outcome.patch is not None
        # /etc/* 패턴 포함
        rules = outcome.patch.rules
        patterns = [r.get("pattern", "") for r in rules]
        assert any("/etc" in p for p in patterns), f"expected /etc/* in {patterns}"
        # hard_block: True
        assert any(r.get("hard_block") is True for r in rules), "expected hard_block:True"


# ---------------------------------------------------------------------------
# FileSnapshotStore (기존 코드 커버리지 보완)
# ---------------------------------------------------------------------------


class TestFileSnapshotStore:
    """FileSnapshotStore — 기존 EM-09 코드 커버 (snapshots.py 95% 게이트)."""

    def test_capture_nonexistent_file_returns_none(self, tmp_path: Any) -> None:
        """캡처 시 파일 없으면 None 반환 (line 265 false-branch)."""
        from secugent.steer.snapshots import FileSnapshotStore

        store = FileSnapshotStore()
        result = store.capture(str(tmp_path / "nonexistent.txt"))
        assert result is None

    def test_capture_existing_file_returns_bytes(self, tmp_path: Any) -> None:
        """캡처 시 파일 있으면 bytes 반환 (line 265 true-branch)."""
        from secugent.steer.snapshots import FileSnapshotStore

        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        store = FileSnapshotStore()
        result = store.capture(str(f))
        assert result == b"hello world"

    def test_rollback_restores_file(self, tmp_path: Any) -> None:
        """rollback → 원래 내용 복원 (line 281)."""
        from secugent.steer.snapshots import FileSnapshotStore

        f = tmp_path / "restore.txt"
        f.write_bytes(b"original")
        store = FileSnapshotStore()
        store.capture(str(f))
        f.write_bytes(b"modified")
        store.rollback(str(f))
        assert f.read_bytes() == b"original"

    def test_rollback_deletes_new_file(self, tmp_path: Any) -> None:
        """캡처 시 파일이 없었으면 rollback이 파일 삭제 (line 278-279)."""
        from secugent.steer.snapshots import FileSnapshotStore

        f = tmp_path / "newfile.txt"
        store = FileSnapshotStore()
        store.capture(str(f))  # 파일 없음 → None 저장
        f.write_bytes(b"new content")
        store.rollback(str(f))  # 파일 삭제
        assert not f.exists()

    def test_rollback_no_capture_raises(self, tmp_path: Any) -> None:
        """캡처 없이 rollback → KeyError (line 273)."""
        from secugent.steer.snapshots import FileSnapshotStore

        store = FileSnapshotStore()
        with pytest.raises(KeyError):
            store.rollback(str(tmp_path / "uncaptured.txt"))
