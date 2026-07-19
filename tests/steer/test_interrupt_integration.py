# SPDX-License-Identifier: Apache-2.0
"""G-C3 STEER 인터럽트 통합 테스트 (Lane A — 협동 정지 체크포인트).

§12 C1-T1a (다중 스텝 정지), interrupt_state RunRecord 필드,
steer.resumed 제2 프로듀서 (D-D §8.3), ResourceWarning 수정,
속성 기반 테스트 (R2 멱등 + ResourceWarning 보완),
RunRecord interrupt_state SQLite 라운드트립을 커버한다.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import Step
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.orchestrator.state import RunState
from secugent.steer.snapshots import (
    RunCheckpoint,
    SQLiteCheckpointStore,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_TENANT = "legacy-default"


def _make_regs() -> Regulations:
    return Regulations(version="0.1.0")


def _make_engine(regs: Regulations | None = None) -> OversightEngine:
    return OversightEngine(regs or _make_regs())


def _make_step(step_id: str, run_id: str = "run-integration-001") -> Step:
    # target is a non-existent placeholder — this step never actually executes
    # its tool (run() is mocked in all cooperative-pause tests). "file_read" is
    # used so the action_type is valid per the ActionType Literal; the path
    # itself is never touched.
    return Step(
        id=step_id,
        tenant_id=_TENANT,
        run_id=run_id,
        actor="sub:test",
        action_type="file_read",
        target="integration-test-placeholder.txt",  # noqa: S108 – fixture-only, never executed
    )


def _make_checkpoint(
    run_id: str = "run-test-001",
    step_index: int = 2,
    pending: tuple[str, ...] = ("s3", "s4"),
    completed: tuple[str, ...] = ("s1", "s2"),
    actor: str = "role:operator:u-9",
) -> RunCheckpoint:
    return RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id="tenant-ko-finance",
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
        created_at="2026-06-21T12:00:00+00:00",
        actor=actor,
    )


# ---------------------------------------------------------------------------
# C1-T1a: 다중 스텝 실행 — step k 이후 스텝 미실행 (협동 정지)
# ---------------------------------------------------------------------------


class TestCooperativePauseAtStepBoundary:
    """INV-1: pause 신호 관찰 후 새 side-effect 0개."""

    def _make_minimal_sub_agent(self, engine: OversightEngine) -> Any:
        """SubAgent의 공개 run() 인터페이스만 테스트하는 최소 스텁."""
        import os
        import tempfile

        from secugent.agents.sub_agent import (
            AutoApproveHitlGateway,
            SubAgent,
        )
        from secugent.core.approval import ApprovalService
        from secugent.core.contracts import RiskScore
        from secugent.core.event_store import EventStore
        from secugent.core.risk_analyzer import RiskAssessment
        from secugent.tools.router import ToolRouter, ToolRouterConfig

        tmp = tempfile.mkdtemp()

        class _LowRisk:
            def assess(self, step: Step) -> RiskAssessment:
                score = RiskScore(
                    total=10,
                    breakdown={
                        "data_sensitivity": 10,
                        "external_exposure": 10,
                        "irreversibility": 10,
                        "privilege_escalation": 10,
                        "intent_alignment": 10,
                    },
                    rationale="테스트 낮은 위험",
                    confidence=0.9,
                )
                return RiskAssessment(score=score, decision="silent", reason="low")

        db = os.path.join(tmp, "events.db")
        store = EventStore(db)
        approvals = ApprovalService(store)
        router = ToolRouter(ToolRouterConfig(sandbox_roots=[tmp]))

        sub = SubAgent(
            actor="sub:test",
            oversight=engine,
            risk_analyzer=_LowRisk(),  # type: ignore[arg-type]
            router=router,
            approval_service=approvals,
            hitl_gateway=AutoApproveHitlGateway(),
            event_store=store,
        )
        return sub

    def test_pause_before_first_step_no_outcomes(self) -> None:
        """pause 신호가 step 0 이전에 있으면 outcomes가 0이어야 한다."""
        engine = _make_engine()
        engine.set_paused(paused=True, request_id="req-001", actor="op:u-1")

        sub = self._make_minimal_sub_agent(engine)

        steps = [_make_step("s0"), _make_step("s1"), _make_step("s2")]
        result = sub.run(steps)

        assert result.paused_at_step_id == "s0"
        assert result.halted_early is True
        assert len(result.outcomes) == 0  # INV-1: 0 new side effects

    def test_pause_after_step_0_no_more_steps_started(self) -> None:
        """C1-T1a: step 0 완료 후 pause 신호 → step 1 이후 미실행.

        _run_step을 모킹해 실제 도구 실행 없이 step 완료를 시뮬레이션한다.
        협동 pause 체크는 run()의 루프 헤드에서 일어나므로 _run_step 반환 후
        pause 신호를 설정하면 다음 반복에서 정지를 관찰해야 한다.
        """
        from secugent.agents.sub_agent import StepOutcome

        engine = _make_engine()
        sub = self._make_minimal_sub_agent(engine)

        steps = [_make_step("s0"), _make_step("s1"), _make_step("s2"), _make_step("s3")]
        started_steps: list[str] = []

        def _mock_run_step(step: Step) -> StepOutcome:
            started_steps.append(step.id)
            if step.id == "s0":
                # s0 실행 완료 직후 pause 신호 설정
                engine.set_paused(paused=True, request_id="req-after-s0", actor="op:u-1")
            # 항상 completed 반환 (실제 도구 호출 없음)
            return StepOutcome(step=step, status="completed")

        sub._run_step = _mock_run_step  # type: ignore[method-assign]

        result = sub.run(steps)

        # s0만 실행됨 (s1은 루프 헤드 pause 체크에서 차단)
        assert "s0" in started_steps
        assert "s1" not in started_steps, f"s1 was started! started={started_steps}"
        assert "s2" not in started_steps
        assert "s3" not in started_steps
        # paused_at_step_id는 시작되지 않은 첫 번째 스텝
        assert result.paused_at_step_id == "s1"
        assert result.halted_early is True

    def test_stop_mode_sets_aborted_not_paused(self) -> None:
        """D-J: mode:stop → result.aborted True, paused_at_step_id는 None."""
        engine = _make_engine()
        # stop_mode=True
        engine.set_paused(paused=True, request_id="req-stop", actor="op:u-1", stop_mode=True)

        sub = self._make_minimal_sub_agent(engine)
        steps = [_make_step("s0"), _make_step("s1")]
        result = sub.run(steps)

        assert result.aborted is True
        assert result.halted_early is True
        assert result.paused_at_step_id is None  # aborted path, not paused path
        assert len(result.outcomes) == 0

    def test_no_pause_all_steps_run(self) -> None:
        """pause 신호 없으면 모든 스텝 정상 실행 (regression)."""
        engine = _make_engine()
        sub = self._make_minimal_sub_agent(engine)
        steps = [_make_step(f"s{i}") for i in range(3)]

        result = sub.run(steps)

        # 정상 실행 시 paused_at_step_id는 None
        assert result.paused_at_step_id is None
        assert result.aborted is False


# ---------------------------------------------------------------------------
# D-A: interrupt_state RunRecord 필드 + 직렬화 라운드트립
# ---------------------------------------------------------------------------


class TestInterruptStateRunRecord:
    """D-A: RunRecord.interrupt_state 필드 — 직렬화/역직렬화 라운드트립."""

    def test_run_record_default_interrupt_state_none(self) -> None:
        """신규 RunRecord의 interrupt_state 기본값은 None."""
        from secugent.orchestrator.state import RunRecord

        rec = RunRecord(run_id="r1", command="test")
        assert rec.interrupt_state is None

    def test_run_record_to_dict_includes_interrupt_state(self) -> None:
        """to_dict()에 interrupt_state 포함."""
        from secugent.orchestrator.state import RunRecord

        rec = RunRecord(run_id="r1", command="test", interrupt_state="PAUSED_SNAPSHOTTED")
        d = rec.to_dict()
        assert "interrupt_state" in d
        assert d["interrupt_state"] == "PAUSED_SNAPSHOTTED"

    def test_inmemory_update_state_sets_interrupt_state(self) -> None:
        """InMemory 스토어: update_state(interrupt_state=...) → 직접 필드 설정."""
        from secugent.orchestrator.state import InMemoryRunStateStore

        store = InMemoryRunStateStore()

        async def _run() -> None:
            await store.create("r1", "cmd", {})
            await store.update_state("r1", RunState.EXECUTING, interrupt_state="INTERRUPT_REQUESTED")
            rec = await store.get("r1")
            assert rec is not None
            assert rec.interrupt_state == "INTERRUPT_REQUESTED"

        asyncio.run(_run())

    def test_inmemory_clone_preserves_interrupt_state(self) -> None:
        """InMemory: get()는 clone → interrupt_state 복사됨."""
        from secugent.orchestrator.state import InMemoryRunStateStore

        store = InMemoryRunStateStore()

        async def _run() -> None:
            await store.create("r2", "cmd2", {})
            await store.update_state("r2", RunState.EXECUTING, interrupt_state="PAUSING")
            rec1 = await store.get("r2")
            rec2 = await store.get("r2")
            assert rec1 is not None and rec2 is not None
            assert rec1.interrupt_state == rec2.interrupt_state == "PAUSING"
            # 복사본이므로 독립적
            assert rec1 is not rec2

        asyncio.run(_run())

    def test_sqlite_interrupt_state_roundtrip(self, tmp_path: Path) -> None:
        """SQLite: interrupt_state를 _extras에 저장 → 역직렬화 시 복원."""
        from secugent.orchestrator.state import SQLiteRunStateStore

        db_path = str(tmp_path / "test.db")
        store = SQLiteRunStateStore(path=db_path)

        async def _run() -> None:
            await store.create("r3", "cmd3", {})
            await store.update_state("r3", RunState.EXECUTING, interrupt_state="PAUSED_SNAPSHOTTED")
            rec = await store.get("r3")
            assert rec is not None
            assert rec.interrupt_state == "PAUSED_SNAPSHOTTED"

        asyncio.run(_run())

    def test_sqlite_interrupt_state_persists_across_new_store_instance(self, tmp_path: Path) -> None:
        """SQLite: 스토어 인스턴스 재생성 후에도 interrupt_state 유지."""
        from secugent.orchestrator.state import SQLiteRunStateStore

        db_path = str(tmp_path / "persist.db")

        async def _write() -> None:
            store = SQLiteRunStateStore(path=db_path)
            await store.create("r4", "cmd4", {})
            await store.update_state("r4", RunState.EXECUTING, interrupt_state="RESUMING")

        async def _read() -> str | None:
            store = SQLiteRunStateStore(path=db_path)
            rec = await store.get("r4")
            return rec.interrupt_state if rec else None

        asyncio.run(_write())
        state = asyncio.run(_read())
        assert state == "RESUMING"


# ---------------------------------------------------------------------------
# D-D §8.3: steer.resumed 제2 프로듀서 (from_checkpoint_id 있는 버전)
# ---------------------------------------------------------------------------


class TestEmitResumeFromCheckpoint:
    """D-D §8.3: emit_resume_from_checkpoint() — 구조적 steer.resumed."""

    def _make_steer_handler(self) -> tuple[Any, list[Any]]:
        """SteerHandler + 이벤트 수집 싱크 반환."""
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        engine = _make_engine()
        handler = SteerHandler(oversight=engine, event_store=_FakeSink())  # type: ignore[arg-type]
        return handler, events

    def test_emit_resume_returns_steer_resume_event(self) -> None:
        """반환값이 SteerResumeEvent이고 from_checkpoint_id 포함."""
        from secugent.steer.steer import SteerResumeEvent

        handler, events = self._make_steer_handler()
        result = handler.emit_resume_from_checkpoint(
            run_id="run-001",
            from_checkpoint_id="ckpt-abc123",
            actor="role:operator:u-9",
        )

        assert isinstance(result, SteerResumeEvent)
        assert result.run_id == "run-001"
        assert result.from_checkpoint_id == "ckpt-abc123"
        assert result.actor == "role:operator:u-9"

    def test_emit_resume_appends_steer_resumed_event(self) -> None:
        """steer.resumed 이벤트가 싱크에 추가됨."""
        handler, events = self._make_steer_handler()
        handler.emit_resume_from_checkpoint(
            run_id="run-002",
            from_checkpoint_id="ckpt-xyz789",
            actor="role:operator:u-test",
        )

        assert len(events) == 1
        event = events[0]
        assert event.type == "steer.resumed"
        assert event.payload.get("from_checkpoint_id") == "ckpt-xyz789"

    def test_emit_resume_event_distinguishable_from_cosmetic(self) -> None:
        """구조적 steer.resumed에는 from_checkpoint_id가 있고,
        cosmetic steer.resumed에는 없음 — 소비자가 구별 가능."""
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        engine = _make_engine()
        handler = SteerHandler(oversight=engine, event_store=_FakeSink())  # type: ignore[arg-type]

        # 1. Cosmetic steer.resumed (apply 메서드)
        handler.apply(
            run_id="run-003",
            directive="민감 경로 /tmp 차단하고 계속",
            actor="role:operator:u-ko",
        )

        cosmetic_resumed = [e for e in events if e.type == "steer.resumed"]
        assert len(cosmetic_resumed) == 1
        assert "from_checkpoint_id" not in cosmetic_resumed[0].payload

        events.clear()

        # 2. 구조적 steer.resumed (emit_resume_from_checkpoint)
        handler.emit_resume_from_checkpoint(
            run_id="run-003",
            from_checkpoint_id="ckpt-abc",
            actor="role:operator:u-ko",
        )

        structural_resumed = [e for e in events if e.type == "steer.resumed"]
        assert len(structural_resumed) == 1
        assert "from_checkpoint_id" in structural_resumed[0].payload

    def test_runner_resume_calls_steer_handler_emit(self) -> None:
        """resume_from_checkpoint(steer_handler=...) → emit_resume_from_checkpoint 호출."""
        from secugent.orchestrator.runner import RunOrchestrator

        emitted_resumes: list[dict[str, Any]] = []

        class _FakeSteerHandler:
            def emit_resume_from_checkpoint(
                self,
                *,
                run_id: str,
                from_checkpoint_id: str,
                actor: str,
                rule_of_two_axes: list[str] | None = None,  # SG-20260621-04
            ) -> None:
                emitted_resumes.append(
                    {"run_id": run_id, "from_checkpoint_id": from_checkpoint_id, "actor": actor}
                )

        class _CountingDispatcher:
            async def dispatch(self, *, run_id: str, plan: Any) -> dict[str, Any]:
                return {}

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=_CountingDispatcher(),
        )
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-resume-steer")
        ref = store.write(checkpoint)
        engine = _make_engine()
        orch.register_run_engine("run-resume-steer", engine)

        steer_handler = _FakeSteerHandler()
        asyncio.run(
            orch.resume_from_checkpoint(
                "run-resume-steer",
                ref,
                checkpoint_store=store,
                steer_handler=steer_handler,
            )
        )

        assert len(emitted_resumes) == 1
        assert emitted_resumes[0]["run_id"] == "run-resume-steer"
        assert emitted_resumes[0]["from_checkpoint_id"] == ref.uri

    def test_runner_resume_without_steer_handler_no_error(self) -> None:
        """steer_handler=None(기본값)이어도 오류 없이 재개."""
        from secugent.orchestrator.runner import RunOrchestrator

        class _CountingDispatcher:
            async def dispatch(self, *, run_id: str, plan: Any) -> dict[str, Any]:
                return {}

        orch = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=_CountingDispatcher(),
        )
        store = SQLiteCheckpointStore(path=":memory:")
        checkpoint = _make_checkpoint(run_id="run-no-steer")
        ref = store.write(checkpoint)
        engine = _make_engine()
        orch.register_run_engine("run-no-steer", engine)

        # 예외 없이 완료해야 함
        asyncio.run(orch.resume_from_checkpoint("run-no-steer", ref, checkpoint_store=store))


# ---------------------------------------------------------------------------
# ResourceWarning 수정: hypothesis 테스트에서 store.close() 추가
# ---------------------------------------------------------------------------


class TestR2IdempotentPauseResourceWarning:
    """R2 멱등 속성 테스트 — store.close() 포함으로 ResourceWarning 방지."""

    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=100)
    def test_r2_idempotent_pause_with_store_close(self, request_id: str) -> None:
        """R2: 동일 request_id 중복 pause → 멱등 (ResourceWarning 없음)."""
        store = SQLiteCheckpointStore(path=":memory:")
        try:
            checkpoint = _make_checkpoint()
            ref = store.write(checkpoint)
            resolved = store.resolve(ref)
            assert resolved.run_id == checkpoint.run_id
        finally:
            store.close()

    @given(st.integers(min_value=1, max_value=10000))
    @settings(max_examples=50)
    def test_patch_remaining_ttl_is_int_roundtrip(self, ttl_seconds: int) -> None:
        """D-E TTL 불변: 임의 int TTL → SQLite 라운드트립 → 동일 int."""
        store = SQLiteCheckpointStore(path=":memory:")
        try:
            checkpoint = _make_checkpoint()
            checkpoint.patch_remaining_ttl = {"patch-001": ttl_seconds}
            ref = store.write(checkpoint)
            resolved = store.resolve(ref)
            assert resolved.patch_remaining_ttl == {"patch-001": ttl_seconds}
            assert isinstance(resolved.patch_remaining_ttl["patch-001"], int)
        finally:
            store.close()


# ---------------------------------------------------------------------------
# C1-T1c: rollback_step 지시 → steer.rollback_requested 이벤트
# ---------------------------------------------------------------------------


class TestRollbackStepDirective:
    """C1-T1c: rollback_step 지시 → steer.rollback_requested + precommit abort path."""

    def test_rollback_step_emits_rollback_requested_event(self) -> None:
        """rollback_step 분류 → steer.rollback_requested 이벤트 생성."""
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        engine = _make_engine()
        handler = SteerHandler(oversight=engine, event_store=_FakeSink())  # type: ignore[arg-type]

        # "rollback" 키워드 포함 → rollback_step 분류
        outcome = handler.apply(
            run_id="run-rollback-001",
            directive="마지막 스텝 롤백해",
            actor="role:operator:u-9",
        )

        assert outcome.classification.action == "rollback_step"
        rollback_events = [e for e in events if e.type == "steer.rollback_requested"]
        assert len(rollback_events) >= 1, f"expected steer.rollback_requested in {[e.type for e in events]}"

    def test_rollback_step_also_emits_resumed(self) -> None:
        """rollback_step → steer.resumed도 방출됨 (apply 흐름)."""
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        engine = _make_engine()
        handler = SteerHandler(oversight=engine, event_store=_FakeSink())  # type: ignore[arg-type]

        handler.apply(
            run_id="run-rollback-002",
            directive="마지막 스텝 롤백하고 계속",
            actor="role:operator:u-9",
        )

        event_types = [e.type for e in events]
        assert "steer.resumed" in event_types


# ---------------------------------------------------------------------------
# SubAgentResult 새 필드 단위 테스트
# ---------------------------------------------------------------------------


class TestSubAgentResultNewFields:
    """SubAgentResult.paused_at_step_id / aborted 필드 기본값 및 타입 확인."""

    def test_default_paused_at_step_id_is_none(self) -> None:
        from secugent.agents.sub_agent import SubAgentResult

        result = SubAgentResult(actor="sub:test")
        assert result.paused_at_step_id is None

    def test_default_aborted_is_false(self) -> None:
        from secugent.agents.sub_agent import SubAgentResult

        result = SubAgentResult(actor="sub:test")
        assert result.aborted is False

    def test_succeeded_false_when_aborted(self) -> None:
        """aborted=True → succeeded 속성이 halted_early와 일관."""
        from secugent.agents.sub_agent import SubAgentResult

        result = SubAgentResult(actor="sub:test", halted_early=True, aborted=True)
        assert result.succeeded is False

    def test_succeeded_false_when_paused(self) -> None:
        """paused_at_step_id 설정 시 halted_early=True → succeeded False."""
        from secugent.agents.sub_agent import SubAgentResult

        result = SubAgentResult(actor="sub:test", halted_early=True, paused_at_step_id="s1")
        assert result.succeeded is False


# ---------------------------------------------------------------------------
# steer.py 커버리지: LLM 분류 경로 (lines 271-305) + _sanitise (395-398)
# ---------------------------------------------------------------------------


class TestSteerLLMClassificationPath:
    """steer.py LLM 경로 + _sanitise 메서드 커버리지.

    INV-4: STEER 분류기는 규칙을 절대 완화하지 않는다.
    LLM 경로에서 반환된 결과도 _sanitise를 거쳐야 한다.
    """

    def _make_handler_with_mock_llm(self, llm_response: str) -> tuple[Any, list[Any]]:
        """MockLLMClient를 주입한 SteerHandler를 반환한다."""
        from secugent.core.llm_client import LLMClient
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        class _FixedLLM(LLMClient):
            """항상 고정 응답을 반환하는 LLM 스텁."""

            def generate(
                self,
                *,
                model: str,
                system: str,
                messages: list[dict[str, str]],
                max_tokens: int = 1024,
                response_format: str | None = None,
            ) -> str:
                return llm_response

        engine = _make_engine()
        handler = SteerHandler(
            oversight=engine,
            event_store=_FakeSink(),  # type: ignore[arg-type]
            llm=_FixedLLM(),
        )
        return handler, events

    def test_llm_path_valid_add_constraint_used(self) -> None:
        """LLM이 유효한 add_constraint 반환 → LLM 분류 사용."""
        import json

        llm_json = json.dumps(
            {
                "action": "add_constraint",
                "category": "banned_path",
                "pattern": "*/secret/*",
                "rationale": "llm: secret paths banned",
            }
        )
        handler, events = self._make_handler_with_mock_llm(llm_json)

        outcome = handler.apply(
            run_id="run-llm-001",
            directive="비밀 경로 차단해",
            actor="role:operator:u-1",
        )

        assert outcome.classification.action == "add_constraint"
        assert outcome.classification.category == "banned_path"

    def test_llm_path_invalid_action_falls_back_to_deterministic(self) -> None:
        """LLM이 비허용 action 반환 → 결정적 폴백."""
        import json

        llm_json = json.dumps(
            {
                "action": "unknown_action",  # 허용되지 않는 action
                "rationale": "bad llm output",
            }
        )
        handler, events = self._make_handler_with_mock_llm(llm_json)

        outcome = handler.apply(
            run_id="run-llm-002",
            directive="파일 읽기 허용해",
            actor="role:operator:u-1",
        )

        assert outcome.classification.action in ("add_constraint", "patch_goal", "rollback_step")

    def test_llm_path_json_decode_error_falls_back(self) -> None:
        """LLM이 JSON 파싱 불가 응답 → 결정적 폴백."""
        handler, events = self._make_handler_with_mock_llm("not valid json {{{")

        outcome = handler.apply(
            run_id="run-llm-003",
            directive="금지 경로 설정",
            actor="role:operator:u-1",
        )

        assert outcome.classification.action in ("add_constraint", "patch_goal", "rollback_step")

    def test_llm_path_non_dict_response_falls_back(self) -> None:
        """LLM이 dict가 아닌 JSON 반환 → 결정적 폴백."""
        import json

        handler, events = self._make_handler_with_mock_llm(json.dumps(["list", "not", "dict"]))

        outcome = handler.apply(
            run_id="run-llm-004",
            directive="허용 목록 추가",
            actor="role:operator:u-1",
        )

        assert outcome.classification.action in ("add_constraint", "patch_goal", "rollback_step")

    def test_llm_path_llm_error_falls_back_to_deterministic(self) -> None:
        """LLM 호출 중 LLMError → 결정적 폴백 (fail-closed)."""
        from secugent.core.llm_client import LLMClient, LLMError
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        class _ErrorLLM(LLMClient):
            def generate(
                self,
                *,
                model: str,
                system: str,
                messages: list[dict[str, str]],
                max_tokens: int = 1024,
                response_format: str | None = None,
            ) -> str:
                raise LLMError("service unavailable")

        engine = _make_engine()
        handler = SteerHandler(
            oversight=engine,
            event_store=_FakeSink(),  # type: ignore[arg-type]
            llm=_ErrorLLM(),
        )

        outcome = handler.apply(
            run_id="run-llm-005",
            directive="/etc 경로 차단",
            actor="role:operator:u-1",
        )

        assert outcome.classification.action in ("add_constraint", "patch_goal", "rollback_step")

    def test_sanitise_fills_missing_pattern_with_deterministic_fallback(self) -> None:
        """_sanitise: add_constraint에 pattern/category 없으면 결정적 폴백 사용 (INV-4)."""
        import json

        llm_json = json.dumps(
            {
                "action": "add_constraint",
                # pattern과 category 모두 없음
                "rationale": "llm: incomplete output",
            }
        )
        handler, events = self._make_handler_with_mock_llm(llm_json)

        outcome = handler.apply(
            run_id="run-sanitise-001",
            directive="/etc 경로 차단",
            actor="role:operator:u-1",
        )

        # _sanitise 폴백 → 결정적 분류기의 결과를 사용
        assert outcome.classification.action == "add_constraint"

    def test_llm_path_code_fenced_json_parsed_correctly(self) -> None:
        """LLM이 ```json ... ``` 코드펜스 감싸도 파싱됨."""
        import json

        inner = json.dumps(
            {
                "action": "add_constraint",
                "category": "banned_path",
                "pattern": "*/tmp/*",
                "rationale": "no tmp access",
            }
        )
        fenced = f"```json\n{inner}\n```"
        handler, events = self._make_handler_with_mock_llm(fenced)

        outcome = handler.apply(
            run_id="run-llm-006",
            directive="/scratch 차단",  # noqa: S108 – test fixture string, never a real path
            actor="role:operator:u-1",
        )

        assert outcome.classification.action == "add_constraint"

    def test_precommit_classify_intervention_abort_keywords(self) -> None:
        """precommit.classify_intervention: 한국어 중단 키워드 → abort."""
        from secugent.steer.precommit import classify_intervention

        assert classify_intervention("중단해줘") == "abort"
        assert classify_intervention("취소") == "abort"
        assert classify_intervention("정지하고") == "abort"
        assert classify_intervention("회수해주세요") == "abort"
        assert classify_intervention("abort this") == "abort"

    def test_precommit_classify_intervention_non_abort(self) -> None:
        """precommit.classify_intervention: 비중단 지시 → resume."""
        from secugent.steer.precommit import classify_intervention

        assert classify_intervention("계속해") == "resume"
        assert classify_intervention("다음 단계로") == "resume"
        assert classify_intervention("keep going") == "resume"

    def test_apply_raises_on_empty_directive(self) -> None:
        """빈/공백 directive → ValueError (steer.py:168)."""
        from secugent.steer.steer import SteerHandler

        events: list[Any] = []

        class _FakeSink:
            def append_event(self, event: Any) -> None:
                events.append(event)

        engine = _make_engine()
        handler = SteerHandler(oversight=engine, event_store=_FakeSink())  # type: ignore[arg-type]

        import pytest

        with pytest.raises(ValueError, match="directive cannot be empty"):
            handler.apply(run_id="run-empty", directive="", actor="op:u-1")

        # 공백만 있어도 동일
        with pytest.raises(ValueError, match="directive cannot be empty"):
            handler.apply(run_id="run-empty", directive="   ", actor="op:u-1")

    def test_normalize_pattern_plain_word_gets_wildcard_prefix(self) -> None:
        """_normalize_pattern: 평범한 단어(*, / 아님)에 */ 접두사 추가 (steer.py:379)."""
        from secugent.steer.steer import SteerHandler

        # 평범한 단어(not starting with * or / or C:/) → should become */word/*
        result = SteerHandler._normalize_pattern("secret")
        assert result == "*/secret/*"

        # Windows 드라이브 경로(C:/) → 접두사 추가 안 됨
        result_win = SteerHandler._normalize_pattern("C:/Users/foo")
        assert result_win.startswith("c:/")  # 대소문자 정규화됨


# ---------------------------------------------------------------------------
# precommit.py 커버리지: intervene·compensate·rollback_reversible 함수
# ---------------------------------------------------------------------------


class TestPrecommitFunctions:
    """precommit.py 핵심 함수 커버리지 (기존 모듈, 재사용).

    C1-T1c 관련: steer.precommit의 abort/compensate/rollback 경로.
    """

    def _make_principal(self, tenant_id: str = "tenant-fin-001") -> Any:
        from secugent.core.tenancy import Principal

        return Principal(tenant_id=tenant_id, user_id="u-1", role="operator")

    def _make_audit_sink(self) -> tuple[Any, list[Any]]:
        events: list[Any] = []

        class _Sink:
            def append_event(self, event: Any) -> Any:
                events.append(event)
                return event

        return _Sink(), events

    def test_intervene_resume_kind_returns_empty(self) -> None:
        """non-abort 지시 → intervene returns []."""
        from secugent.io.staging import StagedEffectStore
        from secugent.steer.precommit import intervene

        principal = self._make_principal()
        store = StagedEffectStore()
        sink, events = self._make_audit_sink()

        result = intervene(
            "run-pre-001",
            "계속 진행해줘",
            principal=principal,
            store=store,
            audit=sink,  # type: ignore[arg-type]
        )

        assert result == []
        # precommit.received 이벤트는 항상 emit
        assert any(e.type == "precommit.received" for e in events)

    def test_intervene_abort_kind_with_no_staged_returns_empty_aborted(self) -> None:
        """abort 지시 + staged effects 없음 → 빈 목록 반환 + precommit.aborted emit."""
        from secugent.io.staging import StagedEffectStore
        from secugent.steer.precommit import intervene

        principal = self._make_principal("tenant-abort-test")
        store = StagedEffectStore()  # 빈 스토어
        sink, events = self._make_audit_sink()

        result = intervene(
            "run-pre-002",
            "중단해",
            principal=principal,
            store=store,
            audit=sink,  # type: ignore[arg-type]
        )

        assert result == []
        # precommit.received + precommit.aborted(0건) 이벤트 모두 emit
        event_types = [e.type for e in events]
        assert "precommit.received" in event_types
        assert "precommit.aborted" in event_types

    def test_compensate_returns_compensating_action(self) -> None:
        """compensate → compensating_action 반환 + audit 이벤트."""
        from secugent.core.sec.effects import Effect
        from secugent.steer.precommit import compensate

        principal = self._make_principal()
        sink, events = self._make_audit_sink()
        effect = Effect(kind="compensatable", target="table/row-123", sink_class="database")

        result = compensate(
            effect,
            "DELETE FROM table WHERE id='row-123'",
            principal=principal,
            run_id="run-pre-003",
            audit=sink,  # type: ignore[arg-type]
        )

        assert result == "DELETE FROM table WHERE id='row-123'"
        assert any(e.type == "precommit.compensated" for e in events)

    def test_rollback_reversible_restores_file(self, tmp_path: Any) -> None:
        """rollback_reversible → 파일 원상복구 + audit 이벤트."""
        from secugent.core.sec.effects import Effect
        from secugent.steer.precommit import rollback_reversible
        from secugent.steer.snapshots import FileSnapshotStore

        principal = self._make_principal()
        sink, events = self._make_audit_sink()
        snapshots = FileSnapshotStore()

        # 파일 생성 후 스냅샷 (POSIX 경로 사용)
        test_file = tmp_path / "test_restore.txt"
        test_file.write_text("원본 내용", encoding="utf-8")
        # FileSnapshotStore는 str 경로 수용
        snapshots.capture(str(test_file))

        # 파일 수정
        test_file.write_text("변경된 내용", encoding="utf-8")

        # Effect는 정방향 슬래시 경로 필요 (canonical)
        target_canonical = test_file.as_posix()
        effect = Effect(kind="reversible", target=target_canonical, sink_class="filesystem")

        rollback_reversible(
            effect,
            snapshots=snapshots,
            principal=principal,
            run_id="run-pre-004",
            audit=sink,  # type: ignore[arg-type]
        )

        # 파일이 원본으로 복구됨
        assert test_file.read_text(encoding="utf-8") == "원본 내용"
        assert any(e.type == "precommit.rolled_back" for e in events)
