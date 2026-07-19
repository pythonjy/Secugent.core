# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-02 회귀 테스트: paused_at_step_id → checkpoint 기록 + steer.paused 발행.

DispatcherAdapter._handle_pause_result 가 체크포인트를 SQLiteCheckpointStore에
기록하고 ChainedEventStore에 steer.paused 이벤트를 발행하는지 검증한다.
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------


def _make_chain(tmp_path: Path) -> tuple[Any, Any]:
    """Return (SQLiteCheckpointStore, ChainedEventStore) using a shared tmp db."""
    from secugent.audit.hash_chain import ChainedEventStore
    from secugent.core.event_store import EventStore

    db_path = str(tmp_path / "test_events.db")
    event_store = EventStore(db_path)
    chain = ChainedEventStore(event_store)
    return chain, event_store


# ---------------------------------------------------------------------------
# Minimal sub-result stub (SubAgentResult 모사)
# ---------------------------------------------------------------------------


class _PausedSubResult:
    """SubAgentResult 최솟값 모사 — paused_at_step_id 설정."""

    def __init__(self, *, paused_at: str, actor: str = "role:operator:u-test") -> None:
        self.paused_at_step_id: str | None = paused_at
        self.aborted: bool = False
        self.halted_early: bool = False
        self.actor: str = actor
        self.step_index: int = 2
        self.tenant_id: str = "tenant-sg02"
        self.pending_step_ids: list[str] = ["step-3", "step-4"]
        self.completed_step_ids: list[str] = ["step-1", "step-2"]
        self.session_patch_set: list[Any] = []
        self.patch_remaining_ttl: dict[str, int] = {}
        self.regulations_version: str = "1.0.0"
        self.envelope_hash: str = "dummy-env-hash"
        self.rule_of_two_axes: list[str] = ["sensitive_access"]
        self.approval_scope_ref: str = "scope-sg02"
        self.staged_effect_disposition: list[Any] = []
        self.file_before_images_ref: dict[str, str] = {}
        self.directive_log_ref: list[Any] = []


# ---------------------------------------------------------------------------
# SG-02: DispatcherAdapter accepts checkpoint_store parameter
# ---------------------------------------------------------------------------


class TestDispatcherAdapterHasCheckpointStore:
    """DispatcherAdapter.__init__ に checkpoint_store + audit_chain パラメータが存在する."""

    def test_checkpoint_store_param_exists(self) -> None:
        """DispatcherAdapter.__init__ signature에 checkpoint_store가 있어야 한다."""
        from secugent.orchestrator.adapters import DispatcherAdapter

        sig = inspect.signature(DispatcherAdapter.__init__)
        assert "checkpoint_store" in sig.parameters, (
            "DispatcherAdapter.__init__에 checkpoint_store 파라미터 없음 — SG-20260621-02 미구현"
        )

    def test_audit_chain_param_exists(self) -> None:
        """DispatcherAdapter.__init__ signature에 audit_chain이 있어야 한다."""
        from secugent.orchestrator.adapters import DispatcherAdapter

        sig = inspect.signature(DispatcherAdapter.__init__)
        assert "audit_chain" in sig.parameters, (
            "DispatcherAdapter.__init__에 audit_chain 파라미터 없음 — SG-20260621-02 미구현"
        )

    def test_handle_pause_result_method_exists(self) -> None:
        """_handle_pause_result async 메서드가 존재해야 한다."""
        from secugent.orchestrator.adapters import DispatcherAdapter

        assert hasattr(DispatcherAdapter, "_handle_pause_result"), (
            "DispatcherAdapter._handle_pause_result 없음 — SG-20260621-02 미구현"
        )
        assert asyncio.iscoroutinefunction(DispatcherAdapter._handle_pause_result), (
            "_handle_pause_result는 async 메서드여야 한다"
        )


# ---------------------------------------------------------------------------
# SG-02: _handle_pause_result writes checkpoint + emits steer.paused
# ---------------------------------------------------------------------------


class TestHandlePauseResult:
    """pause 발생 시 checkpoint_store.write + steer.paused 이벤트 발행."""

    def _make_adapter(
        self,
        checkpoint_store: SQLiteCheckpointStore | None,
        audit_chain: Any = None,
    ) -> Any:
        """DispatcherAdapter를 최소 의존성으로 생성."""
        from secugent.orchestrator.adapters import DispatcherAdapter

        adapter = DispatcherAdapter.__new__(DispatcherAdapter)
        adapter._checkpoint_store = checkpoint_store
        adapter._audit_chain = audit_chain
        return adapter

    def test_checkpoint_written_on_pause(self) -> None:
        """paused_at_step_id 설정 → checkpoint_store.write 호출 → SnapshotRef 반환."""
        store = SQLiteCheckpointStore(":memory:")
        adapter = self._make_adapter(checkpoint_store=store)
        result = _PausedSubResult(paused_at="step-3")

        asyncio.run(adapter._handle_pause_result("run-sg02-001", result))

        # 체크포인트가 실제로 저장됐는지 DB에서 확인
        cur = store._conn.execute(
            "SELECT run_id, tenant_id, step_index FROM run_checkpoints WHERE run_id=?",
            ("run-sg02-001",),
        )
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "run-sg02-001"
        assert rows[0][1] == "tenant-sg02"
        assert rows[0][2] == 2
        store.close()

    def test_steer_paused_event_emitted(self, tmp_path: Path) -> None:
        """checkpoint 기록 성공 후 steer.paused 이벤트가 audit chain에 발행된다."""
        store = SQLiteCheckpointStore(str(tmp_path / "ckpt.db"))
        chain, _ev = _make_chain(tmp_path)

        adapter = self._make_adapter(checkpoint_store=store, audit_chain=chain)
        result = _PausedSubResult(paused_at="step-3")

        asyncio.run(adapter._handle_pause_result("run-sg02-002", result))

        records = chain.read_chain(tenant_id="tenant-sg02")
        assert len(records) == 1
        assert records[0].event.type == "steer.paused"
        assert records[0].event.run_id == "run-sg02-002"
        assert records[0].event.payload.get("paused_at_step_id") == "step-3"
        assert "context_snapshot_ref" in records[0].event.payload
        assert records[0].event.payload["context_snapshot_ref"].startswith("snap://")

        chain.close()
        store.close()

    def test_checkpoint_uri_in_steer_paused_payload(self, tmp_path: Path) -> None:
        """steer.paused payload의 context_snapshot_ref이 실제 checkpoint URI여야 한다."""
        store = SQLiteCheckpointStore(str(tmp_path / "ckpt.db"))
        chain, _ev = _make_chain(tmp_path)

        adapter = self._make_adapter(checkpoint_store=store, audit_chain=chain)
        result = _PausedSubResult(paused_at="step-4", actor="sys")

        asyncio.run(adapter._handle_pause_result("run-sg02-003", result))

        records = chain.read_chain(tenant_id="tenant-sg02")
        assert records
        ref_uri: str = records[0].event.payload["context_snapshot_ref"]
        # URI 형식 검증: snap://{run_id}/step-{step_index}/{checkpoint_id}
        assert ref_uri.startswith("snap://run-sg02-003/step-2/")

        chain.close()
        store.close()

    def test_no_checkpoint_store_emits_warning_not_raises(self) -> None:
        """checkpoint_store=None이어도 예외가 발생하지 않는다 (경고만)."""
        adapter = self._make_adapter(checkpoint_store=None)
        result = _PausedSubResult(paused_at="step-x")
        # Should not raise
        asyncio.run(adapter._handle_pause_result("run-sg02-nowire", result))

    def test_checkpoint_write_failure_emits_steer_failed(self, tmp_path: Path) -> None:
        """checkpoint_store.write 실패 시 steer.failed 이벤트를 발행하고 예외를 삼키지 않는다."""
        broken_store = MagicMock(spec=SQLiteCheckpointStore)
        broken_store.write.side_effect = RuntimeError("disk full")

        chain, _ev = _make_chain(tmp_path)

        adapter = self._make_adapter(checkpoint_store=broken_store, audit_chain=chain)
        result = _PausedSubResult(paused_at="step-5", actor="sys")

        # Must NOT raise despite write failure
        asyncio.run(adapter._handle_pause_result("run-sg02-fail", result))

        # steer.failed should have been emitted
        records = chain.read_chain(tenant_id="tenant-sg02")
        assert len(records) == 1
        assert records[0].event.type == "steer.failed"
        chain.close()

    def test_durable_before_broadcast_order(self, tmp_path: Path) -> None:
        """체크포인트가 steer.paused 발행보다 먼저 기록되어야 한다 (INV-5)."""
        from secugent.audit.hash_chain import ChainedEventStore
        from secugent.core.event_store import EventStore

        write_calls: list[str] = []

        class _TrackingStore(SQLiteCheckpointStore):
            def write(self, checkpoint: RunCheckpoint) -> Any:
                write_calls.append("checkpoint_write")
                return super().write(checkpoint)

        class _TrackingChain(ChainedEventStore):
            def append_event(self, event: Any) -> Any:
                write_calls.append(f"event:{event.type}")
                return super().append_event(event)

        db_path = str(tmp_path / "order_events.db")
        inner_event_store = EventStore(db_path)
        tracking_chain = _TrackingChain(inner_event_store)
        tracking_store = _TrackingStore(str(tmp_path / "order_ckpt.db"))

        adapter = self._make_adapter(checkpoint_store=tracking_store, audit_chain=tracking_chain)
        result = _PausedSubResult(paused_at="step-3")
        asyncio.run(adapter._handle_pause_result("run-sg02-order", result))

        assert write_calls == ["checkpoint_write", "event:steer.paused"], (
            f"순서 위반: {write_calls} — 체크포인트가 먼저 기록돼야 한다"
        )

        tracking_chain.close()
        tracking_store.close()


# ---------------------------------------------------------------------------
# SG-02: SQLiteCheckpointStore 기본 연기 테스트
# ---------------------------------------------------------------------------


class TestSQLiteCheckpointStoreSanity:
    """SQLiteCheckpointStore 연기 테스트 (이미 test_interrupt_core에 있지만 SG-02 회귀용)."""

    def test_write_and_resolve_roundtrip(self) -> None:
        """write → resolve 라운드트립이 성공해야 한다."""
        store = SQLiteCheckpointStore(":memory:")
        ckpt = RunCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            run_id="run-sg02-rt",
            tenant_id="t1",
            step_index=1,
            pending_step_ids=["s2"],
            completed_step_ids=["s1"],
            session_patch_set=[],
            patch_remaining_ttl={},
            regulations_version="1.0.0",
            envelope_hash="",
            rule_of_two_axes=[],
            approval_scope_ref="",
            staged_effect_disposition=[],
            file_before_images_ref={},
            directive_log_ref=[],
            created_at=datetime.now(tz=UTC).isoformat(),
            actor="system",
        )
        ref = store.write(ckpt)
        resolved = store.resolve(ref)
        assert resolved.run_id == "run-sg02-rt"
        assert resolved.step_index == 1
        assert resolved.pending_step_ids == ["s2"]
        store.close()
