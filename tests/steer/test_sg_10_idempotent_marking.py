# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-10 회귀 테스트: dispatch 실패 시 checkpoint가 재시도 가능."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from secugent.orchestrator.runner import RunOrchestrator
from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore


def _make_ckpt(run_id: str) -> RunCheckpoint:
    return RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id="t1",
        step_index=1,
        pending_step_ids=["s1"],
        completed_step_ids=[],
        session_patch_set=[],
        patch_remaining_ttl={},
        regulations_version="1.0.0",
        envelope_hash="abc",
        rule_of_two_axes=[],
        approval_scope_ref="",
        staged_effect_disposition=[],
        file_before_images_ref={},
        directive_log_ref=[],
        created_at=datetime.now(tz=UTC).isoformat(),
        actor="op",
    )


class TestIdempotentMarking:
    """dispatch 실패 → URI가 marked되지 않아 재시도 가능."""

    def test_uri_not_marked_after_dispatch_failure(self) -> None:
        """dispatch가 실패하면 _resumed_checkpoints에 URI가 추가되지 않는다."""
        dispatcher = MagicMock()
        dispatcher.dispatch = AsyncMock(side_effect=RuntimeError("dispatch failed"))

        runner = RunOrchestrator(planner=MagicMock(), dispatcher=dispatcher)
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt("run-retry")
        ref = store.write(ckpt)

        async def _run_once() -> None:
            await runner.resume_from_checkpoint("run-retry", ref, checkpoint_store=store)

        # First call: dispatch fails → should raise
        with pytest.raises(RuntimeError, match="dispatch failed"):
            asyncio.run(_run_once())

        # The URI must NOT be in _resumed_checkpoints
        with runner._resumed_checkpoints_lock:
            assert ref.uri not in runner._resumed_checkpoints, (
                f"URI {ref.uri!r} should NOT be marked after dispatch failure"
            )

    def test_uri_marked_after_dispatch_success(self) -> None:
        """dispatch 성공 후에는 _resumed_checkpoints에 URI가 추가된다."""
        dispatcher = MagicMock()
        dispatcher.dispatch = AsyncMock(return_value={})

        runner = RunOrchestrator(planner=MagicMock(), dispatcher=dispatcher)
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt("run-success")
        ref = store.write(ckpt)

        async def _run_once() -> None:
            await runner.resume_from_checkpoint("run-success", ref, checkpoint_store=store)

        asyncio.run(_run_once())

        with runner._resumed_checkpoints_lock:
            assert ref.uri in runner._resumed_checkpoints, (
                f"URI {ref.uri!r} should be marked after successful dispatch"
            )

    def test_retry_calls_dispatch_again_after_failure(self) -> None:
        """dispatch 실패 후 재호출 시 dispatch가 다시 실행된다."""
        call_count = 0

        async def _dispatch(**kwargs: object) -> dict[str, object]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("dispatch failed first time")
            return {}

        dispatcher = MagicMock()
        dispatcher.dispatch = _dispatch

        runner = RunOrchestrator(planner=MagicMock(), dispatcher=dispatcher)
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt("run-retry2")
        ref = store.write(ckpt)

        async def _run_once() -> None:
            await runner.resume_from_checkpoint("run-retry2", ref, checkpoint_store=store)

        # First call: dispatch fails
        with pytest.raises(RuntimeError):
            asyncio.run(_run_once())

        assert call_count == 1

        # Second call: dispatch should be called again (not skipped due to idempotent guard)
        asyncio.run(_run_once())
        assert call_count == 2, f"Expected dispatch called 2 times total, got {call_count}"
