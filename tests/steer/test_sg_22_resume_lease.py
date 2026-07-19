# SPDX-License-Identifier: Apache-2.0
"""회귀 테스트: resume_from_checkpoint HA lease 재획득.

리스 미보유 노드가 resume → dispatch 미호출 (fail-closed 단일-리더).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from secugent.orchestrator.lease import LeaseLostError
from secugent.orchestrator.runner import RunOrchestrator
from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore


def _make_checkpoint(run_id: str, store: SQLiteCheckpointStore) -> object:
    ckpt = RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id="t1",
        step_index=1,
        pending_step_ids=["s2"],
        completed_step_ids=["s1"],
        session_patch_set=[],
        patch_remaining_ttl={},
        regulations_version="1.0.0",
        envelope_hash="env-hash",
        rule_of_two_axes=["sensitive_access"],
        approval_scope_ref="",
        staged_effect_disposition=[],
        file_before_images_ref={},
        directive_log_ref=[],
        created_at=datetime.now(tz=UTC).isoformat(),
        actor="op",
    )
    return store.write(ckpt)


class TestResumeLease:
    def test_lease_not_held_dispatch_not_called(self) -> None:
        """리스 미보유 노드: LeaseLostError → dispatch 미호출, run.handover 감사."""
        lease_manager = MagicMock()
        # acquire_run raises LeaseLostError (another node holds the lease)
        lease_manager.acquire_run = AsyncMock(side_effect=LeaseLostError("lease held elsewhere"))

        dispatch_mock = AsyncMock()

        runner = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            lease_manager=lease_manager,
        )
        runner._dispatcher.dispatch = dispatch_mock

        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-lease-1", store)

        async def _run() -> None:
            await runner.resume_from_checkpoint("run-lease-1", ref, checkpoint_store=store)

        asyncio.run(_run())  # must NOT raise

        # dispatch must NOT have been called
        dispatch_mock.assert_not_called()

    def test_lease_held_dispatch_called(self) -> None:
        """리스 보유 노드: acquire_run 성공 → dispatch 호출."""
        lease_manager = MagicMock()
        lease_manager.acquire_run = AsyncMock()  # succeeds

        dispatch_called: list[bool] = []

        async def _dispatch(**kwargs: object) -> None:
            dispatch_called.append(True)

        runner = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
            lease_manager=lease_manager,
        )
        runner._dispatcher.dispatch = _dispatch

        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-lease-2", store)

        asyncio.run(runner.resume_from_checkpoint("run-lease-2", ref, checkpoint_store=store))
        assert dispatch_called, "dispatch must be called when lease is acquired"

    def test_no_lease_manager_dispatch_called_directly(self) -> None:
        """lease_manager 없으면 직접 dispatch (단일 노드 모드)."""
        dispatch_called: list[bool] = []

        async def _dispatch(**kwargs: object) -> None:
            dispatch_called.append(True)

        runner = RunOrchestrator(
            planner=MagicMock(),
            dispatcher=MagicMock(),
        )
        runner._dispatcher.dispatch = _dispatch

        store = SQLiteCheckpointStore(":memory:")
        ref = _make_checkpoint("run-lease-3", store)

        asyncio.run(runner.resume_from_checkpoint("run-lease-3", ref, checkpoint_store=store))
        assert dispatch_called
