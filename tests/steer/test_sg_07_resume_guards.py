# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-07 회귀 테스트: terminal run resume 거부 + cross-run checkpoint 거부."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from secugent.orchestrator.runner import CheckpointMismatchError, RunOrchestrator
from secugent.steer.snapshots import RunCheckpoint, SnapshotRef, SQLiteCheckpointStore


def _make_ckpt(run_id: str, tenant_id: str = "t1") -> RunCheckpoint:
    return RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id=tenant_id,
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


def _make_runner() -> RunOrchestrator:
    dispatcher = MagicMock()
    dispatcher.dispatch = AsyncMock(return_value={})
    return RunOrchestrator(planner=MagicMock(), dispatcher=dispatcher)


class TestResumeGuards:
    """resume_from_checkpoint 보호 조건 검증."""

    def test_cross_run_checkpoint_rejected(self) -> None:
        """checkpoint.run_id != run_id → CheckpointMismatchError.

        SQLite resolve adds run_id to WHERE, so the wrong ref raises KeyError
        which is converted to CheckpointMismatchError.
        """
        runner = _make_runner()
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt(run_id="run-actual")
        store.write(ckpt)

        async def _run() -> None:
            # Build a ref that uses wrong run_id — resolve will find nothing
            wrong_ref = SnapshotRef(
                uri=f"snap://run-actual/step-1/{ckpt.checkpoint_id}",
                run_id="run-other",  # wrong run_id for WHERE clause
                step_index=1,
                pending_step_ids=("s1",),
            )
            await runner.resume_from_checkpoint(
                "run-other",
                wrong_ref,
                checkpoint_store=store,
            )

        with pytest.raises(CheckpointMismatchError):
            asyncio.run(_run())

    def test_wrong_tenant_checkpoint_rejected(self) -> None:
        """checkpoint.tenant_id != expected_tenant → CheckpointMismatchError."""
        runner = _make_runner()
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt(run_id="run-t1", tenant_id="tenant-a")
        ref = store.write(ckpt)

        async def _run() -> None:
            await runner.resume_from_checkpoint(
                "run-t1",
                ref,
                checkpoint_store=store,
                expected_tenant="tenant-b",  # wrong tenant
            )

        with pytest.raises(CheckpointMismatchError, match="tenant_id"):
            asyncio.run(_run())

    def test_correct_tenant_allowed(self) -> None:
        """checkpoint.tenant_id == expected_tenant → 정상 통과."""
        runner = _make_runner()
        store = SQLiteCheckpointStore(":memory:")
        ckpt = _make_ckpt(run_id="run-ok", tenant_id="tenant-x")
        ref = store.write(ckpt)

        async def _run() -> None:
            await runner.resume_from_checkpoint(
                "run-ok",
                ref,
                checkpoint_store=store,
                expected_tenant="tenant-x",
            )

        # Should not raise
        asyncio.run(_run())

    def test_run_id_mismatch_in_checkpoint_body_rejected(self) -> None:
        """checkpoint blob run_id != run_id arg → CheckpointMismatchError.

        This catches the case where the checkpoint was stored with a different
        run_id than what the caller is requesting (tampered or confused ref).
        """
        runner = _make_runner()
        store = SQLiteCheckpointStore(":memory:")
        # Write checkpoint for run-real
        ckpt = _make_ckpt(run_id="run-real", tenant_id="tenant-y")
        ref = store.write(ckpt)

        # Now call with run-fake matching the ref's run_id so SQL resolves,
        # but checkpoint.run_id (run-real) != run_id arg (run-fake)
        # We can't easily do this with the SQL guard already applied, so test
        # the actual guard in the runner by patching the store.resolve
        fake_ckpt = _make_ckpt(run_id="run-real", tenant_id="tenant-y")
        mock_store = MagicMock()
        mock_store.resolve.return_value = fake_ckpt

        async def _run_mismatched() -> None:
            await runner.resume_from_checkpoint(
                "run-fake",  # different from fake_ckpt.run_id == "run-real"
                ref,
                checkpoint_store=mock_store,
            )

        with pytest.raises(CheckpointMismatchError, match="run_id"):
            asyncio.run(_run_mismatched())
