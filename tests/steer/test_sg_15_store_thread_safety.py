# SPDX-License-Identifier: Apache-2.0
"""회귀 테스트: SQLiteCheckpointStore 스레드 안전성.

concurrent write + resolve가 데이터 손상 없이 완료됨.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore


def _make_checkpoint(run_id: str, step_index: int = 1) -> RunCheckpoint:
    return RunCheckpoint(
        checkpoint_id=str(uuid.uuid4()),
        run_id=run_id,
        tenant_id="tenant-thread-test",
        step_index=step_index,
        pending_step_ids=["s1", "s2"],
        completed_step_ids=[],
        session_patch_set=[],
        patch_remaining_ttl={},
        regulations_version="1.0.0",
        envelope_hash="abc123",
        rule_of_two_axes=[],
        approval_scope_ref="",
        staged_effect_disposition=[],
        file_before_images_ref={},
        directive_log_ref=[],
        created_at=datetime.now(tz=UTC).isoformat(),
        actor="test-actor",
    )


class TestStoreThreadSafety:
    """SG-15: concurrent write + resolve는 데이터 손상 없음."""

    def test_concurrent_writes_no_corruption(self) -> None:
        """동시 write 10개 — 모든 체크포인트가 손상 없이 저장됨."""
        store = SQLiteCheckpointStore(":memory:")
        refs = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def _write(run_id: str) -> None:
            ckpt = _make_checkpoint(run_id)
            try:
                ref = store.write(ckpt)
                with lock:
                    refs.append((ref, ckpt.checkpoint_id))
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=_write, args=(f"run-{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"스레드 오류 발생: {errors}"
        assert len(refs) == 10

    def test_concurrent_write_and_resolve(self) -> None:
        """write + resolve 동시 실행 — 데이터 일관성 유지."""
        store = SQLiteCheckpointStore(":memory:")
        # pre-write one checkpoint
        ckpt = _make_checkpoint("run-concurrent")
        ref = store.write(ckpt)

        results: list[RunCheckpoint] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def _resolve() -> None:
            try:
                resolved = store.resolve(ref)
                with lock:
                    results.append(resolved)
            except Exception as e:
                with lock:
                    errors.append(e)

        def _write_new() -> None:
            try:
                new_ckpt = _make_checkpoint("run-concurrent-2")
                store.write(new_ckpt)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=_resolve) for _ in range(5)] + [
            threading.Thread(target=_write_new) for _ in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"스레드 오류 발생: {errors}"
        assert len(results) == 5
        for r in results:
            assert r.run_id == ckpt.run_id
