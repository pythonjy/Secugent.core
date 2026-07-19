# SPDX-License-Identifier: Apache-2.0
"""Snapshot + rollback for REVERSIBLE file effects (EM-09).

The honest scope: only genuinely reversible effects (sandbox file writes) can be
rolled back this way. Irreversible effects are caught pre-commit by staging
(``io.staging``); compensatable effects are handled by issuing a compensating
action (``steer.precommit.compensate``).

추가 구성요소: ``SnapshotRef``, ``RunCheckpoint``, ``DurableSnapshotStore`` Protocol,
``SQLiteCheckpointStore`` — 정지 시 런 컨텍스트를 SQLite에 영속하고 재개 시 복원한다.
D-C 결정: run_checkpoints(checkpoint_id PK, run_id, tenant_id, blob JSON, created_at).
D-E 결정: patch_remaining_ttl(잔여 TTL 초)을 동결 — expires_at 절대값이 아님.
INV-SNAP-1/2: durable + atomic (row와 blob 동시 존재 또는 미존재).
URI 형식: snap://{run_id}/step-{step_index}/{checkpoint_id}
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "DurableSnapshotStore",
    "FileSnapshotStore",
    "RunCheckpoint",
    "SnapshotRef",
    "SQLiteCheckpointStore",
]

# ---------------------------------------------------------------------------
# SnapshotRef (frozen, INV-SNAP-1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotRef:
    """재개 체크포인트에 대한 결정적 참조.

    frozen=True → 불변. URI는 checkpoint_id 기반으로 생성되며 결정적이다.
    URI 형식: snap://{run_id}/step-{step_index}/{checkpoint_id}
    uuid나 wall-clock이 canonical 해시 body에 유입되지 않는다 (INV-DET-1).
    """

    uri: str
    run_id: str
    step_index: int
    pending_step_ids: tuple[str, ...]


# ---------------------------------------------------------------------------
# RunCheckpoint (정지 시 컨텍스트 전체 스냅샷)
# ---------------------------------------------------------------------------


@dataclass
class RunCheckpoint:
    """런 일시정지 시 캡처되는 컨텍스트 스냅샷 (§6 내용).

    D-E: patch_remaining_ttl — 동결된 잔여 TTL(초). expires_at 절대값 불가.
    D-H: completed_step_ids는 advisory(감사체인이 권위 소스).
    """

    checkpoint_id: str
    run_id: str
    tenant_id: str
    step_index: int
    """다음에 실행할 스텝 인덱스 (이미 완료된 마지막 스텝 + 1)."""
    pending_step_ids: list[str]
    """아직 실행되지 않은 스텝 ID 목록."""
    completed_step_ids: list[str]
    """완료된 스텝 ID 목록 (advisory — D-H)."""
    session_patch_set: list[dict[str, Any]]
    """활성 SessionRegulationPatch 직렬화."""
    patch_remaining_ttl: dict[str, int]
    """패치 ID → 잔여 TTL(초) (D-E: 동결 — 절대 expires_at 아님)."""
    regulations_version: str
    envelope_hash: str
    rule_of_two_axes: list[str]
    approval_scope_ref: str
    staged_effect_disposition: list[dict[str, Any]]
    file_before_images_ref: dict[str, str]
    """파일 경로 → 이전 스냅샷 URI."""
    directive_log_ref: list[dict[str, Any]]
    created_at: str
    """ISO8601 UTC 타임스탬프 (비결정 필드 — 해시 body 제외)."""
    actor: str
    """정지를 요청한 액터 (§9.1)."""


# ---------------------------------------------------------------------------
# DurableSnapshotStore Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class DurableSnapshotStore(Protocol):
    """체크포인트 영속 저장소 추상화."""

    def write(self, checkpoint: RunCheckpoint) -> SnapshotRef:
        """체크포인트를 저장하고 참조를 반환한다.

        SNAP-2: row와 blob이 동시에 존재하거나 동시에 미존재 (원자적).
        """
        ...

    def resolve(self, ref: SnapshotRef) -> RunCheckpoint:
        """참조로 체크포인트를 복원한다.

        Raises:
            KeyError: ref에 해당하는 체크포인트가 없을 때.
        """
        ...


# ---------------------------------------------------------------------------
# SQLiteCheckpointStore (D-C)
# ---------------------------------------------------------------------------

_CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    blob TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ckpt_run ON run_checkpoints(run_id);
"""


def _make_uri(run_id: str, step_index: int, checkpoint_id: str) -> str:
    """URI 결정 생성 (INV-DET-1: 동일 입력 → 동일 URI)."""
    return f"snap://{run_id}/step-{step_index}/{checkpoint_id}"


class SQLiteCheckpointStore:
    """SQLite 기반 체크포인트 저장소 (D-C).

    - isolation_level=None(autocommit) + 명시 BEGIN/COMMIT으로 원자성 보장.
    - check_same_thread=False: asyncio.Lock 없이 단순 동기 호출을 허용
      (SQLiteRunStateStore와 동일 패턴).
    """

    def __init__(self, path: str) -> None:
        self._path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_CHECKPOINT_SCHEMA)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._conn.close()

    def write(self, checkpoint: RunCheckpoint) -> SnapshotRef:
        """체크포인트를 저장하고 SnapshotRef를 반환한다.

        SNAP-2: 하나의 트랜잭션 내에서 INSERT → row와 blob이 원자적으로 존재.
        실패 시 ROLLBACK → partial-visible row 없음.
        """
        with self._lock:
            blob = json.dumps(
                {
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "run_id": checkpoint.run_id,
                    "tenant_id": checkpoint.tenant_id,
                    "step_index": checkpoint.step_index,
                    "pending_step_ids": checkpoint.pending_step_ids,
                    "completed_step_ids": checkpoint.completed_step_ids,
                    "session_patch_set": checkpoint.session_patch_set,
                    "patch_remaining_ttl": checkpoint.patch_remaining_ttl,
                    "regulations_version": checkpoint.regulations_version,
                    "envelope_hash": checkpoint.envelope_hash,
                    "rule_of_two_axes": checkpoint.rule_of_two_axes,
                    "approval_scope_ref": checkpoint.approval_scope_ref,
                    "staged_effect_disposition": checkpoint.staged_effect_disposition,
                    "file_before_images_ref": checkpoint.file_before_images_ref,
                    "directive_log_ref": checkpoint.directive_log_ref,
                    "created_at": checkpoint.created_at,
                    "actor": checkpoint.actor,
                },
                ensure_ascii=False,
            )
            self._conn.execute("BEGIN")
            try:
                self._conn.execute(
                    "INSERT INTO run_checkpoints"
                    "(checkpoint_id, run_id, tenant_id, step_index, blob, created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (
                        checkpoint.checkpoint_id,
                        checkpoint.run_id,
                        checkpoint.tenant_id,
                        checkpoint.step_index,
                        blob,
                        checkpoint.created_at,
                    ),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

            uri = _make_uri(checkpoint.run_id, checkpoint.step_index, checkpoint.checkpoint_id)
            return SnapshotRef(
                uri=uri,
                run_id=checkpoint.run_id,
                step_index=checkpoint.step_index,
                pending_step_ids=tuple(checkpoint.pending_step_ids),
            )

    def resolve(self, ref: SnapshotRef) -> RunCheckpoint:
        """URI로 체크포인트를 복원한다.

        Raises:
            KeyError: 해당 checkpoint_id 행이 없을 때.
        """
        with self._lock:
            # URI 파싱: snap://{run_id}/step-{step_index}/{checkpoint_id}
            checkpoint_id = ref.uri.rsplit("/", 1)[-1]
            cur = self._conn.execute(
                "SELECT blob FROM run_checkpoints WHERE checkpoint_id=? AND run_id=?",
                (checkpoint_id, ref.run_id),
            )
            row = cur.fetchone()
            if row is None:
                raise KeyError(f"checkpoint not found for ref: {ref.uri!r}")
            data: dict[str, Any] = json.loads(row[0])
            return RunCheckpoint(
                checkpoint_id=data["checkpoint_id"],
                run_id=data["run_id"],
                tenant_id=data["tenant_id"],
                step_index=data["step_index"],
                pending_step_ids=data["pending_step_ids"],
                completed_step_ids=data["completed_step_ids"],
                session_patch_set=data["session_patch_set"],
                patch_remaining_ttl=data["patch_remaining_ttl"],
                regulations_version=data["regulations_version"],
                envelope_hash=data["envelope_hash"],
                rule_of_two_axes=data["rule_of_two_axes"],
                approval_scope_ref=data["approval_scope_ref"],
                staged_effect_disposition=data["staged_effect_disposition"],
                file_before_images_ref=data["file_before_images_ref"],
                directive_log_ref=data["directive_log_ref"],
                created_at=data["created_at"],
                actor=data["actor"],
            )


class FileSnapshotStore:
    """Captures a file's bytes before a reversible write so it can be restored."""

    def __init__(self) -> None:
        self._snapshots: dict[str, bytes | None] = {}

    def capture(self, path: str) -> bytes | None:
        """Snapshot ``path`` (None = file did not exist) and return its content."""
        target = Path(path)
        content = target.read_bytes() if target.is_file() else None
        self._snapshots[str(target)] = content
        return content

    def rollback(self, path: str) -> None:
        """Restore ``path`` to its snapshot. Raises if no snapshot was captured."""
        key = str(Path(path))
        if key not in self._snapshots:
            raise KeyError(f"no snapshot captured for {path!r}")
        content = self._snapshots[key]
        target = Path(path)
        if content is None:
            # Did not exist at snapshot time → remove the file the effect created.
            if target.exists():
                target.unlink()
        else:
            target.write_bytes(content)
