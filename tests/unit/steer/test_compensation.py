# SPDX-License-Identifier: Apache-2.0
"""EM-09 — compensatable = emit compensating action; reversible = snapshot rollback."""

from __future__ import annotations

from pathlib import Path

import pytest

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.tenancy import Principal, TenantId
from secugent.steer.precommit import compensate, rollback_reversible
from secugent.steer.snapshots import FileSnapshotStore

_P = Principal(user_id="alice", tenant_id=TenantId("acme"), role="operator")


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def test_compensate_emits_compensating_action() -> None:
    audit = _Audit()
    eff = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target="general",
        sink_class=SinkClass.EXTERNAL,
        action="slack.post_message",
    )
    action = compensate(eff, "slack.delete_message", principal=_P, run_id="r1", audit=audit)
    assert action == "slack.delete_message"
    assert any(e.type == "precommit.compensated" for e in audit.events)


def test_snapshot_rollback_restores_file(tmp_path: Path) -> None:
    target = str(tmp_path / "doc.txt").replace("\\", "/").lower()
    Path(target).write_bytes(b"original")
    snapshots = FileSnapshotStore()
    snapshots.capture(target)
    Path(target).write_bytes(b"modified by agent")

    eff = Effect(kind=EffectKind.FILE_WRITE, target=target, sink_class=SinkClass.LOCAL_SANDBOX)
    rollback_reversible(eff, snapshots=snapshots, principal=_P, run_id="r1", audit=_Audit())
    assert Path(target).read_bytes() == b"original"


def test_snapshot_rollback_removes_created_file(tmp_path: Path) -> None:
    target = str(tmp_path / "new.txt").replace("\\", "/").lower()
    snapshots = FileSnapshotStore()
    snapshots.capture(target)  # file does not exist yet
    Path(target).write_bytes(b"created by agent")
    snapshots.rollback(target)
    assert not Path(target).exists()


def test_rollback_noop_when_file_never_created(tmp_path: Path) -> None:
    target = str(tmp_path / "ghost.txt").replace("\\", "/").lower()
    snapshots = FileSnapshotStore()
    snapshots.capture(target)  # did not exist
    snapshots.rollback(target)  # still absent → no-op
    assert not Path(target).exists()


def test_rollback_without_snapshot_raises() -> None:
    with pytest.raises(KeyError):
        FileSnapshotStore().rollback("c:/never/snapshotted.txt")
