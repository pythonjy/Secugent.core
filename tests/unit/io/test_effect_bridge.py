# SPDX-License-Identifier: Apache-2.0
"""EM-05 — Step → Effect bridge mapping (deterministic)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secugent.core.contracts import Step
from secugent.core.sec.canonicalize import AmbiguousEffectError
from secugent.core.sec.effects import EffectKind, SinkClass
from secugent.core.tenancy import TenantId
from secugent.io.broker.effect_bridge import build_effect


def _step(action: str, *, target: str | None = None, command: str | None = None) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type=action,  # type: ignore[arg-type]
        target=target,
        command=command,
    )


def test_file_write_maps_to_local_sandbox(tmp_path: Path) -> None:
    eff = build_effect(_step("file_write", target=str(tmp_path / "a.txt")), sandbox_roots=[str(tmp_path)])
    assert eff.kind is EffectKind.FILE_WRITE
    assert eff.sink_class is SinkClass.LOCAL_SANDBOX


def test_file_read_maps(tmp_path: Path) -> None:
    eff = build_effect(_step("file_read", target=str(tmp_path / "a.txt")), sandbox_roots=[str(tmp_path)])
    assert eff.kind is EffectKind.FILE_READ


def test_http_get_maps_to_external_net_recv() -> None:
    eff = build_effect(_step("http_get", target="HTTP://Example.com/Path"), sandbox_roots=[])
    assert eff.kind is EffectKind.NET_RECV
    assert eff.sink_class is SinkClass.EXTERNAL
    assert eff.target == "http://example.com/Path"  # canonical origin + path


def test_compute_maps_to_process_exec() -> None:
    eff = build_effect(_step("compute", command="run analysis"), sandbox_roots=[])
    assert eff.kind is EffectKind.PROCESS_EXEC
    assert eff.sink_class is SinkClass.LOCAL_SANDBOX


def test_desktop_maps_to_process_exec() -> None:
    eff = build_effect(_step("desktop", command="click button"), sandbox_roots=[])
    assert eff.kind is EffectKind.PROCESS_EXEC


def test_process_target_strips_backslash() -> None:
    eff = build_effect(_step("compute", command="C:\\bin\\tool"), sandbox_roots=[])
    assert "\\" not in eff.target  # canonical Effect target uses '/'


def test_process_target_nul_falls_back_to_step_id() -> None:
    step = _step("compute", command="\x00bad")
    eff = build_effect(step, sandbox_roots=[])
    assert eff.target == step.id  # NUL-bearing command falls back to the step id


def test_unknown_action_raises() -> None:
    with pytest.raises(AmbiguousEffectError):
        build_effect(_step("unknown"), sandbox_roots=[])


def test_file_write_without_target_raises(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        build_effect(_step("file_write", target=None), sandbox_roots=[str(tmp_path)])


def test_http_get_without_target_raises() -> None:
    with pytest.raises(AmbiguousEffectError):
        build_effect(_step("http_get", target=None), sandbox_roots=[])
