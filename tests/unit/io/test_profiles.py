# SPDX-License-Identifier: Apache-2.0
"""EM-05 — execution profile boundary (deterministic)."""

from __future__ import annotations

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.io.broker.profiles import ExecutionProfile, allowed_sinks, profile_permits


def _eff(kind: EffectKind, sink: SinkClass, target: str = "c:/sandbox/x") -> Effect:
    if kind in (EffectKind.NET_SEND, EffectKind.NET_RECV):
        target = "https://example.com/x"
    return Effect(kind=kind, target=target, sink_class=sink)


def test_allowed_sinks_per_profile() -> None:
    assert allowed_sinks(ExecutionProfile.AIRGAPPED) == frozenset({SinkClass.LOCAL_SANDBOX})
    assert SinkClass.EXTERNAL not in allowed_sinks(ExecutionProfile.INTERNAL_RW)
    assert SinkClass.EXTERNAL in allowed_sinks(ExecutionProfile.EXTERNAL_BROKERED)


def test_airgapped_blocks_external() -> None:
    eff = _eff(EffectKind.NET_SEND, SinkClass.EXTERNAL)
    assert profile_permits(ExecutionProfile.AIRGAPPED, eff) is False


def test_airgapped_allows_local_sandbox() -> None:
    eff = _eff(EffectKind.FILE_WRITE, SinkClass.LOCAL_SANDBOX)
    assert profile_permits(ExecutionProfile.AIRGAPPED, eff) is True


def test_internal_ro_blocks_write_to_internal() -> None:
    eff = _eff(EffectKind.FILE_WRITE, SinkClass.INTERNAL, target="c:/internal/x")
    assert profile_permits(ExecutionProfile.INTERNAL_RO, eff) is False
    assert profile_permits(ExecutionProfile.INTERNAL_RW, eff) is True


def test_internal_ro_allows_read_internal() -> None:
    eff = _eff(EffectKind.FILE_READ, SinkClass.INTERNAL, target="c:/internal/x")
    assert profile_permits(ExecutionProfile.INTERNAL_RO, eff) is True


def test_external_only_in_external_brokered() -> None:
    eff = _eff(EffectKind.NET_SEND, SinkClass.EXTERNAL)
    assert profile_permits(ExecutionProfile.INTERNAL_RW, eff) is False
    assert profile_permits(ExecutionProfile.EXTERNAL_BROKERED, eff) is True


def test_profile_permits_deterministic_100x() -> None:
    eff = _eff(EffectKind.NET_SEND, SinkClass.EXTERNAL)
    outs = {profile_permits(ExecutionProfile.AIRGAPPED, eff) for _ in range(100)}
    assert outs == {False}
