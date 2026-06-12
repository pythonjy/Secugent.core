# SPDX-License-Identifier: Apache-2.0
"""Execution profiles — the coarsest egress boundary (EM-05).

A run is bound to the *minimum* profile it needs. The profile fixes which
:class:`SinkClass` an effect may target; read-only profiles additionally forbid
mutating effects to anything other than the local sandbox. This is the first
(strongest, cheapest) gate the broker applies.
"""

from __future__ import annotations

from enum import StrEnum

from secugent.core.sec.effects import Effect, EffectKind, SinkClass

__all__ = ["ExecutionProfile", "allowed_sinks", "profile_permits"]


class ExecutionProfile(StrEnum):
    AIRGAPPED = "airgapped"  # local sandbox only — no network, no connectors
    INTERNAL_RO = "internal_ro"  # read internal + sandbox, no mutations off-sandbox
    INTERNAL_RW = "internal_rw"  # read/write internal + sandbox
    EXTERNAL_BROKERED = "external_brokered"  # external egress (still brokered/audited)


_ALLOWED_SINKS: dict[ExecutionProfile, frozenset[SinkClass]] = {
    ExecutionProfile.AIRGAPPED: frozenset({SinkClass.LOCAL_SANDBOX}),
    ExecutionProfile.INTERNAL_RO: frozenset({SinkClass.LOCAL_SANDBOX, SinkClass.INTERNAL}),
    ExecutionProfile.INTERNAL_RW: frozenset({SinkClass.LOCAL_SANDBOX, SinkClass.INTERNAL}),
    ExecutionProfile.EXTERNAL_BROKERED: frozenset(
        {SinkClass.LOCAL_SANDBOX, SinkClass.INTERNAL, SinkClass.EXTERNAL}
    ),
}

_MUTATING_KINDS = frozenset(
    {EffectKind.FILE_WRITE, EffectKind.NET_SEND, EffectKind.CONNECTOR_ACTION, EffectKind.PROCESS_EXEC}
)
_READ_ONLY_PROFILES = frozenset({ExecutionProfile.AIRGAPPED, ExecutionProfile.INTERNAL_RO})


def allowed_sinks(profile: ExecutionProfile) -> frozenset[SinkClass]:
    """Sink classes an effect may target under ``profile``."""
    return _ALLOWED_SINKS[profile]


def profile_permits(profile: ExecutionProfile, effect: Effect) -> bool:
    """Whether ``effect`` is within ``profile``'s boundary.

    Sink must be allowed; read-only profiles additionally forbid mutating effects
    that target anything other than the local sandbox.
    """
    if effect.sink_class not in allowed_sinks(profile):
        return False
    if (
        profile in _READ_ONLY_PROFILES
        and effect.kind in _MUTATING_KINDS
        and effect.sink_class is not SinkClass.LOCAL_SANDBOX
    ):
        return False
    return True
