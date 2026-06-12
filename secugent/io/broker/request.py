# SPDX-License-Identifier: Apache-2.0
"""Broker request/result models (EM-05)."""

from __future__ import annotations

from dataclasses import dataclass

from secugent.core.sec.effects import Effect
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Decision
from secugent.core.tenancy import Principal
from secugent.io.broker.profiles import ExecutionProfile

__all__ = ["EgressRequest", "EgressResult"]


@dataclass(frozen=True)
class EgressRequest:
    """One external-effect request submitted to the broker.

    ``effect`` is already EM-01-normalized; ``content`` carries write-payload bytes
    for write effects (None otherwise).
    """

    effect: Effect
    label: DataLabel
    principal: Principal
    run_id: str
    profile: ExecutionProfile
    content: bytes | None = None


@dataclass(frozen=True)
class EgressResult:
    """The broker's verdict + (on allow) the transport payload + audit anchor."""

    ok: bool
    decision: Decision
    payload: bytes | None
    audit_event_id: str
