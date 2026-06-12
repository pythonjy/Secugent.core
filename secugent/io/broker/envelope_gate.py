# SPDX-License-Identifier: Apache-2.0
"""Broker envelope gate (EM-07 ↔ EM-05 binding).

Adapts the run-scoped :class:`AuthorizationEnvelope` to the broker's
``EnvelopeGate`` protocol: it reads the envelope + usage bound to the current run
context, classifies the effect's reversibility, and calls the pure
``envelope.check``. Lives in ``io`` so ``core.sec.envelope`` stays a leaf that
knows nothing about ``EgressRequest``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from secugent.core.sec.envelope import (
    EnvelopeDecision,
    check,
    current_envelope,
    current_envelope_usage,
)
from secugent.core.sec.reversibility import ManifestRegistry
from secugent.io.broker.request import EgressRequest

__all__ = ["EnvelopeGate"]


class EnvelopeGate:
    """Broker-side envelope check. Deny-by-default when no envelope is bound."""

    def __init__(
        self,
        registry: ManifestRegistry,
        *,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._now_provider = now_provider

    def check(self, request: EgressRequest) -> EnvelopeDecision:
        try:
            envelope = current_envelope()
            usage = current_envelope_usage()
        except LookupError:
            # No envelope bound to this run ⇒ nothing is authorized.
            return EnvelopeDecision(outcome="suspend", reason="no_envelope_bound")
        action = request.effect.action or str(request.effect.kind)
        reversibility = self._registry.classify(action)
        now = self._now_provider() if self._now_provider is not None else None
        return check(request.effect, request.label, envelope, usage, reversibility, now=now)
