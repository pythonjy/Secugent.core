# SPDX-License-Identifier: Apache-2.0
"""Egress Broker package (EM-05) — the single mediated path for external effects.

``get_broker()`` returns the process-wide broker once boot has installed it via
``set_broker()``. Until the go-live wiring lands (deferred — see the EM-05 spec),
the broker is constructed directly in tests.
"""

from __future__ import annotations

from secugent.io.broker.broker import (
    AuditAppendError,
    AuditStore,
    EgressBroker,
    EgressDeniedError,
    EnvelopeGate,
    EnvelopeSuspendedError,
    PolicyLike,
    StagingHeldError,
)
from secugent.io.broker.connector_transport import (
    ConnectorBinding,
    ConnectorEgressResult,
    ConnectorTransport,
)
from secugent.io.broker.credentials import CredentialBroker, CredentialError, scrub_secret
from secugent.io.broker.envelope_gate import EnvelopeGate as EnvelopeGateImpl
from secugent.io.broker.identity import CallIdentity, IdentityStrategy
from secugent.io.broker.profiles import ExecutionProfile, allowed_sinks, profile_permits
from secugent.io.broker.request import EgressRequest, EgressResult
from secugent.io.broker.transport import RouterTransport, Transport

__all__ = [
    "EgressBroker",
    "PolicyLike",
    "EgressRequest",
    "EgressResult",
    "ExecutionProfile",
    "allowed_sinks",
    "profile_permits",
    "Transport",
    "RouterTransport",
    "AuditStore",
    "EnvelopeGate",
    "EnvelopeGateImpl",
    "EgressDeniedError",
    "EnvelopeSuspendedError",
    "AuditAppendError",
    "StagingHeldError",
    "get_broker",
    "set_broker",
    "reset_broker",
    # EM-06 credential delegation + on-behalf-of identity
    "CredentialBroker",
    "CredentialError",
    "scrub_secret",
    "IdentityStrategy",
    "CallIdentity",
    "ConnectorTransport",
    "ConnectorBinding",
    "ConnectorEgressResult",
]

_BROKER: EgressBroker | None = None


def set_broker(broker: EgressBroker) -> None:
    """Install the process-wide broker (called by boot at go-live)."""
    global _BROKER
    _BROKER = broker


def get_broker() -> EgressBroker:
    """Return the installed broker, or raise if boot has not installed one."""
    if _BROKER is None:
        raise RuntimeError("egress broker not initialized (set_broker not called)")
    return _BROKER


def reset_broker() -> None:
    """Clear the process-wide broker back to its uninstalled state.

    Used by the test harness teardown (``tests/conftest.py``) so a broker
    installed by one test can never leak into the next as a stale singleton.
    """
    global _BROKER
    _BROKER = None
