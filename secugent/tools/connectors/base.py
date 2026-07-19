# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — connector Protocol + shared primitives.

Three security guarantees live here so subclasses cannot accidentally
opt-out:

1. **Allow-none policy**: an empty whitelist means *block everything*.
2. **Token-bucket rate limit**: per-tenant, fail-closed on overrun.
3. **OAuth via SecretsManager**: connectors never accept raw tokens; they
   ask the secrets layer for the canonical secret name.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secugent.core.tenancy import Principal

__all__ = [
    "Connector",
    "ConnectorAction",
    "ConnectorError",
    "ConnectorPolicy",
    "ConnectorResult",
    "ConnectorTransportUnavailable",
    "RateLimitExceeded",
    "TokenBucket",
    "WhitelistViolation",
    "COMPENSATABLE_CONNECTOR_ACTIONS",
    "IRREVERSIBLE_CONNECTOR_ACTIONS",
    "_RateLimitedConnector",
]


class ConnectorError(RuntimeError):
    """Base class for connector failures."""


class RateLimitExceeded(ConnectorError):
    """Local per-tenant token-bucket exhausted."""


class WhitelistViolation(ConnectorError):
    """Action target not in the tenant's allowlist."""


class ConnectorTransportUnavailable(ConnectorError):
    """No HTTP transport was injected into ``execute`` (fail-closed, S5).

    Connectors used to fall back to ``{mock: True}`` success when
    ``http_transport`` was ``None`` — a false-green that returned success
    without ever performing egress. A missing transport is a **configuration**
    error (the production wiring did not inject the real transport), distinct
    from a :class:`WhitelistViolation` (a policy decision). Raising this — never
    returning a mock success — makes a misconfigured deployment fail closed
    instead of silently no-op'ing every write (§A-2.2 deny-by-default, §B-8
    fail-fast). The qualified type lets the broker audit the deny reason without
    confusing it with a policy violation.
    """


class ConnectorAction(BaseModel):
    """An unqualified connector action (``post_message``), never the qualified
    ``'<connector>.<action>'`` form.

    ``name`` was a closed ``Literal`` of nine hard-coded actions. That made the
    connector layer un-extensible: a new connector (사내 메신저·ERP·ITSM) could
    not declare its own action without editing this enum, and a typo could only
    be caught against the fixed set. It is now an open ``str`` whose shape is
    still constrained — empty names and the qualified ``'.'`` form are rejected
    so a caller cannot smuggle a ``'<connector>.<action>'`` string in where an
    unqualified action is expected. Per-connector *which* actions are valid is
    enforced by each connector's ``actions`` tuple + the
    :class:`~secugent.tools.connectors.registry.ConnectorRegistry`, not here.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("ConnectorAction.name must be a non-empty action token")
        if "." in value:
            raise ValueError("ConnectorAction.name is unqualified; pass 'action' not 'connector.action'")
        return value


# EM-09: per-action reversibility markers. Mutating connector actions are
# COMPENSATABLE (an undo/delete exists) and thus run through the broker's
# compensating-action path; read actions are reversible. No connector action is
# strictly irreversible (the irreversible 'smtp.send' is not in this set). The
# qualified ('slack.post_message') manifests live in
# ``io.broker.manifests.default_manifest_registry``; these unqualified markers
# let the connector layer self-describe.
COMPENSATABLE_CONNECTOR_ACTIONS: frozenset[str] = frozenset(
    {"post_message", "create_page", "update_page", "create_issue", "transition_issue", "comment_issue"}
)
IRREVERSIBLE_CONNECTOR_ACTIONS: frozenset[str] = frozenset()


class ConnectorPolicy(BaseModel):
    """REGULATIONS slice for one connector (per tenant)."""

    model_config = ConfigDict(extra="forbid")

    allowed_channels: list[str] = Field(default_factory=list)
    redact_patterns: list[str] = Field(default_factory=list)
    allowed_workspace_ids: list[str] = Field(default_factory=list)
    allowed_database_ids: list[str] = Field(default_factory=list)
    allowed_projects: list[str] = Field(default_factory=list)
    allowed_transitions: list[str] = Field(default_factory=list)
    rate_limit_per_sec: int = 5


class ConnectorResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    payload: dict[str, Any] = Field(default_factory=dict)
    redactions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Token bucket — per-tenant rate limit (fail-closed on overrun)
# ---------------------------------------------------------------------------


@dataclass
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float = 0.0
    last_refill: float = 0.0

    def take(self, amount: float = 1.0) -> bool:
        now = time.monotonic()
        if self.last_refill == 0.0:
            self.last_refill = now
            self.tokens = float(self.capacity)
        elapsed = now - self.last_refill
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_per_sec)
        self.last_refill = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


class _RateLimitedConnector:
    """Per-tenant token-bucket rate limiting, shared by connectors.

    The four PHASE-11 connectors (slack/notion/jira + base) each carried an
    identical ``_take_rate_token`` body. Rather than copy it a fifth/sixth/seventh
    time for the extended connectors (groupware/SAP/docs), they inherit this
    mixin (§B-6: extract on the 3rd repetition). It is intentionally NOT retrofitted
    onto the existing connectors here — that would be an unrelated refactor of code
    outside this item's scope — so behaviour is byte-identical to ``slack.py``.

    The bucket is consumed in ``execute`` only; ``validate_action`` MUST stay
    side-effect-free because the transport calls it twice (pre-credential gate +
    re-check inside ``execute``).

    S5: an optional ``http_transport`` may be bound at construction. ``execute``
    uses the per-call transport when one is passed, else this bound default, else
    fails closed (:class:`ConnectorTransportUnavailable`). Binding lets the
    SubAgent → broker → connector path (which calls ``router.dispatch(step)`` with
    no per-call transport) still reach a real transport once the operator wires it.
    """

    name: str

    def __init__(self, *, http_transport: Any | None = None) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._bound_transport = http_transport

    def _resolve_transport(self, http_transport: Any | None) -> Any:
        """Per-call transport > bound transport > fail closed (S5, INV-1/3)."""
        transport = http_transport if http_transport is not None else self._bound_transport
        if transport is None:
            raise ConnectorTransportUnavailable(f"{self.name} connector has no transport configured")
        return transport

    def _take_rate_token(self, principal: Principal, policy: ConnectorPolicy) -> None:
        tenant_id = str(principal.tenant_id)
        bucket = self._buckets.setdefault(
            tenant_id,
            TokenBucket(
                capacity=policy.rate_limit_per_sec,
                refill_per_sec=float(policy.rate_limit_per_sec),
            ),
        )
        if not bucket.take(1.0):
            raise RateLimitExceeded(f"{self.name} rate limit exceeded for tenant {tenant_id}")


class Connector(Protocol):
    name: str
    actions: tuple[str, ...]

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        """Raise :class:`WhitelistViolation` if the action is not allowed.

        MUST be side-effect-free and idempotent: ``ConnectorTransport.dispatch``
        calls it once as a pre-credential policy gate, and ``execute`` calls it
        again at its top — so it must NOT consume rate-limit tokens or mutate state
        (the rate-limit bucket is taken in ``execute``, not here).
        """

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Principal,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        """Carry out the action. ``http_transport`` is an injectable seam for
        tests (must be a callable that returns a dict-shaped fake response).
        ``secret_value`` is the OAuth bearer token resolved via
        :class:`secugent.core.secrets.SecretsManager` by the caller — the
        connector never reads it from env/log itself.
        """
