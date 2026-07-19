# SPDX-License-Identifier: Apache-2.0
"""Connector egress transport (EM-06) — fills the EM-05 connector slot.

``RouterTransport`` (EM-05) deliberately left ``CONNECTOR_ACTION`` egress empty:
"credential delegation is EM-06". This is that path. It combines
:class:`CredentialBroker` (token injected at call time, scrubbed from the
result) and :class:`IdentityStrategy` (on-behalf-of attribution), so the
workload never holds a credential and every connector call is attributed to the
real user.

Async note: connectors and the secrets layer are async, but ``Transport.execute``
(EM-05) is sync. Bridging async connector egress into the broker's sync transport
slot is a **go-live diff** (deferred, like EM-05/07/09 wiring); this module
provides the async ``dispatch`` and is exercised at the integration level.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pydantic import ValidationError

from secugent.core.contracts import Event
from secugent.core.sec.effects import EffectKind
from secugent.core.tenancy import TenantId
from secugent.io.broker.credentials import CredentialBroker, CredentialError
from secugent.io.broker.identity import CallIdentity, IdentityStrategy
from secugent.io.broker.request import EgressRequest
from secugent.tools.connectors.base import (
    Connector,
    ConnectorAction,
    ConnectorPolicy,
    RateLimitExceeded,
    WhitelistViolation,
)
from secugent.tools.connectors.registry import ConnectorNotFound

__all__ = [
    "ConnectorBinding",
    "ConnectorBindingSource",
    "ConnectorEgressResult",
    "ConnectorTransport",
    "PolicyResolvingSource",
    "AuditSink",
]

_log = logging.getLogger("secugent.io.broker.connector_transport")


class AuditSink(Protocol):
    """Durable, hash-chained event sink (satisfied by ChainedEventStore)."""

    def append_event(self, event: Event) -> Any: ...


class ConnectorBindingSource(Protocol):
    """Structural contract for a live binding source (e.g. ``ConnectorRegistry``).

    ``get`` raises on an unknown connector (deny-by-default). Declared
    structurally — not via import — so ``ConnectorRegistry`` can import
    ``ConnectorBinding`` from this module without a cycle.
    """

    def get(self, name: str) -> ConnectorBinding: ...


@runtime_checkable
class PolicyResolvingSource(Protocol):
    """Structural capability for sources that resolve a tenant-effective policy.

    Satisfied by ``ConnectorRegistry.get_policy_for`` (tenant override → binding
    policy → ``None``). Declared structurally — not imported — so a static-Mapping
    source or a custom source lacking the method simply fails ``isinstance`` and
    the transport falls back to the static ``binding.policy``.
    """

    def get_policy_for(
        self, connector_name: str, tenant_id: TenantId | None = None
    ) -> ConnectorPolicy | None: ...


@dataclass(frozen=True)
class ConnectorBinding:
    """A registered connector + its tenant policy + the secret name to inject."""

    connector: Connector
    policy: ConnectorPolicy
    secret_name: str


@dataclass(frozen=True)
class ConnectorEgressResult:
    """Result handed back to the workload — payload is already token-scrubbed."""

    ok: bool
    payload: dict[str, Any]
    identity: CallIdentity


class ConnectorTransport:
    """Executes a connector action with delegated credentials + OBO identity."""

    def __init__(
        self,
        bindings: Mapping[str, ConnectorBinding] | ConnectorBindingSource,
        *,
        credentials: CredentialBroker,
        identity: IdentityStrategy,
        audit_store: AuditSink,
    ) -> None:
        # A static ``Mapping`` is snapshotted (EM-06 behaviour). A live source
        # (e.g. ``ConnectorRegistry``) is consulted at dispatch time so runtime
        # (un)registrations take effect immediately.
        if isinstance(bindings, Mapping):
            self._static: dict[str, ConnectorBinding] | None = dict(bindings)
            self._source: ConnectorBindingSource | None = None
        else:
            self._static = None
            self._source = bindings
        self._credentials = credentials
        self._identity = identity
        self._audit = audit_store

    def _resolve(self, connector_name: str) -> ConnectorBinding | None:
        """Look up a binding, returning ``None`` (not raising) if unknown.

        Normalizes the static-Mapping and live-source paths to the same
        fail-closed signal so :meth:`dispatch` records one ``connector.denied``
        audit and raises one :class:`CredentialError`.
        """
        if self._static is not None:
            return self._static.get(connector_name)
        assert self._source is not None  # exactly one of static/source is set
        try:
            return self._source.get(connector_name)
        except ConnectorNotFound:
            # The deliberate "unregistered" signal ⇒ fail-closed (None). Other
            # exceptions are source bugs (lock errors, custom-source faults) and
            # must NOT be silently coerced to "simple unregistered": log
            # them with a traceback, then still fail closed.
            return None
        except Exception:  # noqa: BLE001 - source bug ⇒ log + fail-closed, never execute
            _log.warning("binding source raised for connector %r", connector_name, exc_info=True)
            return None

    def _effective_policy(
        self, connector_name: str, binding: ConnectorBinding, tenant_id: TenantId
    ) -> ConnectorPolicy:
        """Resolve the **tenant-effective** policy to hand the connector.

        ``apply_tenant_policy`` binds a tenant's
        ``REGULATIONS.connector_policies`` as per-connector overrides, but the
        egress path used to pass the *static* ``binding.policy``, so overrides were
        dead at runtime. Here ``effective`` may differ from ``binding.policy``: a
        live source (the registry) supplies the tenant-resolved override via
        ``get_policy_for``; a static-Mapping source (or any source lacking the
        capability) falls ``isinstance`` and we keep ``binding.policy`` — so the
        no-override / static paths stay byte-identical.
        """
        source = self._source
        if isinstance(source, PolicyResolvingSource):
            resolved = source.get_policy_for(connector_name, tenant_id)
            if resolved is not None:
                return resolved
        return binding.policy

    async def dispatch(
        self, request: EgressRequest, *, http_transport: Any | None = None
    ) -> ConnectorEgressResult:
        effect = request.effect
        if effect.kind is not EffectKind.CONNECTOR_ACTION:
            raise ValueError(f"ConnectorTransport handles CONNECTOR_ACTION, got {effect.kind}")
        action_str = effect.action or ""
        if "." not in action_str:
            raise ValueError(f"connector action must be 'connector.action', got {action_str!r}")
        connector_name, action_name = action_str.split(".", 1)
        binding = self._resolve(connector_name)
        if binding is None:
            # Unknown connector ⇒ no secret to inject ⇒ fail-closed. Record the
            # denial (audit append failure must not mask the deny) then raise.
            self._record_denied(request, connector_name, action_str, "no connector binding registered")
            raise CredentialError(f"no connector binding registered for {connector_name!r}")

        # Validate the unqualified action SHAPE first. ``ConnectorAction.name``
        # rejects empty/qualified tokens, so a malformed residual (e.g. the
        # multi-dot 'a.b' from 'slack.a.b') fails here. It is denied WITH an audit
        # so the malformed-action deny stays audit-symmetric with the
        # unknown-connector deny instead of leaking a bare
        # ValidationError to the caller.
        try:
            action = ConnectorAction.model_validate({"name": action_name, "params": dict(effect.meta)})
        except ValidationError as exc:
            self._record_denied(request, connector_name, action_str, "malformed action")
            raise CredentialError(f"malformed connector action {action_str!r}") from exc

        # Membership gate (deny-by-default):
        # the connector's declared ``actions`` tuple is the authority for *which*
        # actions are valid — ``ConnectorAction.name`` was generalised from a
        # closed ``Literal`` to ``str`` (runtime extensibility), so the membership
        # enforcement moved here. An action not declared by the connector is denied
        # BEFORE any credential is resolved, so a smuggled action never reaches
        # ``execute``. Applies to both the static-Mapping and live-source paths
        # (both flow through ``_resolve``); ``getattr`` guards a duck-typed source.
        declared: tuple[str, ...] = getattr(binding.connector, "actions", ())
        if action.name not in declared:
            self._record_denied(request, connector_name, action_str, "action not declared by connector")
            raise CredentialError(f"action {action.name!r} not declared by connector {connector_name!r}")

        supports_obo = bool(getattr(binding.connector, "supports_obo", False))
        identity = self._identity.resolve(request.principal, supports_obo=supports_obo, run_id=request.run_id)

        # resolve the tenant-effective policy AFTER the membership
        # gate and BEFORE the credential is resolved. ``effective`` may shadow the
        # static ``binding.policy`` with the tenant override (registry path); on the
        # static-Mapping / no-override paths it IS ``binding.policy``. The connector
        # enforces whatever policy it is handed, so this is what makes a bound
        # override actually deny at runtime.
        effective = self._effective_policy(connector_name, binding, request.principal.tenant_id)

        async def _call(token: str) -> dict[str, Any]:
            result = await binding.connector.execute(
                action,
                principal=request.principal,
                policy=effective,
                http_transport=http_transport,
                secret_value=token,
            )
            return dict(result.payload)

        # Enforce the EFFECTIVE policy and audit any denial as ``connector.denied``
        # fail-closed, never swallowed.
        #
        # Two policy gates raise from two places, both surfaced here with their
        # real type so the deny reason is auditable:
        #   * Whitelist (``validate_action``) — a pure, idempotent policy read run
        #     OUTSIDE ``with_credential`` so a tenant-override deny blocks egress
        #     WITHOUT ever fetching the token (every connector also re-checks it at
        #     the top of ``execute``; re-invoking it here is side-effect-free).
        #   * Rate limit (``RateLimitExceeded``) — enforced INSIDE ``execute`` (the
        #     bucket lives there), hence inside ``with_credential``. The credential
        #     broker would normally sanitise any in-call error into ``CredentialError``
        #     and lose its type; ``reraise_types`` tells it to preserve these two
        #     connector-policy types (message still scrubbed, fresh instance) so the
        #     rate-limit deny reaches this handler and is audited too, not masked.
        try:
            await binding.connector.validate_action(action, effective)
            payload = await self._credentials.with_credential(
                binding.secret_name,
                call=_call,
                reraise_types=(WhitelistViolation, RateLimitExceeded),
            )
        except (WhitelistViolation, RateLimitExceeded) as exc:
            self._record_denied(
                request, connector_name, action_str, f"policy violation: {type(exc).__name__}"
            )
            raise
        self._record(request, connector_name, action_str, identity)
        return ConnectorEgressResult(ok=True, payload=payload, identity=identity)

    def _record(
        self, request: EgressRequest, connector_name: str, action_str: str, identity: CallIdentity
    ) -> None:
        tenant_id: TenantId = request.principal.tenant_id
        self._audit.append_event(
            Event(
                tenant_id=tenant_id,
                actor=f"connector:{connector_name}",
                type="connector.dispatched",
                run_id=request.run_id,
                payload={"action": action_str, **identity.audit_meta},
                severity="info",
            )
        )

    def _record_denied(
        self, request: EgressRequest, connector_name: str, action_str: str, reason: str
    ) -> None:
        """Append a ``connector.denied`` audit, tagged with ``reason``.

        ``reason`` distinguishes the deny causes (unknown connector / undeclared
        action / malformed action) so a post-hoc audit can tell why egress was
        blocked. Best-effort: a degraded audit backend must NOT turn a clean
        fail-closed deny into a different exception, so an append failure is
        logged and swallowed — the caller still raises :class:`CredentialError`.
        """
        tenant_id: TenantId = request.principal.tenant_id
        try:
            self._audit.append_event(
                Event(
                    tenant_id=tenant_id,
                    actor=f"connector:{connector_name}",
                    type="connector.denied",
                    run_id=request.run_id,
                    payload={
                        "action": action_str,
                        "reason": reason,
                        "on_behalf_of": request.principal.user_id,
                    },
                    severity="warn",
                )
            )
        except Exception:  # noqa: BLE001 - deny-audit failure must not mask the deny
            _log.warning("connector.denied audit append failed for %r", connector_name)
