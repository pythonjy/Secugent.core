# SPDX-License-Identifier: Apache-2.0
"""Runtime connector registry (P1, §A-3 P1-3) — deterministic, fail-closed.

Lets an operator register a new internal-system connector (사내 메신저·ERP·ITSM)
**at runtime** — no source edit, no redeploy. The registry owns the canonical
``connector name → ConnectorBinding`` map; :class:`ConnectorTransport` consults
it at dispatch time so registrations take effect immediately.

Three security guarantees (deny-by-default, fail-closed):

1. **Unknown connector → raise** (:class:`ConnectorNotFound`). There is no
   silent fallback; an unregistered connector has no secret to inject.
2. **Double registration → raise** (:class:`ConnectorAlreadyRegistered`). A
   connector cannot be quietly overridden — that would be a credential-swap path.
3. **Conservative reversibility**: every connector action not in
   :data:`COMPENSATABLE_CONNECTOR_ACTIONS` defaults to ``IRREVERSIBLE`` (the
   :class:`ManifestRegistry` fail-closed class), so an unknown mutation routes
   through 2-phase staging rather than firing directly.

The registry's own error hierarchy (:class:`ConnectorRegistryError`) is kept
**separate** from :class:`secugent.tools.connectors.base.ConnectorError` so a
registration/lookup failure is never confused with a connector *execution*
failure.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from secugent.core.sec.reversibility import ActionManifest, ReversibilityClass
from secugent.core.tenancy import TenantId
from secugent.tools.connectors.base import COMPENSATABLE_CONNECTOR_ACTIONS, ConnectorPolicy

if TYPE_CHECKING:
    # Type-only imports. A runtime import would form a layering cycle:
    # * ``connector_transport`` (where ``ConnectorBinding`` lives) imports
    #   ``connectors.base``, which triggers this package's ``__init__`` →
    #   ``registry``.
    # * ``core.regulations`` imports ``connectors.base`` (for ``ConnectorPolicy``),
    #   so importing ``Regulations`` here at runtime risks a partial-init cycle.
    # The registry only reads ``.connector_policies`` off the regs object and
    # duck-types a binding (``.connector.name``/``.actions``, ``.secret_name``),
    # so the concrete types are needed for annotations only.
    from secugent.core.regulations import Regulations
    from secugent.io.broker.connector_transport import ConnectorBinding

__all__ = [
    "ConnectorRegistryError",
    "ConnectorAlreadyRegistered",
    "ConnectorNotFound",
    "ConnectorRegistry",
]

_log = logging.getLogger("secugent.tools.connectors.registry")


class ConnectorRegistryError(RuntimeError):
    """Base class for connector registry (registration/lookup) failures."""


class ConnectorAlreadyRegistered(ConnectorRegistryError):
    """A connector with this name is already registered (fail-closed)."""


class ConnectorNotFound(ConnectorRegistryError):
    """No connector is registered under this name (deny-by-default)."""


class ConnectorRegistry:
    """Thread-safe runtime registry of connector bindings (fail-closed lookups)."""

    def __init__(self) -> None:
        self._bindings: dict[str, ConnectorBinding] = {}
        # Per-tenant connector policy overrides bound from REGULATIONS. Keyed
        # ``tenant_id -> {connector_name -> ConnectorPolicy}``. A tenant only ever
        # sees its own slice (tenant isolation), so tenant A's override is never
        # visible to tenant B.
        self._tenant_policies: dict[TenantId, dict[str, ConnectorPolicy]] = {}
        self._lock = threading.RLock()

    def register(self, binding: ConnectorBinding) -> None:
        """Register ``binding`` under ``binding.connector.name``.

        Raises :class:`ConnectorAlreadyRegistered` on a duplicate name and
        :class:`ConnectorRegistryError` if the connector name or secret name is
        empty — an empty secret name would mean "no credential to inject", which
        must fail at registration, not silently at dispatch.
        """
        name = binding.connector.name
        if not name:
            raise ConnectorRegistryError("connector.name must be a non-empty string")
        if not binding.secret_name:
            raise ConnectorRegistryError(f"connector {name!r} requires a non-empty secret_name")
        with self._lock:
            if name in self._bindings:
                raise ConnectorAlreadyRegistered(f"connector {name!r} is already registered")
            self._bindings[name] = binding

    def unregister(self, name: str) -> None:
        """Remove the binding for ``name``; raise :class:`ConnectorNotFound` if absent."""
        with self._lock:
            if name not in self._bindings:
                raise ConnectorNotFound(f"connector {name!r} is not registered")
            del self._bindings[name]

    def get(self, name: str) -> ConnectorBinding:
        """Return the binding for ``name``; raise :class:`ConnectorNotFound` if absent."""
        with self._lock:
            binding = self._bindings.get(name)
        if binding is None:
            raise ConnectorNotFound(f"connector {name!r} is not registered")
        return binding

    # ------------------------------------------------------------------ #
    # Tenant policy binding (REGULATIONS → ConnectorPolicy)
    # ------------------------------------------------------------------ #

    def apply_tenant_policy(self, tenant_id: TenantId, regs: Regulations) -> None:
        """Bind ``regs.connector_policies`` as ``tenant_id``'s per-connector overrides.

        Only policies for *registered* connectors are bound; a policy for an
        unregistered connector is logged at WARNING and skipped (not an error —
        a policy with no connector is inert because dispatch is deny-by-default,
        and connector registration is a separate operator action that may land
        later). Replaces any prior policy set for ``tenant_id`` so a reload is
        not additive across calls. Thread-safe (shares the registry RLock).
        """
        # Read the regs slice outside the lock; snapshot registered names under it.
        proposed = dict(regs.connector_policies)
        with self._lock:
            registered = set(self._bindings)
            applied: dict[str, ConnectorPolicy] = {}
            for name, policy in proposed.items():
                if name not in registered:
                    _log.warning(
                        "apply_tenant_policy: connector %r is not registered; skipping policy for tenant %s",
                        name,
                        tenant_id,
                    )
                    continue
                applied[name] = policy
            self._tenant_policies[tenant_id] = applied

    def get_policy_for(
        self, connector_name: str, tenant_id: TenantId | None = None
    ) -> ConnectorPolicy | None:
        """Resolve the effective :class:`ConnectorPolicy` for a connector.

        Resolution order (fail-closed, tenant-isolated):

        1. If ``tenant_id`` is given AND has an override for ``connector_name``,
           return that override (tenant A's override is never visible to B).
        2. Otherwise fall back to the connector's registered binding policy.
        3. If the connector is not registered, return ``None`` (no silent
           default — the caller decides how to fail closed).
        """
        with self._lock:
            if tenant_id is not None:
                tenant_map = self._tenant_policies.get(tenant_id)
                if tenant_map is not None and connector_name in tenant_map:
                    return tenant_map[connector_name]
            binding = self._bindings.get(connector_name)
        if binding is None:
            return None
        return binding.policy

    def all_bindings(self) -> Mapping[str, ConnectorBinding]:
        """Return an immutable point-in-time snapshot of all bindings.

        The returned mapping is a read-only copy: later (un)registrations do not
        mutate a snapshot already handed out, and the caller cannot mutate the
        registry through it.
        """
        with self._lock:
            return MappingProxyType(dict(self._bindings))

    def is_action_known(self, qualified_action: str) -> bool:
        """``True`` iff ``'<connector>.<action>'`` resolves to a registered action.

        Never raises: a malformed string, unknown connector, or action absent
        from the connector's declared ``actions`` all return ``False``
        (fail-closed). Invariant: ``is_action_known(q)`` ⇔ the connector is
        registered AND the action is in its ``actions`` tuple.
        """
        connector_name, _, action = qualified_action.partition(".")
        if not connector_name or not action:
            return False
        with self._lock:
            binding = self._bindings.get(connector_name)
        if binding is None:
            return False
        return action in binding.connector.actions

    def manifest_entries(self) -> list[ActionManifest]:
        """Reversibility manifests for every registered ``'<connector>.<action>'``.

        Kept in sync with :meth:`all_bindings`. Reversibility is resolved
        per-(connector, action), fail-closed:

        * If the connector declares a ``compensating_actions`` mapping
          (``{action: compensating_action}``) whose target is one of the
          connector's own declared ``actions``, the action is ``COMPENSATABLE``
          with that **real, declared** qualified compensator — so the
          steer/precommit compensation path can actually fire it through the
          transport membership gate (SG-14d-2/5).
        * Otherwise, an action in :data:`COMPENSATABLE_CONNECTOR_ACTIONS` keeps the
          legacy synthetic ``'<connector>.__compensate__'`` compensator
          (backward-compat for slack/notion/jira, whose real undos live in
          ``io.broker.manifests._COMPENSATABLE``).
        * Every other connector action defaults to ``IRREVERSIBLE`` (conservative
          fail-closed), so it routes through 2-phase staging rather than firing
          directly.
        """
        with self._lock:
            snapshot = dict(self._bindings)
        manifests: list[ActionManifest] = []
        for connector_name, binding in snapshot.items():
            connector = binding.connector
            declared = tuple(getattr(connector, "actions", ()))
            declared_compensators = self._declared_compensators(connector, declared)
            for action in declared:
                qualified = f"{connector_name}.{action}"
                real_compensator = declared_compensators.get(action)
                if real_compensator is not None:
                    manifests.append(
                        ActionManifest(
                            qualified,
                            ReversibilityClass.COMPENSATABLE,
                            compensating_action=f"{connector_name}.{real_compensator}",
                        )
                    )
                elif action in COMPENSATABLE_CONNECTOR_ACTIONS:
                    manifests.append(
                        ActionManifest(
                            qualified,
                            ReversibilityClass.COMPENSATABLE,
                            compensating_action=f"{connector_name}.__compensate__",
                        )
                    )
                else:
                    manifests.append(ActionManifest(qualified, ReversibilityClass.IRREVERSIBLE))
        return manifests

    @staticmethod
    def _declared_compensators(connector: object, declared: tuple[str, ...]) -> dict[str, str]:
        """Return the connector's ``{action: compensating_action}`` map, keeping
        only entries whose **compensating** action the connector actually declares.

        A connector may opt into per-action reversibility by exposing a
        ``compensating_actions`` mapping of unqualified action → unqualified
        compensating action. An entry whose compensator is not in the connector's
        own ``actions`` tuple is dropped (fail-closed): a compensator the
        transport membership gate would HARD-DENY is no compensator at all, so the
        action falls back to the conservative ``IRREVERSIBLE`` default rather than
        making a false reversibility promise.
        """
        raw = getattr(connector, "compensating_actions", None)
        if not isinstance(raw, Mapping):
            return {}
        declared_set = set(declared)
        resolved: dict[str, str] = {}
        for action, compensator in raw.items():
            if (
                isinstance(action, str)
                and isinstance(compensator, str)
                and action in declared_set
                and compensator in declared_set
            ):
                resolved[action] = compensator
        return resolved
