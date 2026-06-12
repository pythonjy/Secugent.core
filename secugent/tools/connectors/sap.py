# SPDX-License-Identifier: Apache-2.0
"""BDP_04 §14d — SAP connector (ERP 전표·구매요청 등 회사코드·트랜잭션 통제).

Same shape as :mod:`secugent.tools.connectors.jira`: a duck-typed
:class:`~secugent.tools.connectors.base.Connector` whose ``validate_action`` is a
side-effect-free allow-none whitelist over (회사코드, 트랜잭션코드) and whose
``execute`` re-checks the policy, consumes one rate-limit token, and requires an
OAuth/service secret resolved via
:class:`~secugent.core.secrets.SecretsManager`.

Reuses the existing :class:`~secugent.tools.connectors.base.ConnectorPolicy`
fields — ``allowed_projects`` for the SAP company code and ``allowed_transitions``
for the transaction code — so the policy schema is unchanged and no REGULATIONS
decision path is duplicated. SAP postings are high-impact (재무 전표): the central
:class:`~secugent.io.broker.connector_transport.ConnectorTransport` is the single
Rule-of-Two gate and audit authority; this connector never re-decides. The
optional ``pyrfc``/OData SDK is a lazy import inside the injectable
``http_transport`` callable, never at module import — so importing the core never
requires it and the connector installs/boots air-gapped.

Deny-by-default scope: because SAP is the highest-impact connector, the
company-code allow-none floor covers **every** action — reads, ``search``, and
mutations alike — so an empty/misconfigured policy denies all egress (it can
never enumerate financial records across company codes). Mutating postings
additionally require a whitelisted transaction code.

Reversibility / staging (honest scope): mutating SAP actions are classified
conservatively (the registry defaults non-COMPENSATABLE connector actions to
``IRREVERSIBLE``). The 2-phase staging divert for ``IRREVERSIBLE`` connector
mutations lives in :class:`~secugent.io.broker.broker.EgressBroker` and is reached
only once the deferred EM-06 connector egress is wired into ``main.py`` — it is
NOT yet enforced on the live ``ConnectorTransport.dispatch`` path. This connector
therefore makes no staging guarantee of its own; do not rely on staging until
that go-live wiring lands.
"""

from __future__ import annotations

from typing import Any

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
    _RateLimitedConnector,
)

__all__ = ["SapConnector"]

# SAP is the highest-impact connector (재무 전표·구매요청). EVERY action — reads,
# search, and mutations alike — is company-code scoped: ``search`` is included so
# an empty/misconfigured policy can never enumerate financial records across
# company codes (SG-14d-1/4; mirrors jira's connector-wide allow-none floor).
# Mutating postings additionally carry a whitelisted transaction_code.
_COMPANY_TARGETED_ACTIONS = ("post_document", "create_purchase_req", "read_document", "search")
_TXN_TARGETED_ACTIONS = ("post_document", "create_purchase_req")


class SapConnector(_RateLimitedConnector):
    name = "sap"
    actions = ("post_document", "create_purchase_req", "read_document", "search")

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Connector-wide allow-none floor (fail-closed, §A-2.2): an empty company
        # allowlist HARD-BLOCKS every SAP action — including ``search`` — so the
        # safest/default policy state denies all financial-ERP egress. This mirrors
        # jira.validate_action raising unconditionally when allowed_projects is empty.
        if not policy.allowed_projects:
            raise WhitelistViolation("sap.allowed_projects (회사코드) is empty (allow-none)")

        # Company-code allow-none gate (fail-closed) for every company-scoped action.
        if action.name in _COMPANY_TARGETED_ACTIONS:
            company_code = action.params.get("company_code")
            if company_code not in policy.allowed_projects:
                raise WhitelistViolation(f"sap company_code {company_code!r} not in allowlist")

        # Mutating transactions also require the transaction code on the allowlist.
        if action.name in _TXN_TARGETED_ACTIONS:
            if not policy.allowed_transitions:
                raise WhitelistViolation("sap.allowed_transitions (트랜잭션코드) is empty (allow-none)")
            transaction_code = action.params.get("transaction_code")
            if transaction_code not in policy.allowed_transitions:
                raise WhitelistViolation(f"sap transaction_code {transaction_code!r} not allowed")

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Principal,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        await self.validate_action(action, policy)
        self._take_rate_token(principal, policy)
        if not secret_value:
            raise WhitelistViolation("sap connector requires service token via SecretsManager")
        if http_transport is None:
            return ConnectorResult(ok=True, payload={"mock": True, "action": action.name})
        response = await http_transport(action=action, principal=principal, secret_value=secret_value)
        return ConnectorResult(ok=bool(response.get("ok", True)), payload=response)
