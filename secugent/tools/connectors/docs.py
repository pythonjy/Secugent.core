# SPDX-License-Identifier: Apache-2.0
"""BDP_04 §14d — document-management connector (사내 문서함·전자결재 문서).

Same shape as :mod:`secugent.tools.connectors.notion`: a duck-typed
:class:`~secugent.tools.connectors.base.Connector` whose ``validate_action`` is a
side-effect-free allow-none whitelist over (workspace, folder/document collection)
and whose ``execute`` re-checks the policy, consumes one rate-limit token, and
requires an OAuth secret resolved via
:class:`~secugent.core.secrets.SecretsManager`.

Reuses the existing :class:`~secugent.tools.connectors.base.ConnectorPolicy`
fields — ``allowed_workspace_ids`` for the document workspace and
``allowed_database_ids`` for the folder / document collection — so the policy
schema (and therefore every REGULATIONS decision path) is unchanged. The
connector re-decides nothing; the central
:class:`~secugent.io.broker.connector_transport.ConnectorTransport` is the single
source of truth for Rule-of-Two membership and the audit trail. Optional vendor
SDKs are lazy imports inside the injectable ``http_transport`` callable, never at
module import (air-gapped boot).
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

__all__ = ["DocsConnector"]

# Actions that read/write inside a folder (document collection) need the folder
# on the allowlist; search is workspace-scoped only.
_FOLDER_TARGETED_ACTIONS = ("create_document", "update_document", "read_document")


class DocsConnector(_RateLimitedConnector):
    name = "docs"
    actions = ("create_document", "update_document", "read_document", "search")

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Allow-none over the workspace first (fail-closed for every action).
        if not policy.allowed_workspace_ids:
            raise WhitelistViolation("docs.allowed_workspace_ids is empty (allow-none)")
        workspace = action.params.get("workspace_id")
        if workspace not in policy.allowed_workspace_ids:
            raise WhitelistViolation(f"docs workspace {workspace!r} not in allowlist")

        # Folder-scoped actions also require the folder on the allowlist.
        if action.name in _FOLDER_TARGETED_ACTIONS:
            if not policy.allowed_database_ids:
                raise WhitelistViolation("docs.allowed_database_ids is empty (allow-none)")
            folder = action.params.get("folder_id") or action.params.get("document_id")
            if folder not in policy.allowed_database_ids:
                raise WhitelistViolation(f"docs folder {folder!r} not in allowlist")

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
            raise WhitelistViolation("docs connector requires OAuth token via SecretsManager")
        # S5: per-call transport > bound transport > fail closed (no mock success).
        transport = self._resolve_transport(http_transport)
        response = await transport(action=action, principal=principal, secret_value=secret_value)
        return ConnectorResult(ok=bool(response.get("ok", True)), payload=response)
