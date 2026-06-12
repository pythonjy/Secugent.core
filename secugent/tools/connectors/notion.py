# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — Notion connector."""

from __future__ import annotations

from typing import Any

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
    RateLimitExceeded,
    TokenBucket,
    WhitelistViolation,
)

__all__ = ["NotionConnector"]


class NotionConnector:
    name = "notion"
    actions = ("query_database", "create_page", "update_page")

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Both workspace_id and database_id must be on the allowlist when
        # specified — empty allowlists mean block-all (fail-closed).
        if not policy.allowed_workspace_ids:
            raise WhitelistViolation("notion.allowed_workspace_ids is empty (allow-none)")

        workspace = action.params.get("workspace_id")
        if workspace not in policy.allowed_workspace_ids:
            raise WhitelistViolation(f"notion workspace {workspace!r} not in allowlist")

        if action.name in ("query_database", "update_page"):
            if not policy.allowed_database_ids:
                raise WhitelistViolation("notion.allowed_database_ids empty (allow-none)")
            db_id = action.params.get("database_id") or action.params.get("page_id")
            if db_id not in policy.allowed_database_ids:
                raise WhitelistViolation(f"notion database {db_id!r} not in allowlist")

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
            raise WhitelistViolation("notion connector requires OAuth token via SecretsManager")
        if http_transport is None:
            return ConnectorResult(ok=True, payload={"mock": True, "action": action.name})
        response = await http_transport(action=action, principal=principal, secret_value=secret_value)
        return ConnectorResult(ok=bool(response.get("ok", True)), payload=response)

    def _take_rate_token(self, principal: Principal, policy: ConnectorPolicy) -> None:
        tid = str(principal.tenant_id)
        bucket = self._buckets.setdefault(
            tid,
            TokenBucket(
                capacity=policy.rate_limit_per_sec,
                refill_per_sec=float(policy.rate_limit_per_sec),
            ),
        )
        if not bucket.take(1.0):
            raise RateLimitExceeded(f"notion rate limit exceeded for tenant {tid}")
