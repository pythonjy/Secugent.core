# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — Jira connector."""

from __future__ import annotations

from typing import Any

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
    ConnectorTransportUnavailable,
    RateLimitExceeded,
    TokenBucket,
    WhitelistViolation,
)

__all__ = ["JiraConnector"]


class JiraConnector:
    name = "jira"
    actions = ("create_issue", "transition_issue", "comment_issue", "search")

    def __init__(self, *, http_transport: Any | None = None) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        # optional bound transport (see slack.py).
        self._bound_transport = http_transport

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        if not policy.allowed_projects:
            raise WhitelistViolation("jira.allowed_projects empty (allow-none)")
        if action.name in ("create_issue", "comment_issue"):
            project = action.params.get("project_key")
            if project not in policy.allowed_projects:
                raise WhitelistViolation(f"jira project {project!r} not in allowlist")
        if action.name == "transition_issue":
            transition = action.params.get("transition_name")
            if policy.allowed_transitions and transition not in policy.allowed_transitions:
                raise WhitelistViolation(f"jira transition {transition!r} not allowed")

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
            raise WhitelistViolation("jira connector requires OAuth token via SecretsManager")
        # per-call transport > bound transport > fail closed (no mock success).
        transport = http_transport if http_transport is not None else self._bound_transport
        if transport is None:
            raise ConnectorTransportUnavailable("jira connector has no transport configured")
        response = await transport(action=action, principal=principal, secret_value=secret_value)
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
            raise RateLimitExceeded(f"jira rate limit exceeded for tenant {tid}")
