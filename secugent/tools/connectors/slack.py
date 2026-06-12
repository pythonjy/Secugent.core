# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — Slack connector (mock httpx friendly)."""

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

__all__ = ["SlackConnector"]


class SlackConnector:
    name = "slack"
    actions = ("post_message", "list_channels", "read_thread")

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Allow-none policy: empty whitelist == block everything (fail-closed)
        if action.name in ("post_message", "read_thread"):
            channel = action.params.get("channel")
            if not policy.allowed_channels:
                raise WhitelistViolation("slack.allowed_channels is empty (allow-none)")
            if channel not in policy.allowed_channels:
                raise WhitelistViolation(f"slack channel {channel!r} not in allowlist")
        # list_channels has no target — still subject to rate limit downstream

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
            raise WhitelistViolation("slack connector requires OAuth token via SecretsManager")
        if http_transport is None:
            return ConnectorResult(ok=True, payload={"mock": True, "action": action.name})
        response = await http_transport(action=action, principal=principal, secret_value=secret_value)
        return ConnectorResult(ok=bool(response.get("ok", True)), payload=response, redactions=[])

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
            raise RateLimitExceeded(f"slack rate limit exceeded for tenant {tid}")
