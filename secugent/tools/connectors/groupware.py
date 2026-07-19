# SPDX-License-Identifier: Apache-2.0
"""Groupware connector (사내 그룹웨어: 메신저·공지·전자결재 알림).

Same shape as :mod:`secugent.tools.connectors.slack`: a duck-typed
:class:`~secugent.tools.connectors.base.Connector` whose ``validate_action`` is a
side-effect-free allow-none whitelist (channels) and whose ``execute`` re-checks
the policy, consumes one rate-limit token, and requires an OAuth secret resolved
via :class:`~secugent.core.secrets.SecretsManager`.

This connector adds **no** control logic: which actions exist (Rule-of-Two
membership) and the audit trail are enforced once, centrally, by
:class:`~secugent.io.broker.connector_transport.ConnectorTransport`. There is no
execution path that skips that gate. External transport is an injectable seam
(``http_transport``); the optional vendor SDK, if any, is a **lazy import** inside
the transport callable, never at module import — so the core boots air-gapped.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
    _RateLimitedConnector,
)

__all__ = ["GroupwareConnector"]

# Mutating posts/deletes target a channel; reads (list_channels) have no target.
_CHANNEL_TARGETED_ACTIONS = ("post_message", "post_approval", "delete_message", "read_thread")


class GroupwareConnector(_RateLimitedConnector):
    name = "groupware"
    actions = ("post_message", "post_approval", "delete_message", "list_channels", "read_thread")

    # Per-(connector, action) reversibility (SG-14d-2/5): ``post_message`` is
    # COMPENSATABLE because a REAL, declared ``delete_message`` undo exists. The
    # :class:`~secugent.tools.connectors.registry.ConnectorRegistry` only honours a
    # compensator that is one of this connector's declared ``actions`` — so this
    # cannot promise an undo the transport membership gate would HARD-DENY. The
    # shared unqualified ``COMPENSATABLE_CONNECTOR_ACTIONS`` set (which would map to a
    # synthetic, non-existent ``groupware.__compensate__``) is intentionally NOT
    # relied upon here.
    compensating_actions: Mapping[str, str] = {"post_message": "delete_message"}

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Allow-none: an empty allowlist blocks every channel-targeted action
        # (deny-by-default, fail-closed). Side-effect-free — the transport calls
        # this as a pre-credential gate and execute re-calls it.
        if action.name in _CHANNEL_TARGETED_ACTIONS:
            if not policy.allowed_channels:
                raise WhitelistViolation("groupware.allowed_channels is empty (allow-none)")
            channel = action.params.get("channel")
            if channel not in policy.allowed_channels:
                raise WhitelistViolation(f"groupware channel {channel!r} not in allowlist")

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
            raise WhitelistViolation("groupware connector requires OAuth token via SecretsManager")
        # per-call transport > bound transport > fail closed (no mock success).
        transport = self._resolve_transport(http_transport)
        response = await transport(action=action, principal=principal, secret_value=secret_value)
        return ConnectorResult(ok=bool(response.get("ok", True)), payload=response)
