# SPDX-License-Identifier: Apache-2.0
"""MCP tool-server consume adapter (P1, §A-3 P1-3).

SecuGent *consumes* an external MCP (Model Context Protocol) tool server by
wrapping it as a SecuGent :class:`~secugent.tools.connectors.base.Connector`.
This keeps the architecture-principle of "표준 준수: 외부 연동은 MCP/A2A 채택"
(A-2 원칙 4) — we adopt MCP instead of inventing a protocol — while routing
every external tool call through the *same* connector security path as a SaaS
connector:

* per-connector allowlist (the connector's ``actions`` tuple) — deny-by-default;
* credential delegation (``secret_value`` injected by the caller via
  :class:`secugent.core.secrets.SecretsManager`, never read from env here);
* the broker membership gate + OBO identity (when dispatched through
  :class:`secugent.io.broker.connector_transport.ConnectorTransport`).

Transport is an injectable seam: ``MCPTransport`` is an async callable that
performs the JSON-RPC POST. Tests inject a fake; the real HTTP client is a
go-live concern (no transport ⇒ fail-closed, never a silent no-op).

MCP wire format (JSON-RPC 2.0)::

    POST {url}/rpc
    {"jsonrpc": "2.0", "id": <n>, "method": "tools/call",
     "params": {"name": <action>, "arguments": <params>}}

A successful response carries ``result.content`` (mapped to
:class:`ConnectorResult.payload`); a top-level ``error`` field is surfaced as a
:class:`ConnectorError`.
"""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, Protocol

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
)

__all__ = [
    "MCPConnector",
    "MCPServerConfig",
    "MCPTransport",
]


class MCPTransport(Protocol):
    """Async seam that performs one MCP JSON-RPC POST and returns the parsed dict.

    A real implementation wraps an HTTP client; tests inject a fake. The
    callable must raise on transport failure (timeout / network) — the connector
    translates any raised exception into a :class:`ConnectorError`.
    """

    async def __call__(
        self,
        *,
        url: str,
        method: str,
        params: dict[str, Any],
        secret_value: str,
        timeout_sec: float,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class MCPServerConfig:
    """Static description of one external MCP tool server.

    ``actions`` is the per-connector allowlist: an empty tuple denies every
    action (allow-none, fail-closed). ``url`` is the server base; the JSON-RPC
    endpoint is ``{url}/rpc``.
    """

    url: str
    name: str
    actions: tuple[str, ...]
    timeout_sec: float = 10.0

    def __post_init__(self) -> None:
        if not self.url or not self.url.strip():
            raise ValueError("MCPServerConfig.url must be a non-empty URL")
        if not self.name or not self.name.strip():
            raise ValueError("MCPServerConfig.name must be a non-empty connector name")
        if self.timeout_sec <= 0:
            raise ValueError("MCPServerConfig.timeout_sec must be positive")
        # Normalise a trailing slash so ``{url}/rpc`` never double-slashes.
        normalized = self.url.rstrip("/")
        object.__setattr__(self, "url", normalized)

    @property
    def rpc_endpoint(self) -> str:
        return f"{self.url}/rpc"


class MCPConnector:
    """Adapts an external MCP tool server to the :class:`Connector` Protocol.

    ``name`` / ``actions`` mirror the config so the broker membership gate and
    :class:`~secugent.tools.connectors.registry.ConnectorRegistry` treat an MCP
    server identically to a first-party connector.
    """

    def __init__(self, config: MCPServerConfig, *, http_transport: MCPTransport | None = None) -> None:
        self._config = config
        self.name = config.name
        self.actions = config.actions
        self._transport = http_transport

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        """Raise :class:`WhitelistViolation` if the action is not declared.

        The connector's ``actions`` tuple is the authority for *which* MCP tools
        may be invoked (deny-by-default). An empty tuple blocks everything.
        ``policy`` is accepted to satisfy the Protocol; per-action channel
        constraints are enforced server-side by the MCP host, so SecuGent only
        gates membership here (the broker membership gate provides defence in
        depth on the dispatch path).
        """
        if action.name not in self.actions:
            raise WhitelistViolation(f"MCP action {action.name!r} not declared by server {self.name!r}")

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
        if not secret_value:
            raise WhitelistViolation(f"MCP server {self.name!r} requires a credential via SecretsManager")
        transport = http_transport if http_transport is not None else self._transport
        if transport is None:
            # No injected transport and no real HTTP client wired yet ⇒ fail
            # closed. A connector must never silently succeed without a call.
            raise ConnectorError(f"MCP server {self.name!r} has no transport configured")

        response = await self._call_transport(transport, action, secret_value)
        result = self._parse_response(response)
        return ConnectorResult(ok=True, payload=result)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _call_transport(
        self, transport: MCPTransport, action: ConnectorAction, secret_value: str
    ) -> object:
        params = {"name": action.name, "arguments": dict(action.params)}
        try:
            awaitable: Awaitable[dict[str, Any]] = transport(
                url=self._config.rpc_endpoint,
                method="tools/call",
                params=params,
                secret_value=secret_value,
                timeout_sec=self._config.timeout_sec,
            )
            return await awaitable
        except ConnectorError:
            raise
        except Exception as exc:  # transport timeout / network / decode → fail-closed
            # Do NOT include the credential or arbitrary server text that could
            # leak it; the action name is safe context.
            raise ConnectorError(
                f"MCP transport failed for {self.name!r}.{action.name}: {type(exc).__name__}"
            ) from exc

    def _parse_response(self, response: object) -> dict[str, Any]:
        if not isinstance(response, dict):
            raise ConnectorError(
                f"MCP server {self.name!r} returned non-object response ({type(response).__name__})"
            )
        if response.get("error") is not None:
            error = response["error"]
            code = error.get("code") if isinstance(error, dict) else None
            raise ConnectorError(f"MCP server {self.name!r} returned JSON-RPC error (code={code})")
        if "result" not in response:
            raise ConnectorError(f"MCP server {self.name!r} response missing 'result'")
        result = response["result"]
        if not isinstance(result, dict):
            raise ConnectorError(f"MCP server {self.name!r} 'result' is not an object")
        if "content" in result:
            content = result["content"]
            if isinstance(content, dict):
                return content
            # Non-object content (list / scalar) is wrapped so payload stays a dict.
            return {"content": content}
        return result
