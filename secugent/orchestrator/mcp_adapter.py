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

import itertools
import logging
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel, ConfigDict

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
)
from secugent.tools.connectors.transport import SsrfBlocked, guard_url_host

if TYPE_CHECKING:
    import httpx

__all__ = [
    "HttpxMCPTransport",
    "MCPConnector",
    "MCPServerConfig",
    "MCPSettings",
    "MCPTransport",
    "build_mcp_transport",
]

_log = logging.getLogger("secugent.orchestrator.mcp_adapter")


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


# --------------------------------------------------------------------------- #
# Real httpx JSON-RPC 2.0 transport (S5)
# --------------------------------------------------------------------------- #


class MCPSettings(BaseModel):
    """Operator config for the production MCP transport (boot-time).

    ``allow_internal`` is False by default (deny-by-default §A-2.2); set True only
    for a closed-network 사내 MCP 도구 서버 whose endpoint is RFC-1918.
    """

    model_config = ConfigDict(extra="forbid")

    allow_internal: bool = False


# Monotonic JSON-RPC request id source (process-wide). The id is informational
# for correlation only — the adapter does not match it against the response, so a
# shared counter is safe and avoids per-call state.
_RPC_ID = itertools.count(1)


class HttpxMCPTransport:
    """Real :class:`MCPTransport` — JSON-RPC 2.0 POST to ``{url}`` over httpx.

    ``url`` is already the full ``{server}/rpc`` endpoint (built by
    :class:`MCPServerConfig.rpc_endpoint`). The credential is sent only as a Bearer
    header (INV-5); any timeout / network / non-2xx surfaces as a
    :class:`~secugent.tools.connectors.base.ConnectorError` with NO secret or vendor
    text, which the :class:`MCPConnector` already translates into its terminal
    failure. ``httpx`` is imported lazily (INV-8). An injected ``_mock_transport``
    lets tests drive responses without a socket.
    """

    def __init__(
        self,
        *,
        allow_internal: bool = False,
        _mock_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._allow_internal = allow_internal
        self._mock_transport = _mock_transport

    async def __call__(
        self,
        *,
        url: str,
        method: str,
        params: dict[str, Any],
        secret_value: str,
        timeout_sec: float,
    ) -> dict[str, Any]:
        try:
            guard_url_host(url, allow_internal=self._allow_internal)
        except SsrfBlocked as exc:
            raise ConnectorError(f"MCP endpoint refused: {exc}") from exc

        httpx = _import_httpx()
        envelope = {"jsonrpc": "2.0", "id": next(_RPC_ID), "method": method, "params": params}
        headers = {"Authorization": f"Bearer {secret_value}", "Content-Type": "application/json"}
        client_kwargs: dict[str, Any] = {"timeout": timeout_sec}
        if self._mock_transport is not None:
            client_kwargs["transport"] = self._mock_transport
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.post(url, json=envelope, headers=headers)
        except httpx.TimeoutException as exc:
            raise ConnectorError("MCP transport timed out") from exc
        except httpx.TransportError as exc:
            raise ConnectorError("MCP transport failure: no response") from exc

        if response.status_code >= 400:
            # No vendor body text (could echo the credential); status only.
            raise ConnectorError(f"MCP server returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise ConnectorError("MCP server returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise ConnectorError("MCP server returned a non-object JSON body")
        return body


def _import_httpx() -> Any:
    """Lazy ``httpx`` import (INV-8: never eager at module import)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise ConnectorError(
            "httpx is required for the production MCP transport; install it or inject a transport"
        ) from exc
    return httpx


def build_mcp_transport(settings: MCPSettings) -> HttpxMCPTransport:
    """Materialise the production MCP transport (S5 wire factory).

    The integration step injects the result into :class:`MCPConnector` (or passes
    it at ``execute`` time); this module never reaches ``api/main.py`` itself.
    """
    return HttpxMCPTransport(allow_internal=settings.allow_internal)
