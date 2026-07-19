# SPDX-License-Identifier: Apache-2.0
"""S5 — HttpxMCPTransport: real JSON-RPC 2.0 HTTP transport for MCP consume.

The MCP adapter already fail-closes when no transport is configured. S5 adds the
REAL transport: a JSON-RPC 2.0 POST to ``{url}/rpc`` (via httpx, driven in tests
by an injected ``httpx.MockTransport`` — never a fake-success stub) returning the
parsed JSON body. SSRF guard + credential non-leak + timeout/network fail-closed
are pinned here.

Korean fixture (§C-3): a 사내 MCP 도구 서버 over a closed-network private endpoint.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from secugent.orchestrator.mcp_adapter import (
    HttpxMCPTransport,
    MCPSettings,
    build_mcp_transport,
)
from secugent.tools.connectors.base import ConnectorError


def _transport(handler: Any, *, allow_internal: bool = False) -> HttpxMCPTransport:
    return HttpxMCPTransport(allow_internal=allow_internal, _mock_transport=httpx.MockTransport(handler))


async def test_posts_jsonrpc_2_0_envelope_and_bearer() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization", "")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"content": {"docs": ["a"]}}})

    transport = _transport(handler, allow_internal=True)
    body = await transport(
        url="https://mcp.example.test/rpc",
        method="tools/call",
        params={"name": "search_docs", "arguments": {"q": "보안"}},
        secret_value="tok-1",
        timeout_sec=5.0,
    )
    assert body["result"]["content"] == {"docs": ["a"]}
    assert captured["url"] == "https://mcp.example.test/rpc"
    assert captured["auth"] == "Bearer tok-1"
    env = captured["body"]
    assert env["jsonrpc"] == "2.0"
    assert env["method"] == "tools/call"
    assert env["params"] == {"name": "search_docs", "arguments": {"q": "보안"}}
    assert "id" in env


async def test_non_2xx_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    transport = _transport(handler, allow_internal=True)
    with pytest.raises(Exception):  # noqa: B017,PT011 - adapter wraps to ConnectorError
        await transport(
            url="https://mcp.example.test/rpc",
            method="tools/call",
            params={"name": "x", "arguments": {}},
            secret_value="t",
            timeout_sec=5.0,
        )


async def test_timeout_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow")

    transport = _transport(handler, allow_internal=True)
    with pytest.raises(Exception):  # noqa: B017,PT011
        await transport(
            url="https://mcp.example.test/rpc",
            method="tools/call",
            params={"name": "x", "arguments": {}},
            secret_value="t",
            timeout_sec=0.5,
        )


async def test_credential_not_in_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = _transport(handler, allow_internal=True)
    # PLACEHOLDER value (not a real secret) — keeps this test file OSS-publishable
    # past the release content scanner while still proving non-leak.
    secret = "placeholder-mcp-bearer-001"
    with pytest.raises(ConnectorError) as ei:
        await transport(
            url="https://mcp.example.test/rpc",
            method="tools/call",
            params={"name": "x", "arguments": {}},
            secret_value=secret,
            timeout_sec=5.0,
        )
    assert secret not in str(ei.value)


async def test_ssrf_blocks_metadata_endpoint_even_with_allow_internal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": {}})

    transport = _transport(handler, allow_internal=True)
    with pytest.raises(ConnectorError):
        await transport(
            url="https://169.254.169.254/rpc",  # AWS IMDS — always blocked
            method="tools/call",
            params={"name": "x", "arguments": {}},
            secret_value="t",
            timeout_sec=5.0,
        )


async def test_ssrf_blocks_private_when_public_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200, json={"jsonrpc": "2.0", "result": {}})

    transport = _transport(handler, allow_internal=False)
    with pytest.raises(ConnectorError):
        await transport(
            url="https://10.0.0.5/rpc",
            method="tools/call",
            params={"name": "x", "arguments": {}},
            secret_value="t",
            timeout_sec=5.0,
        )


# --------------------------------------------------------------------------- #
# Korean fixture — 사내 MCP over closed-network private endpoint (opt-in)
# --------------------------------------------------------------------------- #


async def test_korean_internal_mcp_private_endpoint_allowed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"content": {"결과": "성공"}}})

    transport = _transport(handler, allow_internal=True)  # on-prem 사내 MCP opt-in
    body = await transport(
        url="https://10.20.30.40/rpc",
        method="tools/call",
        # Korean tool name + query (§C-3); OAuth bearer tokens are ASCII by spec.
        params={"name": "문서검색", "arguments": {"질의": "전자금융감독규정"}},
        secret_value="sanae-token",
        timeout_sec=5.0,
    )
    assert body["result"]["content"] == {"결과": "성공"}


# --------------------------------------------------------------------------- #
# factory
# --------------------------------------------------------------------------- #


def test_build_mcp_transport_from_settings() -> None:
    transport = build_mcp_transport(MCPSettings(allow_internal=True))
    assert isinstance(transport, HttpxMCPTransport)
