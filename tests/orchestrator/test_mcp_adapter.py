# SPDX-License-Identifier: Apache-2.0
"""MCP consume adapter — unit tests (RED first).

``MCPConnector`` wraps an external MCP (Model Context Protocol) JSON-RPC 2.0
tool server as a SecuGent :class:`~secugent.tools.connectors.base.Connector`
so external tools flow through the existing connector security path
(allowlist · credential injection · membership gate).

Korean enterprise fixture (§C-3): a 사내 MCP 도구 서버 ('사내-mcp').
"""

from __future__ import annotations

from typing import Any

import pytest

from secugent.core.tenancy import Principal, TenantId
from secugent.orchestrator.mcp_adapter import MCPConnector, MCPServerConfig
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
)

# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #


def _principal() -> Principal:
    return Principal(user_id="u1", tenant_id=TenantId("acme"), role="operator")


def _config(
    *,
    name: str = "internal-mcp",
    actions: tuple[str, ...] = ("search_docs", "post_message"),
    url: str = "https://mcp.example.test",
) -> MCPServerConfig:
    return MCPServerConfig(url=url, name=name, actions=actions, timeout_sec=5.0)


def _korean_config() -> MCPServerConfig:
    """한국어 픽스처 — 사내 MCP 도구 서버."""
    return MCPServerConfig(
        url="https://사내-mcp.example.test",
        name="사내-mcp",
        actions=("문서검색", "공지작성"),
        timeout_sec=5.0,
    )


class _FakeTransport:
    """Records calls and returns a canned JSON-RPC response (or raises)."""

    def __init__(self, response: dict[str, Any] | None = None, raises: BaseException | None = None) -> None:
        self.response = (
            response
            if response is not None
            else {"jsonrpc": "2.0", "id": 1, "result": {"content": {"ok": True}}}
        )
        self.raises = raises
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        *,
        url: str,
        method: str,
        params: dict[str, Any],
        secret_value: str,
        timeout_sec: float,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "url": url,
                "method": method,
                "params": params,
                "secret_value": secret_value,
                "timeout_sec": timeout_sec,
            }
        )
        if self.raises is not None:
            raise self.raises
        return self.response


# --------------------------------------------------------------------------- #
# construction
# --------------------------------------------------------------------------- #


def test_empty_url_rejected() -> None:
    with pytest.raises(ValueError):
        MCPServerConfig(url="", name="x", actions=("a",))


def test_empty_name_rejected() -> None:
    with pytest.raises(ValueError):
        MCPServerConfig(url="https://x", name="", actions=("a",))


def test_name_and_actions_exposed_on_connector() -> None:
    conn = MCPConnector(_config())
    assert conn.name == "internal-mcp"
    assert conn.actions == ("search_docs", "post_message")


def test_trailing_slash_stripped_from_url() -> None:
    cfg = MCPServerConfig(url="https://x/", name="n", actions=("a",))
    assert cfg.url == "https://x"


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #


async def test_execute_posts_jsonrpc_tools_call() -> None:
    transport = _FakeTransport(
        response={"jsonrpc": "2.0", "id": 1, "result": {"content": {"docs": ["a", "b"]}}}
    )
    conn = MCPConnector(_config(), http_transport=transport)
    action = ConnectorAction(name="search_docs", params={"q": "보안"})
    result = await conn.execute(
        action,
        principal=_principal(),
        policy=ConnectorPolicy(allowed_channels=["c1"]),
        secret_value="tok-123",
    )
    assert isinstance(result, ConnectorResult)
    assert result.ok is True
    assert result.payload == {"docs": ["a", "b"]}
    call = transport.calls[0]
    assert call["method"] == "tools/call"
    assert call["url"] == "https://mcp.example.test/rpc"
    assert call["params"] == {"name": "search_docs", "arguments": {"q": "보안"}}
    assert call["secret_value"] == "tok-123"


async def test_execute_arg_transport_overrides_ctor_transport() -> None:
    ctor_t = _FakeTransport(response={"jsonrpc": "2.0", "result": {"content": {"from": "ctor"}}})
    arg_t = _FakeTransport(response={"jsonrpc": "2.0", "result": {"content": {"from": "arg"}}})
    conn = MCPConnector(_config(), http_transport=ctor_t)
    result = await conn.execute(
        ConnectorAction(name="search_docs"),
        principal=_principal(),
        policy=ConnectorPolicy(),
        http_transport=arg_t,
        secret_value="t",
    )
    assert result.payload == {"from": "arg"}
    assert ctor_t.calls == []


# --------------------------------------------------------------------------- #
# fail-closed invariants
# --------------------------------------------------------------------------- #


async def test_action_not_in_allowlist_rejected() -> None:
    conn = MCPConnector(_config(actions=("search_docs",)), http_transport=_FakeTransport())
    with pytest.raises(WhitelistViolation):
        await conn.execute(
            ConnectorAction(name="delete_everything"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_empty_actions_denies_everything() -> None:
    conn = MCPConnector(_config(actions=()), http_transport=_FakeTransport())
    with pytest.raises(WhitelistViolation):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_validate_action_rejects_unknown() -> None:
    conn = MCPConnector(_config(actions=("search_docs",)))
    with pytest.raises(WhitelistViolation):
        await conn.validate_action(ConnectorAction(name="nope"), ConnectorPolicy())


async def test_missing_secret_rejected() -> None:
    conn = MCPConnector(_config(), http_transport=_FakeTransport())
    with pytest.raises(WhitelistViolation):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="",
        )


async def test_no_transport_anywhere_fails_closed() -> None:
    conn = MCPConnector(_config())  # no ctor transport, no arg transport
    with pytest.raises(ConnectorError):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_timeout_wrapped_as_connector_error() -> None:
    transport = _FakeTransport(raises=TimeoutError("slow"))
    conn = MCPConnector(_config(), http_transport=transport)
    with pytest.raises(ConnectorError):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_jsonrpc_error_field_raises() -> None:
    transport = _FakeTransport(
        response={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
    )
    conn = MCPConnector(_config(), http_transport=transport)
    with pytest.raises(ConnectorError):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_non_dict_response_raises() -> None:
    transport = _FakeTransport(response=["not", "a", "dict"])  # type: ignore[arg-type]
    conn = MCPConnector(_config(), http_transport=transport)
    with pytest.raises(ConnectorError):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_missing_result_raises() -> None:
    transport = _FakeTransport(response={"jsonrpc": "2.0", "id": 1})
    conn = MCPConnector(_config(), http_transport=transport)
    with pytest.raises(ConnectorError):
        await conn.execute(
            ConnectorAction(name="search_docs"),
            principal=_principal(),
            policy=ConnectorPolicy(),
            secret_value="t",
        )


async def test_non_dict_content_wrapped() -> None:
    transport = _FakeTransport(response={"jsonrpc": "2.0", "result": {"content": ["item1", "item2"]}})
    conn = MCPConnector(_config(), http_transport=transport)
    result = await conn.execute(
        ConnectorAction(name="search_docs"),
        principal=_principal(),
        policy=ConnectorPolicy(),
        secret_value="t",
    )
    assert result.payload == {"content": ["item1", "item2"]}


async def test_result_without_content_key_used_as_payload() -> None:
    transport = _FakeTransport(response={"jsonrpc": "2.0", "result": {"raw": 1}})
    conn = MCPConnector(_config(), http_transport=transport)
    result = await conn.execute(
        ConnectorAction(name="search_docs"),
        principal=_principal(),
        policy=ConnectorPolicy(),
        secret_value="t",
    )
    assert result.payload == {"raw": 1}


# --------------------------------------------------------------------------- #
# Korean fixture
# --------------------------------------------------------------------------- #


async def test_korean_internal_mcp_server() -> None:
    transport = _FakeTransport(response={"jsonrpc": "2.0", "result": {"content": {"결과": "성공"}}})
    conn = MCPConnector(_korean_config(), http_transport=transport)
    result = await conn.execute(
        ConnectorAction(name="문서검색", params={"질의": "전자금융감독규정"}),
        principal=_principal(),
        policy=ConnectorPolicy(),
        secret_value="사내-토큰",
    )
    assert result.ok is True
    assert result.payload == {"결과": "성공"}
    assert transport.calls[0]["params"]["name"] == "문서검색"
