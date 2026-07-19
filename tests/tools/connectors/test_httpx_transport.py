# SPDX-License-Identifier: Apache-2.0
"""S5 — HttpxConnectorTransport: real httpx egress for first-party connectors.

The transport is the async callable a connector ``execute`` receives. It maps an
unqualified ``ConnectorAction`` to a vendor HTTP request, performs it via httpx
(injectable ``httpx.MockTransport`` in tests — NOT the removed mock-success
fallback), classifies the response (4xx permanent / 5xx·timeout transient), and
retries transients. SSRF guard + credential non-leak are pinned here.

Korean fixture (§C-3): a 사내 그룹웨어 webhook posting to '사내-공지'.
"""

from __future__ import annotations

import httpx
import pytest

from secugent.core.tenancy import Principal, TenantId
from secugent.tools.connectors.base import ConnectorAction
from secugent.tools.connectors.transport import (
    ConnectorEndpoint,
    ConnectorHttpError,
    ConnectorHttpTransient,
    ConnectorSettings,
    HttpxConnectorTransport,
    build_connector_transport,
)


def _principal() -> Principal:
    return Principal(user_id="u1", tenant_id=TenantId("acme"), role="operator")


def _transport_with(
    handler: object, *, allow_internal: bool = True, max_attempts: int = 2
) -> HttpxConnectorTransport:
    """Build a transport whose httpx client uses an injected MockTransport."""
    mock = httpx.MockTransport(handler)  # type: ignore[arg-type]
    endpoints = {
        "slack": ConnectorEndpoint(base_url="https://slack.example.test"),
        "groupware": ConnectorEndpoint(base_url="https://gw.corp.example.test"),
        "jira": ConnectorEndpoint(base_url="https://jira.example.test"),
        "notion": ConnectorEndpoint(base_url="https://notion.example.test"),
        "sap": ConnectorEndpoint(base_url="https://sap.example.test"),
        "docs": ConnectorEndpoint(base_url="https://docs.example.test"),
    }
    return HttpxConnectorTransport(
        endpoints,
        connector_name="slack",
        timeout_sec=2.0,
        max_attempts=max_attempts,
        allow_internal=allow_internal,
        _mock_transport=mock,
    )


# --------------------------------------------------------------------------- #
# happy path — 2xx returns the JSON body; credential goes in the header only
# --------------------------------------------------------------------------- #


async def test_2xx_returns_json_body_and_sends_bearer() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization", "")
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"ok": True, "ts": "1"})

    transport = _transport_with(handler)
    result = await transport(
        action=ConnectorAction(name="post_message", params={"channel": "C1", "text": "hi"}),
        principal=_principal(),
        secret_value="xoxb-secret",
    )
    assert result["ok"] is True
    assert seen["auth"] == "Bearer xoxb-secret"
    assert seen["url"].startswith("https://slack.example.test")


# --------------------------------------------------------------------------- #
# 4xx → permanent (no retry); 5xx/timeout → transient (retried)
# --------------------------------------------------------------------------- #


async def test_4xx_is_permanent_no_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(403, json={"error": "forbidden"})

    transport = _transport_with(handler, max_attempts=3)
    with pytest.raises(ConnectorHttpError):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )
    assert calls["n"] == 1  # 4xx is permanent → exactly one attempt


async def test_5xx_is_transient_and_retried_then_terminal() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503, json={"error": "unavailable"})

    transport = _transport_with(handler, max_attempts=3)
    with pytest.raises(ConnectorHttpTransient):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )
    assert calls["n"] == 3  # retried up to max_attempts


async def test_5xx_then_200_recovers() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(502)
        return httpx.Response(200, json={"ok": True})

    transport = _transport_with(handler, max_attempts=3)
    result = await transport(
        action=ConnectorAction(name="post_message", params={"channel": "C1"}),
        principal=_principal(),
        secret_value="t",
    )
    assert result["ok"] is True
    assert calls["n"] == 2


async def test_network_error_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    transport = _transport_with(handler, max_attempts=2)
    with pytest.raises(ConnectorHttpTransient):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )


# --------------------------------------------------------------------------- #
# credential never leaks into the raised error
# --------------------------------------------------------------------------- #


async def test_credential_not_in_error_message() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="nope")

    transport = _transport_with(handler)
    # A distinctive PLACEHOLDER value (not a real secret) — the OSS release content
    # scanner recognises ``placeholder``-marked literals as non-secrets, so this
    # test file stays publishable while still proving the value never leaks.
    secret = "placeholder-bearer-value-001"
    with pytest.raises(ConnectorHttpError) as ei:
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value=secret,
        )
    assert secret not in str(ei.value)


# --------------------------------------------------------------------------- #
# SSRF guard — public-only transport refuses an RFC-1918 endpoint
# --------------------------------------------------------------------------- #


async def test_ssrf_blocks_private_endpoint_when_not_allow_internal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
        return httpx.Response(200, json={"ok": True})

    mock = httpx.MockTransport(handler)
    endpoints = {"slack": ConnectorEndpoint(base_url="https://10.1.2.3")}
    transport = HttpxConnectorTransport(
        endpoints,
        connector_name="slack",
        timeout_sec=2.0,
        max_attempts=1,
        allow_internal=False,  # public-only
        _mock_transport=mock,
    )
    with pytest.raises(ConnectorHttpError):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )


async def test_ssrf_always_blocks_loopback_even_with_allow_internal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
        return httpx.Response(200)

    mock = httpx.MockTransport(handler)
    endpoints = {"slack": ConnectorEndpoint(base_url="https://127.0.0.1")}
    transport = HttpxConnectorTransport(
        endpoints,
        connector_name="slack",
        timeout_sec=2.0,
        max_attempts=1,
        allow_internal=True,  # even opted-in, loopback/IMDS stay blocked
        _mock_transport=mock,
    )
    with pytest.raises(ConnectorHttpError):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )


# --------------------------------------------------------------------------- #
# unknown connector endpoint → fail closed
# --------------------------------------------------------------------------- #


async def test_unknown_connector_endpoint_fails_closed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200)

    mock = httpx.MockTransport(handler)
    transport = HttpxConnectorTransport(
        {},  # no endpoint registered for 'slack'
        connector_name="slack",
        timeout_sec=2.0,
        max_attempts=1,
        allow_internal=True,
        _mock_transport=mock,
    )
    with pytest.raises(ConnectorHttpError):
        await transport(
            action=ConnectorAction(name="post_message", params={"channel": "C1"}),
            principal=_principal(),
            secret_value="t",
        )


# --------------------------------------------------------------------------- #
# Korean fixture — 사내 그룹웨어 post to 사내-공지
# --------------------------------------------------------------------------- #


async def test_korean_groupware_post_approval() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured["body"] = _json.loads(request.content)
        return httpx.Response(200, json={"ok": True, "결과": "성공"})

    mock = httpx.MockTransport(handler)
    endpoints = {"groupware": ConnectorEndpoint(base_url="https://10.50.0.10")}  # on-prem private
    transport = HttpxConnectorTransport(
        endpoints,
        connector_name="groupware",
        timeout_sec=2.0,
        max_attempts=1,
        allow_internal=True,  # closed-network on-prem groupware opt-in
        _mock_transport=mock,
    )
    result = await transport(
        action=ConnectorAction(
            name="post_approval", params={"channel": "사내-공지", "text": "전자결재 승인 요청"}
        ),
        principal=_principal(),
        secret_value="gw-token",
    )
    assert result["ok"] is True
    body = captured["body"]
    assert isinstance(body, dict)
    # the action params are forwarded to the vendor body
    assert "사내-공지" in str(body)


# --------------------------------------------------------------------------- #
# factory — build_connector_transport(settings)
# --------------------------------------------------------------------------- #


def test_build_connector_transport_from_settings() -> None:
    settings = ConnectorSettings(
        endpoints={"slack": "https://slack.example.test"},
        timeout_sec=5.0,
        max_attempts=3,
        allow_internal=False,
    )
    transport = build_connector_transport(settings, connector_name="slack")
    assert isinstance(transport, HttpxConnectorTransport)


def test_connector_settings_rejects_empty_endpoint_url() -> None:
    with pytest.raises(ValueError):
        ConnectorSettings(endpoints={"slack": ""})
