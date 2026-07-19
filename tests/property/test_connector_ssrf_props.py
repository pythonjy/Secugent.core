# SPDX-License-Identifier: Apache-2.0
"""S5 — property + edge tests for the connector SSRF guard and transport branches.

The SSRF guard (INV-6) is security-critical, so beyond the unit cases in
``test_httpx_transport.py`` we pin invariants over a wide IP space with hypothesis
and cover the embedded-v4 IPv6 decomposition (the classic IMDS/loopback bypass)
and the transport's body-parsing / timeout branches.
"""

from __future__ import annotations

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.tenancy import Principal, TenantId
from secugent.tools.connectors.base import ConnectorAction
from secugent.tools.connectors.transport import (
    ConnectorEndpoint,
    ConnectorHttpError,
    ConnectorHttpTransient,
    HttpxConnectorTransport,
    SsrfBlocked,
    guard_url_host,
)


def _principal() -> Principal:
    return Principal(user_id="u1", tenant_id=TenantId("acme"), role="operator")


def _transport(
    base_url: str, *, allow_internal: bool, handler: object | None = None
) -> HttpxConnectorTransport:
    def _ok(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    mock = httpx.MockTransport(handler or _ok)  # type: ignore[arg-type]
    return HttpxConnectorTransport(
        {"slack": ConnectorEndpoint(base_url=base_url)},
        connector_name="slack",
        timeout_sec=1.0,
        max_attempts=1,
        allow_internal=allow_internal,
        _mock_transport=mock,
    )


async def _post(transport: HttpxConnectorTransport) -> dict[str, object]:
    return await transport(
        action=ConnectorAction(name="post_message", params={"channel": "C1"}),
        principal=_principal(),
        secret_value="t",
    )


# --------------------------------------------------------------------------- #
# property — RFC-1918 private octets are ALWAYS blocked when public-only
# --------------------------------------------------------------------------- #


@settings(max_examples=150)
@given(third=st.integers(min_value=0, max_value=255), fourth=st.integers(min_value=1, max_value=254))
async def test_property_private_10_block_when_public_only(third: int, fourth: int) -> None:
    """Any 10.x.y.z endpoint is blocked when allow_internal=False (INV-6)."""
    transport = _transport(f"https://10.{third}.{fourth}.5", allow_internal=False)
    with pytest.raises(ConnectorHttpError):
        await _post(transport)


@settings(max_examples=150)
@given(third=st.integers(min_value=0, max_value=255), fourth=st.integers(min_value=1, max_value=254))
async def test_property_private_10_allowed_when_opted_in(third: int, fourth: int) -> None:
    """The same 10.x.y.z endpoint is reachable once allow_internal=True (on-prem)."""
    transport = _transport(f"https://10.{third}.{fourth}.5", allow_internal=True)
    result = await _post(transport)
    assert result["ok"] is True


# --------------------------------------------------------------------------- #
# embedded-v4 IPv6 — IMDS / loopback / private mapped forms cannot bypass
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "https://[::ffff:169.254.169.254]/x",  # IPv4-mapped AWS IMDS
        "https://[::ffff:127.0.0.1]/x",  # IPv4-mapped loopback
        "https://[64:ff9b::a9fe:a9fe]/x",  # NAT64-embedded 169.254.169.254
    ],
)
def test_embedded_v4_reserved_forms_always_blocked(url: str) -> None:
    with pytest.raises(SsrfBlocked):
        guard_url_host(url, allow_internal=True)


def test_embedded_v4_private_mapped_follows_opt_in() -> None:
    # ::ffff:10.0.0.5 is private → blocked public-only, allowed when opted in.
    with pytest.raises(SsrfBlocked):
        guard_url_host("https://[::ffff:10.0.0.5]/x", allow_internal=False)
    guard_url_host("https://[::ffff:10.0.0.5]/x", allow_internal=True)  # no raise


def test_bare_ipv6_loopback_blocked() -> None:
    with pytest.raises(SsrfBlocked):
        guard_url_host("https://[::1]/x", allow_internal=True)


def test_public_hostname_passes() -> None:
    # A DNS name (not a literal IP) is left to httpx — guard does not raise.
    guard_url_host("https://slack.example.test/x", allow_internal=False)


# --------------------------------------------------------------------------- #
# transport body-parsing + timeout branches
# --------------------------------------------------------------------------- #


async def test_non_json_2xx_body_wrapped_as_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK plain text")

    result = await _post(_transport("https://slack.example.test", allow_internal=False, handler=handler))
    assert result["ok"] is True
    assert result["raw_status"] == 200


async def test_json_list_body_wrapped_as_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["a", "b"])

    result = await _post(_transport("https://slack.example.test", allow_internal=False, handler=handler))
    assert result["content"] == ["a", "b"]


async def test_timeout_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    with pytest.raises(ConnectorHttpTransient):
        await _post(_transport("https://slack.example.test", allow_internal=False, handler=handler))


# --------------------------------------------------------------------------- #
# request mapper round-trip — action name/params reach the vendor body
# --------------------------------------------------------------------------- #


@settings(max_examples=100)
@given(
    action_name=st.sampled_from(["post_message", "create_issue", "create_page"]),
    text=st.text(min_size=0, max_size=20),
)
async def test_property_action_params_forwarded(action_name: str, text: str) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured["path"] = request.url.path
        captured["body"] = _json.loads(request.content) if request.content else {}
        return httpx.Response(200, json={"ok": True})

    transport = _transport("https://slack.example.test", allow_internal=False, handler=handler)
    await transport(
        action=ConnectorAction(name=action_name, params={"channel": "C1", "text": text}),
        principal=_principal(),
        secret_value="t",
    )
    assert captured["path"] == f"/{action_name}"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body.get("text") == text
