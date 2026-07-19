# SPDX-License-Identifier: Apache-2.0
"""S5 — HttpxA2ATransport: real httpx transport for the A2A collaboration adapter.

The A2A adapter already fail-closes when no transport is configured. S5 adds the
REAL transport: an httpx request returning an :class:`A2AHttpResponse`
(status + parsed JSON body), driven in tests by an injected
``httpx.MockTransport``. The adapter's own retry/classification (5xx transient,
4xx permanent) is unchanged — the transport only moves bytes and raises on
timeout/network so the adapter classifies it as transient. SSRF guard +
credential non-leak pinned here.

Korean fixture (§C-3): a remote A2A 에이전트 over a closed-network endpoint.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from secugent.orchestrator.a2a_adapter import (
    A2AHttpResponse,
    A2ASettings,
    HttpxA2ATransport,
    build_a2a_transport,
)
from secugent.tools.connectors.transport import SsrfBlocked


def _transport(handler: Any, *, allow_internal: bool = False) -> HttpxA2ATransport:
    return HttpxA2ATransport(allow_internal=allow_internal, _mock_transport=httpx.MockTransport(handler))


async def test_returns_status_and_parsed_body_with_headers() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization", "")
        captured["body"] = json.loads(request.content)
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"plan_id": "p1", "summary": "원격 계획", "steps": [{"id": "s1"}]})

    transport = _transport(handler, allow_internal=True)
    resp = await transport(
        method="POST",
        url="https://a2a.example.test/agents/remote-1/plan",
        headers={"Authorization": "Bearer btok", "Content-Type": "application/json"},
        json_body={"run_id": "r1", "command": "명령"},
        timeout_sec=5.0,
    )
    assert isinstance(resp, A2AHttpResponse)
    assert resp.status == 200
    assert resp.body["plan_id"] == "p1"
    assert captured["auth"] == "Bearer btok"
    assert captured["body"]["command"] == "명령"


async def test_5xx_returned_as_status_not_raised() -> None:
    # The transport returns the status; the ADAPTER classifies 5xx as transient.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "down"})

    transport = _transport(handler, allow_internal=True)
    resp = await transport(
        method="POST",
        url="https://a2a.example.test/agents/remote-1/plan",
        headers={"Authorization": "Bearer t"},
        json_body={},
        timeout_sec=5.0,
    )
    assert resp.status == 503


async def test_timeout_raises_for_adapter_to_classify() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow")

    transport = _transport(handler, allow_internal=True)
    with pytest.raises(Exception):  # noqa: B017,PT011 - adapter treats raise as transient
        await transport(
            method="POST",
            url="https://a2a.example.test/agents/remote-1/plan",
            headers={"Authorization": "Bearer t"},
            json_body={},
            timeout_sec=0.5,
        )


async def test_non_json_body_yields_text_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    transport = _transport(handler, allow_internal=True)
    resp = await transport(
        method="POST",
        url="https://a2a.example.test/agents/remote-1/plan",
        headers={},
        json_body={},
        timeout_sec=5.0,
    )
    # A non-JSON 2xx body is surfaced as a non-dict so the adapter's strict schema
    # validation rejects it as a permanent (malformed) failure — never a silent ok.
    assert not isinstance(resp.body, dict)


async def test_ssrf_blocks_metadata_even_with_allow_internal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
        return httpx.Response(200, json={})

    transport = _transport(handler, allow_internal=True)
    with pytest.raises(SsrfBlocked):
        await transport(
            method="POST",
            url="https://169.254.169.254/agents/x/plan",
            headers={},
            json_body={},
            timeout_sec=5.0,
        )


async def test_ssrf_blocks_private_when_public_only() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        return httpx.Response(200, json={})

    transport = _transport(handler, allow_internal=False)
    with pytest.raises(SsrfBlocked):
        await transport(
            method="POST",
            url="https://192.168.1.10/agents/x/plan",
            headers={},
            json_body={},
            timeout_sec=5.0,
        )


# --------------------------------------------------------------------------- #
# Korean fixture — remote A2A agent over a closed-network private endpoint
# --------------------------------------------------------------------------- #


async def test_korean_remote_a2a_private_endpoint_allowed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"plan_id": "p9", "summary": "사내 원격 에이전트 계획", "steps": [{"id": "s1"}]}
        )

    transport = _transport(handler, allow_internal=True)  # on-prem peer agent opt-in
    resp = await transport(
        method="POST",
        url="https://10.10.10.10/agents/사내-에이전트/plan",
        headers={"Authorization": "Bearer t"},
        json_body={"command": "전자결재 상신"},
        timeout_sec=5.0,
    )
    assert resp.status == 200
    assert resp.body["summary"] == "사내 원격 에이전트 계획"


# --------------------------------------------------------------------------- #
# factory
# --------------------------------------------------------------------------- #


def test_build_a2a_transport_from_settings() -> None:
    transport = build_a2a_transport(A2ASettings(allow_internal=True))
    assert isinstance(transport, HttpxA2ATransport)
