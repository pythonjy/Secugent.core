# SPDX-License-Identifier: Apache-2.0
"""S5 — connectors fail CLOSED when no transport is injected (no mock success).

Before S5, every connector fell back to ``ConnectorResult(ok=True, payload={"mock": True})``
when ``http_transport`` was ``None``. That false-green returned success without
any egress. S5 removes the fallback: a missing transport raises
:class:`ConnectorTransportUnavailable` (fail-closed, §A-2.2 / §B-8).

These tests assert the **absence** of any mock-success path across all six
first-party connectors.
"""

from __future__ import annotations

from typing import Any

import pytest

from secugent.core.tenancy import Principal, TenantId
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
    ConnectorTransportUnavailable,
)
from secugent.tools.connectors.docs import DocsConnector
from secugent.tools.connectors.groupware import GroupwareConnector
from secugent.tools.connectors.jira import JiraConnector
from secugent.tools.connectors.notion import NotionConnector
from secugent.tools.connectors.sap import SapConnector
from secugent.tools.connectors.slack import SlackConnector


def _principal() -> Principal:
    return Principal(user_id="u1", tenant_id=TenantId("acme"), role="operator")


# (connector, allowing-policy, allowed action) tuples — each action passes the
# whitelist + secret gate so the ONLY thing left to fail is the missing transport.
_CASES = [
    (
        SlackConnector(),
        ConnectorPolicy(allowed_channels=["C1"]),
        ConnectorAction(name="post_message", params={"channel": "C1"}),
    ),
    (
        NotionConnector(),
        ConnectorPolicy(allowed_workspace_ids=["W1"], allowed_database_ids=["D1"]),
        ConnectorAction(name="create_page", params={"workspace_id": "W1"}),
    ),
    (
        JiraConnector(),
        ConnectorPolicy(allowed_projects=["SEC"]),
        ConnectorAction(name="create_issue", params={"project_key": "SEC"}),
    ),
    (
        GroupwareConnector(),
        ConnectorPolicy(allowed_channels=["사내-공지"]),
        ConnectorAction(name="post_approval", params={"channel": "사내-공지"}),
    ),
    (
        SapConnector(),
        ConnectorPolicy(allowed_projects=["1000"], allowed_transitions=["FB01"]),
        ConnectorAction(name="post_document", params={"company_code": "1000", "transaction_code": "FB01"}),
    ),
    (
        DocsConnector(),
        ConnectorPolicy(allowed_workspace_ids=["ws-corp"], allowed_database_ids=["folder-1"]),
        ConnectorAction(name="create_document", params={"workspace_id": "ws-corp", "folder_id": "folder-1"}),
    ),
]


@pytest.mark.parametrize("connector,policy,action", _CASES)
async def test_no_transport_fails_closed_never_mock(
    connector: Any, policy: ConnectorPolicy, action: ConnectorAction
) -> None:
    """A whitelisted, credentialled action with NO transport must RAISE.

    This is the core S5 invariant (INV-1/INV-3): a missing transport can never
    produce ``ok=True`` — that was the false-green being removed.
    """
    with pytest.raises(ConnectorTransportUnavailable):
        await connector.execute(
            action,
            principal=_principal(),
            policy=policy,
            http_transport=None,
            secret_value="live-token",
        )


@pytest.mark.parametrize("connector,policy,action", _CASES)
async def test_injected_transport_response_is_honoured(
    connector: Any, policy: ConnectorPolicy, action: ConnectorAction
) -> None:
    """With a transport injected, the connector returns the vendor response —
    proving the success path is the REAL call, not the removed mock fallback."""

    async def _echo(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        assert secret_value == "live-token"
        return {"ok": True, "vendor_id": f"{action.name}-99"}

    result = await connector.execute(
        action,
        principal=_principal(),
        policy=policy,
        http_transport=_echo,
        secret_value="live-token",
    )
    assert isinstance(result, ConnectorResult)
    assert result.ok is True
    assert result.payload["vendor_id"] == f"{action.name}-99"
    assert result.payload.get("mock") is None  # the mock key is gone for good
