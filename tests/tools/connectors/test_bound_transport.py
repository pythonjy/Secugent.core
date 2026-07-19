# SPDX-License-Identifier: Apache-2.0
"""S5 — bound-transport fallback + missing-secret gate across all connectors.

A connector may be constructed with a bound ``http_transport`` (used when
``execute`` gets no per-call one). These tests pin: (1) the bound transport fires
when no per-call transport is given, (2) a per-call transport overrides the bound
one, (3) the missing-secret gate (WhitelistViolation) fires before the transport.
"""

from __future__ import annotations

from typing import Any

import pytest

from secugent.core.tenancy import Principal, TenantId
from secugent.tools.connectors.base import ConnectorAction, ConnectorPolicy, WhitelistViolation
from secugent.tools.connectors.docs import DocsConnector
from secugent.tools.connectors.groupware import GroupwareConnector
from secugent.tools.connectors.jira import JiraConnector
from secugent.tools.connectors.notion import NotionConnector
from secugent.tools.connectors.sap import SapConnector
from secugent.tools.connectors.slack import SlackConnector


def _principal() -> Principal:
    return Principal(user_id="u1", tenant_id=TenantId("acme"), role="operator")


def _maker(tag: str) -> Any:
    async def _http(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        return {"ok": True, "from": tag, "action": action.name}

    return _http


async def test_bound_transport_fires_when_no_per_call() -> None:
    conn = SlackConnector(http_transport=_maker("bound"))
    result = await conn.execute(
        ConnectorAction(name="post_message", params={"channel": "C1"}),
        principal=_principal(),
        policy=ConnectorPolicy(allowed_channels=["C1"]),
        secret_value="t",
    )
    assert result.payload["from"] == "bound"


async def test_per_call_transport_overrides_bound() -> None:
    conn = NotionConnector(http_transport=_maker("bound"))
    result = await conn.execute(
        ConnectorAction(name="create_page", params={"workspace_id": "W1"}),
        principal=_principal(),
        policy=ConnectorPolicy(allowed_workspace_ids=["W1"], allowed_database_ids=["D1"]),
        http_transport=_maker("per-call"),
        secret_value="t",
    )
    assert result.payload["from"] == "per-call"


async def test_groupware_bound_transport() -> None:
    conn = GroupwareConnector(http_transport=_maker("gw"))
    result = await conn.execute(
        ConnectorAction(name="post_approval", params={"channel": "사내-공지"}),
        principal=_principal(),
        policy=ConnectorPolicy(allowed_channels=["사내-공지"]),
        secret_value="t",
    )
    assert result.payload["from"] == "gw"


@pytest.mark.parametrize(
    "connector,policy,action",
    [
        (
            SlackConnector(http_transport=_maker("x")),
            ConnectorPolicy(allowed_channels=["C1"]),
            ConnectorAction(name="post_message", params={"channel": "C1"}),
        ),
        (
            JiraConnector(http_transport=_maker("x")),
            ConnectorPolicy(allowed_projects=["SEC"]),
            ConnectorAction(name="create_issue", params={"project_key": "SEC"}),
        ),
        (
            DocsConnector(http_transport=_maker("x")),
            ConnectorPolicy(allowed_workspace_ids=["ws"], allowed_database_ids=["f"]),
            ConnectorAction(name="create_document", params={"workspace_id": "ws", "folder_id": "f"}),
        ),
        (
            SapConnector(http_transport=_maker("x")),
            ConnectorPolicy(allowed_projects=["1000"], allowed_transitions=["FB01"]),
            ConnectorAction(
                name="post_document", params={"company_code": "1000", "transaction_code": "FB01"}
            ),
        ),
    ],
)
async def test_missing_secret_blocks_before_transport(
    connector: Any, policy: ConnectorPolicy, action: ConnectorAction
) -> None:
    """Even with a bound transport, an empty secret fails the OAuth gate first —
    the transport is never reached without a credential."""
    with pytest.raises(WhitelistViolation):
        await connector.execute(action, principal=_principal(), policy=policy, secret_value="")


async def test_notion_empty_workspace_allowlist_fails_closed() -> None:
    conn = NotionConnector(http_transport=_maker("x"))
    with pytest.raises(WhitelistViolation, match="allow-none"):
        await conn.validate_action(
            ConnectorAction(name="create_page", params={"workspace_id": "W1"}),
            ConnectorPolicy(allowed_workspace_ids=[]),
        )


async def test_notion_rate_limit_fails_closed() -> None:
    conn = NotionConnector(http_transport=_maker("x"))
    policy = ConnectorPolicy(allowed_workspace_ids=["W1"], allowed_database_ids=["D1"], rate_limit_per_sec=1)
    action = ConnectorAction(name="create_page", params={"workspace_id": "W1"})
    first = await conn.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert first.ok is True
    from secugent.tools.connectors.base import RateLimitExceeded

    with pytest.raises(RateLimitExceeded):
        await conn.execute(action, principal=_principal(), policy=policy, secret_value="t")
