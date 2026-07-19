# SPDX-License-Identifier: Apache-2.0
"""S5 — register_production_connectors: bulk binding registration helper.

The integration step assembles ``ConnectorBinding``s (connector + policy +
secret_name) and registers them with a single helper rather than open-coding the
loop in ``api/main.py``. The helper is fail-closed (duplicate name raises) and
touches only the registry — it does not know about the httpx transport (layering).

Korean fixture (§C-3): a 사내 그룹웨어 'kakaowork' binding to '사내-공지'.
"""

from __future__ import annotations

import pytest

from secugent.io.broker.connector_transport import ConnectorBinding
from secugent.tools.connectors.base import ConnectorPolicy
from secugent.tools.connectors.groupware import GroupwareConnector
from secugent.tools.connectors.registry import (
    ConnectorAlreadyRegistered,
    ConnectorRegistry,
    register_production_connectors,
)
from secugent.tools.connectors.slack import SlackConnector


def _slack_binding() -> ConnectorBinding:
    return ConnectorBinding(
        connector=SlackConnector(),
        policy=ConnectorPolicy(allowed_channels=["C1"]),
        secret_name="slack-bot",
    )


def _kakaowork_binding() -> ConnectorBinding:
    """한국어 픽스처 — 사내 그룹웨어 'groupware' → '사내-공지'."""
    return ConnectorBinding(
        connector=GroupwareConnector(),
        policy=ConnectorPolicy(allowed_channels=["사내-공지"], rate_limit_per_sec=5),
        secret_name="kakaowork-bot-token",
    )


def test_registers_all_bindings() -> None:
    reg = ConnectorRegistry()
    register_production_connectors(reg, bindings=[_slack_binding(), _kakaowork_binding()])
    assert reg.get("slack").secret_name == "slack-bot"
    assert reg.get("groupware").secret_name == "kakaowork-bot-token"


def test_empty_bindings_is_a_no_op() -> None:
    reg = ConnectorRegistry()
    register_production_connectors(reg, bindings=[])
    assert dict(reg.all_bindings()) == {}


def test_duplicate_binding_fails_closed() -> None:
    reg = ConnectorRegistry()
    register_production_connectors(reg, bindings=[_slack_binding()])
    with pytest.raises(ConnectorAlreadyRegistered):
        register_production_connectors(reg, bindings=[_slack_binding()])
