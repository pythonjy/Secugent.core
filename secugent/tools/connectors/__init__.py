# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — SaaS connector catalogue (Slack / Notion / Jira).

All connectors share a common :class:`Connector` Protocol and OAuth-via-
:class:`secugent.core.secrets.SecretsManager` requirement. Mechanical
Oversight (PHASE 1) remains the security gate — connectors are dispatched
through :class:`secugent.tools.router.ToolRouter` with ``action_type =
"connector"`` so policy decisions remain centralised.
"""

from secugent.tools.connectors.base import (
    Connector,
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorResult,
    RateLimitExceeded,
    TokenBucket,
    WhitelistViolation,
)
from secugent.tools.connectors.docs import DocsConnector
from secugent.tools.connectors.groupware import GroupwareConnector
from secugent.tools.connectors.jira import JiraConnector
from secugent.tools.connectors.notion import NotionConnector
from secugent.tools.connectors.registry import (
    ConnectorAlreadyRegistered,
    ConnectorNotFound,
    ConnectorRegistry,
    ConnectorRegistryError,
)
from secugent.tools.connectors.sap import SapConnector
from secugent.tools.connectors.slack import SlackConnector

__all__ = [
    "Connector",
    "ConnectorAction",
    "ConnectorAlreadyRegistered",
    "ConnectorError",
    "ConnectorNotFound",
    "ConnectorPolicy",
    "ConnectorRegistry",
    "ConnectorRegistryError",
    "ConnectorResult",
    "DocsConnector",
    "GroupwareConnector",
    "JiraConnector",
    "NotionConnector",
    "RateLimitExceeded",
    "SapConnector",
    "SlackConnector",
    "TokenBucket",
    "WhitelistViolation",
]
