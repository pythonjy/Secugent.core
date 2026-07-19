# SPDX-License-Identifier: Apache-2.0
"""Regression: dispatch must enforce action ∈ connector.actions.

The ``Literal → str`` generalisation of ``ConnectorAction.name`` removed the only
gate that checked "is this action declared by the connector?" on the dispatch
path. ``ConnectorRegistry.is_action_known`` computes the answer but the dispatch
path never consulted it, so an undeclared action (``slack.delete_everything``)
flowed through ``ConnectorAction.model_validate`` and *executed*, audited as
``connector.dispatched`` (info) instead of ``connector.denied``.

These tests pin the restored membership gate on **both** the static-Mapping path
and the live registry-source path (closing either one alone is bypassable), plus
the audit-consistency follow-ups (malformed/multi-dot actions are
denied with an audit, and a buggy source surfaces rather than being swallowed).

Deterministic module (§B-4a): unit branches here complement the registry triple
harness in ``tests/tools/connectors/test_registry.py``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.connector_transport import ConnectorBinding, ConnectorTransport
from secugent.io.broker.credentials import CredentialBroker, CredentialError
from secugent.io.broker.identity import IdentityStrategy
from secugent.io.broker.profiles import ExecutionProfile
from secugent.io.broker.request import EgressRequest
from secugent.tools.connectors.base import ConnectorAction, ConnectorPolicy, ConnectorResult
from secugent.tools.connectors.registry import ConnectorRegistry

# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #


class _FakeConnector:
    """Minimal Connector — executes any action it is handed (no membership check
    of its own). The transport, not the connector, must reject undeclared actions.
    """

    def __init__(self, name: str, actions: tuple[str, ...], *, supports_obo: bool = False) -> None:
        self.name = name
        self.actions = actions
        self.supports_obo = supports_obo
        self.executed: list[str] = []

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        return None

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Principal,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        self.executed.append(action.name)
        return ConnectorResult(ok=True, payload={"action": action.name, "name": self.name})


class _Secrets:
    async def get(self, name: str, version: str | None = None) -> Any:
        from pydantic import SecretStr

        return SecretStr("xoxb-fake")


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _binding(
    name: str = "slack",
    actions: tuple[str, ...] = ("post_message", "list_channels"),
) -> ConnectorBinding:
    return ConnectorBinding(
        connector=_FakeConnector(name, actions),
        policy=ConnectorPolicy(allowed_channels=["사내-공지"]),
        secret_name="slack-bot-token",
    )


def _principal() -> Principal:
    return Principal(user_id="alice@corp", tenant_id=TenantId("acme"), role="operator")


def _request(action: str) -> EgressRequest:
    effect = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target=action.partition(".")[0],
        sink_class=SinkClass.EXTERNAL,
        action=action,
        meta=(("channel", "사내-공지"),),
    )
    return EgressRequest(
        effect=effect,
        label=DataLabel.PUBLIC,
        principal=_principal(),
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )


def _transport_static(binding: ConnectorBinding, audit: _Audit) -> ConnectorTransport:
    return ConnectorTransport(
        {binding.connector.name: binding},
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=audit,
    )


def _transport_registry(reg: ConnectorRegistry, audit: _Audit) -> ConnectorTransport:
    return ConnectorTransport(
        reg,
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=audit,
    )


# --------------------------------------------------------------------------- #
# 1. declared action → dispatch succeeds (both paths)
# --------------------------------------------------------------------------- #


async def test_declared_action_dispatches_static_path() -> None:
    binding = _binding()
    audit = _Audit()
    transport = _transport_static(binding, audit)
    result = await transport.dispatch(_request("slack.post_message"))
    assert result.ok is True
    assert any(e.type == "connector.dispatched" for e in audit.events)


async def test_declared_action_dispatches_registry_path() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding())
    audit = _Audit()
    transport = _transport_registry(reg, audit)
    result = await transport.dispatch(_request("slack.post_message"))
    assert result.ok is True
    assert any(e.type == "connector.dispatched" for e in audit.events)


# --------------------------------------------------------------------------- #
# 2. UNDECLARED action → fail-closed + connector.denied (CORE regression)
# --------------------------------------------------------------------------- #


async def test_undeclared_action_denied_static_path() -> None:
    binding = _binding(actions=("post_message", "list_channels"))
    audit = _Audit()
    transport = _transport_static(binding, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request("slack.delete_everything"))
    # denied (not dispatched), with the distinguishing reason
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert denied, "undeclared action must be audited as connector.denied"
    assert denied[0].payload["action"] == "slack.delete_everything"
    assert denied[0].payload["reason"] == "action not declared by connector"
    assert not any(e.type == "connector.dispatched" for e in audit.events)
    # the connector must never have been executed
    assert binding.connector.executed == []  # type: ignore[attr-defined]
    # no token leaks into any audit payload
    assert "xoxb-fake" not in json.dumps([e.payload for e in audit.events])


async def test_undeclared_action_denied_registry_path() -> None:
    reg = ConnectorRegistry()
    binding = _binding(actions=("post_message", "list_channels"))
    reg.register(binding)
    audit = _Audit()
    transport = _transport_registry(reg, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request("slack.delete_everything"))
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert denied and denied[0].payload["reason"] == "action not declared by connector"
    assert not any(e.type == "connector.dispatched" for e in audit.events)
    assert binding.connector.executed == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# 3. empty-actions connector → every action denied (both paths)
# --------------------------------------------------------------------------- #


async def test_empty_actions_connector_denies_everything_static() -> None:
    binding = _binding(actions=())
    audit = _Audit()
    transport = _transport_static(binding, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request("slack.post_message"))
    assert any(e.type == "connector.denied" for e in audit.events)
    assert binding.connector.executed == []  # type: ignore[attr-defined]


async def test_empty_actions_connector_denies_everything_registry() -> None:
    reg = ConnectorRegistry()
    binding = _binding(actions=())
    reg.register(binding)
    audit = _Audit()
    transport = _transport_registry(reg, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request("slack.post_message"))
    assert any(e.type == "connector.denied" for e in audit.events)
    assert binding.connector.executed == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# 4. determinism — undeclared action denied identically 100x (§B-4a)
# --------------------------------------------------------------------------- #


async def test_undeclared_action_denial_deterministic_100x() -> None:
    binding = _binding(actions=("post_message",))
    for _ in range(100):
        audit = _Audit()
        transport = _transport_static(binding, audit)
        with pytest.raises(CredentialError):
            await transport.dispatch(_request("slack.delete_everything"))
        kinds = [e.type for e in audit.events]
        assert kinds == ["connector.denied"]


# --------------------------------------------------------------------------- #
# 5. malformed / multi-dot action audited as denied
# --------------------------------------------------------------------------- #


async def test_multi_dot_action_denied_with_audit() -> None:
    # 'slack.a.b' resolves the binding but the residual action 'a.b' is malformed.
    # It must be denied with an audit (not silently raise without an event).
    binding = _binding(actions=("post_message",))
    audit = _Audit()
    transport = _transport_static(binding, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request("slack.a.b"))
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert denied, "malformed multi-dot action must record connector.denied"
    assert binding.connector.executed == []  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# 6. a buggy source error is not silently swallowed
# --------------------------------------------------------------------------- #


async def test_buggy_source_error_is_not_swallowed_as_not_found(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A source raising something OTHER than ConnectorNotFound is a programming
    # bug. It must still fail-closed (deny) but be logged, not silently coerced
    # to "simple unregistered" (§B-8).
    class _BuggySource:
        def get(self, name: str) -> ConnectorBinding:
            raise RuntimeError("source backend exploded")

    audit = _Audit()
    transport = ConnectorTransport(
        _BuggySource(),
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=audit,
    )
    with caplog.at_level("WARNING"):
        with pytest.raises(CredentialError):
            await transport.dispatch(_request("slack.post_message"))
    # the source bug is surfaced (warning + traceback via exc_info), not swallowed
    bug_logs = [
        rec
        for rec in caplog.records
        if rec.levelname == "WARNING" and "binding source raised" in rec.getMessage()
    ]
    assert bug_logs, "a non-not-found source error must be logged, not silently swallowed"
    assert bug_logs[0].exc_info is not None
    # still recorded as denied (fail-closed)
    assert any(e.type == "connector.denied" for e in audit.events)
