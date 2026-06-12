# SPDX-License-Identifier: Apache-2.0
"""ConnectorRegistry — runtime connector registration (deterministic, §B-4a).

Triple test harness: unit (all branches) + property-based (hypothesis) +
scenario regression, plus a 100x determinism proof. Korean enterprise fixture
(``kakaowork`` 사내 그룹웨어) per §C-3.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.connector_transport import ConnectorBinding, ConnectorTransport
from secugent.io.broker.credentials import CredentialBroker, CredentialError
from secugent.io.broker.identity import IdentityStrategy
from secugent.io.broker.manifests import default_manifest_registry, manifest_registry_with
from secugent.io.broker.profiles import ExecutionProfile
from secugent.io.broker.request import EgressRequest
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
)
from secugent.tools.connectors.registry import (
    ConnectorAlreadyRegistered,
    ConnectorNotFound,
    ConnectorRegistry,
    ConnectorRegistryError,
)
from secugent.tools.connectors.slack import SlackConnector

# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #


class _FakeConnector:
    """Minimal Connector for registry tests (no network)."""

    def __init__(self, name: str, actions: tuple[str, ...], *, supports_obo: bool = False) -> None:
        self.name = name
        self.actions = actions
        self.supports_obo = supports_obo
        self.seen_token = ""

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
        self.seen_token = secret_value
        return ConnectorResult(ok=True, payload={"action": action.name, "name": self.name})


def _binding(
    name: str,
    actions: tuple[str, ...] = ("post_message",),
    *,
    secret_name: str = "tok",
    supports_obo: bool = False,
) -> ConnectorBinding:
    return ConnectorBinding(
        connector=_FakeConnector(name, actions, supports_obo=supports_obo),
        policy=ConnectorPolicy(allowed_channels=["C1"]),
        secret_name=secret_name,
    )


def _kakaowork_binding() -> ConnectorBinding:
    """한국어 픽스처 — 사내 그룹웨어 'kakaowork' 커넥터."""
    return ConnectorBinding(
        connector=_FakeConnector("kakaowork", ("post_message", "list_channels")),
        policy=ConnectorPolicy(allowed_channels=["사내-공지"], rate_limit_per_sec=5),
        secret_name="kakaowork-bot-token",
    )


# --------------------------------------------------------------------------- #
# 1. register / get / unregister — happy + fail-closed branches
# --------------------------------------------------------------------------- #


def test_register_then_get_returns_binding() -> None:
    reg = ConnectorRegistry()
    binding = _binding("slack")
    reg.register(binding)
    assert reg.get("slack") is binding


def test_get_unknown_connector_fails_closed() -> None:
    reg = ConnectorRegistry()
    with pytest.raises(ConnectorNotFound):
        reg.get("ghost")


def test_duplicate_registration_fails_closed() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack"))
    with pytest.raises(ConnectorAlreadyRegistered):
        reg.register(_binding("slack"))


def test_unregister_unknown_fails_closed() -> None:
    reg = ConnectorRegistry()
    with pytest.raises(ConnectorNotFound):
        reg.unregister("ghost")


def test_unregister_then_get_fails_closed() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack"))
    reg.unregister("slack")
    with pytest.raises(ConnectorNotFound):
        reg.get("slack")


def test_unregister_then_reregister_is_allowed() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack"))
    reg.unregister("slack")
    reg.register(_binding("slack"))  # not a double registration
    assert reg.get("slack").connector.name == "slack"


def test_register_empty_secret_name_rejected() -> None:
    reg = ConnectorRegistry()
    with pytest.raises(ConnectorRegistryError):
        reg.register(_binding("slack", secret_name=""))


def test_register_empty_connector_name_rejected() -> None:
    reg = ConnectorRegistry()
    with pytest.raises(ConnectorRegistryError):
        reg.register(_binding("", ("post_message",)))


def test_exception_hierarchy_isolated_from_connector_error() -> None:
    from secugent.tools.connectors.base import ConnectorError

    assert issubclass(ConnectorAlreadyRegistered, ConnectorRegistryError)
    assert issubclass(ConnectorNotFound, ConnectorRegistryError)
    assert not issubclass(ConnectorRegistryError, ConnectorError)


# --------------------------------------------------------------------------- #
# 1b. ConnectorAction.name validator — Literal → str, still constrained
# --------------------------------------------------------------------------- #


def test_connector_action_accepts_arbitrary_unqualified_name() -> None:
    # the former closed Literal is now open — a new connector action is valid
    action = ConnectorAction(name="wire_transfer", params={"amount": 100})
    assert action.name == "wire_transfer"


@pytest.mark.parametrize("bad", ["", "   ", "slack.post_message", "a.b"])
def test_connector_action_rejects_empty_or_qualified_name(bad: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ConnectorAction(name=bad)


# --------------------------------------------------------------------------- #
# 2. all_bindings — immutable snapshot
# --------------------------------------------------------------------------- #


def test_all_bindings_returns_snapshot_not_live_view() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack"))
    snapshot = reg.all_bindings()
    reg.register(_binding("notion", ("create_page",)))
    # snapshot taken before the second register must not have grown
    assert set(snapshot) == {"slack"}
    assert set(reg.all_bindings()) == {"slack", "notion"}


def test_all_bindings_is_read_only() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack"))
    snapshot = reg.all_bindings()
    with pytest.raises(TypeError):
        snapshot["x"] = _binding("x")  # type: ignore[index]


# --------------------------------------------------------------------------- #
# 3. is_action_known — invariant 3
# --------------------------------------------------------------------------- #


def test_is_action_known_true_for_registered_action() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message", "list_channels")))
    assert reg.is_action_known("slack.post_message") is True
    assert reg.is_action_known("slack.list_channels") is True


def test_is_action_known_false_for_unknown_connector() -> None:
    reg = ConnectorRegistry()
    assert reg.is_action_known("ghost.post_message") is False


def test_is_action_known_false_for_unknown_action() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message",)))
    assert reg.is_action_known("slack.delete_everything") is False


@pytest.mark.parametrize("bad", ["", "noseparator", "slack.", ".post_message", "."])
def test_is_action_known_false_for_malformed(bad: str) -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message",)))
    assert reg.is_action_known(bad) is False


def test_empty_actions_connector_has_no_known_actions() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("empty", ()))
    assert reg.is_action_known("empty.anything") is False
    assert reg.get("empty").connector.actions == ()


# --------------------------------------------------------------------------- #
# 4. manifest_entries — invariant 4 + 5 (sync + conservative IRREVERSIBLE)
# --------------------------------------------------------------------------- #


def test_manifest_entries_synced_with_bindings() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message", "list_channels")))
    reg.register(_binding("notion", ("create_page",)))
    actions = {m.action for m in reg.manifest_entries()}
    assert actions == {"slack.post_message", "slack.list_channels", "notion.create_page"}


def test_manifest_entries_compensatable_for_known_mutations() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message",)))
    [manifest] = reg.manifest_entries()
    assert manifest.reversibility is ReversibilityClass.COMPENSATABLE
    assert manifest.compensating_action is not None


def test_manifest_entries_irreversible_default_for_unknown_mutation() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("erp", ("wire_transfer",)))
    [manifest] = reg.manifest_entries()
    assert manifest.reversibility is ReversibilityClass.IRREVERSIBLE
    assert manifest.compensating_action is None


def test_manifest_registry_with_extends_defaults() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("erp", ("wire_transfer",)))
    manifests = manifest_registry_with(reg)
    # new connector action is registered (conservative IRREVERSIBLE)
    assert manifests.classify("erp.wire_transfer") is ReversibilityClass.IRREVERSIBLE
    # defaults are preserved
    assert manifests.classify("file_write") is ReversibilityClass.REVERSIBLE
    assert manifests.classify("slack.post_message") is ReversibilityClass.COMPENSATABLE


def test_default_manifest_registry_unchanged_without_registry() -> None:
    # regression: existing default factory still works standalone
    manifests = default_manifest_registry()
    assert manifests.classify("file_write") is ReversibilityClass.REVERSIBLE


# --------------------------------------------------------------------------- #
# 5. determinism — 100x identical input → identical output (§B-4a)
# --------------------------------------------------------------------------- #


def test_get_deterministic_100x() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message", "list_channels")))
    first = reg.get("slack")
    for _ in range(100):
        assert reg.get("slack") is first


def test_is_action_known_deterministic_100x() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("slack", ("post_message",)))
    results = {reg.is_action_known("slack.post_message") for _ in range(100)}
    assert results == {True}


# --------------------------------------------------------------------------- #
# 6. property-based (hypothesis) — invariant 3 over arbitrary combos
# --------------------------------------------------------------------------- #

_ident = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8)


@given(
    connector_name=_ident,
    actions=st.lists(_ident, max_size=5, unique=True).map(tuple),
    probe_connector=_ident,
    probe_action=_ident,
)
@settings(max_examples=250)
def test_is_action_known_iff_registered_and_in_actions(
    connector_name: str,
    actions: tuple[str, ...],
    probe_connector: str,
    probe_action: str,
) -> None:
    reg = ConnectorRegistry()
    reg.register(_binding(connector_name, actions))
    qualified = f"{probe_connector}.{probe_action}"
    expected = probe_connector == connector_name and probe_action in actions
    assert reg.is_action_known(qualified) is expected


# --------------------------------------------------------------------------- #
# 7. concurrency — RLock protects the structure under threads
# --------------------------------------------------------------------------- #


def test_concurrent_register_get_no_corruption() -> None:
    import threading

    reg = ConnectorRegistry()
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            reg.register(_binding(f"c{idx}", ("post_message",)))
            assert reg.get(f"c{idx}").connector.name == f"c{idx}"
        except Exception as exc:  # noqa: BLE001 - surfacing thread errors to assert
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(reg.all_bindings()) == 40


# --------------------------------------------------------------------------- #
# 8. Korean fixture — 사내 그룹웨어 'kakaowork' 등록 시나리오 (§C-3)
# --------------------------------------------------------------------------- #


def test_kakaowork_connector_registration_scenario() -> None:
    reg = ConnectorRegistry()
    reg.register(_kakaowork_binding())
    binding = reg.get("kakaowork")
    assert binding.secret_name == "kakaowork-bot-token"
    assert "사내-공지" in binding.policy.allowed_channels
    assert reg.is_action_known("kakaowork.post_message") is True
    assert reg.is_action_known("kakaowork.read_thread") is False


# --------------------------------------------------------------------------- #
# 9. integration — ConnectorTransport + ConnectorRegistry (runtime binding)
# --------------------------------------------------------------------------- #


class _Secrets:
    def __init__(self, *, present: bool = True) -> None:
        self._present = present

    async def get(self, name: str, version: str | None = None) -> Any:
        from pydantic import SecretStr

        if not self._present:
            raise KeyError(name)
        return SecretStr("xoxb-fake")


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _principal() -> Principal:
    return Principal(user_id="alice@corp", tenant_id=TenantId("acme"), role="operator")


def _request(action: str = "kakaowork.post_message") -> EgressRequest:
    effect = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target="kakaowork",
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


def _transport(reg: ConnectorRegistry, audit: _Audit, *, present: bool = True) -> ConnectorTransport:
    return ConnectorTransport(
        reg,
        credentials=CredentialBroker(_Secrets(present=present)),
        identity=IdentityStrategy(),
        audit_store=audit,
    )


async def test_transport_dispatches_runtime_registered_connector() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    transport = _transport(reg, audit)
    # connector NOT known yet → fail-closed
    with pytest.raises(CredentialError):
        await transport.dispatch(_request())
    # register at runtime → now dispatch succeeds
    reg.register(_kakaowork_binding())
    result = await transport.dispatch(_request())
    assert result.ok is True
    assert any(e.type == "connector.dispatched" for e in audit.events)


async def test_transport_unknown_connector_records_denied_audit() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    transport = _transport(reg, audit)
    with pytest.raises(CredentialError):
        await transport.dispatch(_request(action="ghost.post_message"))
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert denied and denied[0].payload["action"] == "ghost.post_message"
    # no token ever leaks into the denial audit
    assert "xoxb-fake" not in json.dumps([e.payload for e in audit.events])


async def test_transport_denial_survives_audit_backend_failure() -> None:
    # a degraded audit backend must NOT turn the fail-closed deny into a
    # different exception — the deny is still a CredentialError (§C-1 fail-closed).
    class _FailingAudit:
        def append_event(self, event: Event) -> Event:
            raise RuntimeError("audit store down")

    reg = ConnectorRegistry()
    transport = ConnectorTransport(
        reg,
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=_FailingAudit(),
    )
    with pytest.raises(CredentialError):
        await transport.dispatch(_request(action="ghost.post_message"))


async def test_transport_static_mapping_still_works() -> None:
    # regression: ConnectorTransport must still accept a plain Mapping (EM-06 API)
    audit = _Audit()
    binding = _kakaowork_binding()
    transport = ConnectorTransport(
        {"kakaowork": binding},
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=audit,
    )
    result = await transport.dispatch(_request())
    assert result.ok is True


async def test_transport_with_real_slack_connector_via_registry() -> None:
    # the real SlackConnector registers + dispatches through a registry unchanged
    reg = ConnectorRegistry()
    reg.register(
        ConnectorBinding(
            connector=SlackConnector(),
            policy=ConnectorPolicy(allowed_channels=["C1"]),
            secret_name="slack-bot",
        )
    )
    audit = _Audit()
    transport = _transport(reg, audit)
    effect = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target="slack",
        sink_class=SinkClass.EXTERNAL,
        action="slack.post_message",
        meta=(("channel", "C1"), ("text", "hi")),
    )
    request = EgressRequest(
        effect=effect,
        label=DataLabel.PUBLIC,
        principal=_principal(),
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )
    result = await transport.dispatch(request)
    assert result.ok is True
