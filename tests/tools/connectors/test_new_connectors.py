# SPDX-License-Identifier: Apache-2.0
"""BDP_04 §14d — groupware / SAP / docs connectors (deterministic, §B-4a-ish).

These three connectors follow the EXISTING slack/notion/jira pattern (a duck-typed
:class:`~secugent.tools.connectors.base.Connector`: ``name`` + ``actions`` +
``validate_action`` + ``execute``). They add NO new control logic — the policy
gate (REGULATIONS deny-by-default + Rule-of-Two membership) is the single source
of truth that lives in :class:`~secugent.io.broker.connector_transport.ConnectorTransport`.

Hard invariants pinned here:

* **I1 (no bypass)** — every connector action flows through the transport policy
  gate before ``execute``; an action NOT declared by the connector (Rule-of-Two
  membership violation) and a deny-by-default whitelist miss are BOTH
  HARD-BLOCKED, the connector never runs, and a ``connector.denied`` audit is
  written.
* **I2 (audited)** — an allowed action emits exactly one ``connector.dispatched``
  audit; a denied action emits exactly one ``connector.denied`` audit; no secret
  leaks into any audit payload.

Korean fixtures (§C-3): 사내 그룹웨어 '사내-공지' 채널, 사내 전자결재 문서함 '전자결재함'.
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
from secugent.io.broker.profiles import ExecutionProfile
from secugent.io.broker.request import EgressRequest
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    RateLimitExceeded,
    WhitelistViolation,
)
from secugent.tools.connectors.docs import DocsConnector
from secugent.tools.connectors.groupware import GroupwareConnector
from secugent.tools.connectors.registry import ConnectorRegistry
from secugent.tools.connectors.sap import SapConnector

# --------------------------------------------------------------------------- #
# Korean fixtures (§C-3)
# --------------------------------------------------------------------------- #

_GW_CHANNEL = "사내-공지"
_GW_CHANNEL_DENIED = "임원-전용"
_DOC_FOLDER = "전자결재함"
_DOC_FOLDER_DENIED = "대외비함"
_SAP_COMPANY = "1000"  # 회사 코드
_SAP_TXN = "FB60"  # 전표 입력 트랜잭션


# --------------------------------------------------------------------------- #
# Shared test doubles (mirror tests/tools/connectors/test_registry.py)
# --------------------------------------------------------------------------- #


class _Secrets:
    async def get(self, name: str, version: str | None = None) -> Any:
        from pydantic import SecretStr

        return SecretStr("sekret-token")


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _principal(tenant: str = "acme") -> Principal:
    return Principal(user_id="alice@corp", tenant_id=TenantId(tenant), role="operator")


def _request(action: str, *, meta: tuple[tuple[str, str], ...]) -> EgressRequest:
    effect = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target=action.partition(".")[0],
        sink_class=SinkClass.EXTERNAL,
        action=action,
        meta=meta,
    )
    return EgressRequest(
        effect=effect,
        label=DataLabel.PUBLIC,
        principal=_principal(),
        run_id="r-14d",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )


def _transport(reg: ConnectorRegistry, audit: _Audit) -> ConnectorTransport:
    return ConnectorTransport(
        reg,
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=audit,
    )


def _register(reg: ConnectorRegistry, connector: Any, policy: ConnectorPolicy, secret: str) -> None:
    reg.register(ConnectorBinding(connector=connector, policy=policy, secret_name=secret))


# --------------------------------------------------------------------------- #
# Per-connector allow / deny fixtures
# --------------------------------------------------------------------------- #


def _gw_allow_policy() -> ConnectorPolicy:
    return ConnectorPolicy(allowed_channels=[_GW_CHANNEL], rate_limit_per_sec=5)


def _docs_allow_policy() -> ConnectorPolicy:
    return ConnectorPolicy(
        allowed_workspace_ids=["ws-corp"],
        allowed_database_ids=[_DOC_FOLDER],
        rate_limit_per_sec=5,
    )


def _sap_allow_policy() -> ConnectorPolicy:
    return ConnectorPolicy(
        allowed_projects=[_SAP_COMPANY],
        allowed_transitions=[_SAP_TXN],
        rate_limit_per_sec=5,
    )


# --------------------------------------------------------------------------- #
# 1. static contract — name / actions / unqualified action names
# --------------------------------------------------------------------------- #


def test_connectors_expose_name_and_actions() -> None:
    assert GroupwareConnector().name == "groupware"
    assert DocsConnector().name == "docs"
    assert SapConnector().name == "sap"
    # actions are non-empty, unqualified tokens (the registry/transport authority)
    for connector in (GroupwareConnector(), DocsConnector(), SapConnector()):
        assert connector.actions, f"{connector.name} must declare actions"
        for act in connector.actions:
            ConnectorAction(name=act)  # raises if qualified/empty


# --------------------------------------------------------------------------- #
# 2. I1 — allow path: action passes the policy gate and executes (audited)
# --------------------------------------------------------------------------- #


async def test_groupware_allowed_action_passes_gate_and_audited() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, GroupwareConnector(), _gw_allow_policy(), "gw-bot")
    transport = _transport(reg, audit)

    result = await transport.dispatch(
        _request("groupware.post_message", meta=(("channel", _GW_CHANNEL), ("text", "공지")))
    )
    assert result.ok is True
    dispatched = [e for e in audit.events if e.type == "connector.dispatched"]
    assert len(dispatched) == 1
    assert dispatched[0].payload["action"] == "groupware.post_message"


async def test_docs_allowed_action_passes_gate_and_audited() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, DocsConnector(), _docs_allow_policy(), "docs-bot")
    transport = _transport(reg, audit)

    result = await transport.dispatch(
        _request(
            "docs.create_document",
            meta=(("workspace_id", "ws-corp"), ("folder_id", _DOC_FOLDER), ("title", "결재")),
        )
    )
    assert result.ok is True
    assert any(e.type == "connector.dispatched" for e in audit.events)


async def test_sap_allowed_action_passes_gate_and_audited() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, SapConnector(), _sap_allow_policy(), "sap-svc")
    transport = _transport(reg, audit)

    result = await transport.dispatch(
        _request(
            "sap.post_document",
            meta=(("company_code", _SAP_COMPANY), ("transaction_code", _SAP_TXN)),
        )
    )
    assert result.ok is True
    assert any(e.type == "connector.dispatched" for e in audit.events)


# --------------------------------------------------------------------------- #
# 3. I1 — deny-by-default whitelist miss is HARD-BLOCKED (connector never runs)
# --------------------------------------------------------------------------- #


async def test_groupware_denied_channel_hard_blocked_and_audited() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    connector = GroupwareConnector()
    _register(reg, connector, _gw_allow_policy(), "gw-bot")
    transport = _transport(reg, audit)

    with pytest.raises(WhitelistViolation):
        await transport.dispatch(
            _request("groupware.post_message", meta=(("channel", _GW_CHANNEL_DENIED), ("text", "x")))
        )
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert len(denied) == 1
    assert [e for e in audit.events if e.type == "connector.dispatched"] == []
    assert "sekret-token" not in json.dumps([e.payload for e in audit.events])


async def test_docs_denied_folder_hard_blocked() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, DocsConnector(), _docs_allow_policy(), "docs-bot")
    transport = _transport(reg, audit)

    with pytest.raises(WhitelistViolation):
        await transport.dispatch(
            _request(
                "docs.create_document",
                meta=(("workspace_id", "ws-corp"), ("folder_id", _DOC_FOLDER_DENIED)),
            )
        )
    assert len([e for e in audit.events if e.type == "connector.denied"]) == 1


async def test_sap_denied_company_code_hard_blocked() -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, SapConnector(), _sap_allow_policy(), "sap-svc")
    transport = _transport(reg, audit)

    with pytest.raises(WhitelistViolation):
        await transport.dispatch(
            _request("sap.post_document", meta=(("company_code", "9999"), ("transaction_code", _SAP_TXN)))
        )
    assert len([e for e in audit.events if e.type == "connector.denied"]) == 1


# --------------------------------------------------------------------------- #
# 4. I1 — empty allowlist == block-everything (allow-none, fail-closed)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("connector_factory", "action", "meta"),
    [
        (GroupwareConnector, "groupware.post_message", (("channel", _GW_CHANNEL),)),
        (
            DocsConnector,
            "docs.create_document",
            (("workspace_id", "ws-corp"), ("folder_id", _DOC_FOLDER)),
        ),
        (SapConnector, "sap.post_document", (("company_code", _SAP_COMPANY), ("transaction_code", _SAP_TXN))),
    ],
)
async def test_empty_allowlist_blocks_everything(
    connector_factory: Any, action: str, meta: tuple[tuple[str, str], ...]
) -> None:
    reg = ConnectorRegistry()
    audit = _Audit()
    # Empty ConnectorPolicy → every allowlist empty → block-all (allow-none).
    _register(reg, connector_factory(), ConnectorPolicy(), "tok")
    transport = _transport(reg, audit)

    with pytest.raises(WhitelistViolation):
        await transport.dispatch(_request(action, meta=meta))
    assert len([e for e in audit.events if e.type == "connector.denied"]) == 1


# --------------------------------------------------------------------------- #
# 5. I1 — Rule-of-Two membership: an UNDECLARED action never reaches execute
# --------------------------------------------------------------------------- #


async def test_undeclared_action_blocked_before_execute() -> None:
    """An action not in the connector's ``actions`` tuple is denied by the
    transport membership gate BEFORE any credential is resolved or execute runs
    — the single source of truth for "which actions exist" is the connector's
    declared tuple, enforced once in the transport."""
    reg = ConnectorRegistry()
    audit = _Audit()
    _register(reg, GroupwareConnector(), _gw_allow_policy(), "gw-bot")
    transport = _transport(reg, audit)

    with pytest.raises(CredentialError):
        await transport.dispatch(_request("groupware.drop_database", meta=(("channel", _GW_CHANNEL),)))
    denied = [e for e in audit.events if e.type == "connector.denied"]
    assert len(denied) == 1
    assert denied[0].payload["reason"] == "action not declared by connector"


# --------------------------------------------------------------------------- #
# 6. execute requires a secret (OAuth via SecretsManager, never raw)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("connector_factory", "policy_factory", "action", "params"),
    [
        (GroupwareConnector, _gw_allow_policy, "post_message", {"channel": _GW_CHANNEL}),
        (
            DocsConnector,
            _docs_allow_policy,
            "create_document",
            {"workspace_id": "ws-corp", "folder_id": _DOC_FOLDER},
        ),
        (
            SapConnector,
            _sap_allow_policy,
            "post_document",
            {"company_code": _SAP_COMPANY, "transaction_code": _SAP_TXN},
        ),
    ],
)
async def test_execute_without_secret_fails_closed(
    connector_factory: Any, policy_factory: Any, action: str, params: dict[str, Any]
) -> None:
    connector = connector_factory()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            ConnectorAction(name=action, params=params),
            principal=_principal(),
            policy=policy_factory(),
            secret_value="",
        )


# --------------------------------------------------------------------------- #
# 7. rate limit fail-closed (bucket lives in execute, not validate_action)
# --------------------------------------------------------------------------- #


async def test_groupware_rate_limit_fails_closed() -> None:
    connector = GroupwareConnector()
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL], rate_limit_per_sec=1)
    action = ConnectorAction(name="post_message", params={"channel": _GW_CHANNEL})
    principal = _principal()
    first = await connector.execute(action, principal=principal, policy=policy, secret_value="t")
    assert first.ok is True
    with pytest.raises(RateLimitExceeded):
        await connector.execute(action, principal=principal, policy=policy, secret_value="t")


# --------------------------------------------------------------------------- #
# 8. validate_action is side-effect-free (called twice by the transport)
# --------------------------------------------------------------------------- #


async def test_validate_action_is_idempotent_no_rate_consumption() -> None:
    connector = GroupwareConnector()
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL], rate_limit_per_sec=1)
    action = ConnectorAction(name="post_message", params={"channel": _GW_CHANNEL})
    # Calling validate_action many times must NOT consume the rate bucket.
    for _ in range(10):
        await connector.validate_action(action, policy)
    # the single execute still succeeds (no token was consumed by validate)
    result = await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True


# --------------------------------------------------------------------------- #
# 9. read actions need no whitelisted target but still require a secret
# --------------------------------------------------------------------------- #


async def test_groupware_list_channels_read_action_executes() -> None:
    connector = GroupwareConnector()
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL])
    action = ConnectorAction(name="list_channels", params={})
    await connector.validate_action(action, policy)  # read action: no target gate
    result = await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True


# --------------------------------------------------------------------------- #
# 10. determinism — 100x deny is identical (§B-4a flavour for the gate)
# --------------------------------------------------------------------------- #


async def test_sap_deny_deterministic_100x() -> None:
    for _ in range(100):
        reg = ConnectorRegistry()
        audit = _Audit()
        _register(reg, SapConnector(), _sap_allow_policy(), "sap-svc")
        transport = _transport(reg, audit)
        with pytest.raises(WhitelistViolation):
            await transport.dispatch(
                _request(
                    "sap.post_document",
                    meta=(("company_code", "9999"), ("transaction_code", _SAP_TXN)),
                )
            )
        assert len([e for e in audit.events if e.type == "connector.denied"]) == 1


# --------------------------------------------------------------------------- #
# 11. property — any non-allowlisted groupware channel is ALWAYS blocked
# --------------------------------------------------------------------------- #

_channel = st.text(
    alphabet=st.characters(blacklist_characters="\x00\\ \t\n\r", min_codepoint=33), min_size=1, max_size=12
)


@settings(max_examples=200)
@given(channel=_channel)
async def test_property_non_allowlisted_channel_always_blocked(channel: str) -> None:
    """Invariant: for a single-entry allowlist, ANY channel != the allowed one is
    rejected by validate_action (deny-by-default). Channels equal to the allowed
    one are accepted."""
    connector = GroupwareConnector()
    allowed = "사내-공지"
    policy = ConnectorPolicy(allowed_channels=[allowed])
    action = ConnectorAction(name="post_message", params={"channel": channel})
    if channel == allowed:
        await connector.validate_action(action, policy)  # no raise
    else:
        with pytest.raises(WhitelistViolation):
            await connector.validate_action(action, policy)


# --------------------------------------------------------------------------- #
# 12. real http_transport seam — response is honoured (not the mock path)
# --------------------------------------------------------------------------- #


async def _fake_http(*, action: Any, principal: Any, secret_value: str) -> dict[str, Any]:
    # echoes a vendor-shaped response; proves secret reaches the transport seam,
    # never the connector's own env/log.
    assert secret_value == "live-token"
    return {"ok": True, "id": f"{action.name}-1"}


async def test_groupware_real_http_transport_path() -> None:
    connector = GroupwareConnector()
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL])
    action = ConnectorAction(name="post_message", params={"channel": _GW_CHANNEL})
    result = await connector.execute(
        action, principal=_principal(), policy=policy, http_transport=_fake_http, secret_value="live-token"
    )
    assert result.ok is True
    assert result.payload["id"] == "post_message-1"


async def test_docs_real_http_transport_path() -> None:
    connector = DocsConnector()
    policy = ConnectorPolicy(allowed_workspace_ids=["ws-corp"], allowed_database_ids=[_DOC_FOLDER])
    action = ConnectorAction(
        name="create_document", params={"workspace_id": "ws-corp", "folder_id": _DOC_FOLDER}
    )
    result = await connector.execute(
        action, principal=_principal(), policy=policy, http_transport=_fake_http, secret_value="live-token"
    )
    assert result.ok is True


async def test_sap_real_http_transport_path() -> None:
    connector = SapConnector()
    policy = ConnectorPolicy(allowed_projects=[_SAP_COMPANY], allowed_transitions=[_SAP_TXN])
    action = ConnectorAction(
        name="post_document", params={"company_code": _SAP_COMPANY, "transaction_code": _SAP_TXN}
    )
    result = await connector.execute(
        action, principal=_principal(), policy=policy, http_transport=_fake_http, secret_value="live-token"
    )
    assert result.ok is True


# --------------------------------------------------------------------------- #
# 13. docs — folder-scoped vs workspace-only action branches
# --------------------------------------------------------------------------- #


async def test_docs_search_is_workspace_scoped_no_folder_gate() -> None:
    """``search`` is workspace-scoped: it passes with only a whitelisted
    workspace and no folder gate, even if allowed_database_ids is empty."""
    connector = DocsConnector()
    policy = ConnectorPolicy(allowed_workspace_ids=["ws-corp"])  # no folder allowlist
    action = ConnectorAction(name="search", params={"workspace_id": "ws-corp", "query": "결재"})
    result = await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True


async def test_docs_update_document_uses_document_id_for_folder_gate() -> None:
    """update/read use ``document_id`` as the folder-allowlist key when
    ``folder_id`` is absent (mirrors notion's database_id/page_id fallback)."""
    connector = DocsConnector()
    policy = ConnectorPolicy(allowed_workspace_ids=["ws-corp"], allowed_database_ids=[_DOC_FOLDER])
    action = ConnectorAction(
        name="update_document", params={"workspace_id": "ws-corp", "document_id": _DOC_FOLDER}
    )
    result = await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True


async def test_docs_folder_allowlist_empty_blocks_folder_action() -> None:
    connector = DocsConnector()
    policy = ConnectorPolicy(allowed_workspace_ids=["ws-corp"])  # folder allowlist empty
    action = ConnectorAction(
        name="create_document", params={"workspace_id": "ws-corp", "folder_id": _DOC_FOLDER}
    )
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(action, policy)


# --------------------------------------------------------------------------- #
# 14. sap — read (company-only gate) vs search (no gate) vs txn-missing branch
# --------------------------------------------------------------------------- #


async def test_sap_read_document_company_gate_only() -> None:
    """``read_document`` is company-scoped but NOT transaction-scoped: a
    whitelisted company_code with no transaction_code passes."""
    connector = SapConnector()
    policy = ConnectorPolicy(allowed_projects=[_SAP_COMPANY])  # no transaction allowlist needed
    action = ConnectorAction(name="read_document", params={"company_code": _SAP_COMPANY})
    result = await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True


async def test_sap_search_empty_policy_hard_blocked() -> None:
    """SG-14d-1/4 regression: ``sap.search`` MUST honour the connector-wide
    allow-none floor. An empty ``ConnectorPolicy()`` (every allowlist empty)
    is the safest/default state and must HARD-BLOCK every SAP action —
    including ``search`` — so a misconfigured/empty SAP policy cannot enumerate
    financial records across company codes (deny-by-default, §A-2.2)."""
    connector = SapConnector()
    policy = ConnectorPolicy()  # everything empty — search must be blocked, not allowed
    action = ConnectorAction(name="search", params={"query": "전표"})
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(action, policy)
    with pytest.raises(WhitelistViolation):
        await connector.execute(action, principal=_principal(), policy=policy, secret_value="t")


async def test_sap_search_requires_whitelisted_company_code() -> None:
    """SG-14d-1/4 regression: ``search`` is company-scoped — with a non-empty
    company allowlist, a search whose ``company_code`` is NOT on the allowlist
    (or absent) is blocked; only a whitelisted company_code passes. This keeps
    per-tenant company-code isolation on the highest-impact connector."""
    connector = SapConnector()
    policy = ConnectorPolicy(allowed_projects=[_SAP_COMPANY])
    # company_code absent → blocked
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(ConnectorAction(name="search", params={"query": "전표"}), policy)
    # wrong company_code → blocked
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(
            ConnectorAction(name="search", params={"company_code": "9999", "query": "전표"}), policy
        )
    # whitelisted company_code → allowed (no transaction gate for a read/search)
    result = await connector.execute(
        ConnectorAction(name="search", params={"company_code": _SAP_COMPANY, "query": "전표"}),
        principal=_principal(),
        policy=policy,
        secret_value="t",
    )
    assert result.ok is True


async def test_sap_search_empty_policy_hard_blocked_via_transport_100x() -> None:
    """Determinism (§B-4a): an empty-policy ``sap.search`` is denied through the
    central transport 100x identically, emitting exactly one ``connector.denied``
    audit each time and never reaching ``execute``."""
    for _ in range(100):
        reg = ConnectorRegistry()
        audit = _Audit()
        _register(reg, SapConnector(), ConnectorPolicy(), "sap-svc")
        transport = _transport(reg, audit)
        with pytest.raises(WhitelistViolation):
            await transport.dispatch(_request("sap.search", meta=(("query", "전표"),)))
        assert len([e for e in audit.events if e.type == "connector.denied"]) == 1
        assert [e for e in audit.events if e.type == "connector.dispatched"] == []


async def test_sap_transaction_allowlist_empty_blocks_posting() -> None:
    connector = SapConnector()
    policy = ConnectorPolicy(allowed_projects=[_SAP_COMPANY])  # company ok, but txn allowlist empty
    action = ConnectorAction(
        name="post_document", params={"company_code": _SAP_COMPANY, "transaction_code": _SAP_TXN}
    )
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(action, policy)


async def test_sap_transaction_not_in_allowlist_blocked() -> None:
    connector = SapConnector()
    policy = ConnectorPolicy(allowed_projects=[_SAP_COMPANY], allowed_transitions=[_SAP_TXN])
    action = ConnectorAction(
        name="post_document", params={"company_code": _SAP_COMPANY, "transaction_code": "ZZ99"}
    )
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(action, policy)


# --------------------------------------------------------------------------- #
# 15. groupware — read_thread (channel-gated) + denied-channel read
# --------------------------------------------------------------------------- #


async def test_groupware_read_thread_channel_gated() -> None:
    connector = GroupwareConnector()
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL])
    ok_action = ConnectorAction(name="read_thread", params={"channel": _GW_CHANNEL})
    result = await connector.execute(ok_action, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True
    bad_action = ConnectorAction(name="read_thread", params={"channel": _GW_CHANNEL_DENIED})
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(bad_action, policy)


# --------------------------------------------------------------------------- #
# 16. SG-14d-2/5 — generated compensating action MUST be a declared action
# --------------------------------------------------------------------------- #


def _qualified_manifests(connector: Any, secret: str = "tok") -> dict[str, Any]:
    """Register ``connector`` and return its ``manifest_entries()`` keyed by the
    qualified ``'<connector>.<action>'`` string."""
    reg = ConnectorRegistry()
    reg.register(
        ConnectorBinding(
            connector=connector, policy=ConnectorPolicy(allowed_channels=["c"]), secret_name=secret
        )
    )
    return {m.action: m for m in reg.manifest_entries()}


async def test_groupware_post_message_compensator_is_a_declared_action() -> None:
    """SG-14d-2/5 regression: ``groupware.post_message`` is COMPENSATABLE only if
    the generated ``compensating_action`` is an action the connector actually
    DECLARES (so the steer/precommit compensation path can fire it through the
    transport membership gate). A synthetic ``groupware.__compensate__`` that the
    connector never declares is a false reversibility promise and is rejected."""
    connector = GroupwareConnector()
    manifests = _qualified_manifests(connector)
    entry = manifests["groupware.post_message"]
    assert entry.reversibility is ReversibilityClass.COMPENSATABLE
    # The compensator must be a REAL, declared connector action — not a synthetic
    # '__compensate__' that the membership gate would HARD-DENY.
    assert entry.compensating_action is not None
    comp_connector, _, comp_action = entry.compensating_action.partition(".")
    assert comp_connector == "groupware"
    assert comp_action in connector.actions, (
        f"compensator {entry.compensating_action!r} is not a declared groupware action"
    )


async def test_groupware_delete_message_is_channel_gated() -> None:
    """SG-14d-2/5: the real compensator ``delete_message`` is itself a declared,
    channel-gated mutating action (deny-by-default like ``post_message``) — so
    compensation cannot be used to reach a non-whitelisted channel."""
    connector = GroupwareConnector()
    assert "delete_message" in connector.actions
    policy = ConnectorPolicy(allowed_channels=[_GW_CHANNEL])
    ok = ConnectorAction(name="delete_message", params={"channel": _GW_CHANNEL, "ts": "1"})
    result = await connector.execute(ok, principal=_principal(), policy=policy, secret_value="t")
    assert result.ok is True
    bad = ConnectorAction(name="delete_message", params={"channel": _GW_CHANNEL_DENIED, "ts": "1"})
    with pytest.raises(WhitelistViolation):
        await connector.validate_action(bad, policy)


def test_groupware_delete_message_defaults_irreversible() -> None:
    """``delete_message`` is a mutation with no declared undo of its own, so the
    registry classifies it conservatively as IRREVERSIBLE (fail-closed)."""
    manifests = _qualified_manifests(GroupwareConnector())
    assert manifests["groupware.delete_message"].reversibility is ReversibilityClass.IRREVERSIBLE


def test_every_compensatable_connector_action_names_a_declared_compensator() -> None:
    """SG-14d-2/5 invariant (generalised): for EVERY new 14d connector, any
    action classified COMPENSATABLE by the registry must name a compensating
    action that the connector declares. This forbids re-introducing the
    unqualified-token false promise on the new connectors."""
    for connector in (GroupwareConnector(), DocsConnector(), SapConnector()):
        for entry in _qualified_manifests(connector, secret="tok").values():
            if entry.reversibility is ReversibilityClass.COMPENSATABLE:
                assert entry.compensating_action is not None
                comp_connector, _, comp_action = entry.compensating_action.partition(".")
                assert comp_connector == connector.name
                assert comp_action in connector.actions, (
                    f"{connector.name}: COMPENSATABLE {entry.action!r} names undeclared "
                    f"compensator {entry.compensating_action!r}"
                )
