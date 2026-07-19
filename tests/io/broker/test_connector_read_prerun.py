# SPDX-License-Identifier: Apache-2.0
"""EgressBroker.dispatch_connector_read — pre-run gated read path (2026-07-14).

The grounding producer runs a retrieval at submission time (before the run
dispatches and binds its authorization envelope). ``dispatch_connector_read`` runs
the SAME deny-by-default gate chain as ``dispatch_connector`` but SKIPS ONLY the
run-scoped EM-07 envelope gate (which would deny-by-default with no envelope bound).

These tests prove the relaxation is bounded — the read path skips the envelope gate
yet STILL enforces every other control: EM-03 signed policy, §A-2.1 Rule-of-Two
3-axis, EM-02 egress-label cap, and audit-before-act. A defect that skipped any of
those would fail these tests. Korean 여신 retrieval fixture (§C-3).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from secugent.audit.hash_chain import ChainedEventStore
from secugent.core.contracts import Step
from secugent.core.event_store import EventStore
from secugent.core.sec.label_store import InMemoryLabelStore
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import TenantId
from secugent.io.broker import EgressBroker, ExecutionProfile, RouterTransport
from secugent.io.broker.broker import EgressDeniedError
from secugent.io.broker.connector_transport import ConnectorBinding, ConnectorTransport
from secugent.io.broker.credentials import CredentialBroker
from secugent.io.broker.identity import IdentityStrategy
from secugent.io.broker.label_resolver import LabelResolver
from secugent.tools.connectors.base import ConnectorAction, ConnectorPolicy, ConnectorResult
from secugent.tools.router import ToolDispatchError, ToolRouter, ToolRouterConfig

_CONTAINER = "step-여신-검색-001"

_EVIDENCE = {
    "source_uri": "s3://loan-review/2026/여신심사_00123.pdf",
    "doc_id": "LR-00123",
    "retrieved_at": "2026-07-14T09:00:00+09:00",
    "snippet": "담보 평가액은 3.2억원",
    "score": 0.91,
}


class _RetrievalFake:
    """Minimal read-only 'retrieval' connector returning an evidence payload."""

    def __init__(self) -> None:
        self.name = "retrieval"
        self.actions = ("search",)
        self.supports_obo = False

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        return None

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Any,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        return ConnectorResult(ok=True, payload={"evidence": [dict(_EVIDENCE)]})


class _Secrets:
    async def get(self, name: str, version: str | None = None) -> Any:
        from pydantic import SecretStr

        return SecretStr("retrieval-dummy-token")


class _DenyEnvelope:
    """Envelope gate that denies-by-default (models a run with no bound envelope)."""

    def check(self, req: Any) -> Any:
        return SimpleNamespace(outcome="deny", reason="no_envelope_bound")


def _allow_all() -> Any:
    return compile_policy(
        PolicyDoc(
            version="1",
            tenant_id="_base",
            rules=[Rule(id="a", effect="allow", match=Match(), rationale="ok")],
        )
    )


def _deny_all() -> Any:
    return compile_policy(
        PolicyDoc(version="1", tenant_id="_base", rules=[]),  # no rule matches → default_deny
    )


def _transport(chained: ChainedEventStore) -> ConnectorTransport:
    binding = ConnectorBinding(
        connector=_RetrievalFake(),
        policy=ConnectorPolicy(),
        secret_name="retrieval-bot-token",
    )
    return ConnectorTransport(
        {"retrieval": binding},
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=chained,
    )


async def _broker(
    chained: ChainedEventStore,
    *,
    policy: Any,
    resolver: LabelResolver | None,
    max_external: DataLabel = DataLabel.INTERNAL_USE,
) -> EgressBroker:
    return EgressBroker(
        policy=policy,
        audit_store=chained,
        transport=RouterTransport(ToolRouter(ToolRouterConfig())),
        connector_transport=_transport(chained),
        label_resolver=resolver,
        envelope_gate=_DenyEnvelope(),  # deny-by-default: no envelope bound
        default_profile=ExecutionProfile.EXTERNAL_BROKERED,
        default_label=DataLabel.CONFIDENTIAL,
        max_external=max_external,
    )


def _step(*, untrusted: bool = False) -> Step:
    params: dict[str, str] = {"workspace_id": "여신-collection", "query": "여신 한도 상향 근거"}
    if untrusted:
        params["untrusted_input"] = "true"
    return Step(
        id=_CONTAINER,
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="operator:grounding",
        action_type="connector_action",
        target="retrieval.search",
        context={"params": params},
    )


async def _public_resolver() -> LabelResolver:
    store = InMemoryLabelStore()
    await store.tag(TenantId("acme"), _CONTAINER, DataLabel.PUBLIC)
    return LabelResolver(store)


async def test_read_skips_envelope_but_dispatch_enforces_it(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        broker = await _broker(chained, policy=_allow_all(), resolver=await _public_resolver())
        # The run-execution path is DENIED by the (no-envelope) envelope gate
        # (EnvelopeSuspendedError, a ToolDispatchError)...
        with pytest.raises(ToolDispatchError):
            await broker.dispatch_connector(_step())
        # ...but the pre-run read path skips ONLY that gate and succeeds.
        result = await broker.dispatch_connector_read(_step())
        assert result.ok is True
        assert result.payload["connector_payload"]["evidence"][0]["doc_id"] == "LR-00123"
    finally:
        chained.close()


async def test_read_still_enforces_egress_label_cap(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        # No resolver → default_label CONFIDENTIAL; max_external INTERNAL_USE on the
        # EXTERNAL connector sink → EM-02 must DENY (not skipped with the envelope).
        broker = await _broker(chained, policy=_allow_all(), resolver=None)
        with pytest.raises(EgressDeniedError):
            await broker.dispatch_connector_read(_step())
    finally:
        chained.close()


async def test_read_label_cap_passes_when_ceiling_raised(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        # Raising max_external to CONFIDENTIAL (operator opt-in) lets the same
        # CONFIDENTIAL default label through — proves the cap is the actual gate.
        broker = await _broker(
            chained, policy=_allow_all(), resolver=None, max_external=DataLabel.CONFIDENTIAL
        )
        result = await broker.dispatch_connector_read(_step())
        assert result.ok is True
    finally:
        chained.close()


async def test_read_still_enforces_signed_policy(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        broker = await _broker(chained, policy=_deny_all(), resolver=await _public_resolver())
        with pytest.raises(EgressDeniedError):
            await broker.dispatch_connector_read(_step())
    finally:
        chained.close()


async def test_read_still_enforces_rule_of_two_3axis(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        # untrusted_input + sensitive_access(connector) + external_comm(EXTERNAL) =
        # all three axes → Rule-of-Two HITL gate must DENY (not skipped).
        broker = await _broker(chained, policy=_allow_all(), resolver=await _public_resolver())
        with pytest.raises(EgressDeniedError):
            await broker.dispatch_connector_read(_step(untrusted=True))
    finally:
        chained.close()


async def test_read_audits_before_act(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        broker = await _broker(chained, policy=_allow_all(), resolver=await _public_resolver())
        await broker.dispatch_connector_read(_step())
        allowed = chained.inner.list_events(tenant_id="acme", event_type="egress.allowed")
        assert len(allowed) == 1
        assert chained.verify_chain(tenant_id="acme") is True
    finally:
        chained.close()
