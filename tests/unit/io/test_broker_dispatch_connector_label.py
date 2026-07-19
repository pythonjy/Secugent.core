# SPDX-License-Identifier: Apache-2.0
"""LabelResolver TRUE arm on the async connector dispatch path (deterministic, §B-4a).

Covers ``EgressBroker.dispatch_connector`` branch 638->639: when a
``LabelResolver`` is wired, the connector label is resolved from the
``LabelStore`` (per-container classification) instead of the broker's
``_default_label`` fallback.

The test is *non-vacuous*: the broker's ``_default_label`` is set to
``CONFIDENTIAL`` (which, against the default ``max_external=INTERNAL_USE``
ceiling, would be DENIED on the EXTERNAL connector sink). The resolver, given a
container tagged ``PUBLIC``, returns ``PUBLIC`` — so the dispatch only succeeds,
and the ``egress.allowed`` audit event only records ``label == int(PUBLIC)``, if
the resolved (non-default) label actually flows into the gate. If the FALSE arm
were taken instead, the CONFIDENTIAL default would be used and the gate would
deny — so a passing assertion proves the TRUE arm executed.

Korean fixture: a 사내 ``kakaowork.post_message`` connector action posting to the
Korean channel ``사내-공지`` (§C-3).
"""

from __future__ import annotations

from typing import Any

from secugent.audit.hash_chain import ChainedEventStore
from secugent.core.contracts import Step
from secugent.core.event_store import EventStore
from secugent.core.sec.label_store import InMemoryLabelStore
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import TenantId
from secugent.io.broker import EgressBroker, ExecutionProfile, RouterTransport
from secugent.io.broker.connector_transport import ConnectorBinding, ConnectorTransport
from secugent.io.broker.credentials import CredentialBroker
from secugent.io.broker.identity import IdentityStrategy
from secugent.io.broker.label_resolver import LabelResolver
from secugent.tools.connectors.base import ConnectorAction, ConnectorPolicy, ConnectorResult
from secugent.tools.router import ToolRouter, ToolRouterConfig

_CONTAINER_ID = "step-사내-공지-001"


class _FakeConnector:
    """Minimal Connector executing any declared action (no own membership check)."""

    def __init__(self, name: str, actions: tuple[str, ...]) -> None:
        self.name = name
        self.actions = actions
        self.supports_obo = False
        self.executed: list[str] = []

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
        self.executed.append(action.name)
        return ConnectorResult(ok=True, payload={"sent": action.name, "to": self.name})


class _Secrets:
    async def get(self, name: str, version: str | None = None) -> Any:
        from pydantic import SecretStr

        # Placeholder-marked dummy token: matches the slack-token shape but the
        # 'dummy' marker keeps the public-release secret scanner (G3) from
        # flagging it as a real leaked credential. Not a real secret.
        return SecretStr("xoxb-dummy-token")


def _binding() -> ConnectorBinding:
    return ConnectorBinding(
        connector=_FakeConnector("kakaowork", ("post_message",)),
        policy=ConnectorPolicy(allowed_channels=["사내-공지"]),
        secret_name="kakaowork-bot-token",
    )


def _allow_all() -> Any:
    return compile_policy(
        PolicyDoc(
            version="1",
            tenant_id="_base",
            rules=[Rule(id="a", effect="allow", match=Match(), rationale="ok")],
        )
    )


def _step() -> Step:
    return Step(
        id=_CONTAINER_ID,
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:messenger",
        action_type="connector_action",
        target="kakaowork.post_message",
        context={"params": {"channel": "사내-공지"}},
    )


async def test_dispatch_connector_uses_resolved_label_not_default(tmp_path: Any) -> None:
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        # Tag THIS connector container PUBLIC. The store default is CONFIDENTIAL,
        # so the tag is what makes the EXTERNAL gate pass.
        store = InMemoryLabelStore()
        await store.tag(TenantId("acme"), _CONTAINER_ID, DataLabel.PUBLIC)
        resolver = LabelResolver(store)

        binding = _binding()
        transport = ConnectorTransport(
            {binding.connector.name: binding},
            credentials=CredentialBroker(_Secrets()),
            identity=IdentityStrategy(),
            audit_store=chained,
        )
        broker = EgressBroker(
            policy=_allow_all(),
            audit_store=chained,
            transport=RouterTransport(ToolRouter(ToolRouterConfig())),
            connector_transport=transport,
            label_resolver=resolver,
            default_profile=ExecutionProfile.EXTERNAL_BROKERED,
            # CONFIDENTIAL would EXCEED max_external (INTERNAL_USE) on the EXTERNAL
            # sink → deny. Success therefore proves the resolved PUBLIC was used.
            default_label=DataLabel.CONFIDENTIAL,
        )

        result = await broker.dispatch_connector(_step())

        assert result.ok is True
        assert result.payload["connector_ok"] is True
        assert binding.connector.executed == ["post_message"]  # type: ignore[attr-defined]

        # The resolved (non-default) PUBLIC label flowed into the gate AND the
        # decision audit payload — not the CONFIDENTIAL default.
        allowed = chained.inner.list_events(tenant_id="acme", event_type="egress.allowed")
        assert len(allowed) == 1
        assert allowed[0].payload["label"] == int(DataLabel.PUBLIC)
        assert allowed[0].payload["label"] != int(DataLabel.CONFIDENTIAL)
        assert chained.verify_chain(tenant_id="acme") is True
    finally:
        chained.close()


async def test_dispatch_connector_resolver_arm_is_deterministic(tmp_path: Any) -> None:
    # Same tagged container → same resolved PUBLIC label, every run (§B-4a).
    chained = ChainedEventStore(EventStore(tmp_path / "db.sqlite"))
    try:
        store = InMemoryLabelStore()
        await store.tag(TenantId("acme"), _CONTAINER_ID, DataLabel.PUBLIC)
        resolver = LabelResolver(store)
        for _ in range(100):
            label = await resolver.resolve(
                tenant_id=TenantId("acme"), container_id=_CONTAINER_ID, taint_ctx=None
            )
            assert label is DataLabel.PUBLIC
    finally:
        chained.close()


# --------------------------------------------------------------------------- #
# F3 — a fail-safe-derived label never egresses EXTERNAL, regardless of ceiling
# --------------------------------------------------------------------------- #


class _BrokenStore:
    """LabelStore that always raises on get() (drives the fail-safe path)."""

    async def tag(self, tenant_id: TenantId, container_id: str, label: DataLabel) -> None: ...

    async def get(self, tenant_id: TenantId, container_id: str) -> DataLabel:
        raise RuntimeError("backend unavailable")


def _broker_with(store: Any, *, max_external: DataLabel, db_path: Any) -> tuple[EgressBroker, Any, Any]:
    """Build a broker whose connector sink is EXTERNAL, at the given ceiling."""
    binding = _binding()
    chained = ChainedEventStore(EventStore(db_path))
    transport = ConnectorTransport(
        {binding.connector.name: binding},
        credentials=CredentialBroker(_Secrets()),
        identity=IdentityStrategy(),
        audit_store=chained,
    )
    broker = EgressBroker(
        policy=_allow_all(),
        audit_store=chained,
        transport=RouterTransport(ToolRouter(ToolRouterConfig())),
        connector_transport=transport,
        label_resolver=LabelResolver(store),
        default_profile=ExecutionProfile.EXTERNAL_BROKERED,
        max_external=max_external,
    )
    return broker, binding, chained


async def test_dispatch_connector_fail_safe_denied_despite_raised_ceiling(tmp_path: Any) -> None:
    """LabelStore failure ⇒ EXTERNAL egress denied even at the CONFIDENTIAL ceiling.

    Without F3, ``may_egress(CONFIDENTIAL, EXTERNAL, max_external=CONFIDENTIAL)`` would
    ALLOW (2 <= 2) — the store-failure path would fail OPEN once the operator raised
    the ceiling to enable grounding. F3 denies it on provenance (INV-D).
    """
    from secugent.io.broker.broker import EgressDeniedError

    broker, binding, chained = _broker_with(
        _BrokenStore(), max_external=DataLabel.CONFIDENTIAL, db_path=tmp_path / "f3a.sqlite"
    )
    try:
        try:
            await broker.dispatch_connector(_step())
            raise AssertionError("expected the fail-safe label to be denied at EXTERNAL")
        except EgressDeniedError as exc:
            assert "label_provenance_uncertain" in str(exc)
        # The connector transport was never reached (deny-before-act).
        assert binding.connector.executed == []  # type: ignore[attr-defined]
        denied = chained.inner.list_events(tenant_id="acme", event_type="egress.denied")
        assert denied and denied[0].payload["rationale"] == "egress_label:label_provenance_uncertain"
    finally:
        chained.close()


async def test_dispatch_connector_fail_safe_denied_even_at_secret_ceiling(tmp_path: Any) -> None:
    """Regardless-of-ceiling: even max_external=SECRET cannot re-open the path."""
    from secugent.io.broker.broker import EgressDeniedError

    broker, binding, chained = _broker_with(
        _BrokenStore(), max_external=DataLabel.SECRET, db_path=tmp_path / "f3b.sqlite"
    )
    try:
        try:
            await broker.dispatch_connector(_step())
            raise AssertionError("expected deny even at the SECRET ceiling")
        except EgressDeniedError as exc:
            assert "label_provenance_uncertain" in str(exc)
        assert binding.connector.executed == []  # type: ignore[attr-defined]
    finally:
        chained.close()


async def test_dispatch_connector_normal_confidential_allowed_at_confidential_ceiling(
    tmp_path: Any,
) -> None:
    """Regression: a REAL CONFIDENTIAL label still egresses at the CONFIDENTIAL ceiling.

    F3 must deny only the fail-safe (store-down) path — the operator's legitimate
    grounding use case (raise ceiling to CONFIDENTIAL) must keep working.
    """
    store = InMemoryLabelStore()
    await store.tag(TenantId("acme"), _CONTAINER_ID, DataLabel.CONFIDENTIAL)
    broker, binding, chained = _broker_with(
        store, max_external=DataLabel.CONFIDENTIAL, db_path=tmp_path / "f3c.sqlite"
    )
    try:
        result = await broker.dispatch_connector(_step())
        assert result.ok is True
        assert binding.connector.executed == ["post_message"]  # type: ignore[attr-defined]
        allowed = chained.inner.list_events(tenant_id="acme", event_type="egress.allowed")
        assert len(allowed) == 1 and allowed[0].payload["label"] == int(DataLabel.CONFIDENTIAL)
    finally:
        chained.close()
