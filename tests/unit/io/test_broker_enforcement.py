# SPDX-License-Identifier: Apache-2.0
"""EM-05 — broker gate enforcement + audit-before-act + fail-closed."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from secugent.core.contracts import Event, Step
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import Principal, TenantId
from secugent.io import broker as broker_module
from secugent.io.broker import (
    EgressBroker,
    EgressDeniedError,
    EgressRequest,
    EnvelopeSuspendedError,
    ExecutionProfile,
)

_PRINCIPAL = Principal(user_id="alice", tenant_id=TenantId("acme"), role="operator")


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[EgressRequest] = []

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        self.calls.append(request)
        return b"executed"


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


class _FailingAudit:
    def append_event(self, event: Event) -> Event:
        raise RuntimeError("durable audit store is down")


def _policy(*rules: Rule) -> Any:
    return compile_policy(PolicyDoc(version="1", tenant_id="_base", rules=list(rules)))


_ALLOW_ALL = _policy(Rule(id="a", effect="allow", match=Match(), rationale="allow all"))


def _broker(
    policy: Any, audit: Any, transport: Any, *, max_external: DataLabel = DataLabel.INTERNAL_USE
) -> EgressBroker:
    return EgressBroker(policy=policy, audit_store=audit, transport=transport, max_external=max_external)


def _req(
    effect: Effect,
    *,
    label: DataLabel = DataLabel.PUBLIC,
    profile: ExecutionProfile = ExecutionProfile.INTERNAL_RW,
) -> EgressRequest:
    return EgressRequest(effect=effect, label=label, principal=_PRINCIPAL, run_id="r1", profile=profile)


_SANDBOX_WRITE = Effect(
    kind=EffectKind.FILE_WRITE, target="c:/sandbox/out.txt", sink_class=SinkClass.LOCAL_SANDBOX
)
_EXTERNAL_SEND = Effect(
    kind=EffectKind.NET_SEND, target="https://evil.example/x", sink_class=SinkClass.EXTERNAL
)


# 1. profile boundary
async def test_airgapped_external_denied_transport_not_called() -> None:
    transport = _RecordingTransport()
    broker = _broker(_ALLOW_ALL, _RecordingAudit(), transport)
    result = await broker.submit(_req(_EXTERNAL_SEND, profile=ExecutionProfile.AIRGAPPED))
    assert result.ok is False
    assert result.decision.rationale.startswith("profile_boundary")
    assert transport.calls == []


# 2. policy hard_block
async def test_policy_hard_block_transport_not_called() -> None:
    transport = _RecordingTransport()
    policy = _policy(
        Rule(id="h", effect="hard_block", match=Match(kind=EffectKind.FILE_WRITE), rationale="no writes")
    )
    broker = _broker(policy, _RecordingAudit(), transport)
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is False
    assert result.decision.outcome == "hard_block"
    assert transport.calls == []


# 3. label egress (CONFIDENTIAL + EXTERNAL → deny)
async def test_confidential_external_denied() -> None:
    transport = _RecordingTransport()
    broker = _broker(_ALLOW_ALL, _RecordingAudit(), transport, max_external=DataLabel.INTERNAL_USE)
    result = await broker.submit(
        _req(_EXTERNAL_SEND, label=DataLabel.CONFIDENTIAL, profile=ExecutionProfile.EXTERNAL_BROKERED)
    )
    assert result.ok is False
    assert "egress_label" in result.decision.rationale
    assert transport.calls == []


# 4. happy path
async def test_allowed_path_executes_once_and_audits() -> None:
    transport = _RecordingTransport()
    audit = _RecordingAudit()
    broker = _broker(_ALLOW_ALL, audit, transport)
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is True
    assert result.payload == b"executed"
    assert len(transport.calls) == 1
    # decision event recorded BEFORE execution, plus a post-exec event
    assert any(e.type == "egress.allowed" for e in audit.events)
    assert result.audit_event_id


# 5. audit append failure → fail-closed (no execution)
async def test_audit_failure_refuses_execution() -> None:
    transport = _RecordingTransport()
    broker = _broker(_ALLOW_ALL, _FailingAudit(), transport)
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is False
    assert result.decision.rationale == "audit_append_failed"
    assert transport.calls == []  # fail-closed: transport never called


# 6. determinism
async def test_decision_deterministic_100x() -> None:
    broker = _broker(_ALLOW_ALL, _RecordingAudit(), _RecordingTransport())
    req = _req(_EXTERNAL_SEND, profile=ExecutionProfile.AIRGAPPED)  # denied path (no side effect)
    outs = {(await broker.submit(req)).decision.rationale for _ in range(100)}
    assert len(outs) == 1


# 7. denials are audited
async def test_denials_are_audited() -> None:
    audit = _RecordingAudit()
    broker = _broker(_ALLOW_ALL, audit, _RecordingTransport())
    await broker.submit(_req(_EXTERNAL_SEND, profile=ExecutionProfile.AIRGAPPED))
    assert any(e.type == "egress.denied" for e in audit.events)


# --------------------------------------------------------------------------- #
# envelope gate (EM-07 injection point) + audit edge paths
# --------------------------------------------------------------------------- #


class _Gate:
    def __init__(self, outcome: str) -> None:
        self._outcome = outcome

    def check(self, request: EgressRequest) -> Any:
        return SimpleNamespace(outcome=self._outcome, reason="envelope")


class _FailAfterFirst:
    def __init__(self) -> None:
        self.n = 0

    def append_event(self, event: Event) -> Event:
        self.n += 1
        if self.n > 1:
            raise RuntimeError("post-exec audit down")
        return event


async def test_envelope_suspend_denies_and_skips_transport() -> None:
    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL, audit_store=_RecordingAudit(), transport=transport, envelope_gate=_Gate("suspend")
    )
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == []


async def test_envelope_allow_passes() -> None:
    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL, audit_store=_RecordingAudit(), transport=transport, envelope_gate=_Gate("allow")
    )
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is True
    assert len(transport.calls) == 1


async def test_deny_audit_failure_is_nonfatal() -> None:
    transport = _RecordingTransport()
    broker = _broker(_ALLOW_ALL, _FailingAudit(), transport)
    result = await broker.submit(_req(_EXTERNAL_SEND, profile=ExecutionProfile.AIRGAPPED))
    assert result.ok is False  # still denied; deny-audit failure is non-fatal
    assert result.audit_event_id == ""
    assert transport.calls == []


async def test_post_exec_audit_failure_does_not_fake_failure() -> None:
    transport = _RecordingTransport()
    broker = _broker(_ALLOW_ALL, _FailAfterFirst(), transport)
    result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is True  # effect already executed; never fake success
    assert len(transport.calls) == 1


# --------------------------------------------------------------------------- #
# go-live dispatch shim
# --------------------------------------------------------------------------- #


def _file_step(tmp_path: Path) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type="file_write",
        target=str(tmp_path / "out.txt"),
    )


def test_dispatch_shim_denied_raises_egress_denied(tmp_path: Path) -> None:
    deny = _policy(Rule(id="d", effect="deny", match=Match(), rationale="no"))
    broker = EgressBroker(
        policy=deny,
        audit_store=_RecordingAudit(),
        transport=_RecordingTransport(),
        sandbox_roots=[str(tmp_path)],
    )
    with pytest.raises(EgressDeniedError):
        broker.dispatch(_file_step(tmp_path), content="x")


def test_dispatch_shim_suspend_raises(tmp_path: Path) -> None:
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=_RecordingTransport(),
        envelope_gate=_Gate("suspend"),
        sandbox_roots=[str(tmp_path)],
    )
    with pytest.raises(EnvelopeSuspendedError):
        broker.dispatch(_file_step(tmp_path), content="x")


# --------------------------------------------------------------------------- #
# process-wide broker registry
# --------------------------------------------------------------------------- #


def test_set_then_get_broker() -> None:
    saved = broker_module._BROKER
    broker = _broker(_ALLOW_ALL, _RecordingAudit(), _RecordingTransport())
    try:
        broker_module.set_broker(broker)
        assert broker_module.get_broker() is broker
    finally:
        broker_module._BROKER = saved


def test_get_broker_unset_raises() -> None:
    saved = broker_module._BROKER
    broker_module._BROKER = None
    try:
        with pytest.raises(RuntimeError):
            broker_module.get_broker()
    finally:
        broker_module._BROKER = saved


def test_reset_broker_clears_singleton() -> None:
    saved = broker_module._BROKER
    try:
        broker_module.set_broker(_broker(_ALLOW_ALL, _RecordingAudit(), _RecordingTransport()))
        broker_module.reset_broker()
        assert broker_module._BROKER is None
        with pytest.raises(RuntimeError):
            broker_module.get_broker()
    finally:
        broker_module._BROKER = saved


def test_reset_broker_is_exported() -> None:
    assert "reset_broker" in broker_module.__all__


# --------------------------------------------------------------------------- #
# EM-07 envelope gate ↔ broker integration (real EnvelopeGate + bind_envelope)
# --------------------------------------------------------------------------- #


def _reg_with_write_reversible() -> Any:
    from secugent.core.sec.reversibility import ActionManifest, ManifestRegistry, ReversibilityClass

    reg = ManifestRegistry()
    reg.register(ActionManifest("file_write", ReversibilityClass.REVERSIBLE))
    return reg


async def test_broker_in_envelope_allows() -> None:
    from secugent.core.sec.envelope import AuthorizationEnvelope, EnvelopeUsage, bind_envelope
    from secugent.io.broker.envelope_gate import EnvelopeGate

    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        envelope_gate=EnvelopeGate(_reg_with_write_reversible()),
    )
    env = AuthorizationEnvelope(
        max_data_label=DataLabel.CONFIDENTIAL,
        allowed_sinks=frozenset({SinkClass.LOCAL_SANDBOX}),
        allowed_actions=frozenset({"file_write"}),
    )
    with bind_envelope(env, EnvelopeUsage()):
        result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is True
    assert len(transport.calls) == 1


async def test_broker_out_of_envelope_suspends() -> None:
    from secugent.core.sec.envelope import AuthorizationEnvelope, EnvelopeUsage, bind_envelope
    from secugent.io.broker.envelope_gate import EnvelopeGate

    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        envelope_gate=EnvelopeGate(_reg_with_write_reversible()),
    )
    with bind_envelope(AuthorizationEnvelope(), EnvelopeUsage()):  # empty = deny-all
        result = await broker.submit(_req(_SANDBOX_WRITE))
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == []


async def test_broker_no_envelope_bound_suspends() -> None:
    from secugent.io.broker.envelope_gate import EnvelopeGate

    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        envelope_gate=EnvelopeGate(_reg_with_write_reversible()),
    )
    result = await broker.submit(_req(_SANDBOX_WRITE))  # no bind_envelope active
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == []


# --------------------------------------------------------------------------- #
# EM-09 staging divert (irreversible → 2-phase staging)
# --------------------------------------------------------------------------- #

_SMTP_SEND = Effect(
    kind=EffectKind.CONNECTOR_ACTION, target="inbox", sink_class=SinkClass.EXTERNAL, action="smtp.send"
)


def _ext_req(effect: Effect) -> EgressRequest:
    return EgressRequest(
        effect=effect,
        label=DataLabel.PUBLIC,
        principal=_PRINCIPAL,
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )


async def test_reversible_with_registry_executes_directly() -> None:
    from secugent.io.broker.manifests import default_manifest_registry
    from secugent.io.staging import StagedEffectStore

    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        registry=default_manifest_registry(),
        staging_store=StagedEffectStore(),
    )
    result = await broker.submit(_req(_SANDBOX_WRITE))  # file_write is REVERSIBLE
    assert result.ok is True
    assert len(transport.calls) == 1


async def test_irreversible_without_staging_is_denied() -> None:
    from secugent.io.broker.manifests import default_manifest_registry

    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        registry=default_manifest_registry(),
        staging_store=None,  # misconfigured
        max_external=DataLabel.SECRET,
    )
    result = await broker.submit(_ext_req(_SMTP_SEND))
    assert result.ok is False
    assert result.decision.rationale == "irreversible_requires_staging"
    assert transport.calls == []


async def test_irreversible_stages_with_now_fallback() -> None:
    from secugent.io.broker.manifests import default_manifest_registry
    from secugent.io.staging import StagedEffectStore

    transport = _RecordingTransport()
    store = StagedEffectStore()
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=transport,
        registry=default_manifest_registry(),
        staging_store=store,
        hold_sec=0,  # no now_provider → real-clock fallback
        max_external=DataLabel.SECRET,
    )
    result = await broker.submit(_ext_req(_SMTP_SEND))
    assert result.ok is False
    assert result.decision.rationale.startswith("staged:")
    assert transport.calls == []
    assert len(store.list_staged("r1")) == 1


def test_staging_store_without_registry_rejected() -> None:
    from secugent.io.staging import StagedEffectStore

    with pytest.raises(ValueError):  # would fail OPEN for I-C otherwise
        EgressBroker(
            policy=_ALLOW_ALL,
            audit_store=_RecordingAudit(),
            transport=_RecordingTransport(),
            staging_store=StagedEffectStore(),
            registry=None,
        )


def test_dispatch_shim_staged_raises(tmp_path: Path) -> None:
    from secugent.core.sec.reversibility import ActionManifest, ManifestRegistry, ReversibilityClass
    from secugent.io.broker import StagingHeldError
    from secugent.io.staging import StagedEffectStore

    reg = ManifestRegistry()
    reg.register(ActionManifest("file_write", ReversibilityClass.IRREVERSIBLE))  # force staging via dispatch
    broker = EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=_RecordingAudit(),
        transport=_RecordingTransport(),
        registry=reg,
        staging_store=StagedEffectStore(),
        hold_sec=10,
        now_provider=lambda: datetime(2026, 1, 1, tzinfo=UTC),
        sandbox_roots=[str(tmp_path)],
    )
    with pytest.raises(StagingHeldError):
        broker.dispatch(_file_step(tmp_path), content="x")


# --------------------------------------------------------------------------- #
# EM-04 unscoped-effect telemetry (default_deny, rule_id is None → policy.unscoped)
# --------------------------------------------------------------------------- #

_SECRET_POLICY_WRITE = Effect(
    kind=EffectKind.FILE_WRITE, target="c:/secret/a.txt", sink_class=SinkClass.LOCAL_SANDBOX
)
_UNSCOPED_WRITE = Effect(
    kind=EffectKind.FILE_WRITE, target="c:/other/a.txt", sink_class=SinkClass.LOCAL_SANDBOX
)


def _deny_secret_policy() -> Any:
    return _policy(
        Rule(id="d", effect="deny", match=Match(target_glob="c:/secret/*"), rationale="no secrets")
    )


async def test_default_deny_records_unscoped_effect() -> None:
    from secugent.audit.unscoped import UnscopedRecorder

    audit = _RecordingAudit()
    broker = EgressBroker(
        policy=_deny_secret_policy(),
        audit_store=audit,
        transport=_RecordingTransport(),
        unscoped_recorder=UnscopedRecorder(audit),
    )
    result = await broker.submit(_req(_UNSCOPED_WRITE))  # matches no rule → default_deny
    assert result.ok is False
    assert result.decision.rule_id is None
    unscoped = [e for e in audit.events if e.type == "policy.unscoped"]
    assert len(unscoped) == 1
    assert unscoped[0].payload["target"] == "c:/other/a.txt"


async def test_explicit_rule_match_is_not_unscoped() -> None:
    from secugent.audit.unscoped import UnscopedRecorder

    audit = _RecordingAudit()
    broker = EgressBroker(
        policy=_deny_secret_policy(),
        audit_store=audit,
        transport=_RecordingTransport(),
        unscoped_recorder=UnscopedRecorder(audit),
    )
    result = await broker.submit(_req(_SECRET_POLICY_WRITE))  # matches explicit deny "d"
    assert result.ok is False
    assert result.decision.rule_id == "d"
    assert [e for e in audit.events if e.type == "policy.unscoped"] == []


async def test_unscoped_recorder_absent_is_safe() -> None:
    audit = _RecordingAudit()
    broker = EgressBroker(
        policy=_deny_secret_policy(),
        audit_store=audit,
        transport=_RecordingTransport(),
    )  # no unscoped_recorder wired
    result = await broker.submit(_req(_UNSCOPED_WRITE))
    assert result.ok is False
    assert [e for e in audit.events if e.type == "policy.unscoped"] == []


async def test_unscoped_recorder_failure_is_nonfatal() -> None:
    from secugent.audit.unscoped import UnscopedRecorder

    # a degraded audit backend must NOT turn a default-deny into a raised exception
    broker = EgressBroker(
        policy=_deny_secret_policy(),
        audit_store=_RecordingAudit(),
        transport=_RecordingTransport(),
        unscoped_recorder=UnscopedRecorder(_FailingAudit()),  # record() will raise
    )
    result = await broker.submit(_req(_UNSCOPED_WRITE))  # default_deny path
    assert result.ok is False  # still a clean structured deny, not an exception
    assert result.decision.rule_id is None
