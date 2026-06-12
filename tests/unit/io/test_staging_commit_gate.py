# SPDX-License-Identifier: Apache-2.0
"""EM-09 — staging store + commit gate (hold window + budget/HITL)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker import EgressRequest, ExecutionProfile
from secugent.io.staging import CommitGate, CommitRefusedError, StagedEffectStore, StageState

_P = Principal(user_id="alice", tenant_id=TenantId("acme"), role="operator")
_IRR = ReversibilityClass.IRREVERSIBLE


def _now() -> datetime:
    return datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


class _Transport:
    def __init__(self) -> None:
        self.calls: list[Any] = []

    def execute(self, request: Any, *, http_transport: Any | None = None) -> bytes | None:
        self.calls.append(request)
        return b"sent"


def _req() -> EgressRequest:
    eff = Effect(
        kind=EffectKind.CONNECTOR_ACTION, target="inbox", sink_class=SinkClass.EXTERNAL, action="smtp.send"
    )
    return EgressRequest(
        effect=eff,
        label=DataLabel.PUBLIC,
        principal=_P,
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )


def test_stage_holds_and_audits() -> None:
    store = StagedEffectStore()
    audit = _Audit()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=60, now=_now(), audit=audit)
    assert staged.state is StageState.STAGED
    assert store.list_staged("r1") == [staged]
    assert any(e.type == "egress.staged" for e in audit.events)


def test_commit_refused_without_budget_or_hitl() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    with pytest.raises(CommitRefusedError):
        store.commit(staged.id, principal=_P, gate=CommitGate(), now=_now(), transport=transport)
    assert transport.calls == []


def test_commit_refused_before_hold_window() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=300, now=_now())
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id, principal=_P, gate=CommitGate(hitl_approved=True), now=_now(), transport=transport
        )
    assert transport.calls == []


def test_commit_with_hitl_after_hold_executes() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    audit = _Audit()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    after = _now() + timedelta(seconds=1)
    result = store.commit(
        staged.id,
        principal=_P,
        gate=CommitGate(hitl_approved=True),
        now=after,
        transport=transport,
        audit=audit,
    )
    assert result.ok is True
    assert len(transport.calls) == 1
    assert store.get(staged.id).state is StageState.COMMITTED  # type: ignore[union-attr]
    assert any(e.type == "egress.committed" for e in audit.events)


def test_commit_with_envelope_budget_executes() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    after = _now() + timedelta(seconds=1)
    result = store.commit(
        staged.id,
        principal=_P,
        gate=CommitGate(envelope_budget_remaining=True),
        now=after,
        transport=transport,
    )
    assert result.ok is True
    assert len(transport.calls) == 1


def test_negative_hold_sec_rejected() -> None:
    with pytest.raises(ValueError):
        StagedEffectStore().stage(_req(), reversibility=_IRR, hold_sec=-1, now=_now())


def test_abort_without_audit_sink() -> None:
    store = StagedEffectStore()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    store.abort(staged.id, principal=_P, reason="manual", audit=None)
    assert store.get(staged.id).state is StageState.ABORTED  # type: ignore[union-attr]


def test_abort_unknown_id_refused() -> None:
    with pytest.raises(CommitRefusedError):
        StagedEffectStore().abort("nope", principal=_P, reason="x")


def test_double_commit_refused() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    after = _now() + timedelta(seconds=1)
    store.commit(staged.id, principal=_P, gate=CommitGate(hitl_approved=True), now=after, transport=transport)
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id, principal=_P, gate=CommitGate(hitl_approved=True), now=after, transport=transport
        )


def test_commit_after_abort_refused() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())
    store.abort(staged.id, principal=_P, reason="recalled")
    after = _now() + timedelta(seconds=1)
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id, principal=_P, gate=CommitGate(hitl_approved=True), now=after, transport=transport
        )
    assert transport.calls == []


# --------------------------------------------------------------------------- #
# cross-tenant staging isolation (confused-deputy defense)
# --------------------------------------------------------------------------- #

_OTHER = Principal(user_id="mallory", tenant_id=TenantId("other-tenant"), role="operator")


def test_cross_tenant_commit_denied() -> None:
    store = StagedEffectStore()
    transport = _Transport()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())  # tenant 'acme'
    after = _now() + timedelta(seconds=1)
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id, principal=_OTHER, gate=CommitGate(hitl_approved=True), now=after, transport=transport
        )
    assert transport.calls == []
    assert store.get(staged.id).state is StageState.STAGED  # type: ignore[union-attr]


def test_cross_tenant_abort_denied() -> None:
    store = StagedEffectStore()
    staged = store.stage(_req(), reversibility=_IRR, hold_sec=0, now=_now())  # tenant 'acme'
    with pytest.raises(CommitRefusedError):
        store.abort(staged.id, principal=_OTHER, reason="malicious recall")
    assert store.get(staged.id).state is StageState.STAGED  # type: ignore[union-attr]
