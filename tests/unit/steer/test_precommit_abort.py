# SPDX-License-Identifier: Apache-2.0
"""EM-09 — STEER aborts staged irreversible effects before commit."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker import EgressRequest, ExecutionProfile
from secugent.io.staging import StagedEffectStore, StageState
from secugent.steer.precommit import classify_intervention, intervene

_P = Principal(user_id="alice", tenant_id=TenantId("acme"), role="operator")


def _now() -> datetime:
    return datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _stage(store: StagedEffectStore, audit: Any) -> Any:
    eff = Effect(
        kind=EffectKind.CONNECTOR_ACTION, target="inbox", sink_class=SinkClass.EXTERNAL, action="smtp.send"
    )
    req = EgressRequest(
        effect=eff,
        label=DataLabel.PUBLIC,
        principal=_P,
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )
    return store.stage(
        req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=300, now=_now(), audit=audit
    )


def test_classify_abort_keywords() -> None:
    assert classify_intervention("이메일 회수해줘") == "abort"
    assert classify_intervention("recall that message") == "abort"
    assert classify_intervention("계속 진행") == "resume"


def test_intervene_abort_recalls_staged() -> None:
    store = StagedEffectStore()
    audit = _Audit()
    staged = _stage(store, audit)
    aborted = intervene("r1", "이메일 발송 회수", principal=_P, store=store, audit=audit)
    assert staged.id in aborted
    assert store.get(staged.id).state is StageState.ABORTED  # type: ignore[union-attr]
    assert store.list_staged("r1") == []  # nothing left staged
    assert any(e.type == "precommit.aborted" for e in audit.events)
    assert any(e.type == "egress.aborted" for e in audit.events)


def test_intervene_skips_other_tenant_staged() -> None:
    # Two effects share run_id "r1" but belong to different tenants; an abort by
    # 'acme' must recall only acme's effect, never the other tenant's.
    store = StagedEffectStore()
    audit = _Audit()
    mine = _stage(store, audit)
    other_principal = Principal(user_id="mallory", tenant_id=TenantId("other-tenant"), role="operator")
    other_eff = Effect(
        kind=EffectKind.CONNECTOR_ACTION, target="inbox", sink_class=SinkClass.EXTERNAL, action="smtp.send"
    )
    other_req = EgressRequest(
        effect=other_eff,
        label=DataLabel.PUBLIC,
        principal=other_principal,
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
    )
    theirs = store.stage(other_req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=300, now=_now())

    aborted = intervene("r1", "회수", principal=_P, store=store, audit=audit)
    assert aborted == [mine.id]  # only my tenant's effect recalled
    assert store.get(theirs.id).state is StageState.STAGED  # type: ignore[union-attr]


def test_intervene_resume_aborts_nothing() -> None:
    store = StagedEffectStore()
    audit = _Audit()
    staged = _stage(store, audit)
    aborted = intervene("r1", "그대로 진행", principal=_P, store=store, audit=audit)
    assert aborted == []
    assert store.get(staged.id).state is StageState.STAGED  # type: ignore[union-attr]
