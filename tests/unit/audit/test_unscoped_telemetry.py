# SPDX-License-Identifier: Apache-2.0
"""EM-04 — unscoped-effect telemetry recording + clustering."""

from __future__ import annotations

from secugent.audit.unscoped import UnscopedRecorder, cluster_unscoped
from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.tenancy import TenantId

_T = TenantId("acme")


class _Audit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _eff(target: str) -> Effect:
    return Effect(kind=EffectKind.FILE_WRITE, target=target, sink_class=SinkClass.LOCAL_SANDBOX)


def test_record_emits_policy_unscoped_event() -> None:
    audit = _Audit()
    UnscopedRecorder(audit).record(tenant_id=_T, effect=_eff("c:/x/a.txt"), run_id="r1")
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.type == "policy.unscoped"
    assert event.tenant_id == _T
    assert event.payload["target"] == "c:/x/a.txt"


def test_cluster_groups_same_fingerprint() -> None:
    audit = _Audit()
    rec = UnscopedRecorder(audit)
    rec.record(tenant_id=_T, effect=_eff("c:/x/a.txt"), run_id="r1")
    rec.record(tenant_id=_T, effect=_eff("c:/x/a.txt"), run_id="r2")  # same fingerprint
    rec.record(tenant_id=_T, effect=_eff("c:/y/b.txt"), run_id="r3")  # different
    clusters = cluster_unscoped(audit.events)
    assert len(clusters) == 2
    assert clusters[0].count == 2  # sorted by -count: the repeated one first
    assert clusters[1].count == 1


def test_cluster_ignores_non_unscoped_events() -> None:
    other = Event(tenant_id=_T, actor="x", type="egress.denied", payload={})
    assert cluster_unscoped([other]) == []
