# SPDX-License-Identifier: Apache-2.0
"""S3 / G-H15 — EnvelopeReviewGate wired into the broker.

Tests that:
  1. A "suspend" envelope verdict calls EnvelopeReviewGate.on_suspend().
  2. A §C-2 HITL pending audit event is emitted into the hash chain.
  3. on_approve() / on_reject() transitions are correctly tracked.
  4. Broker with no review_gate still denies (backward-compat).
  5. Property: any suspend verdict always produces a SUSPENDED state.

Korean fixture: 한국 금융기관 CONFIDENTIAL 문서 외부 전송 시 envelope 초과 → HITL.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker import (
    EgressBroker,
    EgressRequest,
    ExecutionProfile,
)
from secugent.orchestrator.envelope_gate import EnvelopeReviewGate, ReviewState

_TENANT = TenantId("shinhan-bank")
_PRINCIPAL = Principal(user_id="컴플라이언스-담당자", tenant_id=_TENANT, role="operator")
_NOW = datetime(2026, 6, 24, 9, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[EgressRequest] = []

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        self.calls.append(request)
        return b"transmitted"


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


_ALLOW_ALL = compile_policy(
    PolicyDoc(
        version="1",
        tenant_id="_base",
        rules=[Rule(id="a", effect="allow", match=Match(), rationale="allow all")],
    )
)


class _SuspendGate:
    """Stub envelope gate: always suspends."""

    def check(self, request: EgressRequest) -> SimpleNamespace:
        return SimpleNamespace(outcome="suspend", reason="envelope_test_suspend")


class _AllowGate:
    """Stub envelope gate: always allows."""

    def check(self, request: EgressRequest) -> SimpleNamespace:
        return SimpleNamespace(outcome="allow", reason="")


def _fss_req() -> EgressRequest:
    """한국 금융감독원 보고서 전송 요청 (외부 대상)."""
    return EgressRequest(
        effect=Effect(
            kind=EffectKind.NET_SEND,
            target="https://fss.or.kr/regulatory-report",
            sink_class=SinkClass.EXTERNAL,
        ),
        label=DataLabel.CONFIDENTIAL,
        principal=_PRINCIPAL,
        run_id="run-신한-보고서",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content=b"\xea\xb8\x88\xec\x9c\xb5\xea\xb0\x90\xeb\x8f\x85\xec\x9b\x90",  # "금융감독원"
    )


def _broker(
    *,
    gate: Any = None,
    review_gate: EnvelopeReviewGate | None = None,
    review_gate_factory: Any = None,
    transport: _RecordingTransport | None = None,
    audit: _RecordingAudit | None = None,
) -> EgressBroker:
    from secugent.core.sec.labels import DataLabel

    t = transport or _RecordingTransport()
    a = audit or _RecordingAudit()
    return EgressBroker(
        policy=_ALLOW_ALL,
        audit_store=a,
        transport=t,
        envelope_gate=gate,
        review_gate=review_gate,
        review_gate_factory=review_gate_factory,
        # Allow CONFIDENTIAL through the label gate so the envelope gate is the
        # deciding factor in these tests (not the label gate).
        max_external=DataLabel.CONFIDENTIAL,
    )


def _fss_req_run(run_id: str, tenant: TenantId = _TENANT) -> EgressRequest:
    """A suspend-triggering request with an explicit (tenant, run) identity."""
    return EgressRequest(
        effect=Effect(
            kind=EffectKind.NET_SEND,
            target="https://fss.or.kr/regulatory-report",
            sink_class=SinkClass.EXTERNAL,
        ),
        label=DataLabel.CONFIDENTIAL,
        principal=Principal(user_id="op", tenant_id=tenant, role="operator"),
        run_id=run_id,
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content=b"report",
    )


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def test_suspend_without_review_gate_is_deny() -> None:
    """Backward-compat: no review_gate → suspend is a plain deny (no HITL event)."""
    transport = _RecordingTransport()
    audit = _RecordingAudit()
    b = _broker(gate=_SuspendGate(), review_gate=None, transport=transport, audit=audit)
    req = _fss_req()
    result = b._submit(req)
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == []


def test_suspend_with_review_gate_transitions_to_suspended() -> None:
    """G-H15: suspend verdict calls on_suspend → gate transitions to SUSPENDED."""
    review_gate = EnvelopeReviewGate()
    transport = _RecordingTransport()
    audit = _RecordingAudit()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate, transport=transport, audit=audit)
    req = _fss_req()
    result = b._submit(req)
    # Effect is still denied (HITL pending, not approved yet).
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    # Transport was NOT called.
    assert transport.calls == []
    # EnvelopeReviewGate is now SUSPENDED.
    assert review_gate.state is ReviewState.SUSPENDED
    assert review_gate.pending is not None
    assert review_gate.pending.reason == "envelope_test_suspend"


def test_suspend_emits_hitl_pending_audit_event() -> None:
    """G-H15 §C-2: suspend emits a gate=hitl audit event into the hash chain."""
    review_gate = EnvelopeReviewGate()
    audit = _RecordingAudit()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate, audit=audit)
    req = _fss_req()
    b._submit(req)
    # Find the HITL pending event.
    hitl_events = [e for e in audit.events if e.type == "hitl.pending"]
    assert len(hitl_events) >= 1
    ev = hitl_events[0]
    assert ev.payload["gate"] == "hitl"
    assert ev.payload["decision"] == "pending"
    assert "envelope_suspend" in ev.payload["rationale"]


def test_allow_gate_does_not_trigger_review_gate() -> None:
    """An allow verdict must NOT touch the EnvelopeReviewGate."""
    review_gate = EnvelopeReviewGate()
    transport = _RecordingTransport()
    b = _broker(gate=_AllowGate(), review_gate=review_gate, transport=transport)
    req = _fss_req()
    result = b._submit(req)
    assert result.ok is True
    assert review_gate.state is ReviewState.RUNNING
    assert review_gate.pending is None
    assert len(transport.calls) == 1


def test_review_gate_on_approve_resumes() -> None:
    """on_approve() after on_suspend() transitions back to RUNNING."""
    review_gate = EnvelopeReviewGate()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate)
    req = _fss_req()
    b._submit(req)
    assert review_gate.state is ReviewState.SUSPENDED
    # Human approves.
    suspended = review_gate.on_approve()
    assert review_gate.state is ReviewState.RUNNING
    assert review_gate.pending is None
    assert suspended.reason == "envelope_test_suspend"


def test_review_gate_on_reject_aborts() -> None:
    """on_reject() after on_suspend() transitions to ABORTED."""
    review_gate = EnvelopeReviewGate()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate)
    req = _fss_req()
    b._submit(req)
    assert review_gate.state is ReviewState.SUSPENDED
    # Human rejects.
    rejected = review_gate.on_reject(reason="compliance_denial")
    assert review_gate.state is ReviewState.ABORTED
    assert review_gate.pending is None
    assert rejected.reason == "envelope_test_suspend"


def test_review_gate_history_records_approve_and_reject() -> None:
    """History captures each decision with its effect."""
    review_gate = EnvelopeReviewGate()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate)
    # First effect: suspend → approve.
    b._submit(_fss_req())
    review_gate.on_approve()
    # Gate is RUNNING again; submit another effect to trigger another suspend.
    b._submit(_fss_req())
    review_gate.on_reject(reason="policy_change")
    # Two historical decisions.
    assert len(review_gate.history) == 2
    assert review_gate.history[0][0] == "approve"
    assert review_gate.history[1][0] == "reject"


# ---------------------------------------------------------------------------
# SG-20260624-01 (round 2) — per-(tenant, run) gate registry
# ---------------------------------------------------------------------------


def test_factory_mints_distinct_gate_per_tenant_run() -> None:
    """review_gate_factory → a suspend in two distinct (tenant, run) keys mints
    two distinct gates (no cross-tenant / cross-run contamination)."""
    b = _broker(gate=_SuspendGate(), review_gate_factory=EnvelopeReviewGate)
    b._submit(_fss_req_run("run-A", TenantId("tenant-a")))
    b._submit(_fss_req_run("run-B", TenantId("tenant-b")))
    gate_a = b.resolve_review_gate(TenantId("tenant-a"), "run-A")
    gate_b = b.resolve_review_gate(TenantId("tenant-b"), "run-B")
    assert gate_a is not None and gate_b is not None
    assert gate_a is not gate_b
    assert gate_a.state is ReviewState.SUSPENDED
    assert gate_b.state is ReviewState.SUSPENDED


def test_resolve_review_gate_returns_none_before_suspend() -> None:
    """resolve_review_gate is read-only: no gate exists until a suspend mints one."""
    b = _broker(gate=_SuspendGate(), review_gate_factory=EnvelopeReviewGate)
    assert b.resolve_review_gate(_TENANT, "never-suspended") is None


def test_no_factory_no_seed_returns_none() -> None:
    """Neither factory nor seed wired → suspend is a plain deny, no gate minted."""
    transport = _RecordingTransport()
    b = _broker(gate=_SuspendGate(), transport=transport)
    result = b._submit(_fss_req_run("run-A"))
    assert result.ok is False
    assert b.resolve_review_gate(_TENANT, "run-A") is None
    assert transport.calls == []


def test_seed_reused_for_first_key_then_collision_returns_none() -> None:
    """Seed-only broker: the single seed is registered under the FIRST (tenant,
    run) that suspends; a SECOND distinct key gets no isolated gate (returns
    None) rather than silently sharing the seed across runs (broker.py:481)."""
    seed = EnvelopeReviewGate()
    b = _broker(gate=_SuspendGate(), review_gate=seed)
    # First key claims the seed.
    b._submit(_fss_req_run("run-A", TenantId("tenant-a")))
    assert b.resolve_review_gate(TenantId("tenant-a"), "run-A") is seed
    # A second distinct key cannot reuse the already-claimed seed → no gate,
    # so on_suspend is never driven for it (the seed is single-run by contract).
    b._submit(_fss_req_run("run-B", TenantId("tenant-b")))
    assert b.resolve_review_gate(TenantId("tenant-b"), "run-B") is None


def test_same_key_suspend_reuses_cached_gate() -> None:
    """Two suspends on the SAME (tenant, run) resolve to the SAME cached gate."""
    b = _broker(gate=_SuspendGate(), review_gate_factory=EnvelopeReviewGate)
    b._submit(_fss_req_run("run-A", TenantId("tenant-a")))
    gate_first = b.resolve_review_gate(TenantId("tenant-a"), "run-A")
    assert gate_first is not None
    # Resolve again (approve to clear pending, then the registry still holds it).
    gate_first.on_approve()
    b._submit(_fss_req_run("run-A", TenantId("tenant-a")))
    gate_second = b.resolve_review_gate(TenantId("tenant-a"), "run-A")
    assert gate_second is gate_first


def test_no_envelope_gate_no_review_gate_passthrough() -> None:
    """No envelope gate → effect executes directly (policy/label permitting)."""
    transport = _RecordingTransport()
    b = _broker(gate=None, review_gate=None, transport=transport)
    req = _fss_req()
    result = b._submit(req)
    assert result.ok is True
    assert len(transport.calls) == 1


# ---------------------------------------------------------------------------
# SG-20260624-03 — G-H15 error-branch coverage (broker ~307-308, ~333-334)
# ---------------------------------------------------------------------------


class _RaisingReviewGate(EnvelopeReviewGate):
    """on_suspend always raises (gate state error) → must fail-closed (deny)."""

    def on_suspend(self, *, reason: str, effect_fingerprint: str, action: str) -> Any:
        raise RuntimeError("gate state corrupted")


class _RaisingAudit:
    """append_event always raises → HITL-pending append fails → fail-closed."""

    def append_event(self, event: Event) -> Event:
        raise RuntimeError("audit chain unavailable")


def test_on_suspend_failure_denies_and_skips_transport() -> None:
    """broker ~307-308: on_suspend() raising must NOT execute the transport.

    A corrupted review-gate state is fail-closed — the effect is still denied
    (suspend rationale) and the transport is never called.
    """
    transport = _RecordingTransport()
    audit = _RecordingAudit()
    review_gate = _RaisingReviewGate()
    b = _broker(gate=_SuspendGate(), review_gate=review_gate, transport=transport, audit=audit)
    result = b._submit(_fss_req())
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == [], "on_suspend failure must not reach the transport"


def test_hitl_audit_append_failure_denies_and_skips_transport() -> None:
    """broker ~333-334: a failing HITL-pending audit append must fail-closed.

    The hash-chain append for the HITL-pending event raises; the effect must
    remain denied and the transport must never be called (append-before-act).
    """
    transport = _RecordingTransport()
    review_gate = EnvelopeReviewGate()
    b = _broker(
        gate=_SuspendGate(),
        review_gate=review_gate,
        transport=transport,
        audit=_RaisingAudit(),  # type: ignore[arg-type]
    )
    result = b._submit(_fss_req())
    assert result.ok is False
    assert "envelope_suspend" in result.decision.rationale
    assert transport.calls == [], "HITL audit append failure must not reach the transport"
    # on_suspend still transitioned the gate before the audit append failed.
    assert review_gate.state is ReviewState.SUSPENDED


# ---------------------------------------------------------------------------
# Property-based tests
# ---------------------------------------------------------------------------


@given(st.booleans())
@settings(max_examples=200)
def test_property_suspend_always_leaves_not_ok(has_review_gate: bool) -> None:
    """suspend verdict always → ok=False regardless of whether review_gate is wired."""
    review_gate = EnvelopeReviewGate() if has_review_gate else None
    b = _broker(gate=_SuspendGate(), review_gate=review_gate)
    result = b._submit(_fss_req())
    assert result.ok is False


@given(st.booleans())
@settings(max_examples=200)
def test_property_suspend_never_calls_transport(has_review_gate: bool) -> None:
    """suspend verdict → transport is NEVER called."""
    transport = _RecordingTransport()
    review_gate = EnvelopeReviewGate() if has_review_gate else None
    b = _broker(gate=_SuspendGate(), review_gate=review_gate, transport=transport)
    b._submit(_fss_req())
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Determinism: 100-run invariant (§B-4a)
# ---------------------------------------------------------------------------


def test_determinism_100_runs_suspend_outcome() -> None:
    """Same input → same rationale/result for 100 consecutive runs."""
    results: list[str] = []
    for _ in range(100):
        review_gate = EnvelopeReviewGate()
        b = _broker(gate=_SuspendGate(), review_gate=review_gate)
        result = b._submit(_fss_req())
        results.append(result.decision.rationale)
    assert len(set(results)) == 1, "suspend outcome is not deterministic"


def test_determinism_100_runs_allow_outcome() -> None:
    """Same input → same success for 100 consecutive allow-gate runs."""
    results: list[bool] = []
    for _ in range(100):
        t = _RecordingTransport()
        b = _broker(gate=_AllowGate(), transport=t)
        result = b._submit(_fss_req())
        results.append(result.ok)
    assert all(r is True for r in results), "allow outcome is not deterministic"
