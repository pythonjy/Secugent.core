# SPDX-License-Identifier: Apache-2.0
"""Unit + integration tests for the embed SDK ``@require_oversight`` decorator.

These pin the BDP_02 item 4 IO contract (§4.5/§4.6/§4.7):

* a REGULATIONS-violating action wrapped by the decorator is HARD BLOCKed
  (``HardBlockException`` raised, not swallowed) and never executes;
* a compliant action passes and emits **exactly one** §C-2 audit event;
* a 3-axis (Rule of Two) step forces HITL via the injected gateway; an
  ``AutoRejectHitlGateway`` → blocked (``OversightBlocked``);
* a HITL timeout (gateway raises ``HitlTimeoutError``) → fail-closed block;
* sync AND async callables are both wrapped;
* nested wraps evaluate the gate exactly once (no double evaluation);
* the wrapped function's own exception is re-raised unchanged;
* the SDK verdict is identical to calling the core engine directly
  (determinism — the SDK adds no divergence).

The decorator MUST call the existing deterministic core (OversightEngine +
rule_of_two + the audit emitter) — it never re-implements control logic (I1).
"""

from __future__ import annotations

import asyncio
from typing import Any, NamedTuple

import pytest

from secugent.core.contracts import HardBlockException, Step
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations, load_regulations_from_dict
from secugent.core.rule_of_two import RuleOfTwoContext, classify_axes
from secugent.core.tenancy import TenantId
from secugent.sdk import OversightMiddleware, require_oversight, wrap_tool  # noqa: F401  (surface)
from secugent.sdk.gate import (
    AuditSink,
    OversightBlocked,
    OversightGate,
    build_step,
)

_TENANT = TenantId("sdk-tenant")
_RUN = "run_sdk_test0"


def _korean_regulations() -> Regulations:
    """A minimal Korean REGULATIONS doc with a HARD BLOCK banned path (§C-3)."""
    doc = {
        "version": "sdk-1.0.0",
        "banned_paths": [
            {
                "rule_id": "대외비-디렉터리-차단",
                "pattern": "*/대외비/*",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "대외비 디렉터리 접근은 결정적으로 차단된다.",
            }
        ],
    }
    return load_regulations_from_dict(doc, source="<sdk-test>")


def _engine() -> OversightEngine:
    return OversightEngine(_korean_regulations())


def _gate(sink: AuditSink) -> OversightGate:
    return OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
    )


class _RecordingSink:
    """Captures emitted §C-2 audit events for assertions."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: dict[str, object]) -> None:
        self.events.append(event)


# --------------------------------------------------------------------------- #
# HARD BLOCK
# --------------------------------------------------------------------------- #


def test_violating_sync_action_is_hard_blocked_and_not_executed() -> None:
    sink = _RecordingSink()
    executed: list[str] = []

    @require_oversight(action_type="file_write", gate=_gate(sink))
    def write_secret(target: str) -> str:
        executed.append(target)
        return "wrote"

    with pytest.raises(HardBlockException):
        write_secret("/srv/대외비/payroll.xlsx")

    assert executed == [], "the wrapped function must never run on a HARD BLOCK"


def test_violation_emits_a_reject_audit_event() -> None:
    sink = _RecordingSink()

    @require_oversight(action_type="file_write", gate=_gate(sink))
    def write_secret(target: str) -> str:
        return "wrote"

    with pytest.raises(HardBlockException):
        write_secret("/srv/대외비/payroll.xlsx")

    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "reject"
    assert sink.events[0]["gate"] == "plan_review"


# --------------------------------------------------------------------------- #
# Compliant pass + exactly one audit event (I2)
# --------------------------------------------------------------------------- #


def test_compliant_action_passes_and_emits_exactly_one_event() -> None:
    sink = _RecordingSink()

    @require_oversight(action_type="file_read", gate=_gate(sink))
    def read_public(target: str) -> str:
        return f"read {target}"

    out = read_public("/srv/공개/notice.txt")

    assert out == "read /srv/공개/notice.txt"
    assert len(sink.events) == 1, "I2: exactly one §C-2 audit event per passed action"
    event = sink.events[0]
    assert event["decision"] == "approve"
    # §C-2 schema fields present.
    for field in (
        "event_id",
        "timestamp",
        "gate",
        "decision",
        "rationale",
        "rule_of_two_axes",
        "prev_event_id",
    ):
        assert field in event, f"missing §C-2 field: {field}"


# --------------------------------------------------------------------------- #
# Rule of Two → forced HITL
# --------------------------------------------------------------------------- #


class _ThreeAxisKwargs(NamedTuple):
    """Typed bundle for a 3-axis step's decorator kwargs.

    Returning a typed structure (not a ``dict[str, object]``) lets ``target`` /
    ``context`` flow into ``require_oversight`` without an ``arg-type`` ignore.
    """

    target: str
    context: dict[str, Any]


def _three_axis_kwargs() -> _ThreeAxisKwargs:
    """A connector_action (axes ②③) + declared untrusted input (axis ①) = HITL."""
    return _ThreeAxisKwargs(
        target="crm.export",
        context={"rule_of_two": {"untrusted_input": True}},
    )


def test_three_axis_step_invokes_hitl_gateway_and_autoreject_blocks() -> None:
    from secugent.agents.sub_agent import AutoRejectHitlGateway

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
        hitl=AutoRejectHitlGateway(),
    )
    kw = _three_axis_kwargs()

    @require_oversight(
        action_type="connector_action",
        target=kw.target,
        context=kw.context,
        gate=gate,
    )
    def export_crm() -> str:
        return "exported"

    with pytest.raises(OversightBlocked):
        export_crm()


def test_three_axis_step_without_gateway_is_fail_closed() -> None:
    """Deny-by-default: a 3-axis step with NO HITL gateway configured blocks."""
    sink = _RecordingSink()
    kw = _three_axis_kwargs()
    gate = OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
        hitl=None,  # no gateway
    )

    @require_oversight(
        action_type="connector_action",
        target=kw.target,
        context=kw.context,
        gate=gate,
    )
    def export_crm() -> str:
        return "exported"

    with pytest.raises(OversightBlocked):
        export_crm()
    assert sink.events[-1]["decision"] == "reject"


def test_three_axis_step_with_approving_gateway_passes() -> None:
    """A 3-axis step with an auto-approve gateway passes and emits an approve."""
    from secugent.agents.sub_agent import AutoApproveHitlGateway

    sink = _RecordingSink()
    kw = _three_axis_kwargs()
    gate = OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
        hitl=AutoApproveHitlGateway(),
    )
    executed: list[str] = []

    @require_oversight(
        action_type="connector_action",
        target=kw.target,
        context=kw.context,
        gate=gate,
    )
    def export_crm() -> str:
        executed.append("ran")
        return "exported"

    assert export_crm() == "exported"
    assert executed == ["ran"]
    # Exactly one approve event, recorded at the HITL gate.
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"
    assert sink.events[0]["gate"] == "hitl"


def test_hitl_modify_decision_is_fail_closed() -> None:
    """A non-approve (modify) HITL outcome blocks (only approve passes)."""
    from secugent.agents.sub_agent import HitlDecision

    from secugent.core.contracts import Approval
    from secugent.core.risk_analyzer import RiskAssessment

    class _ModifyGateway:
        def request_decision(self, *, approval: Approval, step: Step, risk: RiskAssessment) -> HitlDecision:
            return HitlDecision(action="modify", reason="needs change")

    sink = _RecordingSink()
    kw = _three_axis_kwargs()
    gate = OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
        hitl=_ModifyGateway(),
    )

    @require_oversight(
        action_type="connector_action",
        target=kw.target,
        context=kw.context,
        gate=gate,
    )
    def export_crm() -> str:
        return "exported"

    with pytest.raises(OversightBlocked):
        export_crm()


def test_decorator_with_no_positional_args_uses_none_target() -> None:
    """The default target extractor yields None when there is no positional arg
    (action-type Rule-of-Two axes still apply; a path rule simply does not fire)."""
    sink = _RecordingSink()

    @require_oversight(action_type="compute", gate=_gate(sink))
    def pure_compute() -> str:
        return "computed"

    assert pure_compute() == "computed"
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


def test_hitl_timeout_is_fail_closed() -> None:
    from secugent.agents.sub_agent import HitlDecision, HitlTimeoutError

    from secugent.core.contracts import Approval
    from secugent.core.risk_analyzer import RiskAssessment

    class _TimeoutGateway:
        def request_decision(self, *, approval: Approval, step: Step, risk: RiskAssessment) -> HitlDecision:
            raise HitlTimeoutError("no human responded")

    sink = _RecordingSink()
    kw = _three_axis_kwargs()
    gate = OversightGate(
        oversight=_engine(),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
        hitl=_TimeoutGateway(),
    )

    @require_oversight(
        action_type="connector_action",
        target=kw.target,
        context=kw.context,
        gate=gate,
    )
    def export_crm() -> str:
        return "exported"

    with pytest.raises(OversightBlocked):
        export_crm()


# --------------------------------------------------------------------------- #
# async wrapping
# --------------------------------------------------------------------------- #


async def test_async_compliant_action_passes() -> None:
    sink = _RecordingSink()

    @require_oversight(action_type="file_read", gate=_gate(sink))
    async def read_async(target: str) -> str:
        await asyncio.sleep(0)
        return f"async {target}"

    out = await read_async("/srv/공개/x.txt")
    assert out == "async /srv/공개/x.txt"
    assert len(sink.events) == 1


async def test_async_violation_is_hard_blocked() -> None:
    sink = _RecordingSink()
    executed: list[str] = []

    @require_oversight(action_type="file_write", gate=_gate(sink))
    async def write_async(target: str) -> str:
        executed.append(target)
        return "wrote"

    with pytest.raises(HardBlockException):
        await write_async("/srv/대외비/x.xlsx")
    assert executed == []


# --------------------------------------------------------------------------- #
# nested wrap → single evaluation
# --------------------------------------------------------------------------- #


def test_nested_wrap_evaluates_gate_once() -> None:
    sink = _RecordingSink()
    gate = _gate(sink)

    @require_oversight(action_type="file_read", gate=gate)
    def inner(target: str) -> str:
        return f"inner {target}"

    @require_oversight(action_type="file_read", gate=gate)
    def outer(target: str) -> str:
        return inner(target)

    out = outer("/srv/공개/notice.txt")
    assert out == "inner /srv/공개/notice.txt"
    # Only the outermost wrap evaluates the gate (no double evaluation).
    assert len(sink.events) == 1, "nested wraps must evaluate the gate exactly once"


# --------------------------------------------------------------------------- #
# wrapped exception re-raised unchanged
# --------------------------------------------------------------------------- #


def test_wrapped_function_exception_is_reraised_unchanged() -> None:
    sink = _RecordingSink()

    class _Boom(RuntimeError):
        pass

    @require_oversight(action_type="file_read", gate=_gate(sink))
    def boom(target: str) -> str:
        raise _Boom("downstream failure")

    with pytest.raises(_Boom, match="downstream failure"):
        boom("/srv/공개/ok.txt")
    # The gate still ran and approved before the wrapped fn raised.
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


async def test_wrapped_async_function_exception_is_reraised_unchanged() -> None:
    sink = _RecordingSink()

    class _Boom(RuntimeError):
        pass

    @require_oversight(action_type="file_read", gate=_gate(sink))
    async def boom(target: str) -> str:
        raise _Boom("async downstream failure")

    with pytest.raises(_Boom, match="async downstream failure"):
        await boom("/srv/공개/ok.txt")


# --------------------------------------------------------------------------- #
# determinism: SDK verdict == core engine verdict
# --------------------------------------------------------------------------- #


def test_sdk_verdict_matches_core_engine_directly() -> None:
    sink = _RecordingSink()
    engine = _engine()
    step = build_step(
        action_type="file_write",
        target="/srv/대외비/payroll.xlsx",
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
    )
    # Core verdict computed directly.
    core_result = engine.evaluate(step)
    assert core_result.hard_block is True

    # SDK gate over the same step yields the same hard-block verdict.
    gate = OversightGate(
        oversight=engine,
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:embedded",
        audit=sink,
    )
    with pytest.raises(HardBlockException):
        gate.enforce(step)

    # And the axes match the core classifier exactly (no divergence).
    sdk_axes = sorted(a.value for a in classify_axes(step, RuleOfTwoContext.from_step(step)))
    assert sink.events[0]["rule_of_two_axes"] == sdk_axes


def test_build_step_defaults_are_deterministic() -> None:
    a = build_step(
        action_type="file_read",
        target="/x",
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:e",
    )
    b = build_step(
        action_type="file_read",
        target="/x",
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="sub:e",
    )
    assert isinstance(a, Step)
    # Deterministic step id derived from inputs (not a random uuid) so the SDK is
    # reproducible across calls.
    assert a.id == b.id
