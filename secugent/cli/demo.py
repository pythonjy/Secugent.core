# SPDX-License-Identifier: Apache-2.0
"""Key-less, air-gap-first ``secugent demo`` (BDP Phase 1 item 3).

Runs one self-contained round of the SecuGent trust loop with **no API key and
no network** (§A-2.6 폐쇄망 우선):

    1. REGULATIONS HARD BLOCK — a Korean banned-path policy deterministically
       blocks a forbidden ``file_write`` via :class:`OversightEngine` (the same
       deterministic core the product enforces). Recorded as a ``reject`` at the
       ``plan_review`` gate.
    2. HITL approval — a fresh, step-scoped approval is requested, granted by a
       (mock) human, and consumed before the step executes via
       :class:`ApprovalService` (single-use nonce, re-verified at execute time).
       Recorded as an ``approve`` at the ``hitl`` gate.
    3. Audit record — every decision gate is appended to an append-only,
       hash-chained store (:class:`ChainedEventStore`) and surfaced as a
       :class:`DemoAuditEvent` conforming to the §C-2 schema (``event_id`` /
       ``prev_event_id`` chain, ``rule_of_two_axes``, ``decision`` …).

The demo is **deterministic**: a fixed seed (monotonic event counter + a fixed
KST timestamp) makes ``run_demo()`` produce byte-identical output across runs so
it doubles as a reproducibility proof. It uses :class:`MockLLMClient` and a
throw-away temp :class:`EventStore`, so it needs no credentials and writes
nothing under the project tree (Docker-non-root safe).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secugent.audit.hash_chain import ChainedEventStore
from secugent.core.approval import ApprovalService
from secugent.core.contracts import (
    Approval,
    ApprovalScope,
    Event,
    Step,
)
from secugent.core.event_store import EventStore
from secugent.core.llm_client import MockLLMClient
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations, load_regulations_from_dict
from secugent.core.rule_of_two import (
    RuleOfTwoContext,
    axes_to_audit,
    classify_axes,
    requires_hitl,
)
from secugent.core.tenancy import TenantId

__all__ = [
    "C2_REQUIRED_FIELDS",
    "DemoAuditEvent",
    "DemoResult",
    "build_demo_regulations",
    "run_demo",
]

# The §C-2 decision-gate log schema field set. Kept here so the demo's audit
# view stays in lock-step with CLAUDE.md §C-2 (a test asserts every field).
C2_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {
        "event_id",
        "timestamp",
        "actor",
        "gate",
        "input_hash",
        "decision",
        "rationale",
        "regulations_version",
        "context_snapshot_ref",
        "risk_score",
        "rule_of_two_axes",
        "prev_event_id",
    }
)

# Fixed demo seed: a single tenant, a fixed KST instant, and a fixed run id so
# the whole round is reproducible regardless of wall-clock / environment.
_DEMO_TENANT = TenantId("demo-tenant")
_DEMO_RUN_ID = "run_demo0000000"
_KST = timezone(timedelta(hours=9))
_FIXED_TS = datetime(2026, 6, 7, 9, 0, 0, tzinfo=_KST)
# Approval expiry is validated against the *real* wall clock at grant/consume
# time, so a fixed past instant would always read as expired. We therefore pin
# expiry to a fixed far-future instant: it keeps the demo reproducible (it is
# never surfaced in the demo output) while never tripping the TTL check.
_FIXED_EXPIRY = datetime(2099, 1, 1, 0, 0, 0, tzinfo=_KST)


@dataclass(frozen=True)
class DemoAuditEvent:
    """A §C-2-shaped decision-gate audit record (JSON-serialisable, frozen).

    Field-for-field a CLAUDE.md §C-2 log entry. ``prev_event_id`` links each
    event to its predecessor (the genesis event's is ``None``), forming the
    immutable chain that the durable :class:`ChainedEventStore` independently
    hashes — so the human-readable view and the cryptographic chain agree.
    """

    event_id: str
    timestamp: str
    actor: dict[str, str]
    gate: str
    input_hash: str
    decision: str
    rationale: str
    regulations_version: str
    context_snapshot_ref: str
    risk_score: int
    rule_of_two_axes: list[str]
    prev_event_id: str | None


@dataclass(frozen=True)
class DemoResult:
    """Outcome of one demo round."""

    blocked: list[str]
    approvals: list[str]
    audit_events: list[DemoAuditEvent]
    summary: str


def build_demo_regulations() -> Regulations:
    """A minimal Korean REGULATIONS doc with a HARD BLOCK banned path (C-3).

    The banned-path rule id/description are Korean so the demo doubles as a
    Korean-enterprise fixture (§C-3). Returned via the real loader so the demo
    exercises the same validation path the product uses.
    """
    doc = {
        "version": "demo-1.0.0",
        "banned_paths": [
            {
                "rule_id": "대외비-디렉터리-차단",
                "pattern": "*/대외비/*",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "대외비 디렉터리에 대한 쓰기·읽기는 결정적으로 차단된다.",
            }
        ],
        "banned_commands": [
            {
                "rule_id": "위험-명령-차단",
                "pattern": r"rm\s+-rf\s+/",
                "severity": "critical",
                "hard_block": True,
                "description": "루트 전체 삭제 명령은 차단된다.",
            }
        ],
    }
    return load_regulations_from_dict(doc, source="<secugent-demo>")


class _DeterministicAuditor:
    """Builds the §C-2 audit view + the durable hash chain in lock-step.

    Each :meth:`record` call appends a durable :class:`Event` to the
    append-only :class:`ChainedEventStore` (so ``verify_chain`` holds) AND emits
    a :class:`DemoAuditEvent`. Determinism is guaranteed by a monotonic counter
    (``evt-0``, ``evt-1`` …) and a fixed timestamp — nothing depends on the
    wall clock or randomness.
    """

    def __init__(self, store: ChainedEventStore, *, regulations_version: str) -> None:
        self._store = store
        self._regs_version = regulations_version
        self._counter = 0
        self._prev_event_id: str | None = None
        self.events: list[DemoAuditEvent] = []

    def record(
        self,
        *,
        gate: str,
        actor_type: str,
        actor_id: str,
        decision: str,
        rationale: str,
        step: Step,
        risk_score: int,
        rule_of_two_axes: list[str],
    ) -> DemoAuditEvent:
        event_id = f"evt-{self._counter}"
        self._counter += 1
        input_hash = hashlib.sha256(
            json.dumps(step.model_dump(mode="json"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        context_snapshot_ref = f"snapshot://{_DEMO_RUN_ID}/{event_id}"

        audit = DemoAuditEvent(
            event_id=event_id,
            timestamp=_FIXED_TS.isoformat(),
            actor={"type": actor_type, "id": actor_id},
            gate=gate,
            input_hash=input_hash,
            decision=decision,
            rationale=rationale,
            regulations_version=self._regs_version,
            context_snapshot_ref=context_snapshot_ref,
            risk_score=risk_score,
            rule_of_two_axes=rule_of_two_axes,
            prev_event_id=self._prev_event_id,
        )

        # Persist the same decision to the append-only hash chain so the audit
        # log is independently verifiable (I2). The durable Event carries the
        # full §C-2 payload; the chain links them with sha256(prev || body).
        durable = Event(
            id=event_id,
            tenant_id=_DEMO_TENANT,
            ts=_FIXED_TS,
            actor=f"{actor_type}:{actor_id}",
            type=f"gate.{gate}.{decision}",
            payload={
                "gate": gate,
                "decision": decision,
                "rationale": rationale,
                "input_hash": input_hash,
                "regulations_version": self._regs_version,
                "context_snapshot_ref": context_snapshot_ref,
                "risk_score": risk_score,
                "rule_of_two_axes": rule_of_two_axes,
                "prev_event_id": self._prev_event_id,
            },
            severity="critical" if decision == "reject" else "info",
            run_id=_DEMO_RUN_ID,
            step_id=step.id,
        )
        self._store.append_event(durable)

        self._prev_event_id = event_id
        self.events.append(audit)
        return audit


def _blocked_step() -> Step:
    """A step that violates the Korean banned-path rule (deterministic id)."""
    return Step(
        id="step-blocked",
        tenant_id=_DEMO_TENANT,
        run_id=_DEMO_RUN_ID,
        actor="sub:researcher",
        action_type="file_write",
        target="/srv/대외비/payroll.xlsx",
    )


def _hitl_step() -> Step:
    """A step that trips all three Rule-of-Two axes ⇒ forced HITL.

    ``connector_action`` is axes ②+③; declaring untrusted input adds axis ①,
    so :func:`requires_hitl` is True and the approval must be step-dedicated.
    """
    return Step(
        id="step-hitl",
        tenant_id=_DEMO_TENANT,
        run_id=_DEMO_RUN_ID,
        actor="sub:operator",
        action_type="connector_action",
        target="crm.export",
        context={"rule_of_two": {"untrusted_input": True}},
    )


def _run_block_gate(engine: OversightEngine, auditor: _DeterministicAuditor, *, emit: bool) -> list[str]:
    """Evaluate the forbidden step; record a reject if HARD BLOCKed."""
    step = _blocked_step()
    result = engine.evaluate(step)
    blocked: list[str] = []
    if result.hard_block and result.violation is not None:
        blocked.append(result.violation.rule_id)
        if emit:
            axes = classify_axes(step, RuleOfTwoContext.from_step(step))
            auditor.record(
                gate="plan_review",
                actor_type="sec",
                actor_id="mechanical-oversight",
                decision="reject",
                rationale=(
                    f"REGULATIONS HARD BLOCK: {result.violation.message} "
                    "(위험점수와 무관하게 결정적으로 차단)"
                ),
                step=step,
                risk_score=0,
                rule_of_two_axes=axes_to_audit(axes),
            )
    return blocked


def _run_hitl_gate(
    service: ApprovalService,
    inner: EventStore,
    auditor: _DeterministicAuditor,
    *,
    emit: bool,
) -> list[str]:
    """Request → grant → consume a step-dedicated HITL approval; record approve."""
    step = _hitl_step()
    axes = classify_axes(step, RuleOfTwoContext.from_step(step))
    # Fail fast if the demo step is not actually a forced-HITL step (keeps the
    # demo honest — it must exercise the real Rule-of-Two boundary).
    if not requires_hitl(axes):
        raise RuntimeError("demo HITL step does not trip all three Rule of Two axes")

    scope = ApprovalScope(
        tenant_id=_DEMO_TENANT,
        run_id=_DEMO_RUN_ID,
        step_ids=[step.id],  # dedicated to this exact step (Rule of Two)
        allowed_action_types=[],
        max_risk=100,
        expires_at=_FIXED_EXPIRY,
    )
    # Construct the durable approval with a FIXED id + nonce and save it directly
    # so the demo output is reproducible (the real ``request_approval`` mints a
    # random uuid id and nonce). The security-meaningful grant→consume→verify
    # path (single-use, step-dedicated, Rule-of-Two re-check) still runs exactly
    # as in production via the service below.
    approval = Approval(
        id="apv_demo00000001",
        actor="human:demo-operator",
        scope=scope,
        expires_at=_FIXED_EXPIRY,
        nonce="demo-fixed-nonce-0001",
        status="pending",
        created_at=_FIXED_TS,
    )
    inner.save_approval(approval)
    service.grant(approval.id, reason="데모: 운영자 승인")
    consumed = service.consume(approval.id, step)

    approvals = [consumed.id]
    if emit:
        auditor.record(
            gate="hitl",
            actor_type="human",
            actor_id="demo-operator",
            decision="approve",
            rationale="HITL 승인: 3축(Rule of Two) 위반 단계에 대해 운영자가 단계 전용 승인을 발급함.",
            step=step,
            risk_score=42,
            rule_of_two_axes=axes_to_audit(axes),
        )
    return approvals


def _summarize(blocked: Iterable[str], approvals: Iterable[str], audit_n: int) -> str:
    blocked_list = list(blocked)
    approval_list = list(approvals)
    return (
        f"HARD BLOCK {len(blocked_list)}건(차단 규칙={blocked_list}) · "
        f"HITL 승인 {len(approval_list)}건 · 감사 이벤트 {audit_n}건 기록(append-only 해시체인)."
    )


def run_demo(*, steps: int = 3, emit_audit: bool = True) -> DemoResult:
    """Run one key-less demo round (HARD BLOCK → HITL approval → audit).

    ``steps`` is accepted for forward-compat / CLI symmetry but the demo always
    runs the canonical 2-gate round (1 block + 1 approval); it bounds how many
    audit events may be emitted. Returns a :class:`DemoResult`. Deterministic:
    same input → byte-identical output. No API key / network required (I1).
    """
    workdir = Path(tempfile.mkdtemp(prefix="secugent-demo-"))
    inner = EventStore(workdir / "demo.db")
    store = ChainedEventStore(inner)
    # The mock client stands in for the LLM; the demo's decisions are all
    # deterministic-core (oversight + approval), so no generate() call is needed,
    # but constructing it proves the key-less path (I1).
    _ = MockLLMClient()
    try:
        regulations = build_demo_regulations()
        engine = OversightEngine(regulations)
        service = ApprovalService(inner)
        auditor = _DeterministicAuditor(store, regulations_version=regulations.version)

        blocked = _run_block_gate(engine, auditor, emit=emit_audit)
        approvals = _run_hitl_gate(service, inner, auditor, emit=emit_audit)

        audit_events = list(auditor.events)
        summary = _summarize(blocked, approvals, len(audit_events))
        return DemoResult(
            blocked=blocked,
            approvals=approvals,
            audit_events=audit_events,
            summary=summary,
        )
    finally:
        store.close()
        shutil.rmtree(workdir, ignore_errors=True)
