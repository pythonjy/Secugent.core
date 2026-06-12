# SPDX-License-Identifier: Apache-2.0
"""The single embed-SDK oversight gate — a thin wrapper over the core decision path.

BDP_02 item 4 invariant **I1**: the SDK must call the existing deterministic core
(``OversightEngine`` + ``rule_of_two`` + the §C-2 audit emitter) and never
re-implement control logic. :class:`OversightGate` is the **one** place that
composes that decision, in the exact order the production ``SubAgent`` uses:

1. **REGULATIONS deny-by-default** — ``OversightEngine.evaluate(step)`` →
   ``raise_if_blocked()``. A hard-block raises :class:`HardBlockException`
   (the same exception the agent raises) and the wrapped action never runs.
2. **Rule of Two** — ``classify_axes(step, RuleOfTwoContext.from_step(step))``
   and ``requires_hitl(axes)``. When all three axes are active — OR for any
   ``connector_action`` (mirroring ``SubAgent``'s ``is_connector_action``
   carve-out), OR when a *soft* (non-hard-block) REGULATIONS rule matched — HITL
   is forced via the injected :class:`~secugent.agents.sub_agent.HitlGateway`; a
   reject/modify/timeout (or, with an :class:`ApprovalService`, a nonce mismatch)
   fails **closed** (:class:`OversightBlocked`).
3. **§C-2 audit** — every passed action leaves a terminal audit record (I2). A
   clean pass emits exactly one ``approve`` event; a soft REGULATIONS violation
   additionally emits a faithful ``violation`` event first (it is NEVER recorded
   as a clean approve); a deny emits a ``reject`` event then raises.

Every public embed surface (``@require_oversight``, ``OversightMiddleware``,
``wrap_tool``, the LangChain handler) routes through :meth:`OversightGate.enforce`
so there is provably no execution path that bypasses oversight (§4.8 boundary
check). The gate adds **no** policy of its own — its verdict is byte-for-byte the
core engine's verdict (a determinism test asserts this).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Protocol

from secugent.core.contracts import ActionType, Approval, Step
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.risk_analyzer import RiskAssessment
from secugent.core.rule_of_two import (
    RuleOfTwoContext,
    axes_to_audit,
    classify_axes,
    requires_hitl,
)
from secugent.core.tenancy import TenantId

if TYPE_CHECKING:
    # Imported under TYPE_CHECKING so the gate's runtime import surface does not
    # pull in the agent package (F3): the Protocol below references the concrete
    # production types statically without an import-at-load coupling.
    from secugent.agents.sub_agent import HitlDecision
    from secugent.audit.hash_chain import ChainedEventStore
    from secugent.core.approval import ApprovalService

__all__ = [
    "AuditSink",
    "ChainedEventStoreAuditSink",
    "HitlGatewayLike",
    "OversightBlocked",
    "OversightConfigError",
    "OversightDecision",
    "OversightGate",
    "build_step",
]

_KST = timezone(timedelta(hours=9))


class OversightBlocked(RuntimeError):
    """Raised when the Rule-of-Two HITL gate denies (reject / modify / timeout).

    Distinct from :class:`HardBlockException` (a REGULATIONS deny-by-default
    violation): this is the *human-in-the-loop* denial. Both are fail-closed —
    the wrapped action never executes. Never swallowed (§B-8).
    """


class OversightConfigError(RuntimeError):
    """Raised when an embed surface cannot derive a required resource (fail-closed).

    Specifically: an ASGI ``scope`` is handed to a path/domain ``action_type`` but
    no request path/host can be extracted, so a resource-anchored REGULATIONS rule
    could not be evaluated. Deny-by-default forbids silently proceeding with a
    resource-less step — the caller must wire an explicit ``target_from``. This is
    a *configuration* error (mis-wiring), distinct from a policy deny.
    """


class AuditSink(Protocol):
    """Minimal sink the gate emits a §C-2 decision-gate event into.

    Implemented by callers (an in-memory recorder in tests, a
    :class:`~secugent.audit.hash_chain.ChainedEventStore`-backed writer in
    production). The gate hands it a plain ``dict`` already shaped to the §C-2
    schema so the sink stays decoupled from the durable-store types.
    """

    def emit(self, event: dict[str, Any]) -> None: ...


class HitlGatewayLike(Protocol):
    """Structural subtype of :class:`secugent.agents.sub_agent.HitlGateway`.

    Declared here (rather than importing the agent Protocol at runtime) so the
    gate module's import surface does not pull in the agent package; the concrete
    :class:`~secugent.core.contracts.Approval` /
    :class:`~secugent.agents.sub_agent.HitlDecision` types are referenced under
    ``TYPE_CHECKING`` only.

    F3: the parameter is typed ``approval: Approval`` (NOT ``Any``) — the exact
    contract the production ``HitlGateway`` (and any real ``PendingApprovalGateway``
    driving :class:`~secugent.core.approval.ApprovalService`) consumes. The gate
    now hands the gateway a *real* :class:`Approval` (see
    :meth:`OversightGate._build_approval`), so a gateway that reads
    ``approval.status`` / ``approval.scope`` / ``approval.nonce`` type-checks and
    works against the same structural contract production relies on. The return is
    ``HitlDecision`` so ``decision.action`` / ``decision.nonce`` are statically
    known instead of laundered through ``Any``.
    """

    def request_decision(self, *, approval: Approval, step: Step, risk: RiskAssessment) -> HitlDecision: ...


@dataclass(frozen=True)
class OversightDecision:
    """The gate's verdict for one action (returned by :meth:`OversightGate.enforce`)."""

    allowed: bool
    axes: list[str]
    hitl_forced: bool
    event: dict[str, Any]


def _deterministic_step_id(*, action_type: str, target: str | None, run_id: str, actor: str) -> str:
    """A reproducible step id derived from its inputs (no random uuid).

    The embed SDK wraps the *same* call site repeatedly; a content-addressed id
    keeps the audit trail stable and the SDK reproducible (a determinism test
    asserts two builds yield the same id).
    """
    seed = json.dumps(
        {"action_type": action_type, "target": target, "run_id": run_id, "actor": actor},
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    return f"step_{digest}"


def build_step(
    *,
    action_type: ActionType,
    tenant_id: TenantId,
    run_id: str,
    actor: str,
    target: str | None = None,
    command: str | None = None,
    context: dict[str, Any] | None = None,
) -> Step:
    """Construct the :class:`Step` the core engine evaluates for a wrapped call.

    Pure and deterministic: the step id is content-addressed (see
    :func:`_deterministic_step_id`) so the same wrapped call always yields the
    same step (and audit input hash).
    """
    return Step(
        id=_deterministic_step_id(action_type=action_type, target=target, run_id=run_id, actor=actor),
        tenant_id=tenant_id,
        run_id=run_id,
        actor=actor,
        action_type=action_type,
        target=target,
        command=command,
        context=dict(context) if context else {},
    )


def _forced_hitl_risk() -> RiskAssessment:
    """A deterministic ``RiskAssessment`` for a Rule-of-Two-forced HITL.

    The embed SDK does not run the probabilistic RISKANALYZER (it is a control
    wrapper around the *deterministic* gate). When the Rule of Two forces HITL we
    therefore present an explicit, score-less assessment whose ``decision`` is
    ``"hitl"`` — honest about *why* HITL was forced (the deterministic 3-axis
    rule, not a risk score).
    """
    return RiskAssessment(
        score=None,
        decision="hitl",
        reason="rule_of_two: all three axes active (deterministic HITL)",
    )


@dataclass
class OversightGate:
    """Composes the core decision path for one embedding scope (I1 single source).

    Construct one per tenant/run embedding context and reuse it across wrapped
    callables. Each emitted §C-2 event carries a globally-unique ``event_id``
    (uuid4, F7/F11) and threads ``prev_event_id`` from the previous emit so a
    durable sink (:class:`ChainedEventStoreAuditSink`) can derive the same advisory
    ordering — but the **durable** chain integrity is owned by the store, not this
    counter. ``_prev_event_id`` is therefore advisory only; sharing a single
    :class:`ChainedEventStoreAuditSink` across gates is safe (uuid ids never
    collide). Concurrent ``enforce`` on one instance is still unsupported (the
    ``_prev_event_id`` write is unlocked) — embed one gate per request/worker.

    F8: when an :class:`~secugent.core.approval.ApprovalService` is injected via
    ``approvals``, a forced HITL is routed through the **real** approval lifecycle
    (``request_approval`` → gateway decision → ``grant``/``consume`` with
    single-use nonce verification) exactly as ``SubAgent._secure_approval`` does —
    no parallel self-approval path. When ``approvals`` is ``None`` the gate still
    hands the gateway a real step-scoped :class:`Approval` and verifies the
    returned nonce, but cannot enforce durable single-use; production deployments
    MUST inject an ``ApprovalService`` (a determinism/back-compat shim for the
    test gateways, documented as NOT contract-complete on its own).
    """

    oversight: OversightEngine
    tenant_id: TenantId
    run_id: str
    actor: str
    audit: AuditSink
    hitl: HitlGatewayLike | None = None
    approvals: ApprovalService | None = None
    regulations_version: str | None = None
    approval_ttl_seconds: int = 900
    _prev_event_id: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.regulations_version is None:
            # Stamp the engine's effective REGULATIONS version (§C-2 field) without
            # reaching into private state — the engine exposes it read-only. NOTE
            # (F10): this is the engine's policy id (``Regulations.version``), which
            # is a free string, NOT a validated semver. The §C-2 audit field is
            # therefore the *engine policy id*; consumers must not assume semver.
            self.regulations_version = self.oversight.regulations.version

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    def select_blocking_target(
        self, *, action_type: ActionType, candidates: list[str], context: dict[str, Any] | None
    ) -> str | None:
        """Pick the resource the gate should evaluate from several candidates.

        F5b (security): a wrapped call may carry the real resource in EITHER a
        positional OR a conventional kwarg (and both at once). To stay deny-by-
        default we evaluate each candidate against the deterministic core engine
        (a side-effect-free ``evaluate`` — it emits NO audit event) and return the
        FIRST candidate the engine would deny (``not allowed`` — a hard-block OR a
        soft violation). That denied resource then becomes the step's target, so
        the single §C-2 event ``enforce`` emits reflects the actual violating
        resource (I2 preserved — exactly one terminal event for the action).

        When no candidate is banned we return the primary candidate (the first),
        or ``None`` if there are none (an action with no resource — the action-type
        Rule-of-Two axes still apply). This selection NEVER relaxes a verdict: a
        banned candidate can only ever be *added* to consideration, never hidden.

        A candidate that yields only a ``normalization`` / ``unknown_action``
        violation is SKIPPED (not treated as blocking): that just means the value
        is not a valid resource *for this action type* (e.g. an ASGI request path
        fed to an ``http_get`` domain matcher), not that the resource is banned. We
        keep scanning so a genuinely banned sibling candidate (the Host header) is
        not masked by a non-substantive normalization error on an earlier one.
        """
        if not candidates:
            return None
        first_evaluable: str | None = None
        for candidate in candidates:
            probe = build_step(
                action_type=action_type,
                tenant_id=self.tenant_id,
                run_id=self.run_id,
                actor=self.actor,
                target=candidate,
                context=context,
            )
            result = self.oversight.evaluate(probe)
            violation = result.violation
            non_substantive = violation is not None and violation.category in (
                "normalization",
                "unknown_action",
            )
            if not result.allowed and not non_substantive:
                # A genuine policy match (hard-block or soft violation) — pick it.
                return candidate
            if not non_substantive and first_evaluable is None:
                # Remember the first candidate that IS a valid resource for this
                # action type (whether it passed clean or not), so the fallback
                # never lands on a value that only normalization-errors.
                first_evaluable = candidate
        # No candidate was substantively banned: prefer a value the matchers can
        # actually evaluate; else the primary (fail-closed on a misconfigured
        # resource — enforce will surface the normalization error).
        return first_evaluable if first_evaluable is not None else candidates[0]

    def enforce(self, step: Step) -> OversightDecision:
        """Run the full gate for ``step``; raise on any deny (fail-closed).

        Order matches ``SubAgent._run_step`` exactly:
        oversight HARD BLOCK → Rule-of-Two forced HITL → §C-2 audit emit.
        On a HARD BLOCK a reject event is emitted *then* :class:`HardBlockException`
        is raised. On a HITL denial :class:`OversightBlocked` is raised. On success
        an approve event is emitted and the decision returned.
        """
        axes = classify_axes(step, RuleOfTwoContext.from_step(step))
        axis_values = axes_to_audit(axes)

        # 1. REGULATIONS deny-by-default. The core engine returns ``allowed=False``
        #    for ANY matched rule — a hard-block (``hard_block=True``) AND a *soft*
        #    violation (``hard_block=False``, e.g. a ``DataLabel`` whose default is
        #    False). F1: we must branch on ``not allowed`` (not only ``hard_block``)
        #    so a soft violation is never silently dropped and never audited as a
        #    clean approve.
        result = self.oversight.evaluate(step)
        soft_violation = False
        if not result.allowed and result.violation is not None:
            if result.hard_block:
                self._emit(
                    step=step,
                    gate="plan_review",
                    decision="reject",
                    rationale=(
                        f"REGULATIONS HARD BLOCK: {result.violation.message} "
                        "(위험점수와 무관하게 결정적으로 차단)"
                    ),
                    axes=axis_values,
                    actor_type="sec",
                )
                # raise_if_blocked() raises the canonical HardBlockException (I1: we
                # reuse the core's own raise path rather than minting a new error).
                result.raise_if_blocked()
            else:
                # Soft violation: mirror ``SubAgent._run_step``'s
                # ``step.oversight_violation`` (severity=warn) — record the matched
                # rule faithfully in the audit chain BEFORE proceeding, and force
                # HITL so a policy-flagged action cannot run unreviewed at the embed
                # boundary (deny-by-default, §A-2.2). The action is NOT auto-approved.
                soft_violation = True
                self._emit(
                    step=step,
                    gate="plan_review",
                    decision="violation",
                    rationale=(
                        f"REGULATIONS 소프트 위반(차단 아님): {result.violation.message} "
                        "(rule_id="
                        f"{result.violation.rule_id}) — HITL 검토 강제"
                    ),
                    axes=axis_values,
                    actor_type="sec",
                )

        # 2. Rule of Two — force HITL when all three axes are active, OR for any
        #    ``connector_action`` (F4: mirror ``SubAgent._secure_approval``'s
        #    ``is_connector_action`` carve-out — external comm always takes a fresh,
        #    step-scoped HITL regardless of axis count), OR when a soft REGULATIONS
        #    violation was matched (F1: never run a policy-flagged action unreviewed).
        hitl_forced = requires_hitl(axes) or step.action_type == "connector_action" or soft_violation
        if hitl_forced:
            self._enforce_hitl(step, axis_values)

        # 3. §C-2 audit — exactly one terminal pass event for the action (I2). The
        #    rationale is honest: it never claims "REGULATIONS 위반 없음" when a soft
        #    rule actually matched.
        if soft_violation:
            approve_rationale = "HITL 승인: REGULATIONS 소프트 위반 단계가 사람 검토 후 승인됨."
        elif hitl_forced:
            approve_rationale = "HITL 승인: Rule of Two/connector_action 단계가 승인됨."
        else:
            approve_rationale = "정책 통과: REGULATIONS 위반 없음, Rule of Two 3축 미충족."
        event = self._emit(
            step=step,
            gate="hitl" if hitl_forced else "plan_review",
            decision="approve",
            rationale=approve_rationale,
            axes=axis_values,
            actor_type="human" if hitl_forced else "sec",
        )
        return OversightDecision(allowed=True, axes=axis_values, hitl_forced=hitl_forced, event=event)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _enforce_hitl(self, step: Step, axis_values: list[str]) -> None:
        """Force a HITL decision through the real approval lifecycle (fail-closed).

        Deny-by-default: no gateway configured, or any non-approve outcome
        (reject / modify), or a gateway timeout, or a nonce mismatch blocks the
        action. The gateway's own ``HitlTimeoutError`` is converted to
        :class:`OversightBlocked` so the SDK surface raises a single, documented
        deny type.

        F8: when an :class:`ApprovalService` is injected we drive the SAME path as
        ``SubAgent._secure_approval`` — issue a fresh, step-scoped, nonce-bearing
        :class:`Approval` via ``request_approval``, present it to the gateway,
        then ``grant`` + ``consume`` (single-use ``verify_for_step``) verifying the
        returned ``decision.nonce`` against the approval. A replayed / forged /
        absent nonce therefore fails closed at ``consume``. When no service is
        injected we still hand the gateway a real step-scoped :class:`Approval` and
        verify the returned nonce in-process (no durable single-use — see the class
        docstring; production must inject a service).
        """
        if self.hitl is None:
            self._emit(
                step=step,
                gate="hitl",
                decision="reject",
                rationale="HITL 강제 단계인데 HITL 게이트웨이가 없음 (fail-closed).",
                axes=axis_values,
                actor_type="human",
            )
            raise OversightBlocked("HITL required but no gateway was configured (fail-closed)")

        # Import lazily to keep gate.py's import surface free of the agent package.
        from secugent.agents.sub_agent import HitlTimeoutError

        approval = self._build_approval(step)
        try:
            decision = self.hitl.request_decision(
                approval=approval,
                step=step,
                risk=_forced_hitl_risk(),
            )
        except HitlTimeoutError as exc:
            if self.approvals is not None:
                self.approvals.reject(approval.id, reason="hitl-timeout")
            self._emit(
                step=step,
                gate="hitl",
                decision="reject",
                rationale=f"HITL 타임아웃 (fail-closed): {exc}",
                axes=axis_values,
                actor_type="human",
            )
            raise OversightBlocked(f"HITL timeout (fail-closed): {exc}") from exc

        if decision.action != "approve":
            reason = decision.reason or decision.action or "denied"
            if self.approvals is not None:
                self.approvals.reject(approval.id, reason=reason)
            self._emit(
                step=step,
                gate="hitl",
                decision="reject",
                rationale=f"HITL 거부 (fail-closed): {reason}",
                axes=axis_values,
                actor_type="human",
            )
            raise OversightBlocked(f"HITL denied (fail-closed): {reason}")

        # Approved: verify + consume the single-use nonce. A forged/absent nonce
        # raises ApprovalError → fail-closed (F8: no token, no execution).
        if self.approvals is not None:
            from secugent.core.contracts import ApprovalError

            try:
                granted = self.approvals.grant(approval.id, reason=decision.reason or "human-approved")
                self.approvals.consume(
                    granted.id,
                    step,
                    observed_nonce=decision.nonce or granted.nonce,
                )
            except ApprovalError as exc:
                self._emit(
                    step=step,
                    gate="hitl",
                    decision="reject",
                    rationale=f"HITL 승인 토큰 검증 실패 (fail-closed): {exc}",
                    axes=axis_values,
                    actor_type="human",
                )
                raise OversightBlocked(f"HITL approval token invalid (fail-closed): {exc}") from exc

    def _build_approval(self, step: Step) -> Approval:
        """Issue (or synthesize) a fresh, step-scoped, nonce-bearing approval.

        With an injected :class:`ApprovalService` this is the durable
        ``request_approval`` (the gateway then drives ``grant``/``consume``). Without
        one it is an in-memory :class:`Approval` so the gateway still receives the
        full structural contract (``id`` / ``scope`` / ``nonce`` / ``status``) and
        the gate can verify the returned nonce — but with no durable single-use.
        """
        from secugent.core.contracts import ApprovalScope

        # Mirror ``SubAgent._secure_approval`` exactly: a ``connector_action`` is
        # forbidden in ``allowed_action_types`` (ApprovalScope validation) and is
        # authorized solely by the step-id scope; every other action_type must list
        # itself so ``_action_allowed`` (which fail-closes on an empty list) admits
        # the consume. The scope is step-dedicated (``step_ids=[step.id]``) so a
        # Rule-of-Two 3-axis / connector step passes ``verify_for_step``'s
        # step-dedication check.
        allowed: list[ActionType] = [] if step.action_type == "connector_action" else [step.action_type]
        scope = ApprovalScope(
            tenant_id=step.tenant_id,
            run_id=step.run_id,
            plan_id=step.plan_id,
            step_ids=[step.id],
            allowed_action_types=allowed,
            max_risk=70,
            expires_at=datetime.now(tz=UTC) + timedelta(seconds=self.approval_ttl_seconds),
        )
        if self.approvals is not None:
            return self.approvals.request_approval(
                actor=f"hitl-for:{self.actor}",
                scope=scope,
                ttl_seconds=self.approval_ttl_seconds,
            )
        return Approval(
            actor=f"hitl-for:{self.actor}",
            scope=scope,
            expires_at=scope.expires_at,
            nonce=uuid.uuid4().hex,
            status="pending",
        )

    def _emit(
        self,
        *,
        step: Step,
        gate: str,
        decision: str,
        rationale: str,
        axes: list[str],
        actor_type: str,
    ) -> dict[str, Any]:
        """Build and emit one §C-2 decision-gate event.

        F7/F11: ``event_id`` is a fresh uuid4 (per the §C-2 ``uuid`` schema) so two
        gates sharing one durable sink never collide on the ``event_id TEXT PRIMARY
        KEY``. ``prev_event_id`` threads the previous emit's id as an *advisory*
        ordering hint only — the durable, tamper-evident chain is owned by the
        store (see :class:`ChainedEventStoreAuditSink`), which re-derives
        ``prev_hash``/``seq`` itself. F10: ``risk_score`` is ``None`` (not 0) because
        the embed SDK deliberately never runs the probabilistic RISKANALYZER —
        emitting 0 would falsely assert "assessed and found zero risk".
        """
        event_id = str(uuid.uuid4())
        input_hash = hashlib.sha256(
            json.dumps(step.model_dump(mode="json"), sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        event: dict[str, Any] = {
            "event_id": event_id,
            "timestamp": datetime.now(tz=_KST).isoformat(),
            "tenant_id": str(self.tenant_id),
            "actor": {"type": actor_type, "id": self.actor},
            "gate": gate,
            "input_hash": input_hash,
            "decision": decision,
            "rationale": rationale,
            "regulations_version": self.regulations_version,
            "context_snapshot_ref": f"snapshot://{self.run_id}/{event_id}",
            "risk_score": None,
            "rule_of_two_axes": axes,
            "prev_event_id": self._prev_event_id,
        }
        self.audit.emit(event)
        self._prev_event_id = event_id
        return event


class ChainedEventStoreAuditSink:
    """A durable, tamper-evident :class:`AuditSink` backed by a
    :class:`~secugent.audit.hash_chain.ChainedEventStore` (F9/F11).

    Maps the §C-2 ``dict`` the gate emits onto a canonical
    :class:`~secugent.core.contracts.Event` and appends it via
    ``ChainedEventStore.append_event`` — so the **durable** ``prev_hash`` / ``seq``
    hash chain (``verify_chain``) covers every SDK-emitted decision-gate event,
    not a volatile in-memory counter. The dict's advisory ``event_id`` /
    ``prev_event_id`` are deliberately NOT trusted for chaining: the store owns the
    link hashes. The full §C-2 dict is preserved under the event payload so no
    field (input_hash, rationale, rule_of_two_axes, ...) is lost.
    """

    def __init__(self, store: ChainedEventStore) -> None:
        self._store = store

    def emit(self, event: dict[str, Any]) -> None:
        from secugent.core.contracts import Event

        actor = event.get("actor")
        actor_id = actor.get("id") if isinstance(actor, dict) else None
        ctx_ref = event.get("context_snapshot_ref")
        run_id = ctx_ref.split("/")[2] if isinstance(ctx_ref, str) and ctx_ref.count("/") >= 2 else None
        durable = Event(
            tenant_id=str(event["tenant_id"]),
            actor=str(actor_id or "sub:embedded"),
            type=f"sdk.decision.{event.get('gate', 'plan_review')}",
            severity="warn" if event.get("decision") in ("reject", "violation") else "info",
            run_id=run_id,
            payload=dict(event),
        )
        self._store.append_event(durable)
