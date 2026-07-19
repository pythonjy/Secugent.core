# SPDX-License-Identifier: Apache-2.0
"""The Egress Broker — single mediated chokepoint for external effects (EM-05).

Every external side-effect is submitted here. The broker evaluates a fixed,
strongest-deny-first gate sequence — profile → policy (EM-03) → egress label
(EM-02) → envelope (EM-07, optional) — then records a decision Event to the
durable hash chain *before* the transport runs. Any denial, or an audit-append
failure, means the transport is never called (fail-closed, I-A / durable).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any, Protocol, TypeVar

from secugent.core.contracts import Event, Step
from secugent.core.sec.canonicalize import AmbiguousEffectError
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel, may_egress
from secugent.core.sec.policy import Decision
from secugent.core.sec.reversibility import ManifestRegistry, ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.effect_bridge import build_effect
from secugent.io.broker.label_resolver import LabelResolver
from secugent.io.broker.profiles import ExecutionProfile, profile_permits
from secugent.io.broker.request import EgressRequest, EgressResult
from secugent.io.broker.transport import Transport
from secugent.orchestrator.envelope_gate import EnvelopeReviewGate
from secugent.tools import builtin
from secugent.tools.router import ToolDispatchError

__all__ = [
    "EGRESS_MAX_EXTERNAL_DEFAULT",
    "EgressBroker",
    "AuditStore",
    "EnvelopeGate",
    "ConnectorTransportLike",
    "EgressDeniedError",
    "EnvelopeSuspendedError",
    "AuditAppendError",
    "StagingHeldError",
    "StagingStore",
    "PolicyLike",
]


class PolicyLike(Protocol):
    """Structural interface for the broker's policy evaluator (EM-03).

    Both :class:`~secugent.core.sec.policy.CompiledPolicy` (direct) and the
    :class:`OversightEngineShim` (routes through
    ``OversightEngine.evaluate_effect``) satisfy this Protocol so the broker
    never needs to import the concrete engine class (avoiding a core→io cycle).
    """

    def evaluate(self, effect: Effect, label: DataLabel) -> Decision: ...


_T = TypeVar("_T")

_log = logging.getLogger("secugent.io.broker")

# Single source of truth for the EM-02 egress-label ceiling default. The
# ``EgressBroker`` constructor default AND ``boot_wiring._MAX_EXTERNAL_DEFAULT``
# both reference THIS constant (via ``is``), so raising/lowering the deny-by-default
# ceiling is a one-line change with no comment-coupled restatement (INV-3).
EGRESS_MAX_EXTERNAL_DEFAULT: DataLabel = DataLabel.INTERNAL_USE

# Write-class effects carry a payload; dispatching one without content would
# silently "write nothing" (fail-OPEN). These kinds require an explicit payload
# (an *empty* payload b"" is a legitimate truncate; only a missing one is refused).
_WRITE_KINDS: frozenset[EffectKind] = frozenset(
    {EffectKind.FILE_WRITE, EffectKind.NET_SEND, EffectKind.CONNECTOR_ACTION}
)


# Broker denials are ToolDispatchError subclasses so the live SubAgent's existing
# `except (... ToolDispatchError)` handles them with zero changes.
class EgressDeniedError(ToolDispatchError):
    """A gate (profile/policy/label) denied the effect."""


class EnvelopeSuspendedError(ToolDispatchError):
    """The effect is outside the authorization envelope → HITL required (EM-07)."""


class AuditAppendError(ToolDispatchError):
    """The pre-execution audit append failed → execution refused (fail-closed)."""


class StagingHeldError(ToolDispatchError):
    """An irreversible effect was held in 2-phase staging (EM-09) — not executed."""


class AuditStore(Protocol):
    """Durable, hash-chained event sink (satisfied by ChainedEventStore)."""

    def append_event(self, event: Event) -> Any: ...


class EnvelopeVerdict(Protocol):
    outcome: str  # "allow" | "suspend"
    reason: str


class EnvelopeGate(Protocol):
    """EM-07 injection point: decide whether a request is within the envelope."""

    def check(self, request: EgressRequest) -> EnvelopeVerdict: ...


class UnscopedSink(Protocol):
    """EM-04 injection point: record an effect that matched no explicit rule
    (satisfied structurally by ``audit.unscoped.UnscopedRecorder``)."""

    def record(self, *, tenant_id: Any, effect: Any, run_id: str | None = ...) -> Any: ...


class StagingStore(Protocol):
    """EM-09 injection point: hold an irreversible effect for 2-phase commit
    (satisfied structurally by ``io.staging.StagedEffectStore``)."""

    def stage(
        self,
        req: EgressRequest,
        *,
        reversibility: ReversibilityClass,
        hold_sec: int,
        now: datetime,
        compensating_action: str | None = ...,
        audit: Any = ...,
    ) -> Any: ...


class ConnectorEgressResultLike(Protocol):
    """The shape :class:`ConnectorTransport.dispatch` returns (token-scrubbed)."""

    ok: bool
    payload: dict[str, Any]


class ConnectorTransportLike(Protocol):
    """EM-06 connector egress injection point (satisfied by ``ConnectorTransport``).

    Declared structurally — not imported — so the broker does not depend on the
    concrete EM-06 transport (back-compat: connector egress stays a go-live diff).
    ``dispatch`` is async; the broker bridges its sync drop-in to it.
    """

    async def dispatch(
        self, request: EgressRequest, *, http_transport: Any | None = ...
    ) -> ConnectorEgressResultLike: ...


class EgressBroker:
    """Mediates, evaluates, audits, and executes every external effect."""

    def __init__(
        self,
        *,
        policy: PolicyLike,
        audit_store: AuditStore,
        transport: Transport,
        max_external: DataLabel = EGRESS_MAX_EXTERNAL_DEFAULT,
        label_resolver: LabelResolver | None = None,
        envelope_gate: EnvelopeGate | None = None,
        review_gate: EnvelopeReviewGate | None = None,
        review_gate_factory: Callable[[], EnvelopeReviewGate] | None = None,
        connector_transport: ConnectorTransportLike | None = None,
        registry: ManifestRegistry | None = None,
        staging_store: StagingStore | None = None,
        unscoped_recorder: UnscopedSink | None = None,
        hold_sec: int = 0,
        now_provider: Callable[[], datetime] | None = None,
        sandbox_roots: list[str] | None = None,
        default_profile: ExecutionProfile = ExecutionProfile.INTERNAL_RW,
        default_label: DataLabel = DataLabel.CONFIDENTIAL,
        actor: str = "broker",
    ) -> None:
        self._policy = policy
        self._audit = audit_store
        self._transport = transport
        self._max_external = max_external
        # EM-02: LabelResolver resolves the effective egress
        # label per dispatch call (taint + LabelStore upper-bound). When None
        # the broker falls back to ``_default_label`` (backward-compatible).
        self._label_resolver = label_resolver
        self._envelope_gate = envelope_gate
        # EnvelopeReviewGate drives the SUSPEND → HITL →
        # RESUME/ABORT state machine. An envelope "suspend" verdict calls
        # on_suspend() instead of converting directly to a deny.
        #
        # The gate is per-(tenant, run): a single process-global gate would let a
        # tenant-X decision resolve a tenant-Y suspend (cross-tenant HITL
        # contamination) and would collide when two runs suspend concurrently.
        # ``review_gate_factory`` (preferred for the multi-tenant live boot) mints
        # a fresh gate the first time a given (tenant, run) suspends; the broker
        # keys them in ``_review_gates``. ``review_gate`` (single instance) stays
        # for single-run unit tests / explicit callers: it is reused for whatever
        # (tenant, run) suspends first and registered under that key so the outbox
        # endpoints resolve the same instance. Exactly one of the two is the
        # source; the factory wins when both are supplied.
        self._review_gate_factory = review_gate_factory
        self._review_gate_seed = review_gate
        self._review_gates: dict[tuple[str, str], EnvelopeReviewGate] = {}
        self._review_gate_lock = threading.Lock()
        # EM-06: connector egress transport. None until go-live wiring lands; a
        # connector_action submitted with no transport configured fails closed.
        self._connector_transport = connector_transport
        # EM-09: reversibility registry + staging store. When both are set,
        # irreversible effects are diverted to 2-phase staging instead of the
        # transport (I-C); if a registry classifies IRREVERSIBLE but no staging
        # store is wired, the effect is denied (fail-closed).
        self._registry = registry
        self._staging_store = staging_store
        if staging_store is not None and registry is None:
            # Misconfiguration would fail OPEN for I-C (irreversible effects would
            # execute directly). Require a registry whenever staging is wired.
            raise ValueError("staging_store requires a registry to classify reversibility (I-C)")
        self._unscoped = unscoped_recorder
        self._hold_sec = hold_sec
        self._now_provider = now_provider
        self._sandbox_roots = list(sandbox_roots or [])
        self._default_profile = default_profile
        self._default_label = default_label
        self._actor = actor

    async def submit(self, req: EgressRequest) -> EgressResult:
        """Async public API (transport may become async with connectors/EM-06)."""
        return self._submit(req)

    # ------------------------------------------------------------------ #
    # Core gate sequence (sync — strongest-deny-first, fail-closed)
    # ------------------------------------------------------------------ #

    def _run_gates(
        self, req: EgressRequest, *, skip_envelope: bool = False
    ) -> tuple[EgressResult, None] | tuple[None, tuple[Decision, Event]]:
        """Run the strongest-deny-first gate chain + audit-before-act (I-A).

        Returns ``(deny_result, None)`` if any gate denied / staged / the
        pre-execution audit append failed, or ``(None, (allow_decision, audit_event))``
        when the effect is cleared to execute (the durable decision event is
        already appended). The SAME chain backs both the sync router transport
        path (:meth:`_submit`) and the async connector path
        (:meth:`dispatch_connector`) so neither can skip a gate.

        ``skip_envelope`` omits ONLY the EM-07 authorization-envelope gate, for the
        pre-run read path (:meth:`dispatch_connector_read`): that gate presupposes a
        bound run envelope, which does not exist before a run dispatches, so it would
        deny-by-default. Every other control — profile, EM-03 signed policy,
        Rule-of-Two, EM-02 egress-label cap, EM-09 staging, audit-before-act —
        still runs, so the relaxation is bounded (no run-scoped authorization), never
        an ungated bypass.
        """
        # 1. Profile boundary.
        if not profile_permits(req.profile, req.effect):
            return (
                self._deny(
                    req,
                    Decision(
                        outcome="deny",
                        rule_id=None,
                        rationale=f"profile_boundary:{req.effect.sink_class} not allowed in {req.profile}",
                    ),
                ),
                None,
            )
        # 2. Signed policy (EM-03).
        decision = self._policy.evaluate(req.effect, req.label)
        if decision.outcome != "allow":
            # EM-04: an effect that matched NO explicit rule (default_deny,
            # rule_id is None) is 'unscoped' — record it for the completeness
            # review queue. Audit-only; the effect is still denied. Telemetry must
            # never change the deny semantics, so a recorder failure is swallowed
            # (mirrors the best-effort deny-path audit append below).
            if decision.rule_id is None and self._unscoped is not None:
                try:
                    self._unscoped.record(
                        tenant_id=req.principal.tenant_id, effect=req.effect, run_id=req.run_id
                    )
                except Exception as exc:  # noqa: BLE001 - telemetry is non-fatal to the deny result
                    _log.warning("unscoped telemetry record failed (non-fatal): %s", exc)
            return self._deny(req, decision), None
        # 2.5. Rule-of-Two 3-axis gate.
        # When all three axes are simultaneously true the effect requires HITL;
        # executing it without human approval violates the Rule of Two.
        # This gate runs AFTER policy allow so a
        # permissive policy does NOT bypass the structural constraint — the two
        # controls are independent layers. HITL wiring is a follow-on; today
        # the deny is unconditional (no HITL bypass path exists yet) to match
        # the spec's "HITL 없는 한 deny" semantics conservatively.
        rot_axes = self._rule_of_two_axes(req.effect)
        if all(rot_axes.values()):
            return (
                self._deny(
                    req,
                    Decision(
                        outcome="deny",
                        rule_id=None,
                        rationale="rule_of_two_3axis_requires_hitl",
                    ),
                ),
                None,
            )
        # 3. Egress label (EM-02).
        # F3 (INV-D): a fail-safe-derived label (LabelStore failure ⇒ the
        # container's classification could not be authoritatively determined) must
        # never leave through an EXTERNAL sink, regardless of the operator
        # ``max_external`` ceiling — "cannot classify" is not "safe to send out".
        # A general provenance rule, checked BEFORE the lattice comparison so even a
        # ceiling raised to SECRET cannot re-open this path (which the ceiling alone
        # would: fail-safe CONFIDENTIAL <= CONFIDENTIAL ceiling would otherwise pass).
        if req.label_uncertain and req.effect.sink_class is SinkClass.EXTERNAL:
            return (
                self._deny(
                    req,
                    Decision(
                        outcome="deny",
                        rule_id=None,
                        rationale="egress_label:label_provenance_uncertain",
                    ),
                ),
                None,
            )
        label_decision = may_egress(req.label, req.effect.sink_class, max_external=self._max_external)
        if not label_decision.allow:
            return (
                self._deny(
                    req,
                    Decision(outcome="deny", rule_id=None, rationale=f"egress_label:{label_decision.reason}"),
                ),
                None,
            )
        # 4. Authorization envelope (EM-07, optional). Skipped for the pre-run read
        # path, where no run envelope is bound yet (it would deny-by-default); all
        # other gates above/below still apply.
        if not skip_envelope and self._envelope_gate is not None:
            verdict = self._envelope_gate.check(req)
            if verdict.outcome != "allow":
                # route through the per-(tenant, run) EnvelopeReviewGate
                # when wired so the SUSPEND → HITL → RESUME/ABORT state machine is
                # driven rather than a plain deny. Audit the HITL-pending event
                # before returning (append-before-transport, I-A).
                review_gate = self._review_gate_for(req.principal.tenant_id, req.run_id)
                if review_gate is not None:
                    try:
                        review_gate.on_suspend(
                            reason=verdict.reason,
                            effect_fingerprint=req.effect.fingerprint(),
                            action=req.effect.action or str(req.effect.kind),
                        )
                    except Exception as exc:  # noqa: BLE001 - gate state error → fail-closed deny
                        _log.warning("EnvelopeReviewGate.on_suspend failed: %s", exc)
                    # Emit the HITL-pending audit event into the hash chain.
                    hitl_event = Event(
                        tenant_id=req.principal.tenant_id,
                        actor=self._actor,
                        type="hitl.pending",
                        run_id=req.run_id,
                        payload={
                            "gate": "hitl",
                            "decision": "pending",
                            "rationale": f"envelope_suspend:{verdict.reason}",
                            "effect_fingerprint": req.effect.fingerprint(),
                            "kind": str(req.effect.kind),
                            "sink": str(req.effect.sink_class),
                            "target": req.effect.target,
                            "label": int(req.label),
                            "rule_of_two_axes": list(self._rule_of_two_axes(req.effect).keys()),
                            "regulations_version": "0.0.0",
                            "input_hash": req.effect.fingerprint(),
                            "risk_score": 0,
                        },
                        severity="warn",
                    )
                    try:
                        self._audit.append_event(hitl_event)
                    except Exception as exc:  # noqa: BLE001 - audit write fail → deny (I-A)
                        _log.error("envelope HITL pending audit append failed; refusing execution: %s", exc)
                return (
                    self._deny(
                        req,
                        Decision(
                            outcome="deny", rule_id=None, rationale=f"envelope_suspend:{verdict.reason}"
                        ),
                    ),
                    None,
                )
        # 4b. Irreversible effects divert to 2-phase staging (EM-09, I-C).
        diverted = self._maybe_stage(req)
        if diverted is not None:
            return diverted, None
        # 5. Audit BEFORE act — durable failure ⇒ refuse execution (I-A).
        event = self._decision_event(req, decision, allowed=True, gate="execute")
        try:
            self._audit.append_event(event)
        except Exception as exc:  # noqa: BLE001 - fail-closed: ANY durable failure blocks execution
            _log.error("egress audit append failed; refusing execution: %s", exc)
            return (
                EgressResult(
                    ok=False,
                    decision=Decision(outcome="deny", rule_id=None, rationale="audit_append_failed"),
                    payload=None,
                    audit_event_id="",
                ),
                None,
            )
        return None, (decision, event)

    def _submit(self, req: EgressRequest) -> EgressResult:
        deny, allowed = self._run_gates(req)
        if deny is not None:
            return deny
        assert allowed is not None  # _run_gates returns exactly one of (deny, allowed)
        decision, event = allowed
        # Execute via the sole sync transport, then record completion.
        payload = self._transport.execute(req)
        self._post_audit(req)
        return EgressResult(ok=True, decision=decision, payload=payload, audit_event_id=event.id)

    def _maybe_stage(self, req: EgressRequest) -> EgressResult | None:
        """Return a 'held' result if the effect is irreversible and staged; else
        None (reversible/compensatable, or no registry → execute directly)."""
        if self._registry is None:
            return None
        action_key = req.effect.action or str(req.effect.kind)
        reversibility = self._registry.classify(action_key)
        if reversibility is not ReversibilityClass.IRREVERSIBLE:
            return None
        if self._staging_store is None:
            # Irreversible with no staging wired ⇒ refuse (I-C, fail-closed).
            return self._deny(
                req, Decision(outcome="deny", rule_id=None, rationale="irreversible_requires_staging")
            )
        manifest = self._registry.manifest_for(action_key)
        staged = self._staging_store.stage(
            req,
            reversibility=reversibility,
            hold_sec=self._hold_sec,
            now=self._now(),
            compensating_action=manifest.compensating_action if manifest is not None else None,
            audit=self._audit,
        )
        return EgressResult(
            ok=False,
            decision=Decision(outcome="deny", rule_id=None, rationale=f"staged:{staged.id}"),
            payload=None,
            audit_event_id="",
        )

    def _rule_of_two_axes(self, effect: Effect) -> dict[str, bool]:
        """Classify the three Rule-of-Two axes for ``effect``.

        Returns a mapping with three boolean entries:
          - ``external_comm``: the effect targets an EXTERNAL sink.
          - ``sensitive_access``: the effect kind touches files, network, or
            connector actions (write-class kinds).
          - ``untrusted_input``: the effect's metadata carries the
            ``untrusted_input="true"`` marker set by the head-agent / caller.

        All three True simultaneously → Rule of Two violated → HITL required.
        """
        return {
            "external_comm": effect.sink_class == SinkClass.EXTERNAL,
            "sensitive_access": effect.kind
            in (
                EffectKind.FILE_WRITE,
                EffectKind.NET_SEND,
                EffectKind.CONNECTOR_ACTION,
            ),
            "untrusted_input": dict(effect.meta).get("untrusted_input") == "true",
        }

    def _now(self) -> datetime:
        if self._now_provider is not None:
            return self._now_provider()
        return datetime.now(tz=UTC)

    # ------------------------------------------------------------------ #
    # Per-(tenant, run) EnvelopeReviewGate registry
    # ------------------------------------------------------------------ #

    def _review_gate_for(self, tenant_id: TenantId, run_id: str) -> EnvelopeReviewGate | None:
        """Return (creating on first suspend) the gate for ``(tenant_id, run_id)``.

        Isolation: each (tenant, run) gets its own gate so a decision for one can
        never resolve another's pending HITL state (confused-deputy defense). When
        a ``review_gate_factory`` is wired the gate is minted fresh per key; when
        only a single seed ``review_gate`` was supplied (single-run unit tests),
        the seed is registered under the first key that suspends and reused for it.
        Returns None when neither a factory nor a seed was configured (back-compat).
        """
        factory = self._review_gate_factory
        seed = self._review_gate_seed
        if factory is None and seed is None:
            return None
        key = (str(tenant_id), run_id)
        with self._review_gate_lock:
            gate = self._review_gates.get(key)
            if gate is not None:
                return gate
            if factory is not None:
                gate = factory()
            else:
                # Reuse the single seed for whichever key suspends first; a second
                # distinct key with a seed-only broker has no isolated gate
                # (single-run contract — the live boot uses a factory). ``seed`` is
                # non-None here (the early guard rules out both being None).
                assert seed is not None
                if seed in self._review_gates.values():
                    return None
                gate = seed
            self._review_gates[key] = gate
            return gate

    def resolve_review_gate(self, tenant_id: TenantId, run_id: str) -> EnvelopeReviewGate | None:
        """Public lookup: the registered gate for ``(tenant_id, run_id)`` or None.

        Used by the outbox HITL endpoints so an operator decision resolves ONLY
        the gate of the effect's own (tenant, run) — never a global singleton.
        Does NOT create a gate (read-only; a missing key means nothing suspended).
        """
        with self._review_gate_lock:
            return self._review_gates.get((str(tenant_id), run_id))

    # ------------------------------------------------------------------ #
    # Audit helpers
    # ------------------------------------------------------------------ #

    def _deny(self, req: EgressRequest, decision: Decision) -> EgressResult:
        event = self._decision_event(req, decision, allowed=False, gate="deny")
        audit_id = ""
        try:
            self._audit.append_event(event)
            audit_id = event.id
        except Exception as exc:  # noqa: BLE001 - deny already blocks; record-failure is non-fatal
            _log.warning("egress deny audit append failed: %s", exc)
        return EgressResult(ok=False, decision=decision, payload=None, audit_event_id=audit_id)

    def _post_audit(self, req: EgressRequest) -> None:
        event = Event(
            tenant_id=req.principal.tenant_id,
            actor=self._actor,
            type="egress.executed",
            run_id=req.run_id,
            payload={"effect_fingerprint": req.effect.fingerprint(), "target": req.effect.target},
            severity="info",
        )
        try:
            self._audit.append_event(event)
        except Exception as exc:  # noqa: BLE001 - effect already executed; never fake success
            _log.error("egress post-exec audit failed (effect already executed): %s", exc)

    def _decision_event(self, req: EgressRequest, decision: Decision, *, allowed: bool, gate: str) -> Event:
        return Event(
            tenant_id=req.principal.tenant_id,
            actor=self._actor,
            type="egress.allowed" if allowed else "egress.denied",
            run_id=req.run_id,
            payload={
                "effect_fingerprint": req.effect.fingerprint(),
                "kind": str(req.effect.kind),
                "sink": str(req.effect.sink_class),
                "target": req.effect.target,
                "label": int(req.label),
                "profile": str(req.profile),
                "outcome": decision.outcome,
                "rationale": decision.rationale,
                "gate": gate,
            },
            severity="info" if allowed else "warn",
        )

    # ------------------------------------------------------------------ #
    # Go-live shim (deferred): router-compatible dispatch for SubAgent.
    # Built + unit-tested here; injected into main.py only when it is clean.
    # ------------------------------------------------------------------ #

    def dispatch(
        self,
        step: Step,
        *,
        content: str | bytes | None = None,
        http_transport: Any | None = None,
    ) -> builtin.ToolResult:
        # build_effect failure (ambiguous/non-canonical target) is fail-closed:
        # convert it to a deny so the SubAgent's `except ToolDispatchError` treats
        # it as step.tool_failed (it never reaches a transport).
        try:
            effect = build_effect(step, sandbox_roots=self._sandbox_roots)
        except AmbiguousEffectError as exc:
            raise EgressDeniedError(f"ambiguous_effect:{exc}") from exc
        principal = Principal(user_id="broker", tenant_id=step.tenant_id, role="operator")
        # EM-02: resolve effective label via LabelResolver when
        # wired; fall back to _default_label (CONFIDENTIAL) for backward-compat.
        container_id = step.id or step.run_id or ""
        if self._label_resolver is not None:
            resolved = self._run_coroutine(
                self._label_resolver.resolve_with_provenance(
                    tenant_id=step.tenant_id,
                    container_id=container_id,
                    taint_ctx=None,
                )
            )
            resolved_label = resolved.label
            label_uncertain = resolved.fail_safe  # F3: LabelStore-failure provenance
        else:
            resolved_label = self._default_label
            label_uncertain = False

        # Connector egress (EM-06) bridges the sync drop-in to the async
        # ConnectorTransport, AFTER the same gate chain — never the router path.
        if effect.kind is EffectKind.CONNECTOR_ACTION:
            req = EgressRequest(
                effect=effect,
                label=resolved_label,
                principal=principal,
                run_id=step.run_id,
                profile=self._default_profile,
                content=None,  # connector params travel in effect.meta, not content
                label_uncertain=label_uncertain,
            )
            return self._run_coroutine(self._dispatch_connector_req(req, http_transport=http_transport))

        # The SubAgent calls dispatch(step) without explicit content; mirror
        # ToolRouter's own fallback and carry the write payload from the step so
        # it survives the Step→Effect→Step round-trip through the transport.
        if content is None:
            ctx_content = step.context.get("content")
            if isinstance(ctx_content, (str, bytes)):
                content = ctx_content
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        # Fail-closed: a write-class effect with no payload must not be silently
        # submitted (it would "write nothing"). Refuse before any transport/audit.
        if content_bytes is None and effect.kind in _WRITE_KINDS:
            raise EgressDeniedError(
                f"write_content_missing:{effect.kind} effect requires content "
                "(none supplied via argument or step.context['content'])"
            )
        req = EgressRequest(
            effect=effect,
            label=resolved_label,
            principal=principal,
            run_id=step.run_id,
            profile=self._default_profile,
            content=content_bytes,
            label_uncertain=label_uncertain,
        )
        result = self._submit(req)
        if not result.ok:
            raise _result_error(result)
        return builtin.ToolResult(ok=True, payload={"audit_event_id": result.audit_event_id})

    async def _build_connector_req(self, step: Step) -> EgressRequest:
        """Build the gated :class:`EgressRequest` for a connector_action ``step``.

        Shared by :meth:`dispatch_connector` (run-execution) and
        :meth:`dispatch_connector_read` (pre-run) so both mint the request — and
        resolve the EM-02 label — identically; only the gate set they then run
        differs (the read path skips the run-scoped envelope gate).
        """
        try:
            effect = build_effect(step, sandbox_roots=self._sandbox_roots)
        except AmbiguousEffectError as exc:
            raise EgressDeniedError(f"ambiguous_effect:{exc}") from exc
        if effect.kind is not EffectKind.CONNECTOR_ACTION:
            raise EgressDeniedError(f"dispatch_connector requires a connector_action step, got {effect.kind}")
        principal = Principal(user_id="broker", tenant_id=step.tenant_id, role="operator")
        # EM-02: resolve effective label via LabelResolver when
        # wired; fall back to _default_label (CONFIDENTIAL) for backward-compat.
        connector_container_id = step.id or step.run_id or ""
        if self._label_resolver is not None:
            connector_resolved = await self._label_resolver.resolve_with_provenance(
                tenant_id=step.tenant_id,
                container_id=connector_container_id,
                taint_ctx=None,
            )
            connector_label = connector_resolved.label
            connector_uncertain = connector_resolved.fail_safe  # F3 provenance
        else:
            connector_label = self._default_label
            connector_uncertain = False
        return EgressRequest(
            effect=effect,
            label=connector_label,
            principal=principal,
            run_id=step.run_id,
            profile=self._default_profile,
            content=None,
            label_uncertain=connector_uncertain,
        )

    async def dispatch_connector(
        self, step: Step, *, http_transport: Any | None = None
    ) -> builtin.ToolResult:
        """Async connector_action drop-in: same gates, then ConnectorTransport.

        Exposed for async callers (and as the awaited core of the sync
        :meth:`dispatch` bridge). Raises a :class:`ToolDispatchError` subclass on
        any deny so the SubAgent's existing handler routes it to step.tool_failed.
        """
        req = await self._build_connector_req(step)
        return await self._dispatch_connector_req(req, http_transport=http_transport)

    async def dispatch_connector_read(
        self, step: Step, *, http_transport: Any | None = None
    ) -> builtin.ToolResult:
        """Fully-gated connector egress for a PRE-RUN read (grounding retrieval).

        Runs the SAME deny-by-default gates as :meth:`dispatch_connector` — profile
        boundary, EM-03 signed policy, Rule-of-Two 3-axis, EM-02 egress-label
        cap, EM-09 irreversible-staging, and audit-before-act — but SKIPS the EM-07
        authorization-envelope gate, which presupposes a bound run envelope. The
        grounding producer runs this at submission time (``POST /api/command``),
        BEFORE the run dispatches and binds its envelope, so the envelope gate would
        otherwise deny-by-default. Every other external-effect control still applies
        (EM-09 still diverts any irreversible action to staging), so a mutating action
        can never use this path to skip 2-phase handling — it is a bounded relaxation
        (no run-scoped authorization), not an ungated bypass. Raises a
        :class:`ToolDispatchError` subclass on any deny.
        """
        req = await self._build_connector_req(step)
        return await self._dispatch_connector_req(req, http_transport=http_transport, skip_envelope=True)

    async def _dispatch_connector_req(
        self, req: EgressRequest, *, http_transport: Any | None, skip_envelope: bool = False
    ) -> builtin.ToolResult:
        # Fail-closed: no connector transport wired ⇒ refuse before any gate work
        # (a connector_action that "passes" with no transport would fail OPEN).
        if self._connector_transport is None:
            raise EgressDeniedError("connector_transport_not_configured")
        # IDENTICAL gate chain as the router path — connectors cannot skip a gate
        # (``skip_envelope`` omits ONLY the run-scoped EM-07 envelope gate; see
        # :meth:`dispatch_connector_read`).
        deny, allowed = self._run_gates(req, skip_envelope=skip_envelope)
        if deny is not None:
            raise _result_error(deny)
        assert allowed is not None
        # Cleared by every broker gate; hand off to the EM-06 transport, which
        # applies its own membership gate + credential isolation (candidate-1).
        try:
            cres = await self._connector_transport.dispatch(req, http_transport=http_transport)
        except ToolDispatchError:
            raise
        except Exception as exc:  # noqa: BLE001 - downstream connector/credential deny ⇒ fail-closed
            # CredentialError (undeclared/malformed action, unknown connector) and
            # any connector execution error are converted to a deny so the SubAgent
            # treats them as step.tool_failed — never as a silent success.
            raise EgressDeniedError(f"connector_dispatch_failed:{type(exc).__name__}:{exc}") from exc
        self._post_audit(req)
        return builtin.ToolResult(
            ok=True,
            payload={
                "audit_event_id": allowed[1].id,
                "connector_ok": bool(cres.ok),
                "connector_payload": dict(cres.payload),
            },
        )

    @staticmethod
    def _run_coroutine(coro: Coroutine[Any, Any, _T]) -> _T:
        """Run ``coro`` to completion from a synchronous caller.

        The SubAgent runs in an ``asyncio.to_thread`` worker (no running loop in
        that thread) → the common path is :func:`asyncio.run`. If a loop *is*
        already running on this thread (a future async caller using the sync
        drop-in), we run the coroutine on a dedicated single-shot worker thread +
        fresh loop so we never deadlock by blocking the live loop.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(coro)).result()


def _result_error(result: EgressResult) -> ToolDispatchError:
    """Map a denied :class:`EgressResult` to the matching broker exception.

    Shared by the sync router path and the connector path so a given deny
    rationale always surfaces as the same :class:`ToolDispatchError` subclass.
    """
    rationale = result.decision.rationale
    if rationale.startswith("envelope_suspend"):
        return EnvelopeSuspendedError(rationale)
    if rationale == "audit_append_failed":
        return AuditAppendError(rationale)
    if rationale.startswith("staged:"):
        return StagingHeldError(rationale)
    return EgressDeniedError(rationale)
