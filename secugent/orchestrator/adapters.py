# SPDX-License-Identifier: Apache-2.0
"""PHASE 8 production wiring — bridge real HeadAgent/Dispatcher to orchestrator.

Two adapters implement the existing
:class:`secugent.orchestrator.runner.PlannerProtocol` /
:class:`secugent.orchestrator.runner.DispatcherProtocol` while delegating to
the real synchronous ``HeadAgent`` / ``Dispatcher`` (wrapped via
:func:`asyncio.to_thread`).

Drift reconciliation (vs. PHASE 8 prompt):

* Existing protocol kwargs ``(*, run_id, command, context)`` / ``(*, run_id,
  plan)`` are kept; the adapter constructs ``HeadPlanRequest`` internally so
  no orchestrator change is required.
* The PHASE 8 prompt's ``ApprovalToken`` concept maps to the existing
  :class:`secugent.core.contracts.Approval`; ``approval_service.validate``
  maps to ``request_plan_approval`` (HEAD) + ``grant`` (here) + per-step
  ``consume`` (inside ``SubAgent``).
* ``tenant_id`` / ``regulations_snapshot`` are PHASE 9 fields and are
  deliberately NOT plumbed yet — see ``docs/PHASE_08_NOTES.md``.

Fail-closed retry policy:

* tenacity ``Retrying(stop=stop_after_attempt(N), wait=wait_exponential)``
  re-runs only on :class:`PlannerTransientError`.
* Anything else (``ValueError``, ``MissingRiskSectionError``, etc.) is
  wrapped in :class:`PlannerFailedError` immediately.
* Exhausted transient retries are likewise raised as
  :class:`PlannerFailedError` so the orchestrator only has to catch one
  terminal type.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from tenacity import (
    RetryError,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from secugent.agents.dispatcher import DispatcherResult
from secugent.agents.head_agent import HeadPlanRequest, PartialApprovalResult
from secugent.core.contracts import (
    AI_GENERATED_MARKER,
    Approval,
    Event,
    MissingRiskSectionError,
    Plan,
)
from secugent.core.llm_client import LLMError
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import RegulationsLoadError
from secugent.core.sec.envelope import AuthorizationEnvelope, EnvelopeUsage, bind_envelope
from secugent.core.sec.envelope_builder import build_minimal_envelope
from secugent.core.sec.envelope_diff import envelope_fingerprint
from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import TenantId
from secugent.orchestrator.errors import (
    DispatcherResultMalformed,
    PlannerFailedError,
    PlannerTransientError,
)
from secugent.orchestrator.runner import PlanLike
from secugent.regulations.tenant_loader import RegulationsLoader, RegulationsSchemaError
from secugent.steer.snapshots import RunCheckpoint, SQLiteCheckpointStore

if TYPE_CHECKING:  # pragma: no cover
    from secugent.agents.head_agent import HeadAgent
    from secugent.agents.sub_agent import SubAgent
    from secugent.audit.hash_chain import ChainedEventStore
    from secugent.core.approval import ApprovalService

_logger = logging.getLogger(__name__)


# BDP_02 item 4: ``HeadPlannerAdapter`` / ``DispatcherAdapter`` are re-exported as
# part of the public embed-SDK surface (``secugent.sdk``) so SI/vendors can wire the
# real HEAD planner / Dispatcher behind the same oversight gate. This is a public
# surface tidy-up only — no behavior change here; the re-export lives in
# ``secugent/sdk/__init__.py`` and these names stay the single definition site.
__all__ = [
    "HeadPlannerAdapter",
    "DispatcherAdapter",
    "RunEngineRegistry",
    "SubFactory",
]


SubFactory = Callable[[str, str, "str | None", OversightEngine, str], "SubAgent"]
"""``(actor, plan_approval_id, envelope_hash, oversight, regulations_version)
-> SubAgent`` factory (G-H4 per-run engine threaded explicitly)."""


class RunEngineRegistry(Protocol):
    """Minimal hook a :class:`DispatcherAdapter` uses to publish the per-run
    :class:`OversightEngine` so STEER can reach the *correct* run's engine.

    Implemented by ``AppState`` (a ``dict[str, OversightEngine]`` wrapper). Kept
    as a Protocol so the adapter stays decoupled from the FastAPI layer and is
    trivially fakeable in tests. ``unregister_run_engine`` is idempotent and must
    never raise on a missing key (a no-op for an absent run)."""

    def register_run_engine(self, run_id: str, engine: OversightEngine) -> None: ...

    def unregister_run_engine(self, run_id: str) -> None: ...


# ---------------------------------------------------------------------------
# HeadPlannerAdapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RetryPolicy:
    """Tenacity-driven retry parameters; isolated so tests can speed it up."""

    max_attempts: int = 3
    wait_initial: float = 0.5
    wait_max: float = 4.0


class HeadPlannerAdapter:
    """Wraps :class:`secugent.agents.head_agent.HeadAgent` for the orchestrator.

    Implements the existing ``PlannerProtocol.plan(*, run_id, command, context)``
    contract. Internally builds a :class:`HeadPlanRequest`, runs the sync
    ``HeadAgent.plan`` via :func:`asyncio.to_thread`, and applies a fail-closed
    retry policy on transient LLM errors.
    """

    def __init__(
        self,
        head_agent: HeadAgent,
        *,
        max_attempts: int = 3,
        wait_initial: float = 0.5,
        wait_max: float = 4.0,
    ) -> None:
        self._head = head_agent
        self._policy = _RetryPolicy(
            max_attempts=max_attempts,
            wait_initial=wait_initial,
            wait_max=wait_max,
        )

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        request = HeadPlanRequest(
            run_id=run_id,
            goal=command,
            available_subs=list(context.get("available_subs", []) or []),
            agent_specs=list(context.get("agent_specs", []) or []),
            head_specs=list(context.get("head_specs", []) or []),
        )

        try:
            for attempt in Retrying(
                stop=stop_after_attempt(self._policy.max_attempts),
                wait=wait_exponential(
                    multiplier=1.0,
                    min=self._policy.wait_initial,
                    max=self._policy.wait_max,
                ),
                retry=retry_if_exception_type(PlannerTransientError),
                reraise=True,
            ):
                with attempt:
                    return await self._invoke_once(request)
        except PlannerTransientError as exc:
            # All retries exhausted → terminal failure
            raise PlannerFailedError(f"planning_error: transient_exhausted: {exc}") from exc
        except RetryError as exc:  # pragma: no cover - tenacity safety net
            raise PlannerFailedError(f"planning_error: retry_error: {exc}") from exc
        # Unreachable — Retrying with reraise=True either returns or raises.
        raise PlannerFailedError("planning_error: unreachable")  # pragma: no cover

    async def _invoke_once(self, request: HeadPlanRequest) -> PlanLike:
        try:
            plan: Plan = await asyncio.to_thread(self._head.plan, request)
        except LLMError as exc:
            raise PlannerTransientError(str(exc)) from exc
        except MissingRiskSectionError as exc:
            raise PlannerFailedError(f"planning_error: missing_risk_section: {exc}") from exc
        except Exception as exc:
            raise PlannerFailedError(f"planning_error: {type(exc).__name__}: {exc}") from exc

        if not isinstance(plan, Plan):
            # Defensive: a future HeadAgent refactor could return a non-Plan
            # — surface that as a terminal planning failure.
            raise PlannerFailedError(f"planning_error: head_returned_non_plan: {type(plan).__name__}")
        return PlanLike(
            id=plan.id,
            summary=plan.goal,
            steps=list(plan.steps),
            raw=plan,
            # DA-H2: carry the native Plan's AI-generated provenance forward so the
            # runner surfaces it on ``/runs/{id}`` for the Plan Review UI (W5-c).
            ai_generated=plan.ai_generated,
            model_id=plan.model_id,
            regulations_version=plan.regulations_version,
            # DA-H4 (W5-c a′): thread the HEAD-declared risks + step→sub mapping so
            # the runner persists them for ``GET /api/plans/{id}`` (the Plan Review
            # risk section + per-step assignment). Serialised to plain dicts here so
            # the runner stays free of the concrete ``Risk`` type.
            risks=[risk.model_dump(mode="json") for risk in plan.risks],
            assigned_subs=dict(plan.assigned_subs),
        )


# ---------------------------------------------------------------------------
# DispatcherAdapter
# ---------------------------------------------------------------------------


class DispatcherAdapter:
    """Wraps :class:`secugent.agents.dispatcher.Dispatcher` for the orchestrator.

    Implements the existing ``DispatcherProtocol.dispatch(*, run_id, plan)``
    contract. Flow:

    1. Validate ``plan.raw`` is a real :class:`Plan` (else
       :class:`DispatcherResultMalformed`).
    2. ``head.request_plan_approval(plan_native)`` → pending Approval.
    3. ``approval_service.grant(...)`` → approved (this is the production
       analogue of the operator-side approval; orchestrator-level Plan Review
       Gate already gated us via the asyncio approval queue).
    4. Run the synchronous ``Dispatcher.dispatch`` in a thread.
    5. Convert :class:`DispatcherResult` into the orchestrator-friendly dict
       (PHASE 8 §2.1 requires ``{"steps_executed","outputs","redactions"}``;
       we keep the legacy ``{"subs","partial_failure","failure_reason"}`` keys
       alongside for ``runner._summarise_results`` compatibility).
    """

    def __init__(
        self,
        *,
        head: HeadAgent,
        dispatcher: Any,  # secugent.agents.dispatcher.Dispatcher — Any for fakes
        approval_service: ApprovalService,
        sub_factory: SubFactory,
        fallback_engine: OversightEngine,
        regulations_loader: RegulationsLoader | None = None,
        run_engine_registry: RunEngineRegistry | None = None,
        checkpoint_store: SQLiteCheckpointStore | None = None,
        audit_chain: ChainedEventStore | None = None,
        runner: Any = None,
    ) -> None:
        self._head = head
        self._dispatcher = dispatcher
        self._approvals = approval_service
        self._sub_factory = sub_factory
        # G-H4: when a directory-mode loader is wired, every dispatch resolves the
        # per-run effective REGULATIONS and builds a fresh per-run engine. When it
        # is ``None`` (file-mode / dev / explicit injection) the boot fallback
        # engine — already fail-closed by G-C1 — is reused byte-for-byte.
        self._regulations_loader = regulations_loader
        self._fallback_engine = fallback_engine
        # Optional STEER registry hook (option A): publish the per-run engine so a
        # ``POST /steer`` for this run reaches THIS engine, not a stale shared one.
        self._run_engines = run_engine_registry
        # SG-20260621-02: checkpoint store and audit chain for pause handling.
        self._checkpoint_store = checkpoint_store
        self._audit_chain = audit_chain
        # SG-20260621-20: runner reference for notify_pause_completed callback.
        # When set, _handle_pause_result drives the state machine after checkpoint write.
        self._runner: Any = runner

    async def dispatch(
        self,
        *,
        run_id: str,
        plan: PlanLike,
        approved_step_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        plan_native = plan.raw
        if not isinstance(plan_native, Plan):
            raise DispatcherResultMalformed(
                f"plan.raw must be a Plan instance, got {type(plan_native).__name__}"
            )

        # G-H4: resolve the per-run effective REGULATIONS and build ONE fresh
        # engine for this dispatch (shared read-only across its SUB workers).
        # Fail-closed: a load/merge/relaxation error fails the run — never an
        # allow-all fallback (spec §2.2 invariant 1).
        per_run_engine, reg_version = self._resolve_per_run_engine(run_id, plan_native)

        # EM-07/08: Plan Review approves a minimal envelope. Bind its fingerprint
        # into the approval scope, and bind the envelope to the run context so the
        # SubAgent (running in the to_thread worker — contextvars propagate) sees
        # it and re-verifies the hash on consume. Within-envelope is the happy path.
        # The data-label ceiling matches the broker's conservative default effect
        # label (CONFIDENTIAL) so the broker EnvelopeGate (EM-08 go-live) admits
        # in-plan effects rather than suspending them on a label mismatch.
        envelope = build_minimal_envelope(plan_native, max_data_label=DataLabel.CONFIDENTIAL)
        # DA-H4: a partial Plan Review approval narrows the minted scope to the
        # selected step subset; ``None`` ⇒ full plan (legacy behaviour unchanged).
        approval = self._issue_plan_approval(plan_native, envelope, approved_step_ids=approved_step_ids)

        # SG-20260603-01: compute the envelope fingerprint eagerly and thread it
        # as an explicit argument. This decouples envelope propagation from the
        # thread execution model (contextvar + copy_context). The bind_envelope
        # binding below is kept as a legacy/compatibility path.
        env_hash: str | None = envelope_fingerprint(envelope)

        # STEER registry (option A): publish the per-run engine for the lifetime
        # of this dispatch only, and ALWAYS remove it afterwards (bounded memory,
        # no cross-run leakage). ``finally`` runs even on dispatcher failure.
        if self._run_engines is not None:
            self._run_engines.register_run_engine(run_id, per_run_engine)
        try:
            with bind_envelope(envelope, EnvelopeUsage()):
                result = await asyncio.to_thread(
                    self._dispatcher.dispatch,
                    plan_native,
                    approval,
                    sub_factory=self._sub_factory,
                    envelope_hash=env_hash,
                    oversight=per_run_engine,
                    regulations_version=reg_version,
                )
        finally:
            if self._run_engines is not None:
                self._run_engines.unregister_run_engine(run_id)

        if result is None:
            raise DispatcherResultMalformed("dispatcher_returned_none")
        if not isinstance(result, DispatcherResult):
            raise DispatcherResultMalformed(
                f"dispatcher returned {type(result).__name__}, expected DispatcherResult"
            )

        # SG-20260621-02: if any sub-agent paused, write checkpoint + emit steer.paused.
        # We inspect each SubAgentResult directly — DispatcherResult.sub_results is
        # {actor: SubAgentResult}. A pause on any sub is propagated.
        for _actor, sub_result in result.sub_results.items():
            if getattr(sub_result, "paused_at_step_id", None) is not None:
                await self._handle_pause_result(run_id, sub_result)
                break  # one pause event per dispatch is sufficient

        return _result_to_dict(result)

    # ------------------------------------------------------------------ #
    # Pause handling (SG-20260621-02)
    # ------------------------------------------------------------------ #

    async def _handle_pause_result(self, run_id: str, sub_result: Any) -> None:
        """Write RunCheckpoint + emit steer.paused when paused_at_step_id is set.

        Durable-before-broadcast: checkpoint is written first, then steer.paused
        is appended to the audit chain.  If checkpoint write fails, steer.failed
        is emitted instead and the run remains RUNNING (fail-open on checkpoint
        storage failure — the run is not aborted by a storage glitch).
        """
        if self._checkpoint_store is None:
            _logger.warning(
                "pause observed for run %s but no checkpoint_store wired; steer.paused not recorded",
                run_id,
            )
            return

        checkpoint = RunCheckpoint(
            checkpoint_id=str(uuid.uuid4()),
            run_id=run_id,
            tenant_id=getattr(sub_result, "tenant_id", "legacy-default"),
            step_index=getattr(sub_result, "step_index", 0),
            pending_step_ids=list(getattr(sub_result, "pending_step_ids", [])),
            completed_step_ids=list(getattr(sub_result, "completed_step_ids", [])),
            session_patch_set=list(getattr(sub_result, "session_patch_set", [])),
            patch_remaining_ttl=dict(getattr(sub_result, "patch_remaining_ttl", {})),
            regulations_version=getattr(sub_result, "regulations_version", "0.0.0"),
            envelope_hash=getattr(sub_result, "envelope_hash", ""),
            rule_of_two_axes=list(getattr(sub_result, "rule_of_two_axes", [])),
            approval_scope_ref=getattr(sub_result, "approval_scope_ref", ""),
            staged_effect_disposition=list(getattr(sub_result, "staged_effect_disposition", [])),
            file_before_images_ref=dict(getattr(sub_result, "file_before_images_ref", {})),
            directive_log_ref=list(getattr(sub_result, "directive_log_ref", [])),
            created_at=datetime.now(tz=UTC).isoformat(),
            actor=getattr(sub_result, "actor", "system"),
        )

        try:
            snap_ref = self._checkpoint_store.write(checkpoint)
        except Exception:
            _logger.exception("checkpoint write failed for run %s; emitting steer.failed", run_id)
            # E4: write failure → emit steer.failed, keep run RUNNING (not aborted).
            # SG-20260621-23b: §C-2 필수 필드 추가 (decision, input_hash,
            # regulations_version, rule_of_two_axes, risk_score, actor dict).
            if self._audit_chain is not None:
                _error_key = "checkpoint_write_failed"
                failed_ev = Event(
                    tenant_id=TenantId(checkpoint.tenant_id),
                    actor="system",
                    type="steer.failed",
                    severity="warn",
                    run_id=run_id,
                    payload={
                        "error": _error_key,
                        "gate": "steer",
                        "decision": "reject",
                        "input_hash": hashlib.sha256(_error_key.encode()).hexdigest(),
                        "regulations_version": checkpoint.regulations_version,
                        "rule_of_two_axes": checkpoint.rule_of_two_axes,
                        "risk_score": None,
                        "rationale": "체크포인트 기록 실패",
                        "actor": {"type": "sec", "id": "system"},
                    },
                )
                self._audit_chain.append_event(failed_ev)
            return

        # SG-20260621-20: Drive state machine INTERRUPT_REQUESTED→PAUSING→PAUSED_SNAPSHOTTED
        # after durable checkpoint write succeeds (before steer.paused broadcast).
        # Use getattr to remain compatible with __new__-created instances in tests
        # that pre-date the runner parameter.
        _runner = getattr(self, "_runner", None)
        if _runner is not None:
            _runner.notify_pause_completed(run_id)

        # Durable-before-broadcast: checkpoint committed — now emit steer.paused.
        # SG-20260621-23b NEW-2: actor도 §C-2 구조화 dict로 payload에 포함한다.
        if self._audit_chain is not None:
            paused_ev = Event(
                tenant_id=TenantId(checkpoint.tenant_id),
                actor="system",
                type="steer.paused",
                severity="info",
                run_id=run_id,
                payload={
                    "paused_at_step_id": sub_result.paused_at_step_id,
                    "context_snapshot_ref": snap_ref.uri,
                    "gate": "steer",
                    "decision": "approve",
                    "input_hash": hashlib.sha256(snap_ref.uri.encode()).hexdigest(),
                    "regulations_version": checkpoint.regulations_version,
                    "rule_of_two_axes": checkpoint.rule_of_two_axes,
                    "risk_score": None,
                    "rationale": f"스텝 {sub_result.paused_at_step_id}에서 실행 일시정지",
                    "actor": {"type": "sec", "id": "system"},
                },
            )
            self._audit_chain.append_event(paused_ev)
        else:
            _logger.warning(
                "checkpoint written for run %s (ref=%s) but no audit_chain wired; steer.paused not emitted",
                run_id,
                snap_ref.uri,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _resolve_per_run_engine(self, run_id: str, plan: Plan) -> tuple[OversightEngine, str]:
        """Resolve the per-run :class:`OversightEngine` + effective version (G-H4).

        * No loader (file-mode / dev / explicit injection) → reuse the boot
          fallback engine and its version verbatim (byte-for-byte unchanged path,
          spec invariant 6). The fallback is already fail-closed (G-C1).
        * Loader present → ``for_run(run_id, tenant_id)`` resolves the effective
          (base + tenant override) bundle and a FRESH engine is built per dispatch.
          A missing tenant policy yields the (stricter) org base — acceptable.
        * A corrupt/relaxing policy raises ``RegulationsLoadError`` /
          ``RegulationsSchemaError`` → surfaced as ``DispatcherResultMalformed`` so
          the run FAILS. We never fall back to allow-all or bare base on error
          (fail-closed, spec §2.2 / SECURITY_CONTRACT §2.1).
        """
        if self._regulations_loader is None:
            return self._fallback_engine, self._fallback_engine.regulations.version
        try:
            bundle = self._regulations_loader.for_run(run_id=run_id, tenant_id=plan.tenant_id)
        except (RegulationsLoadError, RegulationsSchemaError) as exc:
            # Do not echo policy file contents; the exception message is bounded.
            raise DispatcherResultMalformed(
                f"regulations_resolution_failed: {type(exc).__name__}: {exc}"
            ) from exc
        return OversightEngine(bundle.effective), bundle.effective.version

    def _issue_plan_approval(
        self,
        plan: Plan,
        envelope: AuthorizationEnvelope,
        *,
        approved_step_ids: list[str] | None = None,
    ) -> Approval:
        # In production HeadAgent.request_plan_approval mints a *pending*
        # approval bound to all plan step ids. The orchestrator's Plan Review
        # Gate already authorised the run by the time we reach here, so we
        # also grant the approval so Dispatcher.dispatch passes its sanity
        # check (status == 'approved'). The approval is bound to ``envelope``
        # (EM-08) so a substituted envelope at execution fails closed.
        #
        # DA-H4 (W5-c): when ``approved_step_ids`` is supplied (a partial Plan
        # Review approval), build a ``PartialApprovalResult`` so HeadAgent mints a
        # scope bound to EXACTLY those step ids (and the real Rule of Two axes of
        # that subset). Unselected steps are absent from the scope, so the core
        # ``_enforce_scope`` (UNCHANGED) rejects them at execution — fail-closed,
        # deny-by-default (INV-W5C-1 / INV-W5C-5). ``None`` ⇒ full plan approval.
        env_hash = envelope_fingerprint(envelope)
        if approved_step_ids is None:
            # Full plan approval — call signature unchanged (legacy/back-compat).
            pending = self._head.request_plan_approval(plan, envelope_hash=env_hash)
        else:
            selected = sorted(set(approved_step_ids))
            all_ids = [s.id for s in plan.steps]
            deferred = sorted(set(all_ids) - set(selected))
            partial = PartialApprovalResult(approved_step_ids=selected, deferred_step_ids=deferred)
            pending = self._head.request_plan_approval(plan, partial=partial, envelope_hash=env_hash)
        return self._approvals.grant(pending.id, reason="orchestrator-approved")


def _result_to_dict(result: DispatcherResult) -> dict[str, Any]:
    """Convert :class:`DispatcherResult` into the orchestrator-friendly dict.

    Required keys (PHASE 8 §2.1):
      * ``steps_executed`` — int, count of outcomes with ``status=="completed"``
      * ``outputs``        — list of {actor, step_id, payload}
      * ``redactions``     — list (placeholder; logger.redact already applied
                             at store level — kept for forward compatibility)

    Compatibility keys (read by ``runner._summarise_results`` etc.):
      * ``subs``            — {actor: {"status", "completed_steps"}}
      * ``partial_failure`` — bool
      * ``failure_reason``  — str | None
    """
    subs: dict[str, dict[str, Any]] = {}
    outputs: list[dict[str, Any]] = []
    total_completed = 0
    partial = False
    failure_reasons: list[str] = []

    for actor, sub_result in result.sub_results.items():
        completed = sum(1 for o in sub_result.outcomes if o.status == "completed")
        total_completed += completed
        status = "completed" if sub_result.succeeded else "failed"
        if not sub_result.succeeded:
            partial = True
            # Surface the first non-terminal status for diagnostics.
            for o in sub_result.outcomes:
                if o.status != "completed":
                    failure_reasons.append(f"{actor}:{o.status}")
                    break
        subs[actor] = {"status": status, "completed_steps": completed}
        for o in sub_result.outcomes:
            if o.status == "completed" and o.tool_result is not None:
                outputs.append(
                    {
                        "actor": actor,
                        "step_id": o.step.id,
                        "payload": o.tool_result.payload,
                        # DA-H2: every agent free-text output crossing this
                        # orchestrator boundary toward an operator carries the
                        # standardized Korean AI-identification marker. Attached
                        # here (NOT in ``core.llm_client``) so BYO-Model neutrality
                        # is preserved (INV-H2-3) — the marker is the caller's
                        # responsibility, never the SDK wrapper's.
                        "ai_identification": AI_GENERATED_MARKER,
                    }
                )

    failure_reason: str | None = None
    if partial:
        failure_reason = "sub_error: " + ", ".join(failure_reasons) if failure_reasons else "sub_error"

    return {
        "steps_executed": total_completed,
        "outputs": outputs,
        "redactions": [],
        "subs": subs,
        "partial_failure": partial,
        "failure_reason": failure_reason,
        # DA-H2: aggregate AI-identification marker for the whole dispatch result
        # so an operator surface that renders the result envelope (not just a
        # single output) still shows the AI-generated notice.
        "ai_identification": AI_GENERATED_MARKER,
    }
