# SPDX-License-Identifier: Apache-2.0
"""Background pipeline driver.

Responsibilities:

* ``start()`` initialises an :class:`asyncio.Semaphore` worker pool.
* ``enqueue()`` schedules an :func:`asyncio.create_task` wrapping
  :meth:`_run_pipeline`.
* The pipeline transitions PENDING → PLANNING → AWAITING_APPROVAL (or
  APPROVED if ``auto_approve``) → EXECUTING → REPORTING → COMPLETED.
* Any exception in HEAD / Dispatcher / SUB is converted into FAILED +
  ``run.failed`` event so the orchestrator itself stays alive.
* ``stop()`` cancels in-flight tasks, marks the affected runs CANCELLED, and
  causes new ``enqueue()`` calls to raise :class:`OrchestratorStoppedError`.

The orchestrator deliberately depends on *protocols* (planner / dispatcher /
event publisher) rather than concrete classes so unit tests can inject
deterministic stubs without spinning up FastAPI.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from secugent.config import OrchestratorConfig
from secugent.core.rule_of_two import Axis, requires_hitl
from secugent.observability.metrics import HITL_BACKLOG, RUN_LATENCY
from secugent.orchestrator.errors import (
    DispatcherResultMalformed,
    PlannerFailedError,
)
from secugent.orchestrator.events import OrchestratorEventType as ET
from secugent.orchestrator.evidence_binding import (
    EvidenceBindingError,
    evidence_from_connector_payload,
)
from secugent.orchestrator.lease import LeaseLostError, LeaseManager
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunEvent,
    RunRecord,
    RunState,
    RunStateStore,
)
from secugent.steer.interrupt_state import (
    InterruptState,
    InterruptStateError,
    RunInterruptRecord,
)
from secugent.steer.snapshots import SnapshotRef

if TYPE_CHECKING:  # pragma: no cover - typing-only imports, no runtime dependency.
    # ``secugent.cost`` is the BSL-1.1 Enterprise quota-enforcement tier and is
    # NOT shipped in the public OSS Core wheel. The orchestrator only holds an
    # OPTIONAL, injected ``CostLedger`` (defaults to ``None`` = no enforcement),
    # so the annotation is type-only and ``QuotaExceededError`` is needed only on
    # the enforcement path. Importing the tier at module load would break
    # standalone import of Core (``ModuleNotFoundError: secugent.cost``) and leak
    # the tier (open-core boundary I2/I8). The runtime ledger is supplied by the
    # Enterprise wiring; the ``except`` path resolves QuotaExceededError lazily
    # (so it is imported there, not here — only CostLedger is needed for typing).
    from secugent.cost.accounting import CostLedger

__all__ = [
    "ApprovalDecision",
    "CheckpointMismatchError",
    "CheckpointStoreProtocol",
    "OrchestratorStoppedError",
    "OversightEngineProtocol",
    "PlanLike",
    "PlannerProtocol",
    "DispatcherProtocol",
    "EventPublisher",
    "ResumeRequiresHITLError",
    "RunNotDispatchingError",
    "RunOrchestrator",
    "SteerHandlerProtocol",
    "SubFactory",
]


_logger = logging.getLogger("secugent.orchestrator")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OrchestratorStoppedError(RuntimeError):
    """Raised when :meth:`RunOrchestrator.enqueue` is called after stop()."""


class RunNotDispatchingError(RuntimeError):
    """D-L: resolve_run_engine(run_id) is None → 런이 현재 디스패치 중이 아님.

    비디스패칭 런에 대한 pause 요청은 silent fallback 금지 — 반드시 raise.
    """


class ResumeRequiresHITLError(RuntimeError):
    """INV-9 / D-F: 재개 시 Rule-of-Two 3축 → HITL 강제.

    패치로 인해 axes가 3개가 되면 resume_from_checkpoint가 이 예외를 raise한다.
    """


class CheckpointMismatchError(KeyError):
    """재개 요청의 SnapshotRef가 저장소에서 찾을 수 없음 (from_ref 불일치)."""


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@dataclass
class PlanLike:
    """Minimal plan shape the orchestrator needs.

    Real HEAD planners return Pydantic :class:`secugent.core.contracts.Plan`
    objects; the orchestrator only reads ``id``, ``steps`` (length), and the
    free-form ``summary``.
    """

    id: str
    summary: str
    steps: list[Any]
    raw: Any = None  # the underlying Plan or compatible object
    # AI-generated provenance threaded from the native Plan through the
    # orchestrator abstraction so the runner can surface it on ``/runs/{id}``
    # without importing the concrete ``Plan`` type. Defaults mark any plan
    # honestly as AI-generated even when the upstream adapter (e.g. a resume
    # re-dispatch, or a remote A2A planner) does not carry a native Plan.
    ai_generated: bool = True
    model_id: str = "unknown"
    regulations_version: str = "0.0.0"
    # The planner-declared potential risks and step→sub mapping, threaded as plain
    # JSON-friendly structures (NOT concrete ``Risk``/``Plan`` types, keeping the
    # runner import-free of ``core.contracts``). Persisted onto
    # the stored plan dict so ``GET /api/plans/{id}`` can render the HEAD risk
    # section + step assignment for the Plan Review screen. Empty defaults keep
    # legacy / stub planners that do not carry risks backward compatible.
    risks: list[dict[str, Any]] = field(default_factory=list)
    assigned_subs: dict[str, str] = field(default_factory=dict)


class PlannerProtocol(Protocol):
    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike: ...


class DispatcherProtocol(Protocol):
    async def dispatch(
        self,
        *,
        run_id: str,
        plan: PlanLike,
        approved_step_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Execute ``plan``. ``approved_step_ids`` narrows the minted
        plan-approval scope to a step subset (``None`` = full plan)."""
        ...


# ---------------------------------------------------------------------------
# 협력자 Protocol (Any 대체 — mypy strict 체크 가능)
# ---------------------------------------------------------------------------


@runtime_checkable
class OversightEngineProtocol(Protocol):
    """runner가 호출하는 OversightEngine 메서드 계약.

    set_paused 반환값(bool)이 명시돼 멱등 반환값 검사에서도 사용.
    current_pause_request_id는 BLOCKING-1 fix: dedup 판정용 순수 read 프로브.
    """

    def set_paused(
        self,
        *,
        paused: bool,
        request_id: str,
        actor: str,
        stop_mode: bool = ...,
    ) -> bool: ...

    def is_paused(self) -> bool: ...

    def current_pause_request_id(self) -> str | None: ...


@runtime_checkable
class CheckpointStoreProtocol(Protocol):
    """runner가 호출하는 체크포인트 저장소 메서드 계약."""

    def write(self, checkpoint: Any) -> Any: ...

    def resolve(self, ref: Any) -> Any: ...


@runtime_checkable
class SteerHandlerProtocol(Protocol):
    """runner가 호출하는 SteerHandler 메서드 계약."""

    def emit_resume_from_checkpoint(
        self,
        *,
        run_id: str,
        from_checkpoint_id: str,
        actor: str,
        rule_of_two_axes: list[str] | None = ...,
    ) -> Any: ...


EventPublisher = Callable[[str, str, dict[str, Any]], Awaitable[None]]
"""``async (run_id, topic, payload) -> None``."""

SubFactory = Callable[[str, str, "str | None", Any, str], Any]
"""``(actor, plan_approval_id, envelope_hash, oversight, regulations_version)
-> SubAgent`` — kept here so the FastAPI layer can wire concrete SUB agents
without the orchestrator caring. ``oversight`` is the per-run
:class:`~secugent.core.mechanical_oversight.OversightEngine` threaded
explicitly (never via contextvar, mirroring ``envelope_hash``) so each run's
SUBs read that run's effective tenant policy; ``regulations_version`` is the
effective policy version stamped onto audit events."""


# ---------------------------------------------------------------------------
# Approval signal
# ---------------------------------------------------------------------------


@dataclass
class ApprovalDecision:
    action: str  # "approve" | "reject" | "amend"
    approver: str | None = None
    reason: str | None = None
    instruction: str | None = None  # amend only
    # Plan Review partial approval. ``None`` ⇒ full plan approval
    # (every step in scope — the legacy binary ``approve`` behaviour). A non-None
    # list narrows the dispatcher's minted ``ApprovalScope`` to EXACTLY these step
    # ids (deny-by-default: unselected steps are never authorized, INV-W5C-5). Only
    # meaningful when ``action == "approve"``.
    approved_step_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class RunOrchestrator:
    """Asyncio-based pipeline driver. Single-process, in-memory queue."""

    def __init__(
        self,
        *,
        planner: PlannerProtocol,
        dispatcher: DispatcherProtocol,
        state_store: RunStateStore | None = None,
        config: OrchestratorConfig | None = None,
        publish_event: EventPublisher | None = None,
        lease_manager: LeaseManager | None = None,
        worker_id: str = "node-local",
        lease_ttl_seconds: int = 60,
        cost_ledger: CostLedger | None = None,
        external_engine_registry: Any = None,
    ) -> None:
        self._planner = planner
        self._dispatcher = dispatcher
        self._store: RunStateStore = state_store or InMemoryRunStateStore()
        self._config = config or OrchestratorConfig()
        self._publish = publish_event or _noop_publish
        # Optional HA single-leader lease. ``None`` = single-node mode:
        # the dispatch path runs exactly as before (no acquire/release). When set,
        # a run is only dispatched while this node holds that run's lease.
        self._lease_manager = lease_manager
        self._worker_id = worker_id
        self._lease_ttl_seconds = lease_ttl_seconds
        # Optional cost ledger (S8B). None = skip quota enforcement (backward compat).
        self._cost_ledger = cost_ledger
        self._semaphore: asyncio.Semaphore | None = None
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._approval_queues: dict[str, asyncio.Queue[ApprovalDecision]] = {}
        self._stopped = False
        self._lifecycle_lock = asyncio.Lock()
        # Per-run OversightEngine registry (INV-R6 — contextvar 금지).
        # runner가 소유; register_run_engine/deregister_run_engine 호출로 관리.
        # _engine_registry_lock은 threading.Lock (동기 API에서 접근하므로 asyncio.Lock 불가).
        # OversightEngineProtocol로 타입 좁히기.
        self._engine_registry: dict[str, OversightEngineProtocol] = {}
        self._engine_registry_lock = threading.Lock()
        # external registry delegate (AppState._run_engines via
        # run_engine_registry=self wiring in main.py). When set, all engine
        # registry operations delegate here so request_pause sees the correct
        # per-run engines registered by DispatcherAdapter.
        self._external_engine_registry: Any = external_engine_registry
        # 이미 재디스패치된 체크포인트 참조 추적 (INV-3 멱등 resume)
        self._resumed_checkpoints: set[str] = set()
        self._resumed_checkpoints_lock = threading.Lock()
        # per-run interrupt state machine records (INV-SM-1).
        # Serialises pause/resume verbs for the same run so illegal transitions
        # (e.g. RESUMING→resume) raise InterruptStateError, not silent no-ops.
        self._interrupt_records: dict[str, RunInterruptRecord] = {}
        self._interrupt_records_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._semaphore is None:
                self._semaphore = asyncio.Semaphore(self._config.max_concurrent_runs)
                self._stopped = False
                _logger.info(
                    "orchestrator started max_concurrent=%d auto_approve=%s",
                    self._config.max_concurrent_runs,
                    self._config.auto_approve,
                )

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            self._stopped = True
            tasks = list(self._tasks.items())
        for _run_id, task in tasks:  # noqa: B007 - run_id used in second loop only
            task.cancel()
        for run_id, task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: S110 - intentional swallow; see docstring
                pass
            # Best-effort: ensure cancelled runs land in CANCELLED.
            record = await self._store.get(run_id)
            if record and record.state not in _TERMINAL:
                await self._store.update_state(
                    run_id, RunState.CANCELLED, failure_reason="orchestrator_stopped"
                )
                await self._record_and_publish(
                    run_id,
                    ET.RUN_CANCELLED,
                    {"reason": "orchestrator_stopped"},
                )
        self._tasks.clear()
        _logger.info("orchestrator stopped")

    @property
    def is_running(self) -> bool:
        return self._semaphore is not None and not self._stopped

    @property
    def lease_manager(self) -> LeaseManager | None:
        """The HA lease manager (``None`` = single-node). Read-only accessor used
        by boot recovery so it can probe per-run lease ownership (F9)."""
        return self._lease_manager

    def set_lease_manager(self, lease_manager: LeaseManager | None) -> None:
        """Mount/replace the HA lease manager AFTER construction (F3).

        The PG lease backend needs the PG event store, which is only set in the
        lifespan AFTER :class:`AppState` is built (``pg_store`` is ``None`` during
        ``__init__``). The boot path therefore re-resolves the lease manager once
        the PG store is live and installs it here. Must be called before any run
        is dispatched (i.e. in the lifespan, before recovery/enqueue) so the
        single-leader guarantee holds from the first dispatch."""
        self._lease_manager = lease_manager

    # ------------------------------------------------------------------ #
    # Per-run engine registry (INV-R6 — contextvar 절대 금지)
    # ------------------------------------------------------------------ #

    def register_run_engine(self, run_id: str, engine: OversightEngineProtocol) -> None:
        """런 시작 시 per-run OversightEngine을 등록한다.

        INV-R6: pause 신호는 이 레지스트리를 통해 명시 전달 — contextvar 금지.
        Lane B의 wiring에서 dispatch 직전에 호출한다.
        external_engine_registry가 설정되면 위임한다.
        engine은 OversightEngineProtocol로 좁혀 set_paused 호출 검증.
        """
        if self._external_engine_registry is not None:
            self._external_engine_registry.register_run_engine(run_id, engine)
            return
        with self._engine_registry_lock:
            self._engine_registry[run_id] = engine

    def deregister_run_engine(self, run_id: str) -> None:
        """런 종료 시 레지스트리에서 제거 (메모리 누수 방지).

        external_engine_registry가 설정되면 위임한다.
        AppState는 unregister_run_engine 이름을 사용한다.
        """
        if self._external_engine_registry is not None:
            self._external_engine_registry.unregister_run_engine(run_id)
            return
        with self._engine_registry_lock:
            self._engine_registry.pop(run_id, None)

    def resolve_run_engine(self, run_id: str) -> OversightEngineProtocol | None:
        """등록된 OversightEngine을 반환한다. 미등록이면 None.

        D-L: None 반환 = 런이 현재 디스패치 중이 아님.
        request_pause는 None 시 RunNotDispatchingError를 raise해야 한다.
        external_engine_registry가 설정되면 위임한다.
        OversightEngineProtocol 반환 타입으로 set_paused unchecked 차단.
        """
        if self._external_engine_registry is not None:
            # _external_engine_registry는 AppState (Any) — 반환값은 구조적으로 OversightEngineProtocol을 만족함.
            result: OversightEngineProtocol | None = self._external_engine_registry.resolve_run_engine(run_id)
            return result
        with self._engine_registry_lock:
            return self._engine_registry.get(run_id)

    def request_pause(
        self,
        run_id: str,
        *,
        request_id: str,
        mode: Literal["pause", "stop"],
        actor: str,
    ) -> bool:
        """런에 pause/stop 신호를 보낸다 (INV-R6: 명시 엔진 전달).

        D-L: 엔진이 없으면 RunNotDispatchingError (silent fallback 금지).
        R2: 동일 request_id → 멱등 (엔진의 set_paused가 처리).
        actor 파라미터 필수 (인터럽트 이벤트 귀속).

        set_paused의 멱등 반환값을 호출자에게 전달한다.
          True  = 신규 인터럽트 신호 설정 → 이벤트를 적재해야 함.
          False = 동일 request_id 중복 요청 → 이벤트 재방출 금지(중복 방출 위협).
        상태 전이는 엔진 부수효과 *성공 이후*로 미룬다.
        엔진이 None이면 레코드 전이 없이 즉시 RunNotDispatchingError를 raise한다.
        이로써 엔진 None 시 INTERRUPT_REQUESTED에 고착되는 회귀를 방지한다.
        """
        # state guard BEFORE side-effect.
        # Read the current state under the lock to decide if we can proceed;
        # we do NOT transition yet (transition only after set_paused succeeds).
        # INTERRUPT_REQUESTED 상태에서 동일 request_id 재진입은
        # InterruptStateError가 아니라 멱등 no-op(False 반환)으로 처리한다.
        # 이를 위해 엔진의 set_paused를 먼저 시도해 실제 멱등 여부를 확인한다.
        with self._interrupt_records_lock:
            rec = self._interrupt_records.get(run_id)
            if rec is not None and (
                not rec.is_quiescent()
                or rec.interrupt_state
                in (
                    InterruptState.INTERRUPT_REQUESTED,
                    InterruptState.PAUSING,
                )
            ):
                # Already transitioning or already requested.
                # INTERRUPT_REQUESTED 상태에서는 엔진에 멱등 체크를 위임한다.
                # 동일 request_id면 set_paused가 False를 반환 → 멱등 no-op.
                # 다른 request_id면 엔진도 새 pause를 설정하려 시도하지만 상태기계가 막는다.
                if rec.interrupt_state in (InterruptState.INTERRUPT_REQUESTED, InterruptState.PAUSING):
                    # BLOCKING-1 fix: dedup 판정은 순수 read 프로브로만 수행한다.
                    # set_paused(mutate)를 호출하면 다른 request_id의 stop_mode·actor가
                    # 엔진 상태를 오염시킨 뒤 raise된다 (귀속 오염 + abort 위협).
                    _engine_pre = self.resolve_run_engine(run_id)
                    if _engine_pre is not None:
                        _active_req_id = _engine_pre.current_pause_request_id()
                        if _active_req_id == request_id:
                            # 동일 request_id → 멱등 no-op, 이벤트 미방출
                            return False
                    # 다른 request_id (또는 엔진 없음) → 상태기계 위반으로 raise.
                    # 엔진 상태는 변경되지 않았으므로 귀속이 보존된다.
                    raise InterruptStateError(rec.interrupt_state, InterruptState.INTERRUPT_REQUESTED)
                # 그 외 전이 불가 상태 (PAUSED_SNAPSHOTTED, RESUMING 등)
                raise InterruptStateError(rec.interrupt_state, InterruptState.INTERRUPT_REQUESTED)

        # resolve engine BEFORE state transition.
        # If the engine is None, raise without creating/mutating the record.
        engine = self.resolve_run_engine(run_id)
        if engine is None:
            raise RunNotDispatchingError(
                f"런 {run_id!r}은 현재 디스패치 중이 아닙니다 (D-L). "
                "이미 완료됐거나 아직 시작되지 않았을 수 있습니다."
            )
        stop_mode = mode == "stop"
        # capture the idempotent return value.
        # True  = first set for this request_id → caller MUST emit the audit event.
        # False = duplicate request_id → caller MUST skip re-emitting the event.
        is_new_signal = engine.set_paused(
            paused=True,
            request_id=request_id,
            actor=actor,
            stop_mode=stop_mode,
        )
        # State transition AFTER the side-effect succeeded.
        # Now it is safe to record the transition — the engine is set.
        with self._interrupt_records_lock:
            rec = self._interrupt_records.setdefault(run_id, RunInterruptRecord(run_id=run_id))
            # Re-check: another thread might have raced in between; if so, abort.
            if rec.interrupt_state not in (InterruptState.RUNNING,):
                # The state has already moved (concurrent call) — the engine
                # set_paused is idempotent; just return without transitioning again.
                return is_new_signal
            rec.transition_to(InterruptState.INTERRUPT_REQUESTED)
        return is_new_signal

    def notify_pause_completed(self, run_id: str) -> None:
        """체크포인트 write 성공 후 상태기계를 PAUSED_SNAPSHOTTED로 전이한다.

        협조적 정지가 실제 일어나는 지점
        (DispatcherAdapter._handle_pause_result의 체크포인트 write 성공 직후)에서
        runner가 INTERRUPT_REQUESTED→PAUSING→PAUSED_SNAPSHOTTED 전이를 구동한다.
        이 메서드를 호출하지 않으면 resume이 PAUSED_SNAPSHOTTED 상태가 아니어서
        항상 InterruptStateError를 던지는 회귀가 발생한다.
        """
        with self._interrupt_records_lock:
            rec = self._interrupt_records.get(run_id)
            if rec is None:
                # No interrupt record for this run — nothing to transition.
                return
            # Drive INTERRUPT_REQUESTED→PAUSING→PAUSED_SNAPSHOTTED.
            # Each transition validates via _LEGAL_TRANSITIONS.
            if rec.interrupt_state == InterruptState.INTERRUPT_REQUESTED:
                rec.transition_to(InterruptState.PAUSING)
            if rec.interrupt_state == InterruptState.PAUSING:
                rec.transition_to(InterruptState.PAUSED_SNAPSHOTTED)

    async def resume_from_checkpoint(
        self,
        run_id: str,
        from_ref: SnapshotRef,
        *,
        checkpoint_store: CheckpointStoreProtocol,
        steer_handler: SteerHandlerProtocol | None = None,
        expected_tenant: str | None = None,
    ) -> None:
        """체크포인트에서 런을 재개한다 (D-B 신규 메서드).

        기존 resume(record)와 다름: PLANNING에서 재시작이 아니라
        스냅샷된 스텝 목록에서 재디스패치한다.

        INV-3: 동일 from_ref URI로 두 번 호출 → 두 번째는 no-op (멱등).
        D-F/INV-9: rule_of_two_axes가 3개 → ResumeRequiresHITLError.
        CheckpointMismatchError: from_ref가 저장소에 없으면 raise.

        steer_handler (optional) — if provided, emits the second
        steer.resumed producer (structural, with from_checkpoint_id) after the
        engine pause is cleared. When None, the event is omitted (backward-compat
        for callers that have not wired a SteerHandler).

        resume 성공 후 RESUMING→RUNNING 전이를 추가한다.
        이로써 같은 런의 2차 pause/resume도 가능해진다.
        """
        # verify state machine allows resume.
        # PAUSED_SNAPSHOTTED (or REINSTRUCTING) → RESUMING is the only legal path.
        # If no record exists (no prior pause), allow resume without transition
        # (backward-compat: checkpoint may have been written by a prior process).
        with self._interrupt_records_lock:
            rec = self._interrupt_records.get(run_id)
            if rec is not None and not rec.is_quiescent():
                raise InterruptStateError(rec.interrupt_state, InterruptState.RESUMING)
            # Only drive RESUMING if the record exists (prior pause happened)
            if rec is not None:
                rec.transition_to(InterruptState.RESUMING)

        # CheckpointMismatchError: resolve 실패 시 KeyError를 잡아 변환
        try:
            checkpoint = checkpoint_store.resolve(from_ref)
        except KeyError as exc:
            raise CheckpointMismatchError(f"체크포인트를 찾을 수 없습니다: {from_ref.uri!r}") from exc

        # cross-tenant checkpoint validation
        if expected_tenant is not None and checkpoint.tenant_id != expected_tenant:
            raise CheckpointMismatchError(
                f"체크포인트 tenant_id {checkpoint.tenant_id!r} != 예상 {expected_tenant!r}"
            )

        # verify checkpoint belongs to this run
        if checkpoint.run_id != run_id:
            raise CheckpointMismatchError(f"checkpoint.run_id={checkpoint.run_id!r} != run_id={run_id!r}")

        # D-F/INV-9: 3축 확인 → HITL 강제
        try:
            axes: frozenset[Axis] = frozenset(Axis(a) for a in checkpoint.rule_of_two_axes)
        except ValueError:
            axes = frozenset()
        if requires_hitl(axes):
            raise ResumeRequiresHITLError(
                f"재개 시 Rule-of-Two 3축 감지 → HITL 승인 필요 (INV-9). axes={sorted(str(a) for a in axes)}"
            )

        # HA lease 재획득 — _run_pipeline_leased와 동일 단일-리더 보장.
        # If a lease manager is wired, the node resuming a checkpoint MUST hold the
        # lease before dispatching; otherwise two nodes can execute the same run
        # concurrently (fail-open double-execute). LeaseLostError → fail-closed
        # (do not dispatch; emit run.handover audit and return).
        if self._lease_manager is not None:
            try:
                await self._lease_manager.acquire_run(run_id, self._worker_id, self._lease_ttl_seconds)
            except LeaseLostError:
                _logger.warning(
                    "resume: run %s lease held elsewhere; %s declines to dispatch",
                    run_id,
                    self._worker_id,
                )
                await self._record_and_publish(
                    run_id,
                    "run.handover",
                    {
                        "run_id": run_id,
                        "action": "resume_lease_held_elsewhere",
                        "reason": f"lease not acquired by {self._worker_id} on resume",
                    },
                )
                return

        # INV-3: 멱등 — 동일 URI 두 번 호출 시 두 번째는 no-op
        # check-only here; mark AFTER successful dispatch
        with self._resumed_checkpoints_lock:
            if from_ref.uri in self._resumed_checkpoints:
                return

        # 엔진 pause 해제 (재개이므로)
        engine = self.resolve_run_engine(run_id)
        if engine is not None:
            engine.set_paused(
                paused=False,
                request_id=checkpoint.checkpoint_id,
                actor=checkpoint.actor,
            )

        # Emit the second steer.resumed producer (structural,
        # with from_checkpoint_id). Distinguished from apply()'s cosmetic
        # steer.resumed by the presence of ``from_checkpoint_id`` in the payload.
        if steer_handler is not None:
            steer_handler.emit_resume_from_checkpoint(
                run_id=run_id,
                from_checkpoint_id=from_ref.uri,
                actor=checkpoint.actor,
                rule_of_two_axes=checkpoint.rule_of_two_axes,
            )

        # 체크포인트의 pending 스텝으로 재디스패치
        pending_plan = PlanLike(
            id=f"resume-{checkpoint.checkpoint_id}",
            summary=f"재개: step_index={checkpoint.step_index}",
            steps=list(checkpoint.pending_step_ids),
        )
        try:
            await self._dispatcher.dispatch(run_id=run_id, plan=pending_plan)
        except Exception:
            # dispatch 실패 시 URI를 marked하지 않아 재시도 가능
            raise
        # dispatch 성공 후에만 멱등 URI 마킹
        with self._resumed_checkpoints_lock:
            self._resumed_checkpoints.add(from_ref.uri)
        # RESUMING→RUNNING 전이 (dispatch 성공 후).
        # 이로써 같은 런의 2차 pause/resume이 가능해진다.
        with self._interrupt_records_lock:
            rec2 = self._interrupt_records.get(run_id)
            if rec2 is not None and rec2.interrupt_state == InterruptState.RESUMING:
                rec2.transition_to(InterruptState.RUNNING)

    # ------------------------------------------------------------------ #
    # Enqueue + approval signals
    # ------------------------------------------------------------------ #

    async def enqueue(
        self,
        run_id: str,
        command: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Register the run and schedule the pipeline. Non-blocking.

        TOCTOU closed (SG-FIX-05): the initial stopped-check is a fast-path
        guard only. After the two awaits (store.create + record_and_publish)
        we re-acquire _lifecycle_lock and re-check _stopped before claiming
        the task slot. create_task + _tasks insert are both synchronous, so
        "stopped re-check → task claim" is atomic w.r.t. stop() — identical
        to the pattern in resume() (F10, "TOCTOU closed"). The store row
        created above is left as-is when the re-check fires: it is an
        already-persisted row in a non-PENDING state that boot recovery will
        handle if needed; no live pipeline task is ever spawned.
        """
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
        await self._store.create(run_id, command, context or {})
        await self._record_and_publish(run_id, ET.COMMAND_RECEIVED, {"command": command})
        # Re-acquire the lock to close the TOCTOU window opened by the two
        # awaits above. stop() sets _stopped=True under this same lock, so
        # either we see _stopped=True here (and raise, leaving no live task)
        # or stop() has not yet set it and will wait for us to release the
        # lock before it can run — either way it will see our task in _tasks.
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
            # create_task + insert are sync ⇒ check-and-claim is atomic w.r.t.
            # the lock; the task body only runs after we release (next loop tick).
            task = asyncio.create_task(
                self._run_pipeline(run_id, command, dict(context or {})),
                name=f"run-{run_id}",
            )
            self._tasks[run_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(run_id, None))

    async def resume(self, record: RunRecord) -> None:
        """Re-schedule an *existing* (already-persisted) run's pipeline.

        Unlike :meth:`enqueue` this does NOT call ``state_store.create`` — the run
        row already exists (it survived the crash). It just re-launches the
        pipeline task, which drives the run forward from PLANNING again. Safe to
        call only for runs the recovery driver classified as resumable. Re-running
        is idempotent at the recovery-driver level (the current-state guard stops
        a second resume), and here we guard against double-scheduling a run that
        already has a live task.

        F10: the check ("not already scheduled") and the claim (insert into
        ``self._tasks``) happen ATOMICALLY under ``_lifecycle_lock`` — both the
        ``asyncio.create_task`` and the dict insert are synchronous (no ``await``),
        so two concurrent ``resume()`` calls for the same run can never both pass
        the check and launch two pipeline tasks (TOCTOU closed).
        """
        async with self._lifecycle_lock:
            if self._stopped or self._semaphore is None:
                raise OrchestratorStoppedError("orchestrator is not running")
            if record.run_id in self._tasks:
                # Already scheduled — do not double-launch.
                return
            # create_task + insert are sync ⇒ check-and-claim is atomic w.r.t. the
            # lock; the task body only runs after we release it (next loop tick).
            task = asyncio.create_task(
                self._run_pipeline(record.run_id, record.command, dict(record.context)),
                name=f"resume-{record.run_id}",
            )
            self._tasks[record.run_id] = task
        task.add_done_callback(lambda t: self._tasks.pop(record.run_id, None))

    async def approve(self, run_id: str, *, approver: str = "human") -> None:
        await self._signal(run_id, ApprovalDecision(action="approve", approver=approver))

    async def partial_approve(self, run_id: str, *, approver: str, step_ids: list[str]) -> None:
        """Approve ONLY ``step_ids`` of the awaiting plan (Plan Review).

        Signals the same approval queue as :meth:`approve` but carries the selected
        step subset so the dispatcher mints a narrowed :class:`ApprovalScope`.
        Unselected steps are never authorized (deny-by-default / fail-closed,
        INV-W5C-5). The caller (the FastAPI plan-decision route) has already
        validated the subset and stamped the plan_review audit event.
        """
        await self._signal(
            run_id,
            ApprovalDecision(action="approve", approver=approver, approved_step_ids=list(step_ids)),
        )

    async def reject(self, run_id: str, *, reason: str | None = None) -> None:
        await self._signal(run_id, ApprovalDecision(action="reject", reason=reason))

    async def amend(self, run_id: str, *, instruction: str) -> None:
        await self._signal(run_id, ApprovalDecision(action="amend", instruction=instruction))

    async def _signal(self, run_id: str, decision: ApprovalDecision) -> None:
        queue = self._approval_queues.get(run_id)
        if queue is None:
            raise KeyError(f"run {run_id} is not awaiting approval")
        await queue.put(decision)

    # ------------------------------------------------------------------ #
    # Observability helpers (used by FastAPI routes + tests)
    # ------------------------------------------------------------------ #

    async def get_record(self, run_id: str) -> RunRecord | None:
        return await self._store.get(run_id)

    async def find_record_by_plan_id(self, plan_id: str) -> RunRecord | None:
        """Resolve the run record whose stored plan has ``id == plan_id``.

        Plans are keyed by ``run_id`` in the state store, so the read-only
        ``GET /api/plans/{plan_id}`` endpoint resolves the owning record by
        scanning the *open* runs (a plan under review — and through execution — is
        always non-terminal: AWAITING_APPROVAL / APPROVED / EXECUTING / PAUSED /
        REPORTING). A fully finished run (COMPLETED / FAILED / CANCELLED) is out of
        the Plan Review window and resolves to ``None`` (the caller returns 404).
        The tenant check is the caller's responsibility (deny-by-default 404 on a
        cross-tenant id — no existence oracle).
        """
        for record in await self._store.list_open_runs():
            plan = record.plan
            if isinstance(plan, dict) and plan.get("id") == plan_id:
                return record
        return None

    async def list_events(self, run_id: str) -> list[RunEvent]:
        return await self._store.list_events(run_id)

    # ------------------------------------------------------------------ #
    # Pipeline
    # ------------------------------------------------------------------ #

    async def _run_pipeline(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        sem = self._semaphore
        assert sem is not None
        try:
            async with sem:
                if self._lease_manager is None:
                    await self._pipeline_inner(run_id, command, context)
                else:
                    await self._run_pipeline_leased(run_id, command, context)
        except asyncio.CancelledError:
            # stop() path. Record cancellation if not already terminal.
            rec = await self._store.get(run_id)
            if rec and rec.state not in _TERMINAL:
                await self._store.update_state(run_id, RunState.CANCELLED, failure_reason="cancelled")
                await self._record_and_publish(run_id, ET.RUN_CANCELLED, {"reason": "cancelled"})
            raise

    async def _run_pipeline_leased(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        """Run the pipeline only while holding this run's HA lease.

        Fail-closed: if another node already holds the lease, this node does not
        dispatch the run and leaves its state untouched (the lease holder owns
        it). If the lease is lost mid-run we stop dispatching that run. The lease
        is always released on exit if (and only if) this node acquired it.
        """
        manager = self._lease_manager
        assert manager is not None
        try:
            await manager.acquire_run(run_id, self._worker_id, self._lease_ttl_seconds)
        except LeaseLostError:
            # Another node holds this run — do NOT dispatch and do NOT mutate
            # state. Record the deferral on the run's ribbon for auditability.
            _logger.info(
                "run %s lease held elsewhere; %s declines to dispatch",
                run_id,
                self._worker_id,
            )
            await self._record_and_publish(
                run_id,
                ET.RUN_HANDOVER,
                {
                    "run_id": run_id,
                    "action": "lease_held_elsewhere",
                    "reason": f"lease not acquired by {self._worker_id}",
                },
            )
            return
        # F4: keep the lease alive for the whole run. The lease TTL is short (60s
        # default) but a run can block far longer on the HITL approval gate, so a
        # background task renews it every ~ttl/3. If renewal fails (LeaseLostError
        # — another node took over) we abort the pipeline fail-closed so two nodes
        # never run the same run. The renew task is always cancelled before
        # release, and the lease is released only if (and only if) we acquired it.
        renew_task = asyncio.create_task(self._renew_lease_loop(manager, run_id), name=f"renew-{run_id}")
        pipeline_task = asyncio.create_task(
            self._pipeline_inner(run_id, command, context), name=f"pipeline-{run_id}"
        )
        try:
            done, _pending = await asyncio.wait(
                {renew_task, pipeline_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if pipeline_task in done:
                # Pipeline finished (success or its own failure handling) first —
                # surface any exception it raised, then stop renewing.
                pipeline_task.result()
                return
            # The renew task completed first — it only ever completes by RAISING:
            # LeaseLostError (another node took over) or a transient backend error
            # (e.g. a locked SQLite / a PG connection blip). Either way we abort the
            # in-flight pipeline and fail the run CLOSED into a terminal state so it
            # is never left mid-EXECUTING (boot recovery re-picks it up later).
            await self._cancel_task(pipeline_task)
            try:
                renew_task.result()  # re-raises the renew-side exception
            except LeaseLostError:
                _logger.warning(
                    "run %s lease lost mid-run by %s; stopping dispatch",
                    run_id,
                    self._worker_id,
                )
                await self._fail_run_closed(run_id, "lease_lost", f"lease lost mid-run by {self._worker_id}")
            except Exception as exc:  # transient renew error — still fail-closed
                _logger.warning(
                    "run %s lease renew failed (%s) by %s; stopping dispatch",
                    run_id,
                    type(exc).__name__,
                    self._worker_id,
                )
                await self._fail_run_closed(
                    run_id,
                    "renew_error",
                    f"lease renew failed ({type(exc).__name__}) by {self._worker_id}",
                )
        finally:
            await self._cancel_task(renew_task)
            await self._cancel_task(pipeline_task)
            await manager.release(run_id, self._worker_id)

    async def _fail_run_closed(self, run_id: str, action: str, reason: str) -> None:
        """Fail-closed terminal transition + handover audit for a lost/abandoned lease.

        Moves a non-terminal run to ``FAILED`` (so it never lingers mid-EXECUTING)
        and records a ``run.handover`` event. Shared by the lease-lost and the
        transient-renew-error paths so neither leaves a run non-terminal+silent.
        """
        rec = await self._store.get(run_id)
        if rec is not None and rec.state not in _TERMINAL:
            await self._store.update_state(run_id, RunState.FAILED, failure_reason=action)
        await self._record_and_publish(
            run_id,
            ET.RUN_HANDOVER,
            {"run_id": run_id, "action": action, "reason": reason},
        )

    async def _renew_lease_loop(self, manager: LeaseManager, run_id: str) -> None:
        """Renew this run's lease every ~ttl/3 until cancelled (F4).

        Raises :class:`LeaseLostError` the moment a renewal is rejected (another
        node now owns the lease) so the caller can abort the pipeline fail-closed.
        Sleeps ``ttl/3`` (floored at 50ms for very small test TTLs) between
        renewals so a TTL is refreshed ~3× before it could expire — tolerating one
        missed renewal. For the 60s production TTL this is a 20s interval."""
        interval = max(0.05, self._lease_ttl_seconds / 3.0)
        while True:
            await asyncio.sleep(interval)
            # A LeaseLostError here propagates out of the task (the caller surfaces
            # it via renew_task.result()); any other error also propagates rather
            # than being swallowed (fail-fast).
            await manager.renew(run_id, self._worker_id, self._lease_ttl_seconds)

    @staticmethod
    async def _cancel_task(task: asyncio.Task[None]) -> None:
        """Cancel ``task`` and await it, swallowing the CancelledError only.

        A task that already finished is a no-op. Any non-cancellation exception
        the task carried is intentionally ignored here (the primary result/error
        was already surfaced by the caller); we only guarantee the task is done so
        no orphan coroutine outlives the run."""
        if task.done():
            # Retrieve any stored exception so asyncio does not log a spurious
            # "Task exception was never retrieved" when both tasks finished in the
            # same wait batch (the primary result was already surfaced by caller).
            if not task.cancelled():
                task.exception()
            return
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: S110 - see docstring
            # Intentional: the primary result/error was already surfaced by the
            # caller; here we only guarantee the task is finished (no orphan
            # coroutine). Mirrors the cancellation handling in ``stop()``.
            pass

    async def _pipeline_inner(self, run_id: str, command: str, context: dict[str, Any]) -> None:
        amendments: list[str] = []
        # ``tenant_id`` is the metric label (legacy default ``"unknown"`` for runs
        # without a tenant). ``_raw_tenant`` preserves whether a tenant was
        # actually supplied so the cost gate can fail-closed on a *missing* tenant
        # when metering is active (finding 6: a tenant-less run must not silently
        # share a global "unknown" budget under a ledger).
        _raw_tenant = context.get("tenant_id")
        tenant_id: str = str(_raw_tenant) if _raw_tenant is not None else "unknown"
        # S8E: record pipeline start time for RUN_LATENCY histogram.
        _start_time = time.monotonic()

        def _observe_latency(terminal_state: str) -> None:
            """Record run latency at any terminal transition (S8E)."""
            elapsed = time.monotonic() - _start_time
            RUN_LATENCY.labels(tenant_id=tenant_id, terminal_state=terminal_state).observe(elapsed)

        while True:
            # 1. PLANNING
            await self._store.update_state(run_id, RunState.PLANNING)
            plan_context = dict(context)
            if amendments:
                plan_context.setdefault("amendments", []).extend(amendments)
            try:
                plan = await self._planner.plan(run_id=run_id, command=command, context=plan_context)
            except PlannerFailedError as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=str(exc))
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED_ADAPTER,
                    {"reason_class": "PlannerFailedError", "detail": str(exc)},
                )
                return
            except Exception as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(
                    run_id,
                    reason=f"planning_error: {type(exc).__name__}: {exc}",
                )
                return
            await self._record_and_publish(
                run_id,
                ET.PLAN_CREATED,
                {"plan_id": plan.id, "summary": plan.summary, "steps": len(plan.steps)},
            )
            # Grounding producer (2026-07-13): bind any runtime connector/tool
            # evidence (context['grounding_evidence']) onto the plan fail-closed. A
            # malformed grounding payload FAILS the run here — deny-by-default: a
            # corrupt grounding provenance must never reach the human approval gate
            # (INV-RW-2). Absent grounding ⇒ [] (backward compatible, INV-RW-1).
            try:
                plan_evidence = _bind_plan_evidence(plan_context)
            except EvidenceBindingError as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"grounding_evidence_invalid: {exc}")
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED_ADAPTER,
                    {"reason_class": "EvidenceBindingError", "detail": str(exc)},
                )
                return
            await self._store.update_state(
                run_id,
                RunState.PLANNING,
                # Surface immutable AI-generated provenance on the stored plan so
                # ``GET /runs/{id}`` (and the Plan Review UI) can render the
                # AI-identification notice. Read from the threaded PlanLike fields
                # (no concrete ``Plan`` import in the runner).
                # ALSO durably surface the goal, full ``step_list``, planner-declared
                # ``risks`` and ``assigned_subs`` so the read-only
                # ``GET /api/plans/{id}`` Plan Review endpoint has an internal source
                # for the HEAD risk section + per-step checkboxes. The legacy
                # ``steps`` (int count) and provenance keys are preserved verbatim
                # (append-only key additions — backward compatible, INV: no key
                # removed/retyped).
                plan={
                    "id": plan.id,
                    "summary": plan.summary,
                    "goal": plan.summary,
                    "steps": len(plan.steps),
                    "step_list": _serialize_plan_steps(plan.steps),
                    "risks": [dict(r) for r in plan.risks],
                    "assigned_subs": dict(plan.assigned_subs),
                    "ai_generated": plan.ai_generated,
                    "model_id": plan.model_id,
                    "regulations_version": plan.regulations_version,
                    # Grounding citations bound above (INV-RW-1: [] when ungrounded).
                    "evidence": plan_evidence,
                },
            )

            # 2. COST QUOTA GATE — fail-closed BEFORE the human approval gate.
            # An over-budget run must be REFUSED on its own; it must never sit in
            # AWAITING_APPROVAL consuming a human's attention on work that can never
            # run (§12.6 I1, no silent pass). Enforcing here
            # (not after APPROVED) also means a reviewer never approves a plan that
            # the budget will then reject. ``None`` ledger ⇒ no gate (legacy).
            gate = await self._quota_gate(_raw_tenant)
            if gate is not None:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=gate)
                return

            # 3. APPROVAL GATE
            if self._config.auto_approve:
                decision = ApprovalDecision(action="approve", approver="auto")
            else:
                await self._store.update_state(run_id, RunState.AWAITING_APPROVAL)
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_AWAITING_APPROVAL,
                    {"plan_id": plan.id},
                )
                # S8E: track pending HITL approvals in the backlog gauge.
                HITL_BACKLOG.labels(tenant_id=tenant_id).inc()
                try:
                    decision = await self._wait_for_decision(run_id)
                except TimeoutError:
                    HITL_BACKLOG.labels(tenant_id=tenant_id).dec()
                    _observe_latency(RunState.FAILED.value)
                    await self._fail(run_id, reason="approval_timeout")
                    return
                finally:
                    pass
                # S8E: resolution received — decrement backlog.
                HITL_BACKLOG.labels(tenant_id=tenant_id).dec()

            if decision.action == "reject":
                _observe_latency(RunState.CANCELLED.value)
                await self._store.update_state(
                    run_id,
                    RunState.CANCELLED,
                    approver=decision.approver,
                    failure_reason=decision.reason or "rejected",
                )
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_REJECTED,
                    {"plan_id": plan.id, "reason": decision.reason},
                )
                await self._record_and_publish(
                    run_id, ET.RUN_CANCELLED, {"reason": decision.reason or "rejected"}
                )
                return

            if decision.action == "amend":
                amendments.append(decision.instruction or "")
                await self._record_and_publish(
                    run_id,
                    ET.PLAN_AMENDED,
                    {"plan_id": plan.id, "instruction": decision.instruction},
                )
                continue  # back to PLANNING

            # approve
            await self._store.update_state(run_id, RunState.APPROVED, approver=decision.approver)
            await self._record_and_publish(
                run_id, ET.PLAN_APPROVED, {"plan_id": plan.id, "approver": decision.approver}
            )

            # 4. EXECUTING — the quota gate already ran (step 2) before approval.
            await self._store.update_state(run_id, RunState.EXECUTING)

            try:
                # A partial Plan Review approval carries the selected step subset;
                # thread it so the dispatcher mints an ApprovalScope narrowed to
                # EXACTLY those steps. ``None`` ⇒ full plan (legacy approve). Only
                # pass the kwarg when narrowing so legacy dispatcher fakes that do not
                # accept ``approved_step_ids`` keep working on the full-approval path.
                if decision.approved_step_ids is not None:
                    results = await self._dispatcher.dispatch(
                        run_id=run_id, plan=plan, approved_step_ids=decision.approved_step_ids
                    )
                else:
                    results = await self._dispatcher.dispatch(run_id=run_id, plan=plan)
            except DispatcherResultMalformed as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"dispatch_result_malformed: {exc}")
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED_ADAPTER,
                    {"reason_class": "DispatcherResultMalformed", "detail": str(exc)},
                )
                return
            except Exception as exc:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"dispatch_error: {type(exc).__name__}: {exc}")
                return
            await self._record_and_publish(
                run_id,
                ET.DISPATCHER_ROUTED,
                {"plan_id": plan.id, "results": _summarise_results(results)},
            )

            # 4. REPORTING
            await self._store.update_state(run_id, RunState.REPORTING)
            partial = bool(results.get("partial_failure"))
            if partial and self._config.fail_fast:
                _observe_latency(RunState.FAILED.value)
                await self._fail(run_id, reason=f"sub_error: {results.get('failure_reason', 'sub_failed')}")
                return

            terminal = RunState.COMPLETED if not partial else RunState.FAILED
            _observe_latency(terminal.value)
            await self._store.update_state(
                run_id,
                terminal,
                failure_reason=results.get("failure_reason") if partial else None,
            )
            if partial:
                await self._record_and_publish(
                    run_id,
                    ET.RUN_FAILED,
                    {
                        "reason": results.get("failure_reason", "sub_failed"),
                        "results": _summarise_results(results),
                    },
                )
            else:
                await self._record_and_publish(
                    run_id,
                    ET.RUN_COMPLETED,
                    {"results": _summarise_results(results)},
                )
            return

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _quota_gate(self, raw_tenant_id: object | None) -> str | None:
        """Decide whether this run may proceed past the cost gate.

        ``raw_tenant_id`` is the *unparsed* ``context["tenant_id"]`` value (``None``
        when the key was absent). Returns the run's ``failure_reason`` when the run
        must be REFUSED, or ``None`` when it may proceed:

        * No ledger attached ⇒ ``None`` (legacy callers unaffected, no gate).
        * Missing tenant (``None``) **with a ledger attached** ⇒ ``"invalid_tenant"``.
          A tenant-less run must not silently share a global "unknown" budget under
          an active meter — deny-by-default.
        * ``tenant_id`` fails the :class:`TenantId` regex (empty, uppercase,
          leading hyphen, >63 chars, control/path chars, non-str) ⇒
          ``"invalid_tenant"``. For a **deny-by-default** budget control, an
          unidentifiable tenant must FAIL CLOSED — never skip the meter
          and run unbudgeted. Earlier code returned "allow" here, which let any
          programmatic/re-enqueue caller bypass the cap entirely.
        * Over the daily/monthly cap ⇒ ``"quota_exceeded"``.
        * Otherwise ⇒ ``None``.

        The budget decision itself is never re-implemented here: it delegates to
        the single source of truth, :meth:`CostLedger.enforce_or_raise`.

        Concurrency note (concurrency edge case) — HONEST RESIDUAL, not a mitigated gap:
        this pre-flight gate (and the per-step ``SubAgent`` gate) is a pure READ,
        so two same-tenant runs admitted in the same instant both observe the same
        pre-spend total and may together overshoot the cap. A strict atomic
        admission reservation is intentionally NOT shipped: per-run spend is
        unknown at admission (it is metered per model-call), so any reserved
        amount would be arbitrary. This is a documented residual; do not read it
        as defence-in-depth the code does not provide (fail-fast, invariant I1).

        COST-01 (resolved): in-run self-inflicted spend IS now recorded live. The
        usage observer on the live LLM client (installed by ``create_app`` via
        ``secugent.cost.recorder.build_cost_recording_observer``) writes each
        successful ``generate()`` to ``CostLedger`` under the run bound by
        ``bind_cost_context`` in ``HeadAgent.plan`` / ``SubAgent._run_step``. So a
        run's own model calls now grow the ledger total mid-run and the per-step
        gate CAN fire on self-inflicted overspend. Metering is fail-open
        (best-effort → WARN), so under a metering error the bound stays the
        already-recorded external/prior spend and the gate still fails closed; and
        honesty: Anthropic usage is exact; a sovereign adapter is exact when its
        body exposes provider usage and falls back to a length ESTIMATE
        (``UsageEvent.exact=False``) when it does not; the mock always estimates.
        Dollars for an out-of-catalog model record as ``$0`` (tokens preserved),
        so live accrual can conservatively under-account but never over-claims
        precision. The sovereign chokepoint (``llm_clients/_base.py``) emits on
        the closed-network-first path too, so INV-2 holds for on-prem/air-gapped
        deployments and not only the Anthropic/mock paths.
        """
        if self._cost_ledger is None:
            return None
        from secugent.core.tenancy import TenantId as _TenantId

        if raw_tenant_id is None:
            _logger.warning("quota gate: run has no tenant_id — refusing fail-closed")
            return "invalid_tenant"
        try:
            tid = _TenantId(str(raw_tenant_id))
        except ValueError:
            # Deny-by-default: a tenant we cannot identify cannot be metered, so
            # the only safe verdict is to refuse the run (fail-closed), not to
            # grant it unmetered execution (findings 1 & 6, §12.6 I1).
            _logger.warning(
                "quota gate: malformed tenant_id %r — refusing run fail-closed",
                raw_tenant_id,
            )
            return "invalid_tenant"
        # A non-None ledger is only ever injected by the Enterprise wiring, where
        # ``secugent.cost`` IS installed — so this lazy import never runs in the
        # public Core (which keeps ``cost_ledger is None`` and returned above).
        from secugent.cost.accounting import QuotaExceededError as _QuotaExceededError

        try:
            await self._cost_ledger.enforce_or_raise(tid)
        except _QuotaExceededError:
            return "quota_exceeded"
        return None

    async def _wait_for_decision(self, run_id: str) -> ApprovalDecision:
        queue: asyncio.Queue[ApprovalDecision] = asyncio.Queue()
        self._approval_queues[run_id] = queue
        try:
            return await asyncio.wait_for(queue.get(), timeout=self._config.approval_timeout_sec)
        finally:
            self._approval_queues.pop(run_id, None)

    async def _fail(self, run_id: str, *, reason: str) -> None:
        await self._store.update_state(run_id, RunState.FAILED, failure_reason=reason)
        await self._record_and_publish(run_id, ET.RUN_FAILED, {"reason": reason})
        _logger.error("run %s failed: %s", run_id, reason)

    async def _record_and_publish(self, run_id: str, topic: str, payload: dict[str, Any]) -> None:
        event = RunEvent(run_id=run_id, topic=topic, payload=payload)
        await self._store.append_event(run_id, event)
        try:
            await self._publish(run_id, topic, payload)
        except Exception:  # pragma: no cover - defensive
            _logger.exception("event publish failed for run=%s topic=%s", run_id, topic)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _noop_publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
    return None


# The Step fields the Plan Review surface needs. ``context`` is
# included because ``GET /runs/{id}/plan-decision`` recomputes the Rule of Two
# axes (``rule_of_two.axes_for_steps``) from the persisted steps, and axis ①
# (untrusted_input) is carried in ``Step.context`` provenance — dropping it would
# make the audited ``rule_of_two_axes`` under-report the real axes (an audit honesty
# violation). The plan_review audit must match the scope the dispatcher mints.
_PLAN_STEP_FIELDS = (
    "id",
    "tenant_id",
    "run_id",
    "plan_id",
    "actor",
    "action_type",
    "target",
    "command",
    "status",
    "context",
)


def _serialize_plan_steps(steps: list[Any]) -> list[dict[str, Any]]:
    """Project each plan step to a JSON-serialisable dict.

    Duck-typed so the runner stays free of a concrete ``Step`` import: a pydantic
    ``Step`` is dumped via ``model_dump(mode="json")``; a plain dict is read
    directly; anything else contributes an empty dict (never raises — a stored
    plan must always serialise, the SQLite store ``_dumps`` would otherwise fail
    fast on the whole record). Only the Plan-Review-relevant fields are kept so
    the persisted plan does not balloon with unrelated step internals.
    """
    out: list[dict[str, Any]] = []
    for step in steps:
        if hasattr(step, "model_dump"):
            raw = step.model_dump(mode="json")
        elif isinstance(step, dict):
            raw = step
        else:
            raw = {}
        out.append({key: raw.get(key) for key in _PLAN_STEP_FIELDS})
    return out


def _bind_plan_evidence(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Bind runtime connector/tool grounding into persisted ``plan['evidence']``.

    The producer half of the grounding-citation path (2026-07-13). SecuGent builds
    no retrieval engine: a retrieval connector / MCP tool (or the caller
    that ran one) places its result's ``evidence`` list on the run context under
    ``grounding_evidence``; this re-validates it fail-closed against the producer's
    :class:`~secugent.core.grounding.Evidence` schema and returns citation dicts
    for durable persistence.

    * ``grounding_evidence`` absent/``None`` → ``[]`` (an ungrounded plan is
      normal, not an error — INV-RW-1 backward compatibility).
    * present → each element must pass ``Evidence`` validation; a non-list or any
      malformed element raises :class:`EvidenceBindingError` (all-or-nothing,
      INV-RW-2 / INV-N3-4). The caller fails the run closed — a corrupt grounding
      provenance must never reach the human approval gate. Order is preserved.
    """
    raw = context.get("grounding_evidence")
    if raw is None:
        return []
    bound = evidence_from_connector_payload({"evidence": raw})
    return [ev.model_dump(mode="json") for ev in bound]


_TERMINAL = {RunState.COMPLETED, RunState.FAILED, RunState.CANCELLED}


def _summarise_results(results: dict[str, Any]) -> dict[str, Any]:
    # Keep payloads small for events.
    out = {k: v for k, v in results.items() if k in ("partial_failure", "failure_reason")}
    subs = results.get("subs") or {}
    out["subs"] = (
        {k: {"status": v.get("status"), "completed_steps": v.get("completed_steps")} for k, v in subs.items()}
        if isinstance(subs, dict)
        else {}
    )
    return out
