# SPDX-License-Identifier: Apache-2.0
"""Core Pydantic v2 types shared across SecuGent modules.

These types are the *single source of truth* for the data exchanged between
HEAD/SUB agents, Mechanical Oversight, RISKANALYZER, the approval service, and
the durable event store. Validation here is intentionally strict — any module
producing one of these objects must satisfy fail-closed expectations from
SECURITY_CONTRACT.md §3.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secugent.core.sec.envelope import AuthorizationEnvelope, EnvelopeUsage
from secugent.core.tenancy import TenantId

# ---------------------------------------------------------------------------
# Literal enumerations
# ---------------------------------------------------------------------------

RunStatus = Literal[
    "pending",
    "planning",
    "awaiting_approval",
    "approved",
    "executing",
    "paused",
    "done",
    "failed",
    "cancelled",
]

StepStatus = Literal[
    "pending",
    "oversight",
    "risk",
    "hitl",
    "approved",
    "executing",
    "completed",
    "blocked",
    "rejected",
    "rolled_back",
]

ActionType = Literal[
    "file_read",
    "file_write",
    "http_get",
    "desktop",
    "compute",
    "connector_action",
    "unknown",
]

ApprovalStatus = Literal[
    "pending",
    "approved",
    "rejected",
    "expired",
    "consumed",
    "revoked",
]

EventSeverity = Literal["debug", "info", "warn", "error", "critical"]

ViolationCategory = Literal[
    "banned_path",
    "domain_policy",
    "banned_command",
    "data_label",
    "schema",
    "normalization",
    "unknown_action",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _new_id(prefix: str) -> str:
    """Generate a short prefixed UUID for use as a stable record identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class Run(BaseModel):
    """Top-level user command lifecycle."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("run"))
    tenant_id: TenantId
    goal: str = Field(..., min_length=1, max_length=8000)
    status: RunStatus = "pending"
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    # EM-07: machine-enforced effect budget for this run. None ⇒ no envelope bound
    # (legacy/unscoped); confirmed by a human at Plan Review (EM-08).
    envelope: AuthorizationEnvelope | None = None
    envelope_usage: EnvelopeUsage | None = None


class Step(BaseModel):
    """A single executable unit produced by HEAD and consumed by SUB."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("step"))
    tenant_id: TenantId
    run_id: str
    plan_id: str | None = None
    actor: str  # e.g., "sub:researcher"
    action_type: ActionType
    target: str | None = None
    command: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    status: StepStatus = "pending"


class Risk(BaseModel):
    """A planner-declared potential risk for a step or plan."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(..., min_length=1, max_length=2000)
    mitigation: str | None = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"


# §C-1 AI 식별표시 / 한국 AI 기본법 워터마크: the single standardized,
# Korean-default identification marker attached to any AI free-text output that is
# surfaced to a human operator. It is fastened at the orchestrator/runner boundary
# (NOT inside ``core.llm_client`` — that SDK wrapper stays framework/model-neutral).
# It is a module-level constant, so it introduces no wall-clock/uuid and is
# byte-stable across runs (determinism invariant).
AI_GENERATED_MARKER = "AI 생성: 본 산출물은 AI가 생성했습니다."


class Plan(BaseModel):
    """Output of HEAD planner; consumed by Dispatcher after human approval."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("plan"))
    tenant_id: TenantId
    run_id: str
    goal: str
    steps: list[Step] = Field(default_factory=list)
    risks: list[Risk] = Field(default_factory=list)
    assigned_subs: dict[str, str] = Field(default_factory=dict)  # step_id -> sub actor
    approval_id: str | None = None
    # Immutable provenance proving this plan is an AI-generated artifact.
    # ``ai_generated`` is ``Literal[True]`` and ``frozen`` so a forged ``False`` is
    # *unrepresentable* — the value can never be flipped after construction.
    # ``model_id`` / ``regulations_version`` are stamped by :meth:`HeadAgent.plan`
    # from the resolved planner model and the active REGULATIONS version. They are
    # deterministic, wall-clock-free constants/derived strings — NO ``generated_at``
    # timestamp enters the contract, preserving the determinism digest.
    # Defaults keep legacy/test ``Plan(...)`` construction backward compatible; the
    # planner always overwrites them with real values.
    ai_generated: Literal[True] = Field(default=True, frozen=True)
    model_id: str = Field(default="unknown", min_length=1, max_length=200)
    regulations_version: str = Field(default="0.0.0", min_length=1, max_length=64)


# §C-2 ``rule_of_two_axes`` canonical tokens. These MUST stay byte-for-byte equal
# to ``secugent.core.rule_of_two.Axis`` values (``untrusted_input`` /
# ``sensitive_access`` / ``external_comm``). That module imports from THIS one
# (``ActionType``/``Step``), so importing ``Axis`` here would create a cycle — the
# tokens are duplicated as literals and ``tests/unit/test_contracts.py`` asserts
# they equal the ``Axis`` value set so the two can never silently drift.
_RULE_OF_TWO_AXIS_TOKENS: frozenset[str] = frozenset({"untrusted_input", "sensitive_access", "external_comm"})


class ApprovalScope(BaseModel):
    """Strictly typed scope for a human approval token."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    run_id: str
    plan_id: str | None = None
    step_ids: list[str] = Field(default_factory=list)
    allowed_action_types: list[ActionType] = Field(default_factory=list)
    max_risk: int = Field(default=100, ge=0, le=100)
    expires_at: datetime
    # EM-08: bind this approval to a specific authorization envelope. When set,
    # execution must present the same envelope fingerprint (else fail-closed) —
    # an approval for envelope A cannot authorize envelope B. None ⇒ legacy/unbound.
    envelope_hash: str | None = None
    # §C-2 ``rule_of_two_axes``: the Rule of Two axes (§A-2.1) that the
    # steps this scope covers trip, computed deterministically at approval-creation
    # time from ``rule_of_two.axes_for_steps`` over the scoped plan steps. Frozen
    # (INV-M4-2): the axis set that justified a HITL approval is fixed once the
    # token is minted — it can never be mutated after issuance. Sorted &
    # de-duplicated by the validator so the same axis set always serializes
    # identically. Read back verbatim by the HITL approve/reject emitters so the
    # §C-2 audit row carries the real axes (not a dead ``[]`` fill).
    rule_of_two_axes: tuple[str, ...] = Field(default=(), frozen=True)

    @field_validator("rule_of_two_axes")
    @classmethod
    def _canonical_axes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Reject any non-canonical axis token fail-closed (a typo'd/forged axis can
        # never enter an audit row) and normalize to a sorted, de-duplicated tuple
        # so a given axis set has exactly one byte representation (INV-M4-2/M4-3).
        unknown = sorted(set(value) - _RULE_OF_TWO_AXIS_TOKENS)
        if unknown:
            raise ValueError(
                f"rule_of_two_axes contains non-canonical axis tokens {unknown} "
                f"(allowed: {sorted(_RULE_OF_TWO_AXIS_TOKENS)})"
            )
        return tuple(sorted(set(value)))

    @field_validator("allowed_action_types")
    @classmethod
    def _no_preapprovable(cls, value: list[ActionType]) -> list[ActionType]:
        # Neither `unknown` nor `connector_action` may be pre-authorized at the
        # plan level. `unknown` is always HITL; `connector_action` is external
        # communication (Rule of Two axis ③) and must always pass a fresh,
        # step-scoped HITL approval — it can never be bundled into a plan-level
        # pre-approval. Both therefore fail closed here (Pydantic ValidationError).
        forbidden = sorted({"unknown", "connector_action"} & set(value))
        if forbidden:
            raise ValueError(f"allowed_action_types cannot include {forbidden} (must hit step-scoped HITL)")
        return value


class Approval(BaseModel):
    """Durable approval record. Single-use; nonce is cryptographic."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("apv"))
    actor: str  # e.g., "human:alice"
    scope: ApprovalScope
    expires_at: datetime
    nonce: str
    status: ApprovalStatus = "pending"
    reason: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class Event(BaseModel):
    """Durable audit event — appended *before* broadcast on the bus."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("evt"))
    tenant_id: TenantId
    ts: datetime = Field(default_factory=_utcnow)
    actor: str
    type: str  # event_type, free-form e.g. "plan.created", "approval.granted"
    payload: dict[str, Any] = Field(default_factory=dict)
    severity: EventSeverity = "info"
    run_id: str | None = None
    step_id: str | None = None


class Violation(BaseModel):
    """Mechanical Oversight finding."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    category: ViolationCategory
    message: str
    severity: Literal["low", "medium", "high", "critical"] = "high"
    hard_block: bool = True


class RiskScore(BaseModel):
    """RISKANALYZER quantitative output. All 5 breakdown dims required."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(..., ge=0, le=100)
    breakdown: dict[str, int]
    rationale: str
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("breakdown")
    @classmethod
    def _require_dims(cls, value: dict[str, int]) -> dict[str, int]:
        required = {
            "data_sensitivity",
            "external_exposure",
            "irreversibility",
            "privilege_escalation",
            "intent_alignment",
        }
        missing = required - set(value)
        if missing:
            raise ValueError(f"RiskScore.breakdown missing dimensions: {sorted(missing)}")
        for k, v in value.items():
            if not isinstance(v, int) or v < 0 or v > 100:
                raise ValueError(f"RiskScore.breakdown[{k}] must be int in [0,100], got {v!r}")
        return value


class RegulationVersion(BaseModel):
    """Records which REGULATIONS revision is currently active."""

    model_config = ConfigDict(extra="forbid")

    version: str
    checksum: str  # sha256 hex
    created_at: datetime = Field(default_factory=_utcnow)
    source: str  # file path or "session_patch"


class SessionRegulationPatch(BaseModel):
    """STEER-issued, session-scoped REGULATIONS patch. Never written to disk."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: _new_id("patch"))
    tenant_id: TenantId
    run_id: str
    rules: list[dict[str, Any]]
    expires_at: datetime
    reason: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class HardBlockException(Exception):
    """Raised by Mechanical Oversight on a hard-block violation.

    Must NEVER be caught and swallowed silently. Callers either propagate it,
    convert it to a durable `Event(severity=critical)`, or both.
    """

    def __init__(self, violation: Violation) -> None:
        super().__init__(violation.message)
        self.violation = violation


class MissingRiskSectionError(Exception):
    """Raised when HEAD planner LLM omits the mandatory risk section."""


class ApprovalError(Exception):
    """Raised on any approval-token validation failure (scope/expiry/nonce)."""
