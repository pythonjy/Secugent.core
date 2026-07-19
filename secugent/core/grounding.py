# SPDX-License-Identifier: Apache-2.0
"""RAG boundary contract: Evidence schema + grounding enforcement (N2, 갭 ②③).

SecuGent does **not** build a RAG engine (a project Non-goal — no vector DB, no
GraphRAG, no embeddings, no chunking, no re-ranking). It owns only the *boundary
contract* by which an external RAG/search result is admitted:

1. :class:`Evidence` — a frozen, validated schema for a single piece of retrieved
   evidence. Evidence without a source (empty ``source_uri``/``doc_id``) is
   *unrepresentable* (INV-G3): construction fails at the boundary, fail-closed.
2. **Untrusted tagging** — a RAG result can never be a trusted source. It always
   carries :attr:`~secugent.core.provenance.TaintSource.CONNECTOR_RESPONSE`, so
   :func:`~secugent.core.provenance.derive_taint` propagates taint monotonically:
   any step grounded on external evidence trips Rule of Two axis① (INV-G4).
3. **Grounding enforcement** — a high-impact (HIGH/CRITICAL) decision cannot
   proceed without at least one :class:`Evidence` (deny-by-default, INV-G1). This
   is the deterministic core of the "고영향 의사결정에 설명(근거) 첨부" requirement.

This is a **pure leaf module**, held to the same discipline as
:mod:`secugent.core.provenance`: every function is a referentially-transparent
function of its arguments — no I/O, no global state, no mutation, no wall clock,
no randomness. Given the same inputs it always yields the same verdict
(INV-G2), which is why it qualifies for the deterministic test regime.

:class:`ImpactLevel` string values are kept byte-for-byte equal to the
``Risk.severity`` ``Literal`` in :mod:`secugent.core.contracts`
(``low``/``medium``/``high``/``critical``) so N3 can map ``Risk.severity`` →
``ImpactLevel`` losslessly.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from secugent.core.provenance import TaintSource

__all__ = [
    "Evidence",
    "ImpactLevel",
    "UngroundedDecisionError",
    "impact_from_axes",
    "is_high_impact",
    "require_grounding",
    "taint_for_evidence",
]

# The Rule of Two HITL boundary is 3 active axes — the same constant
# ``rule_of_two.requires_hitl`` uses. Kept as a local literal so this stays a pure
# leaf (no import of ``rule_of_two``); the caller passes the axis COUNT, so the two
# never share a type, only this semantic boundary (INV-B1).
_RULE_OF_TWO_AXIS_COUNT = 3


class ImpactLevel(StrEnum):
    """Impact of a decision.

    String values are aligned with the ``Risk.severity`` ``Literal`` in
    :mod:`secugent.core.contracts` (``low``/``medium``/``high``/``critical``) so
    N3 can map ``Risk.severity`` → :class:`ImpactLevel` with no loss.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UngroundedDecisionError(Exception):
    """A high-impact decision was made without attached :class:`Evidence`.

    A fail-closed domain exception (deny-by-default). Callers (N3) catch it and
    map it to an HTTP 422 — it must never be silently swallowed. The message
    carries only field/impact metadata, never the raw ``source_uri``/``snippet``,
    so no sensitive retrieval content leaks through an error path.
    """


class Evidence(BaseModel):
    """A single piece of external RAG/search evidence.

    Frozen and ``extra="forbid"``: once constructed it cannot be mutated
    (INV-G5) and no unexpected field can smuggle in. ``source_uri`` and
    ``doc_id`` must be non-blank (INV-G3 — anonymous evidence is forbidden), and
    ``score``, if present, must lie within ``[0.0, 1.0]`` (INV-G6).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_uri: str
    doc_id: str
    retrieved_at: datetime
    snippet: str
    span: str | None = None
    score: float | None = None

    @field_validator("source_uri", "doc_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        # INV-G3: reject blank identifiers fail-closed so evidence can always be
        # traced back to a real source. Validate on the stripped form but preserve
        # the original value (do not mutate caller data). The error names only the
        # field (Pydantic supplies it) — never the raw value.
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("score")
    @classmethod
    def _score_range(cls, value: float | None) -> float | None:
        # INV-G6: a confidence score, when present, is a probability in [0.0, 1.0].
        # ``None`` means "no score" and is allowed. ``-0.0`` compares equal to
        # ``0.0`` and is therefore accepted.
        if value is not None and not (0.0 <= value <= 1.0):
            raise ValueError("score must be within [0.0, 1.0]")
        return value


def is_high_impact(level: ImpactLevel) -> bool:
    """True iff ``level`` is HIGH or CRITICAL. Pure and deterministic."""
    return level in (ImpactLevel.HIGH, ImpactLevel.CRITICAL)


def impact_from_axes(active_axis_count: int) -> ImpactLevel:
    """Map the number of active Rule of Two axes to an :class:`ImpactLevel`.

    A decision that trips **all three** Rule of Two axes is, by
    definition, at the HITL-forcing maximum — the same boundary
    :func:`secugent.core.rule_of_two.requires_hitl` enforces — so it is
    high-impact (:attr:`ImpactLevel.CRITICAL`). Fewer than three axes contributes
    only :attr:`ImpactLevel.LOW`; the severity-based impact is combined with this
    by the caller (``max`` over :class:`ImpactLevel`), so a two-axis plan is not
    lifted to high-impact by axes alone (deny-by-default, no false positive —
    INV-B3).

    Pure and deterministic (INV-B2): no import of ``rule_of_two`` (leaf-preserving)
    — the caller passes the count, and ``>= 3`` naturally absorbs the impossible
    negative / over-count cases.
    """
    if active_axis_count >= _RULE_OF_TWO_AXIS_COUNT:
        return ImpactLevel.CRITICAL
    return ImpactLevel.LOW


def require_grounding(decision_impact: ImpactLevel, evidence: Sequence[Evidence]) -> None:
    """Enforce that high-impact decisions carry at least one :class:`Evidence`.

    Deny-by-default (INV-G1): if the decision is high-impact
    (:func:`is_high_impact`) and ``evidence`` is empty, raise
    :class:`UngroundedDecisionError`. Low-impact decisions (LOW/MEDIUM) always
    pass. Side-effect free — on failure it only raises; on success it returns
    ``None``. The exception message carries impact/count metadata only, never the
    evidence content.
    """
    if is_high_impact(decision_impact) and len(evidence) == 0:
        raise UngroundedDecisionError(
            f"high-impact decision requires at least one Evidence "
            f"(impact={decision_impact.value}, evidence_count=0)"
        )


def taint_for_evidence() -> TaintSource:
    """The taint source for any external RAG evidence — always CONNECTOR_RESPONSE.

    RAG/search results arrive from systems outside the trust boundary, so they
    can never be a trusted source. :func:`~secugent.core.provenance.is_untrusted`
    of the returned source is always ``True``, and combining it through
    :func:`~secugent.core.provenance.derive_taint` is monotone (turns taint ON,
    never OFF — INV-G4). Pure and deterministic.
    """
    return TaintSource.CONNECTOR_RESPONSE
