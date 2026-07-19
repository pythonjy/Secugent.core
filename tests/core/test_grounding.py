# SPDX-License-Identifier: Apache-2.0
"""§B-4a deterministic triple for the RAG grounding/evidence boundary (N2).

``secugent.core.grounding`` is a pure leaf module (no I/O, no global state, no
mutation) that owns the *boundary contract* for external RAG/search results:

* :class:`Evidence` — a frozen, validated schema; anonymous evidence (empty
  ``source_uri``/``doc_id``) is unrepresentable.
* :func:`taint_for_evidence` — RAG results can never be a trusted source; always
  ``TaintSource.CONNECTOR_RESPONSE`` (untrusted, monotone with ``derive_taint``).
* :func:`require_grounding` — high-impact (HIGH/CRITICAL) decisions cannot proceed
  without at least one :class:`Evidence` (deny-by-default).

This file provides the §B-4a triple:

* unit — table-based cases (ImpactLevel × evidence presence, score bounds, empty
  fields, frozen/extra rejection);
* property (hypothesis) — INV-G1 (grounding ⇔ high-impact ∧ empty), INV-G4 (taint
  monotonicity for any parent bool), INV-G6 (score bounds);
* scenario regression — Korean 여신심사 loan-review fixture (§C-3);
* 100× determinism — same ``(impact, evidence)`` verdict AND byte-identical
  ``model_dump(mode="json")`` 100 times.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import hypothesis.strategies as st
import pytest
from hypothesis import given, settings
from pydantic import ValidationError

from secugent.core.contracts import Risk
from secugent.core.grounding import (
    Evidence,
    ImpactLevel,
    UngroundedDecisionError,
    impact_from_axes,
    is_high_impact,
    require_grounding,
    taint_for_evidence,
)
from secugent.core.provenance import TaintSource, derive_taint, is_untrusted

# A fixed, wall-clock-free timestamp so Evidence construction is deterministic.
_FIXED_TS = datetime(2026, 7, 12, 9, 30, tzinfo=UTC)

# §C-3 Korean fixture: a real-shaped 여신(loan) 심사보고서 evidence item.
_KOREAN_EVIDENCE = Evidence(
    source_uri="s3://loan-review/2026/여신심사_00123.pdf",
    doc_id="LR-00123",
    retrieved_at=_FIXED_TS,
    snippet="차주 신용등급 BBB, 담보인정비율 60%로 여신 승인 요건을 충족함.",
    span="p.3 §2.1",
    score=0.87,
)


def _evidence(**overrides: object) -> Evidence:
    """Build a valid Evidence with sane defaults, overriding named fields."""
    base: dict[str, object] = {
        "source_uri": "s3://kb/doc.pdf",
        "doc_id": "DOC-1",
        "retrieved_at": _FIXED_TS,
        "snippet": "some snippet",
    }
    base.update(overrides)
    return Evidence(**base)  # type: ignore[arg-type]  # dynamic test kwargs


# ---------------------------------------------------------------------------
# Unit — ImpactLevel ↔ Risk.severity lossless alignment
# ---------------------------------------------------------------------------


def test_impact_level_values_match_risk_severity() -> None:
    """N3 maps Risk.severity → ImpactLevel losslessly: string values must match."""
    severity_values = set(Risk.model_fields["severity"].annotation.__args__)  # type: ignore[union-attr]
    impact_values = {level.value for level in ImpactLevel}
    assert impact_values == severity_values == {"low", "medium", "high", "critical"}


def test_impact_level_is_str_enum() -> None:
    # StrEnum members compare equal to their string value (used by N3 mapping).
    assert ImpactLevel.HIGH == "high"
    assert ImpactLevel("critical") is ImpactLevel.CRITICAL


# ---------------------------------------------------------------------------
# Unit — is_high_impact
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (ImpactLevel.LOW, False),
        (ImpactLevel.MEDIUM, False),
        (ImpactLevel.HIGH, True),
        (ImpactLevel.CRITICAL, True),
    ],
)
def test_is_high_impact(level: ImpactLevel, expected: bool) -> None:
    assert is_high_impact(level) is expected


# ---------------------------------------------------------------------------
# Unit — impact_from_axes (INV-B1, B2, B3): Rule-of-Two 3-axis → ImpactLevel
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, ImpactLevel.LOW),
        (1, ImpactLevel.LOW),
        (2, ImpactLevel.LOW),
        (3, ImpactLevel.CRITICAL),
    ],
)
def test_impact_from_axes_boundary(count: int, expected: ImpactLevel) -> None:
    # INV-B1: the >=3 boundary mirrors rule_of_two.requires_hitl (§A-2.1).
    assert impact_from_axes(count) is expected


def test_impact_from_axes_below_three_is_not_high(count: int = 2) -> None:
    # INV-B3: <3 axes never trips grounding (no dead-lock of a legitimate plan).
    assert is_high_impact(impact_from_axes(count)) is False


@pytest.mark.parametrize("count", [-5, -1])
def test_impact_from_axes_negative_is_low(count: int) -> None:
    # There are only three axes; a negative count is impossible but must be LOW.
    assert impact_from_axes(count) is ImpactLevel.LOW


@pytest.mark.parametrize("count", [4, 10, 100])
def test_impact_from_axes_above_three_is_critical(count: int) -> None:
    assert impact_from_axes(count) is ImpactLevel.CRITICAL


@given(n=st.integers(min_value=-1000, max_value=1000))
@settings(max_examples=300)
def test_prop_impact_from_axes_high_iff_ge_three(n: int) -> None:
    """INV-B1: high-impact ⇔ n >= 3, for any int."""
    assert is_high_impact(impact_from_axes(n)) == (n >= 3)


@given(a=st.integers(min_value=-10, max_value=10), b=st.integers(min_value=-10, max_value=10))
@settings(max_examples=200)
def test_prop_impact_from_axes_monotone(a: int, b: int) -> None:
    """Non-decreasing in the axis count (more axes never lowers impact)."""
    lo, hi = (a, b) if a <= b else (b, a)
    rank = {ImpactLevel.LOW: 0, ImpactLevel.MEDIUM: 1, ImpactLevel.HIGH: 2, ImpactLevel.CRITICAL: 3}
    assert rank[impact_from_axes(lo)] <= rank[impact_from_axes(hi)]


def test_determinism_impact_from_axes_100_runs() -> None:
    # INV-B2: pure leaf — same input → same ImpactLevel 100×.
    cases = [-1, 0, 1, 2, 3, 4]
    expected = [impact_from_axes(n) for n in cases]
    for _ in range(100):
        assert [impact_from_axes(n) for n in cases] == expected
    assert expected == [
        ImpactLevel.LOW,
        ImpactLevel.LOW,
        ImpactLevel.LOW,
        ImpactLevel.LOW,
        ImpactLevel.CRITICAL,
        ImpactLevel.CRITICAL,
    ]


def test_scenario_three_axis_plan_is_high_impact() -> None:
    """§C-1 scenario: a plan tripping all three Rule-of-Two axes is high-impact."""
    assert is_high_impact(impact_from_axes(3)) is True


# ---------------------------------------------------------------------------
# Unit — Evidence validation (INV-G3, G5, G6)
# ---------------------------------------------------------------------------


def test_evidence_valid_construction() -> None:
    ev = _evidence()
    assert ev.source_uri == "s3://kb/doc.pdf"
    assert ev.doc_id == "DOC-1"
    assert ev.span is None
    assert ev.score is None


def test_evidence_is_frozen() -> None:
    """INV-G5: frozen — post-construction reassignment raises ValidationError."""
    ev = _evidence()
    with pytest.raises(ValidationError):
        ev.source_uri = "s3://kb/other.pdf"  # type: ignore[misc]


def test_evidence_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _evidence(unexpected="x")


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_evidence_rejects_blank_source_uri(bad: str) -> None:
    """INV-G3: anonymous evidence (blank source_uri) is unrepresentable."""
    with pytest.raises(ValidationError):
        _evidence(source_uri=bad)


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_evidence_rejects_blank_doc_id(bad: str) -> None:
    with pytest.raises(ValidationError):
        _evidence(doc_id=bad)


def test_evidence_blank_source_uri_message_has_no_sensitive_value() -> None:
    """Error names the field, not the raw path/snippet (spec §실패 시 동작)."""
    with pytest.raises(ValidationError) as exc:
        _evidence(source_uri="   ")
    text = str(exc.value)
    assert "source_uri" in text


@pytest.mark.parametrize("score", [0.0, -0.0, 0.5, 1.0, 0.87])
def test_evidence_accepts_in_range_score(score: float) -> None:
    assert _evidence(score=score).score == score


@pytest.mark.parametrize("score", [-0.1, 1.0000001, 2.0, -5.0, 100.0])
def test_evidence_rejects_out_of_range_score(score: float) -> None:
    """INV-G6: score present ⇒ within [0.0, 1.0]."""
    with pytest.raises(ValidationError):
        _evidence(score=score)


def test_evidence_score_none_allowed() -> None:
    assert _evidence(score=None).score is None


def test_evidence_empty_snippet_and_none_span_allowed() -> None:
    ev = _evidence(snippet="", span=None)
    assert ev.snippet == ""
    assert ev.span is None


def test_evidence_unicode_fields_allowed() -> None:
    ev = _KOREAN_EVIDENCE
    assert "여신심사" in ev.source_uri
    assert ev.doc_id == "LR-00123"


# ---------------------------------------------------------------------------
# Unit — require_grounding (INV-G1, deny-by-default)
# ---------------------------------------------------------------------------


def test_require_grounding_high_impact_empty_raises() -> None:
    with pytest.raises(UngroundedDecisionError):
        require_grounding(ImpactLevel.HIGH, [])


def test_require_grounding_critical_empty_raises() -> None:
    with pytest.raises(UngroundedDecisionError):
        require_grounding(ImpactLevel.CRITICAL, [])


@pytest.mark.parametrize("level", [ImpactLevel.LOW, ImpactLevel.MEDIUM])
def test_require_grounding_low_impact_empty_passes(level: ImpactLevel) -> None:
    assert require_grounding(level, []) is None


@pytest.mark.parametrize(
    "level",
    [ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL],
)
def test_require_grounding_with_evidence_always_passes(level: ImpactLevel) -> None:
    assert require_grounding(level, [_evidence()]) is None


def test_require_grounding_high_impact_multiple_evidence_passes() -> None:
    assert require_grounding(ImpactLevel.CRITICAL, [_evidence(), _KOREAN_EVIDENCE]) is None


def test_ungrounded_error_message_has_no_sensitive_value() -> None:
    """Exception must not leak source_uri/snippet — field/impact metadata only."""
    with pytest.raises(UngroundedDecisionError) as exc:
        require_grounding(ImpactLevel.CRITICAL, [])
    text = str(exc.value)
    assert "여신심사" not in text
    assert "s3://" not in text


# ---------------------------------------------------------------------------
# Unit — taint_for_evidence (INV-G4)
# ---------------------------------------------------------------------------


def test_taint_for_evidence_is_connector_response() -> None:
    assert taint_for_evidence() is TaintSource.CONNECTOR_RESPONSE


def test_taint_for_evidence_is_untrusted() -> None:
    assert is_untrusted(taint_for_evidence()) is True


def test_taint_for_evidence_taints_clean_parent() -> None:
    # INV-G4: even a clean (untainted) parent becomes tainted through RAG evidence.
    assert derive_taint(False, taint_for_evidence()) is True


# ---------------------------------------------------------------------------
# Property (hypothesis) — INV-G1, INV-G4, INV-G6
# ---------------------------------------------------------------------------

_IMPACT_LEVELS = st.sampled_from(list(ImpactLevel))
_EVIDENCE_LISTS = st.lists(st.just(_evidence()), min_size=0, max_size=4)


@given(level=_IMPACT_LEVELS, evidence=_EVIDENCE_LISTS)
@settings(max_examples=200)
def test_prop_grounding_iff_high_impact_and_empty(level: ImpactLevel, evidence: list[Evidence]) -> None:
    """INV-G1: require_grounding raises ⇔ (high-impact ∧ evidence empty)."""
    should_raise = is_high_impact(level) and len(evidence) == 0
    if should_raise:
        with pytest.raises(UngroundedDecisionError):
            require_grounding(level, evidence)
    else:
        assert require_grounding(level, evidence) is None


@given(parent=st.booleans())
@settings(max_examples=200)
def test_prop_taint_monotone(parent: bool) -> None:
    """INV-G4: RAG evidence taint turns ON for any parent state, never OFF."""
    result = derive_taint(parent, taint_for_evidence())
    assert result is True
    # Monotone: if parent already tainted, still tainted.
    if parent:
        assert result is True


@given(score=st.floats(allow_nan=False, allow_infinity=False))
@settings(max_examples=300)
def test_prop_score_bounds(score: float) -> None:
    """INV-G6: Evidence accepts score iff 0.0 <= score <= 1.0."""
    in_range = 0.0 <= score <= 1.0
    if in_range:
        assert _evidence(score=score).score == score
    else:
        with pytest.raises(ValidationError):
            _evidence(score=score)


@given(text=st.text())
@settings(max_examples=200)
def test_prop_blank_identifiers_rejected(text: str) -> None:
    """INV-G3: source_uri accepted iff it is non-blank after strip."""
    if text.strip() == "":
        with pytest.raises(ValidationError):
            _evidence(source_uri=text)
    else:
        assert _evidence(source_uri=text).source_uri == text


# ---------------------------------------------------------------------------
# Scenario regression — Korean 여신심사 loan review (§C-3)
# ---------------------------------------------------------------------------


def test_scenario_korean_loan_review_grounded_passes() -> None:
    """High-impact 여신 승인 with a loan-review evidence item proceeds."""
    require_grounding(ImpactLevel.HIGH, [_KOREAN_EVIDENCE])


def test_scenario_korean_loan_review_ungrounded_raises() -> None:
    """The same high-impact decision with evidence removed is blocked."""
    with pytest.raises(UngroundedDecisionError):
        require_grounding(ImpactLevel.HIGH, [])


# ---------------------------------------------------------------------------
# Determinism 100× (INV-G2)
# ---------------------------------------------------------------------------


def test_determinism_require_grounding_100_runs() -> None:
    cases: list[tuple[ImpactLevel, list[Evidence]]] = [
        (ImpactLevel.HIGH, []),
        (ImpactLevel.CRITICAL, []),
        (ImpactLevel.LOW, []),
        (ImpactLevel.MEDIUM, [_KOREAN_EVIDENCE]),
        (ImpactLevel.HIGH, [_KOREAN_EVIDENCE]),
    ]

    def verdict(level: ImpactLevel, ev: list[Evidence]) -> bool:
        try:
            require_grounding(level, ev)
        except UngroundedDecisionError:
            return True
        return False

    expected = [verdict(level, ev) for level, ev in cases]
    for _ in range(100):
        assert [verdict(level, ev) for level, ev in cases] == expected
    # High/critical empty raise; the rest pass.
    assert expected == [True, True, False, False, False]


def test_determinism_evidence_json_dump_100_runs() -> None:
    """Evidence.model_dump(mode="json") is byte-identical across 100 dumps."""
    expected = json.dumps(_KOREAN_EVIDENCE.model_dump(mode="json"), sort_keys=True)
    for _ in range(100):
        got = json.dumps(_KOREAN_EVIDENCE.model_dump(mode="json"), sort_keys=True)
        assert got == expected


def test_determinism_taint_for_evidence_100_runs() -> None:
    expected = taint_for_evidence()
    for _ in range(100):
        assert taint_for_evidence() is expected
