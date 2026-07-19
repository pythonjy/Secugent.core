# SPDX-License-Identifier: Apache-2.0
"""N3 boundary tests — connector payload → validated ``Evidence`` (fail-closed).

Exercises :func:`secugent.orchestrator.evidence_binding.evidence_from_connector_payload`
per spec ``docs/specs/2026-07-12-evidence-orchestration-audit.md`` (INV-N3-4):
malformed evidence must NEVER be admitted (no partial acceptance) and a
connector response with no ``evidence`` key is a normal empty result.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.grounding import Evidence
from secugent.orchestrator.evidence_binding import (
    EvidenceBindingError,
    evidence_from_connector_payload,
)

_FIXED_TS = datetime(2026, 7, 12, 9, 30, tzinfo=UTC)


def _korean_evidence_dict() -> dict[str, Any]:
    # 한국어 픽스처: 여신 심사 근거 문서.
    return {
        "source_uri": "s3://loan-review/2026/여신심사_00123.pdf",
        "doc_id": "LR-00123",
        "retrieved_at": _FIXED_TS.isoformat(),
        "snippet": "여신 심사 기준 초과 항목 발견",
        "score": 0.87,
    }


def test_missing_evidence_key_returns_empty() -> None:
    # 근거 없는 도구 응답은 정상 → [].
    assert evidence_from_connector_payload({"outputs": []}) == []


def test_valid_evidence_roundtrips() -> None:
    out = evidence_from_connector_payload({"evidence": [_korean_evidence_dict()]})
    assert len(out) == 1
    assert isinstance(out[0], Evidence)
    assert out[0].source_uri == "s3://loan-review/2026/여신심사_00123.pdf"
    assert out[0].doc_id == "LR-00123"
    assert out[0].score == 0.87


def test_multiple_valid_evidence_preserve_order() -> None:
    a = _korean_evidence_dict()
    b = _korean_evidence_dict()
    b["doc_id"] = "LR-00124"
    out = evidence_from_connector_payload({"evidence": [a, b]})
    assert [e.doc_id for e in out] == ["LR-00123", "LR-00124"]


def test_non_list_evidence_is_fail_closed() -> None:
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": {"doc_id": "x"}})


def test_explicit_none_evidence_is_fail_closed() -> None:
    # 명시적 None 은 리스트가 아니므로 fail-closed (missing 키만 [] 허용).
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": None})


def test_non_mapping_element_is_fail_closed() -> None:
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": ["not-a-dict"]})


def test_blank_source_element_is_fail_closed() -> None:
    bad = _korean_evidence_dict()
    bad["source_uri"] = "   "
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": [bad]})


def test_missing_required_field_is_fail_closed() -> None:
    bad = _korean_evidence_dict()
    del bad["doc_id"]
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": [bad]})


def test_extra_field_forbidden_is_fail_closed() -> None:
    bad = _korean_evidence_dict()
    bad["unexpected"] = "smuggle"
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": [bad]})


def test_out_of_range_score_is_fail_closed() -> None:
    bad = _korean_evidence_dict()
    bad["score"] = 1.5
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": [bad]})


def test_no_partial_acceptance_one_bad_rejects_all() -> None:
    # 부분 수용 금지: 하나라도 malformed → 전체 거부.
    good = _korean_evidence_dict()
    bad = _korean_evidence_dict()
    bad["doc_id"] = ""
    with pytest.raises(EvidenceBindingError):
        evidence_from_connector_payload({"evidence": [good, bad]})


def test_empty_evidence_list_returns_empty() -> None:
    assert evidence_from_connector_payload({"evidence": []}) == []


@settings(max_examples=60)
@given(
    doc_ids=st.lists(
        st.text(min_size=1).filter(lambda s: s.strip() != ""),
        min_size=0,
        max_size=6,
    ),
    scores=st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=6, max_size=6),
)
def test_hypothesis_valid_dicts_roundtrip(doc_ids: list[str], scores: list[float]) -> None:
    payload = {
        "evidence": [
            {
                "source_uri": f"s3://loan-review/{i}.pdf",
                "doc_id": doc_id,
                "retrieved_at": _FIXED_TS.isoformat(),
                "snippet": "s",
                "score": scores[i],
            }
            for i, doc_id in enumerate(doc_ids)
        ]
    }
    out = evidence_from_connector_payload(payload)
    assert len(out) == len(doc_ids)
    assert [e.doc_id for e in out] == doc_ids
    for evidence in out:
        assert isinstance(evidence, Evidence)
