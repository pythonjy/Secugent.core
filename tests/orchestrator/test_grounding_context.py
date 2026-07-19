# SPDX-License-Identifier: Apache-2.0
"""N1 (생산자 브리지) — connector payloads → run-context ``grounding_evidence`` seed.

Exercises :func:`secugent.orchestrator.grounding_context.seed_grounding_evidence`
per the grounding-producer-bridge spec: the pure,
fail-closed, all-or-nothing producer that is the orchestrator-layer symmetric
counterpart of the consumer :func:`secugent.orchestrator.runner._bind_plan_evidence`.

Invariants under test: INV-A1 (re-validation single-source), INV-A2 (non-mutating,
pure), INV-A3 (fail-closed all-or-nothing), INV-A4 (empty ⇒ no key), INV-A10
(existing ``grounding_evidence`` key ⇒ fail-closed reject).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.orchestrator.evidence_binding import (
    EvidenceBindingError,
    evidence_from_connector_payload,
)
from secugent.orchestrator.grounding_context import seed_grounding_evidence

_FIXED_TS = datetime(2026, 7, 14, 9, 30, tzinfo=UTC)


def _korean_evidence_dict(doc_id: str = "LR-00123") -> dict[str, Any]:
    # 한국어 픽스처: 여신 심사 근거 문서 (§C-3).
    return {
        "source_uri": f"s3://loan-review/2026/여신심사_{doc_id}.pdf",
        "doc_id": doc_id,
        "retrieved_at": _FIXED_TS.isoformat(),
        "snippet": "여신 심사 기준 초과 항목 발견",
        "score": 0.87,
    }


def _payload(*dicts: dict[str, Any]) -> dict[str, Any]:
    return {"evidence": list(dicts)}


def test_single_payload_seeds_context() -> None:
    out = seed_grounding_evidence({"role": "operator"}, [_payload(_korean_evidence_dict())])
    assert out["role"] == "operator"
    assert len(out["grounding_evidence"]) == 1
    assert out["grounding_evidence"][0]["doc_id"] == "LR-00123"


def test_multiple_payloads_combine_in_order() -> None:
    out = seed_grounding_evidence(
        {},
        [
            _payload(_korean_evidence_dict("LR-1"), _korean_evidence_dict("LR-2")),
            _payload(_korean_evidence_dict("LR-3")),
        ],
    )
    assert [e["doc_id"] for e in out["grounding_evidence"]] == ["LR-1", "LR-2", "LR-3"]


def test_empty_payload_list_adds_no_key() -> None:
    # INV-A4: 근거 없는 런은 정상 → 키 미추가.
    out = seed_grounding_evidence({"role": "operator"}, [])
    assert "grounding_evidence" not in out
    assert out == {"role": "operator"}


def test_payloads_with_zero_evidence_add_no_key() -> None:
    # INV-A4: connector 가 빈 hits → evidence 0건 → 키 미추가.
    out = seed_grounding_evidence({"role": "operator"}, [_payload(), _payload()])
    assert "grounding_evidence" not in out


def test_original_context_not_mutated() -> None:
    # INV-A2: 입력 mapping 을 mutate 하지 않고 새 dict 반환.
    ctx: dict[str, Any] = {"role": "operator"}
    out = seed_grounding_evidence(ctx, [_payload(_korean_evidence_dict())])
    assert ctx == {"role": "operator"}
    assert out is not ctx


def test_existing_grounding_key_is_fail_closed() -> None:
    # INV-A10: 이미 씨앗이 있으면 이중-writer 방지 위해 fail-closed.
    with pytest.raises(EvidenceBindingError):
        seed_grounding_evidence(
            {"grounding_evidence": [_korean_evidence_dict()]},
            [_payload(_korean_evidence_dict())],
        )


def test_malformed_element_is_fail_closed() -> None:
    # INV-A3: 하나라도 malformed → 전체 실패 (부분 씨앗 금지).
    bad = _korean_evidence_dict()
    del bad["doc_id"]
    with pytest.raises(EvidenceBindingError):
        seed_grounding_evidence({}, [_payload(bad)])


def test_malformed_in_later_payload_rejects_all() -> None:
    good = _payload(_korean_evidence_dict("LR-good"))
    bad_dict = _korean_evidence_dict()
    bad_dict["score"] = 1.5
    with pytest.raises(EvidenceBindingError):
        seed_grounding_evidence({}, [good, _payload(bad_dict)])


def test_non_list_evidence_is_fail_closed() -> None:
    with pytest.raises(EvidenceBindingError):
        seed_grounding_evidence({}, [{"evidence": {"doc_id": "x"}}])


def test_deterministic_same_input_same_output() -> None:
    payloads = [_payload(_korean_evidence_dict("LR-1"), _korean_evidence_dict("LR-2"))]
    a = seed_grounding_evidence({"role": "operator"}, payloads)
    b = seed_grounding_evidence({"role": "operator"}, payloads)
    assert a == b


@settings(max_examples=60)
@given(doc_ids=st.lists(st.integers(min_value=0, max_value=9999), min_size=1, max_size=6))
def test_hypothesis_producer_consumer_roundtrip(doc_ids: list[int]) -> None:
    # 생산자↔소비자 왕복 불변: seed 후 소비자가 동일 개수·순서를 복원.
    ids = [f"LR-{n}" for n in doc_ids]
    out = seed_grounding_evidence({}, [_payload(*(_korean_evidence_dict(i) for i in ids))])
    restored = evidence_from_connector_payload({"evidence": out["grounding_evidence"]})
    assert [e.doc_id for e in restored] == ids


@settings(max_examples=40)
@given(
    n_before=st.integers(min_value=0, max_value=3),
    bad_at=st.integers(min_value=0, max_value=3),
)
def test_hypothesis_any_malformed_always_fails(n_before: int, bad_at: int) -> None:
    # 임의 위치에 malformed 1건 삽입 → 항상 실패 (all-or-nothing).
    good = [_korean_evidence_dict(f"LR-{i}") for i in range(n_before)]
    bad = _korean_evidence_dict("LR-bad")
    del bad["source_uri"]
    elements = good[:bad_at] + [bad] + good[bad_at:]
    with pytest.raises(EvidenceBindingError):
        seed_grounding_evidence({}, [_payload(*elements)])
