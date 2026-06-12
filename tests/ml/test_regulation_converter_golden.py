# SPDX-License-Identifier: Apache-2.0
"""EM-04 — regulation converter golden set (§B-4b: Korean eval + F1/P/R gate).

The converter is the first *probabilistic* module. Per §B-4b it is gated on a
Korean golden dataset with an F1/Precision/Recall threshold (not a unit assert),
and it must **fail closed** (return ``None`` → human drafting) on every
untrustworthy output. The LLM draft is never enforced — it only feeds the
deterministic ``authoring.sign_off`` gate.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from secugent.core.llm_client import MockLLMClient
from secugent.core.ml.regulation_converter import ConversionResult, RegulationConverter
from secugent.core.sec.policy.fixtures import Fixture
from secugent.core.sec.policy.schema import Match, PolicyDoc

# Micro-averaged F1 gate for the converter (§B-4b). Below this ⇒ PR blocked.
F1_GATE = 0.6

# A rule identity = (effect, kind, target_glob, sink_class, min_label-as-int).
RuleKey = tuple[str, str | None, str | None, str | None, int | None]


@dataclass(frozen=True)
class GoldenCase:
    """One Korean golden example: NL rule → the rule set we expect + the
    (possibly imperfect) draft the mock LLM returns."""

    name: str
    nl_ko: str
    expected: set[RuleKey]
    llm_response: dict[str, object]


def _key_from_match(effect: str, match: Match) -> RuleKey:
    return (
        effect,
        str(match.kind) if match.kind is not None else None,
        match.target_glob,
        str(match.sink_class) if match.sink_class is not None else None,
        int(match.min_label) if match.min_label is not None else None,
    )


def _keys_from_draft(draft: PolicyDoc) -> set[RuleKey]:
    return {_key_from_match(rule.effect, rule.match) for rule in draft.rules}


def _prf(expected: set[RuleKey], got: set[RuleKey]) -> tuple[float, float, float]:
    true_positives = len(expected & got)
    precision = true_positives / len(got) if got else 0.0
    recall = true_positives / len(expected) if expected else 0.0
    denom = precision + recall
    f1 = (2 * precision * recall / denom) if denom else 0.0
    return precision, recall, f1


# --- Korean golden dataset --------------------------------------------------

_PARTIAL = GoldenCase(
    name="confidential-egress+temp-write",
    nl_ko="대외비 이상 데이터는 외부로 전송하지 말 것. 임시 폴더(c:/temp)에는 쓰기를 허용한다.",
    # Ground truth: two rules.
    expected={
        ("deny", "net_send", None, "external", 2),
        ("allow", "file_write", "c:/temp/*", None, None),
    },
    # Mock returns ONLY the deny rule (omits the temp-write allow) → recall 0.5.
    llm_response={
        "draft": {
            "version": "1",
            "tenant_id": "_base",
            "rules": [
                {
                    "id": "r-ext-deny",
                    "effect": "deny",
                    "match": {"kind": "net_send", "sink_class": "external", "min_label": 2},
                    "rationale": "대외비 이상 데이터의 외부 전송 금지",
                }
            ],
        },
        "fixtures": [
            {
                "effect": {
                    "kind": "net_send",
                    "target": "https://crm.example.com/send",
                    "sink_class": "external",
                },
                "label": 2,
                "expected": "deny",
            }
        ],
        "paraphrase_ko": "대외비 이상 데이터는 외부로 전송할 수 없습니다.",
        "confidence": 0.9,
    },
)

_PERFECT = GoldenCase(
    name="secret-egress",
    nl_ko="비밀(SECRET) 등급 데이터는 외부로 전송 금지.",
    expected={("deny", "net_send", None, "external", 3)},
    llm_response={
        "draft": {
            "version": "1",
            "tenant_id": "_base",
            "rules": [
                {
                    "id": "r-secret-deny",
                    "effect": "deny",
                    "match": {"kind": "net_send", "sink_class": "external", "min_label": 3},
                    "rationale": "비밀 등급 데이터의 외부 전송 금지",
                }
            ],
        },
        "fixtures": [
            {
                "effect": {
                    "kind": "net_send",
                    "target": "https://api.partner.com/upload",
                    "sink_class": "external",
                },
                "label": 3,
                "expected": "deny",
            }
        ],
        "paraphrase_ko": "비밀 등급 데이터는 외부로 전송할 수 없습니다.",
        "confidence": 0.95,
    },
)

GOLDEN = [_PARTIAL, _PERFECT]


def _convert(case: GoldenCase) -> ConversionResult:
    llm = MockLLMClient()
    llm.queue_json(case.llm_response)
    result = RegulationConverter(llm, min_confidence=0.5).convert(case.nl_ko, tenant_id="acme")
    assert result is not None, f"golden case {case.name} should convert"
    return result


def test_golden_set_meets_micro_averaged_f1_gate() -> None:
    total_tp = total_got = total_expected = 0
    for case in GOLDEN:
        result = _convert(case)
        # every conversion must carry usable Korean back-translation + fixtures
        assert result.paraphrase_ko
        assert result.fixtures and all(isinstance(f, Fixture) for f in result.fixtures)
        got = _keys_from_draft(result.draft)
        total_tp += len(case.expected & got)
        total_got += len(got)
        total_expected += len(case.expected)

    precision = total_tp / total_got
    recall = total_tp / total_expected
    f1 = 2 * precision * recall / (precision + recall)
    assert f1 >= F1_GATE, f"converter F1={f1:.3f} below gate {F1_GATE}"
    assert precision == pytest.approx(1.0)  # mock never emits a wrong rule
    assert recall == pytest.approx(2 / 3)  # 2 of 3 ground-truth rules recovered


def test_partial_case_has_real_prf_arithmetic() -> None:
    """Guards the harness itself: a known-imperfect draft yields the exact
    P/R/F1 we expect (proves the gate is computed, not hard-coded)."""
    result = _convert(_PARTIAL)
    precision, recall, f1 = _prf(_PARTIAL.expected, _keys_from_draft(result.draft))
    assert precision == pytest.approx(1.0)
    assert recall == pytest.approx(0.5)
    assert f1 == pytest.approx(2 / 3, abs=1e-3)


def test_convert_returns_none_on_non_json() -> None:
    llm = MockLLMClient()
    llm.queue("이건 JSON 형식이 아닙니다.")
    assert RegulationConverter(llm).convert("아무 규칙", tenant_id="acme") is None


def test_convert_returns_none_on_low_confidence() -> None:
    case = dict(_PARTIAL.llm_response)
    case["confidence"] = 0.3  # below min_confidence
    llm = MockLLMClient()
    llm.queue_json(case)
    assert RegulationConverter(llm, min_confidence=0.5).convert("규칙", tenant_id="acme") is None


def test_convert_returns_none_on_empty_fixtures() -> None:
    case = dict(_PARTIAL.llm_response)
    case["fixtures"] = []  # no behavior examples ⇒ cannot review ⇒ fail closed
    llm = MockLLMClient()
    llm.queue_json(case)
    assert RegulationConverter(llm).convert("규칙", tenant_id="acme") is None


def test_convert_returns_none_on_llm_error() -> None:
    llm = MockLLMClient(fail_n=1)  # first generate() raises LLMError
    assert RegulationConverter(llm).convert("규칙", tenant_id="acme") is None


# --- defensive parse branches (fail closed, §B-8) ---------------------------


def test_convert_strips_markdown_json_fence() -> None:
    """LLMs often wrap JSON in a ```json fence despite instructions; the parser
    tolerates it rather than failing closed on a recoverable formatting quirk."""
    import json as _json

    fenced = "```json\n" + _json.dumps(_PARTIAL.llm_response) + "\n```"
    llm = MockLLMClient()
    llm.queue(fenced)
    result = RegulationConverter(llm, min_confidence=0.5).convert(_PARTIAL.nl_ko, tenant_id="acme")
    assert result is not None
    assert result.draft.rules[0].id == "r-ext-deny"


def test_convert_strips_plain_code_fence_without_lang_tag() -> None:
    import json as _json

    fenced = "```\n" + _json.dumps(_PERFECT.llm_response) + "\n```"  # no "json" tag
    llm = MockLLMClient()
    llm.queue(fenced)
    result = RegulationConverter(llm, min_confidence=0.5).convert(_PERFECT.nl_ko, tenant_id="acme")
    assert result is not None
    assert result.draft.rules[0].id == "r-secret-deny"


def test_convert_returns_none_on_non_dict_json() -> None:
    llm = MockLLMClient()
    llm.queue("[1, 2, 3]")  # valid JSON, but not an object
    assert RegulationConverter(llm).convert("규칙", tenant_id="acme") is None


def test_convert_returns_none_on_missing_draft_key() -> None:
    llm = MockLLMClient()
    llm.queue_json({"fixtures": [], "confidence": 0.9})  # no "draft" → KeyError → fail closed
    assert RegulationConverter(llm).convert("규칙", tenant_id="acme") is None


def test_convert_returns_none_on_bad_fixture_expected() -> None:
    case = dict(_PARTIAL.llm_response)
    bad_fixture = {
        "effect": {"kind": "net_send", "target": "https://x.example.com/a", "sink_class": "external"},
        "label": 2,
        "expected": "maybe",  # not allow/deny/hard_block → ValueError → fail closed
    }
    case["fixtures"] = [bad_fixture]
    llm = MockLLMClient()
    llm.queue_json(case)
    assert RegulationConverter(llm).convert("규칙", tenant_id="acme") is None
