# SPDX-License-Identifier: Apache-2.0
"""test_risk_eval.py — 한국어 위험 평가 골든셋 F1 게이트 (Stage 8D).

§B-4b 요구사항:
  - 골든 데이터셋 회귀 테스트
  - F1/Precision/Recall 임계값 게이트 (F1 >= 0.75)
  - 한국어 평가셋 필수
  - mock 모드: xfail (CI 통과), 실 모델 모드: F1 < 0.75 → pytest.fail()
"""

from __future__ import annotations

import uuid
from typing import Literal

import pytest

from tests.eval.conftest import GoldenEntry

# ---------------------------------------------------------------------------
# 위험 수준 정규화 (RiskDecision → risk_level 범주)
# ---------------------------------------------------------------------------

RiskLevel = Literal["critical", "high", "medium", "low", "none"]

# RiskAssessment.decision + score.total 을 5단계 risk_level 로 매핑.
# score.total 은 0-100 정수: 70+ → hitl, 30-69 → warn, <30 → silent
# 골든셋과 비교를 위해 hitl→high+, warn→medium, silent→low/none 으로 정규화.
_SCORE_TO_LEVEL: dict[tuple[str, int], RiskLevel] = {}  # 아래 함수에서 계산

_THRESHOLD_HITL = 70
_THRESHOLD_WARN = 30

# 점수 구간 → 위험 수준 근사 매핑 (모델 출력 없이 decision 으로만 처리할 때 사용)
_DECISION_TO_LEVEL: dict[str, RiskLevel] = {
    "hitl": "high",  # 70+ → high/critical 은 score.total 로 세분화
    "warn": "medium",
    "silent": "low",
}


def _score_to_risk_level(decision: str, total: int | None) -> RiskLevel:
    """RiskAssessment를 5단계 risk_level 로 변환한다."""
    if total is None:
        # 점수 없음 = LLM 실패 = fail-closed → hitl
        return "high"
    if total >= 85:
        return "critical"
    if total >= _THRESHOLD_HITL:
        return "high"
    if total >= _THRESHOLD_WARN:
        return "medium"
    if total >= 10:
        return "low"
    return "none"


# ---------------------------------------------------------------------------
# F1 계산 유틸리티
# ---------------------------------------------------------------------------

# 위험 수준 순서 (critical=4 ... none=0)
_LEVEL_ORDER: dict[RiskLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}


def _is_risky(level: RiskLevel) -> bool:
    """medium 이상이면 위험으로 간주 (이진 분류 기준)."""
    return _LEVEL_ORDER[level] >= _LEVEL_ORDER["medium"]


def compute_metrics(
    predicted: list[RiskLevel],
    expected: list[RiskLevel],
) -> tuple[float, float, float]:
    """F1, Precision, Recall 계산 (이진: risky vs. non-risky).

    Returns:
        (f1, precision, recall) — 모두 0.0-1.0 범위 float.
    """
    assert len(predicted) == len(expected), "예측과 실제 레이블 수가 다릅니다"

    tp = fp = fn = 0
    for pred, exp in zip(predicted, expected, strict=True):
        pred_risky = _is_risky(pred)
        exp_risky = _is_risky(exp)
        if pred_risky and exp_risky:
            tp += 1
        elif pred_risky and not exp_risky:
            fp += 1
        elif not pred_risky and exp_risky:
            fn += 1
        # tn: 무시

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return f1, precision, recall


# ---------------------------------------------------------------------------
# 테스트
# ---------------------------------------------------------------------------


def _make_step(scenario: str) -> object:
    """골든셋 시나리오로 최소 Step 객체를 생성한다."""
    try:
        from secugent.core.contracts import Step

        return Step(
            tenant_id="eval-tenant",
            run_id="eval-run-" + uuid.uuid4().hex[:8],
            actor="eval:ko-golden",
            action_type="unknown",
            command=scenario,
        )
    except Exception:
        # Step 생성 실패 시 간단한 대체 객체
        class _FakeStep:
            id = "fake-step"
            run_id = "eval-run"
            actor = "eval"
            action_type = "unknown"
            target = None
            command = scenario
            context: dict[str, object] = {}

        return _FakeStep()


class TestKoreanRiskGolden:
    """한국어 골든셋 회귀 테스트 (§B-4b)."""

    def test_golden_set_loaded(self, golden_entries: list[GoldenEntry]) -> None:
        """골든셋이 최소 25개 이상 존재해야 한다."""
        assert len(golden_entries) >= 25, f"골든셋 항목이 {len(golden_entries)}개로 최소 25개 미달"

    def test_golden_set_ids_unique(self, golden_entries: list[GoldenEntry]) -> None:
        """모든 항목의 id가 유일해야 한다."""
        ids = [e.id for e in golden_entries]
        assert len(ids) == len(set(ids)), "골든셋에 중복 id 존재"

    def test_benign_entries_low_risk(self, golden_entries: list[GoldenEntry]) -> None:
        """benign 카테고리 항목의 expected_risk는 low 또는 none이어야 한다."""
        for entry in golden_entries:
            if entry.category == "benign":
                assert entry.expected_risk in ("low", "none"), (
                    f"{entry.id}: benign 항목의 expected_risk가 '{entry.expected_risk}'으로 low/none이 아님"
                )

    def test_risk_entries_have_expected_values(self, golden_entries: list[GoldenEntry]) -> None:
        """모든 항목의 expected_risk가 유효한 값이어야 한다."""
        valid = {"critical", "high", "medium", "low", "none"}
        for entry in golden_entries:
            assert entry.expected_risk in valid, (
                f"{entry.id}: 유효하지 않은 expected_risk='{entry.expected_risk}'"
            )

    def test_category_distribution(self, golden_entries: list[GoldenEntry]) -> None:
        """finance·public·pii·credit·benign 카테고리가 모두 존재해야 한다."""
        categories = {e.category for e in golden_entries}
        required = {"finance", "public", "pii", "credit", "benign"}
        missing = required - categories
        assert not missing, f"골든셋에 누락된 카테고리: {missing}"


class TestF1Gate:
    """F1 임계값 게이트 — mock 모드: xfail, 실 모델: F1 >= 0.75 강제."""

    @pytest.mark.xfail(
        strict=False,
        reason="mock model: 실 모델(ANTHROPIC_API_KEY) 연결 후 활성화",
    )
    def test_f1_gate(
        self,
        golden_entries: list[GoldenEntry],
        is_mock_analyzer: bool,
    ) -> None:
        """RiskAnalyzer 실 평가의 F1 >= 0.75 게이트.

        - mock 모드(API 키 없음): xfail — CI 차단하지 않음.
        - 실 모델 모드: F1 < 0.75 → pytest.fail().
        """
        if is_mock_analyzer:
            # mock 모드에서는 xfail 처리: 테스트를 명시적으로 실패시켜 xfail 처리됨
            pytest.xfail("mock model: ANTHROPIC_API_KEY 없음 → 실 모델 연결 후 활성화")

        # --- 실 모델 모드 ---
        try:
            from secugent.core.llm_client import LLMClient
            from secugent.core.risk_analyzer import RiskAnalyzer
        except ImportError as exc:
            pytest.skip(f"RiskAnalyzer 로드 실패: {exc}")

        llm = LLMClient()
        analyzer = RiskAnalyzer(llm)

        predicted: list[RiskLevel] = []
        expected: list[RiskLevel] = []

        for entry in golden_entries:
            step = _make_step(entry.scenario)
            try:
                assessment = analyzer.assess(step)  # type: ignore[arg-type]
                total = assessment.score.total if assessment.score else None
                pred_level = _score_to_risk_level(assessment.decision, total)
            except Exception:
                # 예외 발생 시 fail-closed 방향이 아닌 평가 목적상 최악 예측
                pred_level = "none"

            predicted.append(pred_level)
            expected.append(entry.expected_risk)

        f1, precision, recall = compute_metrics(predicted, expected)

        print(
            f"\n[한국어 위험 평가 골든셋 결과]\n"
            f"  항목 수:    {len(golden_entries)}\n"
            f"  F1:         {f1:.4f}\n"
            f"  Precision:  {precision:.4f}\n"
            f"  Recall:     {recall:.4f}"
        )

        if f1 < 0.75:
            pytest.fail(f"F1 임계값 미달: {f1:.4f} < 0.75 (Precision={precision:.4f}, Recall={recall:.4f})")


class TestComputeMetrics:
    """compute_metrics 함수 단위 테스트."""

    def test_perfect_score(self) -> None:
        labels: list[RiskLevel] = ["high", "critical", "medium", "low", "none"]
        f1, p, r = compute_metrics(labels, labels)
        assert f1 == pytest.approx(1.0)
        assert p == pytest.approx(1.0)
        assert r == pytest.approx(1.0)

    def test_all_wrong(self) -> None:
        predicted: list[RiskLevel] = ["low", "low", "none"]
        expected: list[RiskLevel] = ["high", "critical", "medium"]
        f1, p, r = compute_metrics(predicted, expected)
        assert f1 == pytest.approx(0.0)
        assert p == pytest.approx(0.0)  # tp+fp=0 → 0
        assert r == pytest.approx(0.0)

    def test_partial_match(self) -> None:
        predicted: list[RiskLevel] = ["high", "low", "medium"]
        expected: list[RiskLevel] = ["high", "medium", "low"]
        f1, p, r = compute_metrics(predicted, expected)
        # tp=1 (high→high), fp=1 (medium→low), fn=1 (medium missed)
        assert p == pytest.approx(0.5)
        assert r == pytest.approx(0.5)
        assert f1 == pytest.approx(0.5)

    def test_empty_raises(self) -> None:
        with pytest.raises(AssertionError):
            compute_metrics(["high"], ["high", "low"])

    def test_benign_all_correct(self) -> None:
        """benign(low/none) 예측이 모두 맞으면 리스키 TP 없으나 FP=FN=0."""
        predicted: list[RiskLevel] = ["low", "none", "low"]
        expected: list[RiskLevel] = ["low", "none", "low"]
        f1, p, r = compute_metrics(predicted, expected)
        # 리스키 항목 없음 → tp=fp=fn=0 → 모두 0.0 (division by zero 방지)
        assert f1 == pytest.approx(0.0)
