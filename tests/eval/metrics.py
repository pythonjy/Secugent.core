# SPDX-License-Identifier: Apache-2.0
"""tests/eval/metrics.py — RISKANALYZER 평가 공용 데이터 모델 + 지표 (G-H6).

골든셋 데이터 모델(``GoldenEntry``)·로더(``load_golden``)와 순수 지표
함수(``compute_metrics``·``score_to_risk_level``)를 한 곳에 모은 **단일 출처**다.
``conftest.py`` 픽스처, ``test_risk_eval.py`` 게이트, ``scripts/eval_ab.py`` A/B
하네스가 모두 이 모듈을 재사용한다 (드리프트 0).

§B-4b 분류: 확률적 모듈 평가 도구(테스트 티어). 순수 함수이므로 네트워크·LLM에
의존하지 않으며 결정적이다 (동일 입력 → 동일 출력).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

RiskLevel = Literal["critical", "high", "medium", "low", "none"]

# 위험 수준 순서 (critical=4 ... none=0).
LEVEL_ORDER: dict[RiskLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}

_THRESHOLD_HITL = 70
_THRESHOLD_WARN = 30


@dataclass(frozen=True)
class GoldenEntry:
    """골든셋 단일 항목."""

    id: str
    scenario: str
    expected_risk: RiskLevel
    category: str
    regulation: str | None


def load_golden(path: Path) -> list[GoldenEntry]:
    """JSONL 골든셋 전체를 로드해 ``GoldenEntry`` 리스트로 반환한다.

    빈 줄은 건너뛴다. 파일이 없으면 ``FileNotFoundError``가 전파된다(호출자가
    skip/안내를 결정).
    """
    entries: list[GoldenEntry] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            entries.append(
                GoldenEntry(
                    id=raw["id"],
                    scenario=raw["scenario"],
                    expected_risk=raw["expected_risk"],
                    category=raw["category"],
                    regulation=raw.get("regulation"),
                )
            )
    return entries


def score_to_risk_level(decision: str, total: int | None) -> RiskLevel:
    """``RiskAssessment``(decision + score.total)를 5단계 ``RiskLevel``로 변환한다.

    ``total is None`` (LLM 실패 = fail-closed) → ``high``.

    ``decision == 'hitl'``: HITL 필요 시나리오는 점수와 무관하게 위험
    수준(high)으로 표면화된다. 낮은 점수라도 HITL이 필요한 결정을
    non-risky로 분류하면 false negative가 된다 (E3 fix).
    """
    # E3: HITL-required decision은 점수와 무관하게 항상 risky.
    # fail-closed(total is None)보다 먼저 확인해 두 경로 모두 보장.
    if decision == "hitl":
        return "high"
    if total is None:
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


def is_risky(level: RiskLevel) -> bool:
    """medium 이상이면 위험으로 간주 (이진 분류 기준)."""
    return LEVEL_ORDER[level] >= LEVEL_ORDER["medium"]


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
        pred_risky = is_risky(pred)
        exp_risky = is_risky(exp)
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
