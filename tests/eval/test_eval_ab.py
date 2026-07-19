# SPDX-License-Identifier: Apache-2.0
"""test_eval_ab.py — A/B 모델 교체 증거 하네스 (§B-4b).

상위 명세: 모듈 스펙 (eval CI 게이트)

순수 계산부(evaluate/run_ab)를 fake predictor로 오프라인·결정적으로 검증한다.
실모델 경로(LLM 호출)는 자격증명이 필요하므로 여기서 테스트하지 않는다(§B-4b).
"""

from __future__ import annotations

import pytest

from tests.eval.ab import AbReport, Metrics, evaluate, format_report, main, run_ab
from tests.eval.metrics import GoldenEntry, RiskLevel


def _entry(eid: str, expected: RiskLevel, category: str = "finance") -> GoldenEntry:
    return GoldenEntry(
        id=eid,
        scenario=f"시나리오 {eid}: 한국어 위험 평가 케이스",  # 한국어 픽스처 (§C-3)
        expected_risk=expected,
        category=category,
        regulation="전자금융감독규정",
    )


_GOLDEN = [
    _entry("g1", "high"),
    _entry("g2", "critical"),
    _entry("g3", "low", category="benign"),
    _entry("g4", "none", category="benign"),
]


def _perfect(entry: GoldenEntry) -> RiskLevel:
    return entry.expected_risk


def _always_none(_entry: GoldenEntry) -> RiskLevel:
    return "none"


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


def test_evaluate_perfect_predictor() -> None:
    m = evaluate(_GOLDEN, _perfect, label="perfect")
    assert m.label == "perfect"
    assert m.n == 4
    assert m.errors == 0
    assert m.f1 == pytest.approx(1.0)
    assert m.precision == pytest.approx(1.0)
    assert m.recall == pytest.approx(1.0)


def test_evaluate_all_none_predictor_misses_risky() -> None:
    """Predicting 'none' everywhere → all risky entries are false negatives."""
    m = evaluate(_GOLDEN, _always_none, label="naive")
    # 2 risky (g1,g2) all missed → recall 0 → F1 0.
    assert m.recall == pytest.approx(0.0)
    assert m.f1 == pytest.approx(0.0)


def test_evaluate_surfaces_predictor_errors_without_masking() -> None:
    """A raising predictor is counted in errors and recorded fail-closed ('high'),
    NOT silently masked as best-case (spec edge case)."""

    def _boom(_entry: GoldenEntry) -> RiskLevel:
        raise RuntimeError("model unreachable")

    m = evaluate(_GOLDEN, _boom, label="broken")
    assert m.errors == 4  # every entry raised
    # All recorded as 'high' (risky): risky-expected (g1,g2) → TP, benign (g3,g4) → FP.
    # precision = 2/4 = 0.5, recall = 2/2 = 1.0.
    assert m.precision == pytest.approx(0.5)
    assert m.recall == pytest.approx(1.0)


def test_evaluate_empty_golden_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        evaluate([], _perfect, label="x")


# ---------------------------------------------------------------------------
# run_ab
# ---------------------------------------------------------------------------


def test_run_ab_detects_regression() -> None:
    report = run_ab(_GOLDEN, _perfect, _always_none, baseline_label="base", candidate_label="cand")
    assert isinstance(report, AbReport)
    assert report.baseline.f1 == pytest.approx(1.0)
    assert report.candidate.f1 == pytest.approx(0.0)
    assert report.delta_f1 == pytest.approx(-1.0)
    assert report.regressed is True


def test_run_ab_no_regression_when_equal() -> None:
    """baseline == candidate → delta 0, not flagged as regressed (EPS tolerance)."""
    report = run_ab(_GOLDEN, _perfect, _perfect, baseline_label="a", candidate_label="b")
    assert report.delta_f1 == pytest.approx(0.0)
    assert report.regressed is False


def test_run_ab_improvement_not_regression() -> None:
    report = run_ab(_GOLDEN, _always_none, _perfect, baseline_label="old", candidate_label="new")
    assert report.delta_f1 == pytest.approx(1.0)
    assert report.regressed is False


def test_run_ab_is_deterministic() -> None:
    """INV-4: same (golden, predictors) → identical report (pure function)."""
    r1 = run_ab(_GOLDEN, _perfect, _always_none, baseline_label="b", candidate_label="c")
    r2 = run_ab(_GOLDEN, _perfect, _always_none, baseline_label="b", candidate_label="c")
    assert r1 == r2  # frozen dataclasses compare by value


# ---------------------------------------------------------------------------
# format_report / CLI guard
# ---------------------------------------------------------------------------


def test_format_report_contains_key_fields() -> None:
    report = run_ab(_GOLDEN, _perfect, _always_none, baseline_label="base", candidate_label="cand")
    text = format_report(report)
    assert "A/B" in text
    assert "base" in text and "cand" in text
    assert "F1=" in text
    assert "REGRESSED" in text  # this run regressed


def test_main_without_credentials_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ANTHROPIC_API_KEY and no domestic endpoint → exit 2 (no silent false-pass)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", raising=False)
    rc = main(["--baseline-model", "claude-sonnet-4-6", "--candidate-model", "exaone"])
    assert rc == 2


def test_metrics_dataclass_is_frozen() -> None:
    m = Metrics(label="x", f1=1.0, precision=1.0, recall=1.0, n=1, errors=0)
    with pytest.raises(Exception):  # noqa: B017 — FrozenInstanceError (dataclass)
        m.f1 = 0.0  # type: ignore[misc]
