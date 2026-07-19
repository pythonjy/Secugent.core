# SPDX-License-Identifier: Apache-2.0
"""ab.py — RISKANALYZER 모델 교체 A/B 증거 하네스 (§B-4b).

§B-4b는 "모델 교체 시 A/B 결과를 PR 본문에 첨부"를 요구한다. 이 도구는 한국어
골든셋을 **두 모델**로 평가해 비교 가능한 (F1/Precision/Recall) 리포트를 낸다.

순수 계산부(``evaluate`` / ``run_ab``)는 predictor를 **주입**받아 네트워크·LLM 없이
결정적으로 동작한다 — ``tests/eval/test_eval_ab.py``가 fake predictor로 검증한다.
실모델 경로(``main`` / ``_build_real_predictor``)는 secugent 모듈을 **지연 import**
하므로 이 모듈의 top-level 의존성은 stdlib + ``tests.eval.metrics``(공개 티어)뿐이다
(import-closure I2/I8 유지 — 공개 추출 레포에서도 collect/실행 가능). CLI 진입점은
``scripts/eval_ab.py`` 가 이 모듈의 ``main`` 을 호출한다.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from tests.eval.metrics import (
    GoldenEntry,
    RiskLevel,
    compute_metrics,
    load_golden,
    score_to_risk_level,
)

# A predictor maps a golden entry to a predicted risk level (the model under test).
Predictor = Callable[[GoldenEntry], RiskLevel]

# Float comparison tolerance for "did F1 regress" — avoids flagging numerically
# identical runs as regressions.
_EPS = 1e-9

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_GOLDEN = _REPO_ROOT / "tests" / "eval" / "risk_ko_golden.jsonl"
_DOMESTIC_MODELS = ("exaone", "hyperclova", "ax", "solar")


@dataclass(frozen=True)
class Metrics:
    """단일 모델의 골든셋 평가 지표."""

    label: str
    f1: float
    precision: float
    recall: float
    n: int
    errors: int


@dataclass(frozen=True)
class AbReport:
    """baseline vs candidate 비교 리포트."""

    baseline: Metrics
    candidate: Metrics
    delta_f1: float
    regressed: bool


def evaluate(golden: Sequence[GoldenEntry], predictor: Predictor, *, label: str) -> Metrics:
    """``golden`` 전체를 ``predictor``로 평가해 ``Metrics``를 반환한다 (순수·결정적).

    predictor가 예외를 던지면 ``errors``로 **노출**하고(조용한 마스킹 금지) 시스템의
    fail-closed 등급(``high``)을 기록한다 — best-case로 가리지 않는다.
    """
    if not golden:
        raise ValueError("evaluate: golden set is empty")
    predicted: list[RiskLevel] = []
    expected: list[RiskLevel] = []
    errors = 0
    for entry in golden:
        try:
            pred = predictor(entry)
        except Exception:  # noqa: BLE001 — surfaced via `errors`, never silently swallowed
            errors += 1
            pred = "high"  # fail-closed level (= score_to_risk_level(None)); not best-case
        predicted.append(pred)
        expected.append(entry.expected_risk)
    f1, precision, recall = compute_metrics(predicted, expected)
    return Metrics(label=label, f1=f1, precision=precision, recall=recall, n=len(golden), errors=errors)


def run_ab(
    golden: Sequence[GoldenEntry],
    baseline: Predictor,
    candidate: Predictor,
    *,
    baseline_label: str,
    candidate_label: str,
) -> AbReport:
    """두 predictor를 동일 골든셋으로 평가해 비교 리포트를 만든다 (순수·결정적, INV-4)."""
    base = evaluate(golden, baseline, label=baseline_label)
    cand = evaluate(golden, candidate, label=candidate_label)
    delta_f1 = cand.f1 - base.f1
    regressed = (cand.f1 + _EPS) < base.f1
    return AbReport(baseline=base, candidate=cand, delta_f1=delta_f1, regressed=regressed)


def format_report(report: AbReport) -> str:
    """A/B 리포트를 사람이 읽을 수 있는 텍스트로 렌더링한다 (PR 첨부용)."""
    lines = [
        "[RISKANALYZER 한국어 골든셋 A/B 평가]",
        f"  골든셋 항목 수: {report.baseline.n}",
        "",
        f"  baseline  ({report.baseline.label}):",
        f"    F1={report.baseline.f1:.4f}  P={report.baseline.precision:.4f}  "
        f"R={report.baseline.recall:.4f}  errors={report.baseline.errors}",
        f"  candidate ({report.candidate.label}):",
        f"    F1={report.candidate.f1:.4f}  P={report.candidate.precision:.4f}  "
        f"R={report.candidate.recall:.4f}  errors={report.candidate.errors}",
        "",
        f"  Δ F1 = {report.delta_f1:+.4f}",
        f"  판정: {'⚠️ REGRESSED' if report.regressed else 'OK (회귀 없음)'}",
    ]
    return "\n".join(lines)


def _build_real_predictor(model_id: str) -> Predictor:
    """실모델 predictor를 만든다 (RiskAnalyzer + 모델별 LLM 클라이언트).

    secugent 모듈을 **함수 내부에서 지연 import** 한다 — 이 모듈의 top-level 의존성을
    공개 티어로 유지하기 위함(import-closure). 국산모델 selector(exaone|hyperclova|ax|
    solar)는 ``SECUGENT_DOMESTIC_MODEL_ENDPOINT`` 경유로 구체 어댑터를, 그 외는
    AnthropicLLMClient(BYO)로 만든다. 자격증명/엔드포인트 부재 시 생성 시점 LLMError 전파.
    """
    from secugent.core.contracts import Step
    from secugent.core.risk_analyzer import RiskAnalyzer

    if model_id in _DOMESTIC_MODELS:
        from secugent.core.llm_clients import build_domestic_client

        endpoint = os.environ.get("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "").strip()
        if not endpoint:
            raise SystemExit(f"model '{model_id}' requires SECUGENT_DOMESTIC_MODEL_ENDPOINT to be set.")
        llm = build_domestic_client(
            model_id,
            endpoint=endpoint,
            model_id=os.environ.get("SECUGENT_DOMESTIC_MODEL_ID", "").strip() or None,
            api_key=os.environ.get("SECUGENT_DOMESTIC_MODEL_API_KEY", "").strip() or None,
        )
    else:
        from secugent.core.llm_client import AnthropicLLMClient

        llm = AnthropicLLMClient()

    analyzer = RiskAnalyzer(llm)

    def _predict(entry: GoldenEntry) -> RiskLevel:
        step = Step(
            tenant_id="eval-tenant",
            run_id="eval-ab",
            actor="eval:ko-golden",
            action_type="unknown",
            command=entry.scenario,
        )
        assessment = analyzer.assess(step)
        total = assessment.score.total if assessment.score else None
        return score_to_risk_level(assessment.decision, total)

    return _predict


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 진입점. 실모델 자격증명이 없으면 안내 후 exit 2 (조용한 통과 금지)."""
    parser = argparse.ArgumentParser(description="RISKANALYZER 한국어 골든셋 A/B 평가")
    parser.add_argument("--golden", type=Path, default=_DEFAULT_GOLDEN, help="골든셋 JSONL 경로")
    parser.add_argument("--baseline-model", required=True, help="기준 모델 id (예: claude-sonnet-4-6)")
    parser.add_argument("--candidate-model", required=True, help="후보 모델 id (예: exaone)")
    parser.add_argument("--json", type=Path, default=None, help="리포트 JSON 출력 경로(선택)")
    args = parser.parse_args(argv)

    has_creds = bool(
        os.environ.get("ANTHROPIC_API_KEY", "").strip()
        or os.environ.get("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "").strip()
    )
    if not has_creds:
        print(
            "A/B 실모델 평가에는 자격증명이 필요합니다: ANTHROPIC_API_KEY 또는 "
            "SECUGENT_DOMESTIC_MODEL_ENDPOINT(+SECUGENT_DOMESTIC_MODEL)를 설정하세요. "
            "설정 없이 통과시키지 않습니다(no silent false-pass).",
            file=sys.stderr,
        )
        return 2

    if not args.golden.exists():
        print(f"골든셋 파일 없음: {args.golden}", file=sys.stderr)
        return 2
    golden = load_golden(args.golden)
    if not golden:
        print(f"골든셋 비어 있음: {args.golden}", file=sys.stderr)
        return 2

    report = run_ab(
        golden,
        _build_real_predictor(args.baseline_model),
        _build_real_predictor(args.candidate_model),
        baseline_label=args.baseline_model,
        candidate_label=args.candidate_model,
    )

    print(format_report(report))
    if args.json is not None:
        args.json.write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nJSON 리포트 기록: {args.json}", file=sys.stderr)
    return 0
