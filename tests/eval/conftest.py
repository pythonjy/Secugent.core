# SPDX-License-Identifier: Apache-2.0
"""conftest.py — tests/eval 패키지 공용 픽스처 (Stage 8D).

골든셋 JSONL 로드 및 RiskAnalyzer mock 여부 감지 픽스처를 제공한다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# G-H6: data model + loader now live in the canonical eval module (single source
# of truth shared with test_risk_eval.py and scripts/eval_ab.py). Re-exported
# here so existing ``from tests.eval.conftest import GoldenEntry`` imports stay
# valid (behaviour unchanged).
from tests.eval.metrics import GoldenEntry, RiskLevel, load_golden

__all__ = ["GoldenEntry", "RiskLevel", "golden_entries", "is_mock_analyzer"]

_GOLDEN_PATH = Path(__file__).parent / "risk_ko_golden.jsonl"


@pytest.fixture(scope="session")
def golden_entries() -> list[GoldenEntry]:
    """세션 스코프 골든셋 픽스처 — 파일이 없으면 skip."""
    if not _GOLDEN_PATH.exists():
        pytest.skip(f"골든셋 파일 없음: {_GOLDEN_PATH}")
    entries = load_golden(_GOLDEN_PATH)
    if not entries:
        pytest.skip("골든셋 비어 있음")
    return entries


@pytest.fixture(scope="session")
def is_mock_analyzer() -> bool:
    """RiskAnalyzer가 실 LLM 없이 mock으로 동작하는지 여부를 반환한다.

    실 LLM 클라이언트(ANTHROPIC_API_KEY 등) 없이 테스트를 실행하면 True.
    """
    try:
        import os

        # ANTHROPIC_API_KEY 또는 OPENAI_API_KEY가 설정돼 있으면 실 모델로 간주
        has_key = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))
        return not has_key
    except Exception:
        return True
