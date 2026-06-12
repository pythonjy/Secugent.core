# SPDX-License-Identifier: Apache-2.0
"""conftest.py — tests/eval 패키지 공용 픽스처 (Stage 8D).

골든셋 JSONL 로드 및 RiskAnalyzer mock 여부 감지 픽스처를 제공한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

_GOLDEN_PATH = Path(__file__).parent / "risk_ko_golden.jsonl"

RiskLevel = Literal["critical", "high", "medium", "low", "none"]


@dataclass(frozen=True)
class GoldenEntry:
    """골든셋 단일 항목."""

    id: str
    scenario: str
    expected_risk: RiskLevel
    category: str
    regulation: str | None


def _load_golden() -> list[GoldenEntry]:
    """risk_ko_golden.jsonl 전체를 로드해 GoldenEntry 리스트로 반환한다."""
    entries: list[GoldenEntry] = []
    with _GOLDEN_PATH.open(encoding="utf-8") as fh:
        for _lineno, line in enumerate(fh, start=1):
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


@pytest.fixture(scope="session")
def golden_entries() -> list[GoldenEntry]:
    """세션 스코프 골든셋 픽스처 — 파일이 없으면 skip."""
    if not _GOLDEN_PATH.exists():
        pytest.skip(f"골든셋 파일 없음: {_GOLDEN_PATH}")
    entries = _load_golden()
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
