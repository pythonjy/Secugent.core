# SPDX-License-Identifier: Apache-2.0
"""SG-20260603-04 — RegulationsLoader.for_run canary diagnostic clarity.

When a caller activates the canary path (``canary_share > 0``) but forgets to pass
``canary_payload``, the loader previously fell through to ``for_tenant`` and silently
ran the baseline policy — masking a wiring bug. The contract now fails fast with a
clear message naming ``canary_payload``. A share of 0 with no payload (canary
disabled) must still return the baseline bundle, and a valid payload must still
produce the merged canary bundle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.core.regulations import RegulationsLoadError
from secugent.core.tenancy import TenantId
from secugent.regulations.tenant_loader import RegulationsLoader

# 한국어 픽스처: 전자금융감독규정 기반 base 정책 + 카나리 후보.
_BASE_DOC = {
    "version": "1.0.0",
    "banned_paths": [
        {
            "rule_id": "efs-001",
            "pattern": "c:/금융/비밀/*",
            "severity": "high",
            "hard_block": True,
            "description": "전자금융감독규정: 비밀 디렉터리 접근 차단",
        }
    ],
    "banned_commands": [],
    "data_labels": [],
}


def _make_root(tmp_path: Path) -> Path:
    base_dir = tmp_path / "_base"
    base_dir.mkdir(parents=True)
    (base_dir / "active.json").write_text(json.dumps(_BASE_DOC), encoding="utf-8")
    return tmp_path


def _canary_payload() -> dict[str, object]:
    # additive-only: 추가 금지 명령 한 건을 더하는 카나리 후보.
    return {
        "version": "1.0.1-canary",
        "banned_paths": [],
        "banned_commands": [
            {
                "rule_id": "cmd-canary",
                "pattern": "rm -rf /",
                "hard_block": True,
                "description": "카나리: 파괴적 명령 차단 강화",
            }
        ],
        "data_labels": [],
    }


def test_pick_for_run_canary_share_without_payload_raises_clear_error(tmp_path: Path) -> None:
    loader = RegulationsLoader(_make_root(tmp_path))
    with pytest.raises(RegulationsLoadError) as exc:
        loader.for_run(
            run_id="run-1",
            tenant_id=TenantId("kookmin-bank"),
            canary_payload=None,
            canary_share=0.5,
        )
    assert "canary_payload" in str(exc.value)


def test_pick_for_run_no_canary_payload_none_allowed_when_share_zero(tmp_path: Path) -> None:
    loader = RegulationsLoader(_make_root(tmp_path))
    bundle = loader.for_run(
        run_id="run-1",
        tenant_id=TenantId("kookmin-bank"),
        canary_payload=None,
        canary_share=0.0,
    )
    assert bundle.overrides is None
    assert bundle.effective.version == "1.0.0"


def test_pick_for_run_valid_canary_payload_succeeds(tmp_path: Path) -> None:
    loader = RegulationsLoader(_make_root(tmp_path))
    # canary_share=1.0 → every run_id falls into the canary band deterministically.
    bundle = loader.for_run(
        run_id="run-1",
        tenant_id=TenantId("kookmin-bank"),
        canary_payload=_canary_payload(),
        canary_share=1.0,
    )
    merged_cmd_ids = {bc.rule_id for bc in bundle.effective.banned_commands}
    assert "cmd-canary" in merged_cmd_ids
    # baseline protection preserved (additive merge)
    merged_path_ids = {bp.rule_id for bp in bundle.effective.banned_paths}
    assert "efs-001" in merged_path_ids


def test_pick_for_run_payload_present_share_zero_returns_baseline(tmp_path: Path) -> None:
    # Payload supplied but canary disabled (share 0) → baseline, no error.
    loader = RegulationsLoader(_make_root(tmp_path))
    bundle = loader.for_run(
        run_id="run-1",
        tenant_id=TenantId("kookmin-bank"),
        canary_payload=_canary_payload(),
        canary_share=0.0,
    )
    assert bundle.effective.version == "1.0.0"
