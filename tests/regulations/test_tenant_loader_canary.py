# SPDX-License-Identifier: Apache-2.0
"""SG-20260601-04 — canary runs must keep tenant-strengthened policy.

Korean enterprise context (§C-3): a tenant in a regulated sector hardens the
organisation base; a canary policy experiment must never silently drop that
hardening.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.core.tenancy import TenantId
from secugent.regulations.tenant_loader import (
    RegulationsLoader,
    RegulationsSchemaError,
)

TENANT = TenantId("acme")


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _setup(root: Path) -> RegulationsLoader:
    # Organisation base: r1 at "high".
    _write(
        root / "_base" / "active.json",
        {
            "version": "1",
            "banned_paths": [
                {
                    "rule_id": "r1",
                    "pattern": "*/secret/*",
                    "actions": ["file_read"],
                    "severity": "high",
                    "hard_block": True,
                }
            ],
            "domain_policy": None,
            "banned_commands": [],
            "data_labels": [],
        },
    )
    # Tenant override: strengthen r1 → critical, add tenant-only r2.
    _write(
        root / str(TENANT) / "overrides.json",
        {
            "banned_paths": [
                {
                    "rule_id": "r1",
                    "pattern": "*/secret/*",
                    "actions": ["file_read"],
                    "severity": "critical",
                    "hard_block": True,
                },
                {
                    "rule_id": "r2",
                    "pattern": "*/금융/*",
                    "actions": ["file_read", "file_write"],
                    "severity": "critical",
                    "hard_block": True,
                },
            ]
        },
    )
    return RegulationsLoader(root)


def _canary_payload_additive() -> dict:
    """Canary adds r3 only — does not touch r1/r2 (no relaxation)."""
    return {
        "version": "canary-1",
        "banned_paths": [
            {
                "rule_id": "r3",
                "pattern": "*/experimental/*",
                "actions": ["file_read"],
                "severity": "high",
                "hard_block": True,
            }
        ],
        "domain_policy": None,
        "banned_commands": [],
        "data_labels": [],
    }


def test_canary_preserves_tenant_override(tmp_path: Path) -> None:
    loader = _setup(tmp_path)
    bundle = loader.for_run(
        run_id="any-run",
        tenant_id=TENANT,
        canary_payload=_canary_payload_additive(),
        canary_share=1.0,  # force the canary arm
    )
    by_id = {p.rule_id: p for p in bundle.effective.banned_paths}
    # Tenant strengthening survives the canary path (the SG-04 bug dropped it).
    assert by_id["r1"].severity == "critical"
    assert "r2" in by_id  # tenant-only rule preserved
    assert "r3" in by_id  # canary addition applied


def test_canary_relaxation_still_rejected(tmp_path: Path) -> None:
    loader = _setup(tmp_path)
    relaxing = _canary_payload_additive()
    relaxing["banned_paths"].append(
        {
            "rule_id": "r1",
            "pattern": "*/secret/*",
            "actions": ["file_read"],
            "severity": "low",
            "hard_block": True,
        }
    )
    with pytest.raises(RegulationsSchemaError, match="weaker"):
        loader.for_run(
            run_id="any-run",
            tenant_id=TENANT,
            canary_payload=relaxing,
            canary_share=1.0,
        )


def test_non_canary_run_unchanged(tmp_path: Path) -> None:
    loader = _setup(tmp_path)
    # canary_share=0 → always the normal tenant bundle.
    bundle = loader.for_run(
        run_id="any-run",
        tenant_id=TENANT,
        canary_payload=_canary_payload_additive(),
        canary_share=0.0,
    )
    by_id = {p.rule_id: p for p in bundle.effective.banned_paths}
    assert by_id["r1"].severity == "critical"
    assert "r3" not in by_id
