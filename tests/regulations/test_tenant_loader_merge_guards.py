# SPDX-License-Identifier: Apache-2.0
"""Branch coverage for the strengthen-only ``_merge`` guards.

The deterministic-module gate (§B-4a) requires ≥95% line coverage on
``secugent/regulations/tenant_loader.py``. The new ``data_labels`` guard is
fully exercised by ``test_label_merge_monotonic`` / ``test_label_merge_props``;
this file closes the remaining guard branches that the merge function shares
with ``banned_paths`` / ``banned_commands`` / ``domain_policy`` and the
on-disk loader paths (``load_base`` missing, ``for_tenant`` full-document
override, ``for_run`` non-canary fast-path). All are strengthen-only /
fail-closed assertions — no production behaviour is changed by these tests.

Korean enterprise fixture (§C-3): 전자금융감독규정 banned_path 'deny-고객정보'.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.core.regulations import (
    RegulationsLoadError,
    load_regulations_from_dict,
)
from secugent.core.tenancy import TenantId
from secugent.regulations.tenant_loader import (
    RegulationsLoader,
    RegulationsSchemaError,
)

TENANT = TenantId("acme")


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


# --------------------------------------------------------------------------- #
# banned_paths / banned_commands hard_block-disable guards
# --------------------------------------------------------------------------- #


def test_banned_path_hard_block_disable_rejected() -> None:
    base = load_regulations_from_dict(
        {
            "version": "1",
            "banned_paths": [
                {
                    "rule_id": "deny-고객정보",
                    "pattern": "*/고객정보/*",
                    "actions": ["file_read"],
                    "severity": "critical",
                    "hard_block": True,
                }
            ],
        }
    )
    override = load_regulations_from_dict(
        {
            "version": "o",
            "banned_paths": [
                {
                    "rule_id": "deny-고객정보",
                    "pattern": "*/고객정보/*",
                    "actions": ["file_read"],
                    "severity": "critical",
                    "hard_block": False,  # disables hard_block → reject
                }
            ],
        }
    )
    with pytest.raises(RegulationsSchemaError, match="hard_block"):
        RegulationsLoader._merge(base, override)


def test_banned_command_hard_block_disable_rejected() -> None:
    base = load_regulations_from_dict(
        {
            "version": "1",
            "banned_commands": [
                {"rule_id": "deny-rm-rf", "pattern": "rm -rf", "severity": "critical", "hard_block": True}
            ],
        }
    )
    override = load_regulations_from_dict(
        {
            "version": "o",
            "banned_commands": [
                {"rule_id": "deny-rm-rf", "pattern": "rm -rf", "severity": "critical", "hard_block": False}
            ],
        }
    )
    with pytest.raises(RegulationsSchemaError, match="hard_block"):
        RegulationsLoader._merge(base, override)


# --------------------------------------------------------------------------- #
# data_labels path_patterns superset guard — full _merge path
# --------------------------------------------------------------------------- #


def test_data_label_path_pattern_drop_rejected_via_full_merge() -> None:
    """전자금융감독규정: data_label override가 보호 경로 패턴을 제거하면 (다른 축이
    모두 동일해도) 전체 _merge 경로에서 거부된다 (deny-by-default 완화 차단)."""
    base = load_regulations_from_dict(
        {
            "version": "1",
            "data_labels": [
                {
                    "rule_id": "efs-고객정보",
                    "label": "고객금융정보",
                    "path_patterns": ["*/고객정보/*", "*/financial/*"],
                    "allowed_actions": ["file_read"],
                    "severity": "critical",
                    "hard_block": True,
                }
            ],
        }
    )
    override = load_regulations_from_dict(
        {
            "version": "o",
            "data_labels": [
                {
                    "rule_id": "efs-고객정보",
                    "label": "고객금융정보",
                    "path_patterns": ["*/고객정보/*"],  # drops */financial/*
                    "allowed_actions": ["file_read"],
                    "severity": "critical",
                    "hard_block": True,
                }
            ],
        }
    )
    with pytest.raises(RegulationsSchemaError, match="path_patterns"):
        RegulationsLoader._merge(base, override)


# --------------------------------------------------------------------------- #
# domain_policy mode-switch guard
# --------------------------------------------------------------------------- #


def test_domain_policy_allow_to_deny_rejected() -> None:
    base = load_regulations_from_dict(
        {
            "version": "1",
            "domain_policy": {"mode": "allow_list", "domains": ["example.com"]},
        }
    )
    override = load_regulations_from_dict(
        {
            "version": "o",
            "domain_policy": {"mode": "deny_list", "domains": ["evil.com"]},
        }
    )
    with pytest.raises(RegulationsSchemaError, match="allow_list to deny_list"):
        RegulationsLoader._merge(base, override)


def test_domain_policy_stricter_override_accepted() -> None:
    base = load_regulations_from_dict(
        {
            "version": "1",
            "domain_policy": {"mode": "allow_list", "domains": ["example.com", "docs.python.org"]},
        }
    )
    override = load_regulations_from_dict(
        {
            "version": "o",
            "domain_policy": {"mode": "allow_list", "domains": ["example.com"]},  # narrower
        }
    )
    merged = RegulationsLoader._merge(base, override)
    assert merged.domain_policy is not None
    assert merged.domain_policy.domains == ["example.com"]


# --------------------------------------------------------------------------- #
# on-disk loader paths
# --------------------------------------------------------------------------- #


def test_load_base_missing_raises(tmp_path: Path) -> None:
    loader = RegulationsLoader(tmp_path)  # no _base/active.json
    with pytest.raises(RegulationsLoadError, match="missing base"):
        loader.load_base()


def test_for_tenant_full_document_override(tmp_path: Path) -> None:
    _write(
        tmp_path / "_base" / "active.json",
        {"version": "base", "banned_paths": [], "banned_commands": [], "data_labels": []},
    )
    # A tenant active.json is a *full* document override (not a delta).
    _write(
        tmp_path / str(TENANT) / "active.json",
        {
            "version": "tenant-full",
            "banned_paths": [
                {
                    "rule_id": "deny-고객정보",
                    "pattern": "*/고객정보/*",
                    "severity": "critical",
                    "hard_block": True,
                }
            ],
            "banned_commands": [],
            "data_labels": [],
        },
    )
    bundle = RegulationsLoader(tmp_path).for_tenant(TENANT)
    assert bundle.overrides is not None
    assert any(bp.rule_id == "deny-고객정보" for bp in bundle.effective.banned_paths)


def test_for_run_non_canary_returns_tenant_bundle(tmp_path: Path) -> None:
    _write(
        tmp_path / "_base" / "active.json",
        {"version": "base", "banned_paths": [], "banned_commands": [], "data_labels": []},
    )
    loader = RegulationsLoader(tmp_path)
    bundle = loader.for_run(run_id="r-1", tenant_id=TENANT, canary_payload=None, canary_share=0.0)
    assert bundle.effective.version == "base"


def test_for_run_canary_below_share_merges(tmp_path: Path) -> None:
    _write(
        tmp_path / "_base" / "active.json",
        {"version": "base", "banned_paths": [], "banned_commands": [], "data_labels": []},
    )
    loader = RegulationsLoader(tmp_path)
    payload = {
        "version": "canary",
        "banned_paths": [{"rule_id": "canary-rule", "pattern": "*/c/*", "severity": "high"}],
        "banned_commands": [],
        "data_labels": [],
    }
    # canary_share = 1.0 forces the canary branch deterministically.
    bundle = loader.for_run(run_id="r-2", tenant_id=TENANT, canary_payload=payload, canary_share=1.0)
    assert any(bp.rule_id == "canary-rule" for bp in bundle.effective.banned_paths)
