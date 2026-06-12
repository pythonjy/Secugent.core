# SPDX-License-Identifier: Apache-2.0
"""REGULATIONS → ConnectorPolicy binding — deterministic merge (§B-4a).

Triple harness: unit (all branches) + property-based (hypothesis) + scenario
regression, plus a 100x determinism proof. Korean enterprise fixture (§C-3):
사내 그룹웨어 채널 '사내-공지'.

Covers:
* ``Regulations.connector_policies`` field + backward-compat (absent → {}),
* ``RegulationsLoader._merge`` connector_policies: strengthen-only
  (additive union of allowlists; shrinking an allowlist or raising a rate
  limit is rejected with :class:`RegulationsSchemaError`).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.regulations import (
    Regulations,
    load_regulations_from_dict,
)
from secugent.core.tenancy import TenantId
from secugent.regulations.tenant_loader import (
    RegulationsLoader,
    RegulationsSchemaError,
)
from secugent.tools.connectors.base import ConnectorPolicy

TENANT = TenantId("acme")


# --------------------------------------------------------------------------- #
# Regulations field + backward-compat
# --------------------------------------------------------------------------- #


def test_regulations_default_connector_policies_empty() -> None:
    regs = Regulations(version="1")
    assert regs.connector_policies == {}


def test_legacy_json_without_connector_policies_loads() -> None:
    # A pre-existing document without the new field still validates.
    regs = load_regulations_from_dict(
        {"version": "1", "banned_paths": [], "banned_commands": [], "data_labels": []}
    )
    assert regs.connector_policies == {}


def test_regulations_connector_policies_roundtrip() -> None:
    regs = load_regulations_from_dict(
        {
            "version": "1",
            "connector_policies": {"kakaowork": {"allowed_channels": ["사내-공지"], "rate_limit_per_sec": 3}},
        }
    )
    assert regs.connector_policies["kakaowork"].allowed_channels == ["사내-공지"]
    assert regs.connector_policies["kakaowork"].rate_limit_per_sec == 3


def test_regulations_extra_forbid_still_enforced() -> None:
    from secugent.core.regulations import RegulationsLoadError

    with pytest.raises(RegulationsLoadError):
        load_regulations_from_dict({"version": "1", "bogus_field": 1})


# --------------------------------------------------------------------------- #
# merge — strengthen-only
# --------------------------------------------------------------------------- #


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _loader_with(root: Path, *, base_cp: dict, override_cp: dict) -> RegulationsLoader:
    _write(
        root / "_base" / "active.json",
        {
            "version": "1",
            "banned_paths": [],
            "domain_policy": None,
            "banned_commands": [],
            "data_labels": [],
            "connector_policies": base_cp,
        },
    )
    _write(
        root / str(TENANT) / "overrides.json",
        {"connector_policies": override_cp},
    )
    return RegulationsLoader(root)


def test_merge_adds_new_connector(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={},
        override_cp={"kakaowork": {"allowed_channels": ["사내-공지"]}},
    )
    bundle = loader.for_tenant(TENANT)
    assert "kakaowork" in bundle.effective.connector_policies
    assert bundle.effective.connector_policies["kakaowork"].allowed_channels == ["사내-공지"]


def test_merge_union_adds_channels(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"slack": {"allowed_channels": ["C1"]}},
        override_cp={"slack": {"allowed_channels": ["C1", "C2"]}},
    )
    bundle = loader.for_tenant(TENANT)
    # base order preserved, new channel appended (deterministic).
    assert bundle.effective.connector_policies["slack"].allowed_channels == ["C1", "C2"]


def test_merge_rejects_channel_removal(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"slack": {"allowed_channels": ["C1", "C2"]}},
        override_cp={"slack": {"allowed_channels": ["C1"]}},  # drops C2 → relaxation
    )
    with pytest.raises(RegulationsSchemaError):
        loader.for_tenant(TENANT)


def test_merge_rejects_rate_limit_increase(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"slack": {"allowed_channels": ["C1"], "rate_limit_per_sec": 3}},
        override_cp={"slack": {"allowed_channels": ["C1"], "rate_limit_per_sec": 9}},  # loosen
    )
    with pytest.raises(RegulationsSchemaError):
        loader.for_tenant(TENANT)


def test_merge_allows_rate_limit_decrease(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"slack": {"allowed_channels": ["C1"], "rate_limit_per_sec": 9}},
        override_cp={"slack": {"allowed_channels": ["C1"], "rate_limit_per_sec": 2}},  # strengthen
    )
    bundle = loader.for_tenant(TENANT)
    assert bundle.effective.connector_policies["slack"].rate_limit_per_sec == 2


def test_merge_rejects_workspace_id_removal(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"notion": {"allowed_workspace_ids": ["w1", "w2"]}},
        override_cp={"notion": {"allowed_workspace_ids": ["w1"]}},
    )
    with pytest.raises(RegulationsSchemaError):
        loader.for_tenant(TENANT)


def test_merge_no_override_keeps_base(tmp_path: Path) -> None:
    _write(
        tmp_path / "_base" / "active.json",
        {
            "version": "1",
            "banned_paths": [],
            "domain_policy": None,
            "banned_commands": [],
            "data_labels": [],
            "connector_policies": {"slack": {"allowed_channels": ["C1"]}},
        },
    )
    loader = RegulationsLoader(tmp_path)
    bundle = loader.for_tenant(TENANT)  # no tenant dir
    assert bundle.effective.connector_policies["slack"].allowed_channels == ["C1"]


def test_merge_preserves_other_rule_categories(tmp_path: Path) -> None:
    # connector_policies merge must not disturb banned_paths merge.
    _write(
        tmp_path / "_base" / "active.json",
        {
            "version": "1",
            "banned_paths": [
                {"rule_id": "r1", "pattern": "*/secret/*", "actions": ["file_read"], "severity": "high"}
            ],
            "domain_policy": None,
            "banned_commands": [],
            "data_labels": [],
            "connector_policies": {"slack": {"allowed_channels": ["C1"]}},
        },
    )
    _write(
        tmp_path / str(TENANT) / "overrides.json",
        {"connector_policies": {"slack": {"allowed_channels": ["C1", "C2"]}}},
    )
    loader = RegulationsLoader(tmp_path)
    bundle = loader.for_tenant(TENANT)
    assert len(bundle.effective.banned_paths) == 1
    assert bundle.effective.connector_policies["slack"].allowed_channels == ["C1", "C2"]


# --------------------------------------------------------------------------- #
# determinism — 100 runs
# --------------------------------------------------------------------------- #


def test_merge_determinism_100_runs(tmp_path: Path) -> None:
    loader = _loader_with(
        tmp_path,
        base_cp={"slack": {"allowed_channels": ["C1"]}, "kakaowork": {"allowed_channels": ["사내-공지"]}},
        override_cp={"slack": {"allowed_channels": ["C1", "C2", "C3"]}},
    )
    expected = loader.for_tenant(TENANT).effective.connector_policies["slack"].allowed_channels
    for _ in range(100):
        got = loader.for_tenant(TENANT).effective.connector_policies["slack"].allowed_channels
        assert got == expected


# --------------------------------------------------------------------------- #
# property-based — superset accepted, subset rejected
# --------------------------------------------------------------------------- #

_CHANNEL = st.text(alphabet="abcdefgh", min_size=1, max_size=4)


@given(base=st.lists(_CHANNEL, max_size=5, unique=True), extra=st.lists(_CHANNEL, max_size=5, unique=True))
@settings(max_examples=200)
def test_property_superset_accepted(base: list[str], extra: list[str]) -> None:
    # override = base ∪ extra is always a superset → accepted; result is
    # base order followed by genuinely-new channels (deterministic union).
    override = list(base) + [c for c in extra if c not in base]
    merged = RegulationsLoader._merge(
        Regulations(version="1", connector_policies={"c": ConnectorPolicy(allowed_channels=base)}),
        Regulations(version="o", connector_policies={"c": ConnectorPolicy(allowed_channels=override)}),
    )
    result = merged.connector_policies["c"].allowed_channels
    expected = list(base) + [c for c in override if c not in base]
    assert result == expected


@given(base=st.lists(_CHANNEL, min_size=2, max_size=5, unique=True))
@settings(max_examples=200)
def test_property_subset_rejected(base: list[str]) -> None:
    # Dropping any channel (proper subset) must be rejected.
    override = base[:-1]
    with pytest.raises(RegulationsSchemaError):
        RegulationsLoader._merge(
            Regulations(version="1", connector_policies={"c": ConnectorPolicy(allowed_channels=base)}),
            Regulations(version="o", connector_policies={"c": ConnectorPolicy(allowed_channels=override)}),
        )
