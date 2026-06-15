# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.regulations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secugent.core.regulations import (
    BannedCommand,
    BannedPath,
    DataLabel,
    DomainPolicy,
    RegulationsLoadError,
    load_regulations,
    load_regulations_from_dict,
)

_REGULATIONS_EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "regulations_examples"
_requires_examples = pytest.mark.skipif(
    not _REGULATIONS_EXAMPLES_DIR.is_dir(),
    reason="regulations_examples fixtures not shipped in public core",
)


def _min_payload() -> dict:
    return {
        "version": "test-1",
        "banned_paths": [],
        "domain_policy": None,
        "banned_commands": [],
        "data_labels": [],
    }


def test_load_minimum_payload() -> None:
    regs = load_regulations_from_dict(_min_payload())
    assert regs.version == "test-1"
    assert regs.banned_paths == []
    assert regs.domain_policy is None


def test_extra_field_rejected() -> None:
    bad = _min_payload()
    bad["extra"] = "no"
    with pytest.raises(RegulationsLoadError):
        load_regulations_from_dict(bad)


def test_unknown_action_rejected_in_banned_path() -> None:
    bad = _min_payload()
    bad["banned_paths"] = [{"rule_id": "r1", "pattern": "*", "actions": ["unknown"]}]
    with pytest.raises(RegulationsLoadError):
        load_regulations_from_dict(bad)


def test_domain_entries_lowercased_and_trimmed() -> None:
    payload = _min_payload()
    payload["domain_policy"] = {
        "domains": ["Example.COM.", "  docs.python.org "],
        "mode": "allow_list",
    }
    regs = load_regulations_from_dict(payload)
    assert regs.domain_policy is not None
    assert regs.domain_policy.domains == ["example.com", "docs.python.org"]


def test_empty_domain_string_rejected() -> None:
    payload = _min_payload()
    payload["domain_policy"] = {"domains": [""], "mode": "allow_list"}
    with pytest.raises(RegulationsLoadError):
        load_regulations_from_dict(payload)


@_requires_examples
def test_load_default_example() -> None:
    path = Path(__file__).resolve().parents[2] / "regulations_examples" / "default.json"
    regs = load_regulations(path)
    assert regs.version.startswith("default-")
    assert any(p.rule_id == "deny-confidential" for p in regs.banned_paths)


@_requires_examples
def test_load_strict_finance_example() -> None:
    path = Path(__file__).resolve().parents[2] / "regulations_examples" / "strict_finance.json"
    regs = load_regulations(path)
    assert regs.version.startswith("strict-finance-")
    assert any(p.rule_id == "fin-pf-confidential" for p in regs.banned_paths)


def test_load_nonexistent_file() -> None:
    with pytest.raises(RegulationsLoadError, match="cannot read"):
        load_regulations("D:/nonexistent/REGULATIONS.json")


def test_load_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(RegulationsLoadError, match="valid JSON"):
        load_regulations(p)


def test_load_non_object(tmp_path: Path) -> None:
    p = tmp_path / "arr.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(RegulationsLoadError, match="must be an object"):
        load_regulations(p)


def test_checksum_stable() -> None:
    regs = load_regulations_from_dict(_min_payload())
    a = regs.checksum()
    b = regs.checksum()
    assert a == b
    assert len(a) == 64


def test_checksum_changes_with_content() -> None:
    a = load_regulations_from_dict(_min_payload())
    b = load_regulations_from_dict({**_min_payload(), "version": "test-2"})
    assert a.checksum() != b.checksum()


def test_pydantic_models_construct_directly() -> None:
    bp = BannedPath(rule_id="r1", pattern="C:/a/*", actions=["file_read"])
    bc = BannedCommand(rule_id="r2", pattern="\\brm\\b")
    dp = DomainPolicy(domains=["example.com"], mode="allow_list")
    dl = DataLabel(rule_id="r3", label="public", path_patterns=["*/public/*"], allowed_actions=["file_read"])
    assert bp.rule_id == "r1"
    assert bc.pattern == "\\brm\\b"
    assert dp.domains == ["example.com"]
    assert dl.allowed_actions == ["file_read"]


def test_partial_load_with_only_paths(tmp_path: Path) -> None:
    p = tmp_path / "r.json"
    p.write_text(
        json.dumps(
            {
                "version": "t",
                "banned_paths": [{"rule_id": "r1", "pattern": "*/x/*", "actions": ["file_read"]}],
            }
        ),
        encoding="utf-8",
    )
    regs = load_regulations(p)
    assert len(regs.banned_paths) == 1


def test_regulation_version_record() -> None:
    regs = load_regulations_from_dict(_min_payload())
    rv = regs.to_version_record(source="memory")
    assert rv.version == "test-1"
    assert rv.source == "memory"
    assert rv.checksum == regs.checksum()
