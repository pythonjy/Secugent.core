# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — prompt registry canary tests (RED first)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secugent.prompts.registry import (
    CanaryConfig,
    PromptRegistry,
)


def _write_prompt(
    root: Path, role: str, name: str, version: str, body: str, *, effective: str = "2026-01-01T00:00:00Z"
) -> None:
    dirpath = root / role / name
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / f"v{version}.md").write_text(
        f"""---
version: "{version}"
effective_at: {effective}
deprecated_at: null
owners: ["sec-team"]
---
{body}
""",
        encoding="utf-8",
    )


@pytest.fixture
def registry_root(tmp_path: Path) -> Path:
    _write_prompt(tmp_path, "head", "planner", "1", "BODY v1")
    _write_prompt(tmp_path, "head", "planner", "2", "BODY v2")
    return tmp_path


def test_get_returns_active_version(registry_root: Path) -> None:
    reg = PromptRegistry(registry_root)
    reg.set_canary(role="head", name="planner", config=CanaryConfig(active_version="1"))
    prompt = reg.get(role="head", name="planner", run_id="r1")
    assert prompt.frontmatter.version == "1"


def test_canary_share_zero_never_uses_canary(registry_root: Path) -> None:
    reg = PromptRegistry(registry_root)
    reg.set_canary(
        role="head",
        name="planner",
        config=CanaryConfig(active_version="1", canary_version="2", canary_share=0.0),
    )
    for i in range(20):
        prompt = reg.get(role="head", name="planner", run_id=f"r{i}")
        assert prompt.frontmatter.version == "1"


def test_canary_share_one_always_uses_canary(registry_root: Path) -> None:
    reg = PromptRegistry(registry_root)
    reg.set_canary(
        role="head",
        name="planner",
        config=CanaryConfig(active_version="1", canary_version="2", canary_share=1.0),
    )
    for i in range(20):
        prompt = reg.get(role="head", name="planner", run_id=f"r{i}")
        assert prompt.frontmatter.version == "2"


def test_canary_share_split_deterministic(registry_root: Path) -> None:
    reg = PromptRegistry(registry_root)
    reg.set_canary(
        role="head",
        name="planner",
        config=CanaryConfig(active_version="1", canary_version="2", canary_share=0.5),
    )
    versions = [reg.get(role="head", name="planner", run_id=f"r{i}").frontmatter.version for i in range(100)]
    # Both versions should appear and the same run_id always maps to the same version.
    assert "1" in versions
    assert "2" in versions
    # Determinism check
    assert (
        reg.get(role="head", name="planner", run_id="r1").frontmatter.version
        == reg.get(role="head", name="planner", run_id="r1").frontmatter.version
    )


def test_frontmatter_parsing(registry_root: Path) -> None:
    reg = PromptRegistry(registry_root)
    reg.set_canary(role="head", name="planner", config=CanaryConfig(active_version="2"))
    prompt = reg.get(role="head", name="planner", run_id="r1")
    assert prompt.frontmatter.owners == ["sec-team"]
    assert prompt.body.strip() == "BODY v2"


def test_get_missing_version_raises(tmp_path: Path) -> None:
    reg = PromptRegistry(tmp_path)
    reg.set_canary(role="head", name="planner", config=CanaryConfig(active_version="99"))
    with pytest.raises(FileNotFoundError):
        reg.get(role="head", name="planner", run_id="r1")
