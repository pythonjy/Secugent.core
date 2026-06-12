# SPDX-License-Identifier: Apache-2.0
"""Parse and assert structural invariants of .github/workflows/determinism.yml.

BDP_05 항목 4 — 결정성 증명 워크플로우 구조 검증.

Note: 릴리스 asset 업로드(SBOM, threat_model.md, SECURITY.md) 인보이런트는
의도적으로 release.yml 로 이전됐다. 해당 검증은 tests/ops/test_release_workflow.py
의 TestSbomAndSignatures 클래스에서 수행한다.

Invariants asserted:
  I_DET  — 2x-determinism diff 단계("Assert byte-identical across runs")가 존재한다.
"""

from __future__ import annotations

import codecs
from pathlib import Path
from typing import Any

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WORKFLOW_PATH = Path(__file__).parents[2] / ".github" / "workflows" / "determinism.yml"


# PyYAML returns arbitrary nested types; Any is unavoidable for YAML document nodes.
def _load_workflow() -> dict[str, Any]:
    """Parse the workflow YAML and return the document root."""
    raw = _workflow_path().read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    assert isinstance(doc, dict), "workflow YAML must be a mapping at the root"
    return doc


def _workflow_path() -> Path:
    return _WORKFLOW_PATH


# PyYAML returns arbitrary nested types; Any is unavoidable for YAML document nodes.
def _all_steps(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every step object across all jobs."""
    steps: list[dict[str, Any]] = []
    jobs = doc.get("jobs", {})
    assert isinstance(jobs, dict)
    for job in jobs.values():
        assert isinstance(job, dict)
        for step in job.get("steps", []):
            assert isinstance(step, dict)
            steps.append(step)
    return steps


# PyYAML returns arbitrary nested types; Any is unavoidable for YAML document nodes.
def _step_names(doc: dict[str, Any]) -> list[str]:
    return [s.get("name", "") for s in _all_steps(doc)]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWorkflowExists:
    def test_file_is_parseable_yaml(self) -> None:
        """The workflow file exists and parses without error."""
        assert _workflow_path().exists(), f"workflow not found: {_workflow_path()}"
        doc = _load_workflow()
        assert "jobs" in doc


class TestDeterminismDiffStep:
    """I_DET: 2x byte-identical diff 단계가 존재해야 한다."""

    def test_assert_byte_identical_step_present(self) -> None:
        doc = _load_workflow()
        names = _step_names(doc)

        # Require a step whose name contains "byte-identical" (case-insensitive).
        matching = [n for n in names if "byte-identical" in n.lower()]
        assert matching, (
            "No step name containing 'byte-identical' found. "
            f"Existing step names: {names}. "
            "The 2x determinism diff assertion step is required (Invariant I2)."
        )

    def test_assert_step_references_diff(self) -> None:
        """The byte-identical step's run script must invoke diff or assert equality."""
        doc = _load_workflow()
        steps = _all_steps(doc)
        found_diff_logic = False
        for step in steps:
            name = step.get("name", "")
            run = step.get("run", "")
            if "byte-identical" in name.lower():
                # Must contain either a diff command or a Python equality assert.
                if "diff" in run or "assert" in run or "==" in run:
                    found_diff_logic = True
                    break
        assert found_diff_logic, (
            "The 'byte-identical' step must contain diff/assert logic "
            "to enforce that two independent runs produce the same output."
        )


class TestWorkflowYamlValidity:
    """The YAML is valid and all step names are non-empty strings."""

    def test_all_named_steps_have_string_names(self) -> None:
        doc = _load_workflow()
        for step in _all_steps(doc):
            name = step.get("name")
            if name is not None:
                assert isinstance(name, str), f"Step name must be a string, got: {name!r}"

    def test_jobs_block_non_empty(self) -> None:
        doc = _load_workflow()
        assert doc.get("jobs"), "Workflow must define at least one job."


class TestWorkflowEncodingRobustness:
    """Regression: the workflow file is UTF-8 and every reader must decode it as UTF-8.

    The file legitimately carries non-ASCII content — an em-dash (``—``), the
    section sign (``§``) in comments, and **Korean** audit-fixture strings
    (``배포-{i}``, ``감사 이벤트 {i}``; §C-3 Korean defaults). On a Windows host whose
    system locale defaults to ``cp949``, a reader that calls ``open(path)`` /
    ``Path.read_text()`` WITHOUT ``encoding="utf-8"`` raises
    ``UnicodeDecodeError`` on the very first multibyte sequence (byte ``0xe2`` of
    the em-dash at offset 127) — the failure the release gate hit. These tests
    pin two things so that bug cannot recur:

    1. the file is valid UTF-8 and the production reader (``_load_workflow``,
       which passes ``encoding="utf-8"``) parses it; and
    2. decoding the raw bytes with the legacy ``cp949`` codec WOULD fail — proving
       the explicit ``encoding="utf-8"`` is load-bearing, not incidental.
    """

    def test_workflow_file_is_valid_utf8(self) -> None:
        raw_bytes = _WORKFLOW_PATH.read_bytes()
        # Strict decode raises UnicodeDecodeError if the file is not valid UTF-8.
        text = raw_bytes.decode("utf-8")
        assert text, "workflow file decoded to empty text"

    def test_workflow_contains_non_ascii_so_encoding_matters(self) -> None:
        """Guard the premise: if the file were pure ASCII this regression is moot."""
        raw_bytes = _WORKFLOW_PATH.read_bytes()
        assert any(b > 0x7F for b in raw_bytes), (
            "expected non-ASCII bytes (em-dash/§/Korean fixtures) in the workflow; "
            "without them the cp949-decode regression would not be exercised."
        )

    def test_production_reader_uses_explicit_utf8_and_parses(self) -> None:
        """``_load_workflow`` must decode as UTF-8 and yield a parseable mapping."""
        doc = _load_workflow()
        assert isinstance(doc, dict)
        assert "jobs" in doc

    def test_locale_default_cp949_decode_would_fail(self) -> None:
        """Decoding the bytes with cp949 (Windows default) must raise — proving the
        explicit ``encoding="utf-8"`` is what makes the reader portable."""
        raw_bytes = _WORKFLOW_PATH.read_bytes()
        with pytest.raises(UnicodeDecodeError):
            codecs.decode(raw_bytes, "cp949")


class TestNoReleaseCreation:
    """Negative invariant: determinism.yml must NOT create a GitHub Release.

    GitHub Release creation + asset upload on v* tags is owned exclusively by
    release.yml (sign-release job). determinism.yml runs on every branch/PR push;
    if a future edit reintroduced an ``action-gh-release`` step here it would both
    try to publish a release on every push AND revive the duplicate-release race
    with release.yml — yet every positive assertion (now on release.yml) would
    stay green. This negative gate locks the migration's intent structurally.
    """

    def test_no_release_creation_step(self) -> None:
        doc = _load_workflow()
        offenders = [
            s
            for s in _all_steps(doc)
            if "action-gh-release" in str(s.get("uses", "")) or "softprops" in str(s.get("uses", ""))
        ]
        assert not offenders, (
            "determinism.yml must not create a GitHub Release (owned by release.yml's "
            "sign-release job). Found release-creation step(s): "
            f"{[s.get('name') for s in offenders]}."
        )
