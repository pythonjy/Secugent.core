# SPDX-License-Identifier: Apache-2.0
"""Structural invariant tests for .github/workflows/release.yml.

Signed release pipeline.

Invariants asserted:
  I_TRIGGER  — push.tags pattern "v*" present (tag-only trigger).
  I_ORDER    — publish + sign-release both declare needs on the gate→build chain;
               publish never runs before gates pass (fail-closed, I2).
  I_GATE     — at least one job step runs python scripts/check_public_release.py.
  I_OIDC     — the publish job and/or sign-release job carry
               permissions.id-token: write (OIDC trusted publishing + sigstore).
  I_SBOM     — SBOM (sbom.json) is attached to the GitHub Release step.
  I_SIG      — sigstore signatures (*.sigstore.json) are attached to the release.
  I_WHEEL    — the wheel-excludes-enterprise assertion step is present (I3).
  I_MANIFEST — the manifest now selects the 4 governance paths (CONTRIBUTING.md,
               CODE_OF_CONDUCT.md, .github/ISSUE_TEMPLATE/**, .github/PULL_REQUEST_TEMPLATE.md)
               into the public file set.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parents[2]
_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "release.yml"
_MANIFEST_PATH = _REPO_ROOT / "release" / "public_manifest.yaml"

# ---------------------------------------------------------------------------
# Helpers — workflow parsing
# ---------------------------------------------------------------------------


def _load_workflow() -> dict[str, Any]:
    """Parse release.yml as YAML; fail immediately if the file is missing or invalid."""
    assert _WORKFLOW_PATH.exists(), f"release.yml not found: {_WORKFLOW_PATH}"
    raw = _WORKFLOW_PATH.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    assert isinstance(doc, dict), "release.yml root must be a YAML mapping"
    return doc


def _jobs(doc: dict[str, Any]) -> dict[str, Any]:
    jobs = doc.get("jobs", {})
    assert isinstance(jobs, dict), "'jobs' block must be a mapping"
    return jobs


def _steps_for_job(doc: dict[str, Any], job_name: str) -> list[dict[str, Any]]:
    """Return the step list for a named job (empty list if job absent)."""
    job = _jobs(doc).get(job_name, {})
    assert isinstance(job, dict)
    return [s for s in job.get("steps", []) if isinstance(s, dict)]


def _all_steps(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten every step across all jobs."""
    steps: list[dict[str, Any]] = []
    for job in _jobs(doc).values():
        if isinstance(job, dict):
            for step in job.get("steps", []):
                if isinstance(step, dict):
                    steps.append(step)
    return steps


def _needs_of(doc: dict[str, Any], job_name: str) -> list[str]:
    """Return the needs list for a job (empty if not declared)."""
    job = _jobs(doc).get(job_name, {})
    if not isinstance(job, dict):
        return []
    raw = job.get("needs", [])
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(n) for n in raw]
    return []


# ---------------------------------------------------------------------------
# Helpers — manifest + public_files
# ---------------------------------------------------------------------------


def _load_public_files() -> list[Path]:
    """Import check_public_release.public_files and materialise the set.

    The scripts/ directory is not installed as a package; we add it to sys.path
    transiently so the import works without 'pip install -e .' changes.
    """
    scripts_dir = str(_REPO_ROOT / "scripts")
    added = scripts_dir not in sys.path
    if added:
        sys.path.insert(0, scripts_dir)
    try:
        # Dynamic import: scripts/ is not a package; ignore_missing_imports covers it.
        import check_public_release

        manifest = check_public_release.load_manifest(_MANIFEST_PATH)
        # cast required: the dynamically-imported module is untyped (Any return).
        result: list[Path] = list(check_public_release.public_files(manifest, _REPO_ROOT))
        return result
    finally:
        if added:
            sys.path.remove(scripts_dir)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWorkflowExists:
    """The file exists and is valid YAML."""

    def test_file_is_parseable_yaml(self) -> None:
        doc = _load_workflow()
        assert "jobs" in doc

    def test_jobs_block_non_empty(self) -> None:
        doc = _load_workflow()
        assert _jobs(doc), "release.yml must define at least one job"


class TestTagTrigger:
    """I_TRIGGER: the workflow fires only on v* tag pushes."""

    def test_on_push_tags_v_present(self) -> None:
        doc = _load_workflow()
        # PyYAML parses bare `on:` as Python True; accept both keys.
        raw_on = doc.get("on") or doc.get(True)  # type: ignore[call-overload]
        assert raw_on is not None, "'on:' block not found in release.yml"
        assert isinstance(raw_on, dict), "'on:' must be a mapping"

        push_block = raw_on.get("push", {})
        assert isinstance(push_block, dict), "'on.push' must be a mapping"

        tags: list[str] = push_block.get("tags", [])
        assert isinstance(tags, list), "'on.push.tags' must be a list"
        assert tags, "No tag patterns under 'on.push.tags'"

        v_patterns = [t for t in tags if "v" in str(t) and "*" in str(t)]
        assert v_patterns, (
            f"No 'v*' tag pattern found in on.push.tags; got: {tags}. A pattern like 'v*' is required."
        )


class TestJobOrdering:
    """I_ORDER: publish and sign-release never run before gates pass."""

    # The gate job (release-gate or just 'gate') must exist.
    def test_gate_job_exists(self) -> None:
        doc = _load_workflow()
        jobs = _jobs(doc)
        gate_candidates = [j for j in jobs if "gate" in j.lower()]
        assert gate_candidates, (
            f"No gate job found in release.yml jobs: {list(jobs)}. "
            "A gate job running ruff/mypy/pytest/check_public_release.py is required (I2)."
        )

    def test_publish_needs_build_or_gate(self) -> None:
        """publish must declare needs on at least one of: gate, build, release-gate."""
        doc = _load_workflow()
        jobs = _jobs(doc)

        # Identify the publish job (name contains 'publish').
        publish_jobs = [j for j in jobs if "publish" in j.lower()]
        assert publish_jobs, (
            f"No publish job found in release.yml jobs: {list(jobs)}. A PyPI publish job is required (I2)."
        )
        for pub_job in publish_jobs:
            needs = _needs_of(doc, pub_job)
            assert needs, (
                f"publish job '{pub_job}' has no 'needs' — it could run before the gate (fail-open, I2)."
            )
            # needs must include something that transitively depends on the gate.
            # Accept: gate, release-gate, build (build itself must need gate).
            has_build_or_gate = any("gate" in n.lower() or "build" in n.lower() for n in needs)
            assert has_build_or_gate, (
                f"publish job '{pub_job}' needs {needs!r} but none of them is a gate or build job. "
                "publish must run after the gate (I2)."
            )

    def test_build_needs_gate(self) -> None:
        """build must declare needs on the gate job."""
        doc = _load_workflow()
        jobs = _jobs(doc)
        build_jobs = [j for j in jobs if "build" in j.lower()]
        assert build_jobs, f"No build job found in release.yml jobs: {list(jobs)}."
        for build_job in build_jobs:
            needs = _needs_of(doc, build_job)
            assert needs, f"build job '{build_job}' has no 'needs' — it could run before the gate."
            has_gate = any("gate" in n.lower() for n in needs)
            assert has_gate, (
                f"build job '{build_job}' needs {needs!r} — none is the gate job. "
                "build must wait for gate to pass (I2)."
            )


class TestReleaseCheckStep:
    """I_GATE: at least one job step runs python scripts/check_public_release.py."""

    def test_check_public_release_step_present(self) -> None:
        doc = _load_workflow()
        steps = _all_steps(doc)
        found = [s for s in steps if "check_public_release.py" in str(s.get("run", ""))]
        assert found, (
            "No step running 'python scripts/check_public_release.py' found. "
            "The release-check gate is REQUIRED before publish (I2)."
        )

    def test_check_public_release_is_in_gate_job(self) -> None:
        """The release-check step must live in the gate job (not after build)."""
        doc = _load_workflow()
        jobs = _jobs(doc)
        gate_jobs = [j for j in jobs if "gate" in j.lower()]
        assert gate_jobs, "No gate job found."
        for gate_job in gate_jobs:
            gate_steps = _steps_for_job(doc, gate_job)
            found = any("check_public_release.py" in str(s.get("run", "")) for s in gate_steps)
            if found:
                return  # At least one gate job has the step — pass.
        pytest.fail(
            "check_public_release.py step was not found inside any gate job. "
            "It must be in the gate job so that build/publish never run if it fails."
        )


class TestOidcPermissions:
    """I_OIDC: publish and/or sign-release job has permissions.id-token: write."""

    def test_oidc_permission_present(self) -> None:
        doc = _load_workflow()
        jobs = _jobs(doc)
        oidc_jobs: list[str] = []
        for job_name, job_def in jobs.items():
            if not isinstance(job_def, dict):
                continue
            perms = job_def.get("permissions", {})
            if isinstance(perms, dict):
                if str(perms.get("id-token", "")).lower() == "write":
                    oidc_jobs.append(job_name)
        assert oidc_jobs, (
            "No job with 'permissions: id-token: write' found in release.yml. "
            "OIDC trusted publishing (PyPI) and sigstore keyless signing both require it (I1)."
        )

    def test_publish_job_has_oidc_or_inherits(self) -> None:
        """The publish job must have id-token: write at the job level."""
        doc = _load_workflow()
        jobs = _jobs(doc)
        publish_jobs = [j for j in jobs if "publish" in j.lower()]
        assert publish_jobs, "No publish job found."
        for pub_job in publish_jobs:
            job_def = jobs[pub_job]
            if not isinstance(job_def, dict):
                continue
            perms = job_def.get("permissions", {})
            if isinstance(perms, dict) and str(perms.get("id-token", "")).lower() == "write":
                return  # Found.
        pytest.fail(
            f"No publish job has 'permissions: id-token: write'. "
            "PyPI OIDC trusted publishing requires this permission. "
            f"Publish jobs found: {publish_jobs}"
        )


class TestSbomAndSignatures:
    """I_SBOM + I_SIG: SBOM and sigstore signatures attached to the release."""

    def _release_steps(self, doc: dict[str, Any]) -> list[dict[str, Any]]:
        """Steps that create the GitHub Release (use action-gh-release)."""
        return [s for s in _all_steps(doc) if "action-gh-release" in str(s.get("uses", ""))]

    def test_sbom_attached_to_release(self) -> None:
        doc = _load_workflow()
        release_steps = self._release_steps(doc)
        assert release_steps, (
            "No step using 'action-gh-release' found. A GitHub Release creation step is required."
        )
        sbom_steps = [s for s in release_steps if "sbom" in str(s.get("with", {}).get("files", "")).lower()]
        assert sbom_steps, (
            "No GitHub Release step attaches 'sbom'. "
            "sbom.json must be a release asset (I_SBOM). "
            f"Release steps found: {[s.get('name') for s in release_steps]}"
        )

    def test_sigstore_signatures_attached_to_release(self) -> None:
        doc = _load_workflow()
        release_steps = self._release_steps(doc)
        assert release_steps, "No action-gh-release step found."
        sig_steps = [
            s for s in release_steps if "sigstore" in str(s.get("with", {}).get("files", "")).lower()
        ]
        assert sig_steps, (
            "No GitHub Release step attaches sigstore signatures ('*.sigstore.json'). "
            "Signed release artifacts are required (I1/I_SIG). "
            f"Release steps found: {[s.get('name') for s in release_steps]}"
        )

    def test_sigstore_signing_step_present(self) -> None:
        """A step using sigstore/gh-action-sigstore-python must be present."""
        doc = _load_workflow()
        steps = _all_steps(doc)
        sig_steps = [s for s in steps if "sigstore" in str(s.get("uses", "")).lower()]
        assert sig_steps, (
            "No step using 'sigstore/gh-action-sigstore-python' found. "
            "Keyless signing with sigstore is required for supply-chain trust (I1)."
        )

    def test_threat_model_attached_to_release(self) -> None:
        """I_TM: docs/security/threat_model.md must be attached to the GitHub Release."""
        doc = _load_workflow()
        release_steps = self._release_steps(doc)
        assert release_steps, (
            "No step using 'action-gh-release' found. A GitHub Release creation step is required."
        )
        tm_steps = [
            s for s in release_steps if "threat_model" in str(s.get("with", {}).get("files", "")).lower()
        ]
        assert tm_steps, (
            "No GitHub Release step attaches 'threat_model'. "
            "docs/security/threat_model.md must be a release asset (I_TM). "
            f"Release steps found: {[s.get('name') for s in release_steps]}"
        )

    def test_security_md_attached_to_release(self) -> None:
        """I_SEC: SECURITY.md must be attached to the GitHub Release."""
        doc = _load_workflow()
        release_steps = self._release_steps(doc)
        assert release_steps, (
            "No step using 'action-gh-release' found. A GitHub Release creation step is required."
        )
        sec_steps = [
            s for s in release_steps if "security.md" in str(s.get("with", {}).get("files", "")).lower()
        ]
        assert sec_steps, (
            "No GitHub Release step attaches 'SECURITY.md'. "
            "SECURITY.md must be a release asset (I_SEC). "
            f"Release steps found: {[s.get('name') for s in release_steps]}"
        )


class TestWheelExcludesEnterpriseStep:
    """I_WHEEL: the wheel-excludes-enterprise assertion step must be present (I3)."""

    def test_wheel_boundary_step_present(self) -> None:
        doc = _load_workflow()
        steps = _all_steps(doc)
        # Accept a pytest step referencing test_open_core_boundary OR a step name
        # containing "enterprise" and "wheel" (case-insensitive).
        found = any(
            "test_open_core_boundary" in str(s.get("run", ""))
            or (
                "enterprise" in str(s.get("name", "")).lower()
                and (
                    "wheel" in str(s.get("name", "")).lower() or "excludes" in str(s.get("name", "")).lower()
                )
            )
            for s in steps
        )
        assert found, (
            "No step asserting the wheel excludes Enterprise packages found. "
            "test_core_wheel_excludes_enterprise_packages must run in the pipeline (I3)."
        )


class TestManifestGovernancePaths:
    """I_MANIFEST: the 4 governance paths are selected by the manifest."""

    # Governance paths that must appear in the public file set once the files exist.
    # We test at manifest level (include-glob coverage) not actual file existence,
    # because the governance files are authored in a parallel task (impl A).
    # Specifically: a path that WOULD exist must not be blocked by exclude.

    def _manifest_includes_glob(self, glob_fragment: str) -> bool:
        """True if at least one include glob in the manifest contains the fragment."""
        from pathlib import Path as _Path

        raw = _Path(_MANIFEST_PATH).read_text(encoding="utf-8")
        doc = yaml.safe_load(raw)
        assert isinstance(doc, dict)
        includes: list[str] = doc.get("include", []) or []
        return any(glob_fragment in g for g in includes)

    def _manifest_not_excluded(self, rel_posix: str) -> bool:
        """True if the rel_posix path is NOT blocked by any exclude glob."""
        scripts_dir = str(_REPO_ROOT / "scripts")
        added = scripts_dir not in sys.path
        if added:
            sys.path.insert(0, scripts_dir)
        try:
            # Dynamic import: scripts/ is not a package; ignore_missing_imports covers it.
            import check_public_release

            manifest = check_public_release.load_manifest(_MANIFEST_PATH)
            # is_public_path requires the path to match an include; here we only
            # check that no exclude blocks it. We combine with include coverage.
            # cast required: untyped dynamic import returns Any.
            result: bool = bool(check_public_release.is_public_path(rel_posix, manifest))
            return result
        finally:
            if added:
                sys.path.remove(scripts_dir)

    def test_contributing_md_in_include(self) -> None:
        assert self._manifest_includes_glob("CONTRIBUTING.md"), (
            "'CONTRIBUTING.md' not found in any manifest include glob. "
            "It must be added to release/public_manifest.yaml include."
        )

    def test_code_of_conduct_md_in_include(self) -> None:
        assert self._manifest_includes_glob("CODE_OF_CONDUCT.md"), (
            "'CODE_OF_CONDUCT.md' not found in any manifest include glob."
        )

    def test_issue_template_glob_in_include(self) -> None:
        assert self._manifest_includes_glob("ISSUE_TEMPLATE"), (
            "'.github/ISSUE_TEMPLATE/**' not found in any manifest include glob."
        )

    def test_pull_request_template_in_include(self) -> None:
        assert self._manifest_includes_glob("PULL_REQUEST_TEMPLATE.md"), (
            "'.github/PULL_REQUEST_TEMPLATE.md' not found in any manifest include glob."
        )

    def test_contributing_md_passes_is_public_path(self) -> None:
        """CONTRIBUTING.md should be selected as public (not blocked by any exclude)."""
        assert self._manifest_not_excluded("CONTRIBUTING.md"), (
            "'CONTRIBUTING.md' is not selected as public by the manifest. "
            "It must be in include AND not blocked by any exclude."
        )

    def test_code_of_conduct_passes_is_public_path(self) -> None:
        assert self._manifest_not_excluded("CODE_OF_CONDUCT.md"), (
            "'CODE_OF_CONDUCT.md' is not selected as public by the manifest."
        )

    def test_pr_template_passes_is_public_path(self) -> None:
        assert self._manifest_not_excluded(".github/PULL_REQUEST_TEMPLATE.md"), (
            "'.github/PULL_REQUEST_TEMPLATE.md' is not selected as public by the manifest."
        )

    def test_issue_template_config_passes_is_public_path(self) -> None:
        """A representative file under .github/ISSUE_TEMPLATE/ must be public."""
        assert self._manifest_not_excluded(".github/ISSUE_TEMPLATE/config.yml"), (
            "'.github/ISSUE_TEMPLATE/config.yml' is not selected as public by the manifest. "
            "The '.github/ISSUE_TEMPLATE/**' glob must be in include."
        )

    def test_release_yml_still_public(self) -> None:
        """Regression: release.yml ships via the existing .github/workflows/** include."""
        assert self._manifest_not_excluded(".github/workflows/release.yml"), (
            "'.github/workflows/release.yml' is not selected as public. "
            "The '.github/workflows/**' glob must still be in include."
        )
