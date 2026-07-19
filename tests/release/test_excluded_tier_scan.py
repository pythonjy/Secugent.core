# SPDX-License-Identifier: Apache-2.0
"""Excluded-tier reference gate for shipped NON-Python files — test suite.

Import-closure (I2) AST-parses only ``.py`` files, and the CHG-2 prose scanner
looks for internal-strategy TOKENS — neither looks for an excluded-tier MODULE
string inside a shipped *non-Python* artifact. That gap once let a deploy
``Dockerfile`` (``CMD ["uvicorn", "secugent.api.main:create_app"]``) and a
``docker-compose.yml`` (``image: secugent/api:...``) reference the EXCLUDED
``secugent.api`` tier: the public image could not boot yet the gate stayed green.
This module pins the new fail-closed scan added to ``scan_forbidden_content``:

* **red injection** — a synthetic shipped non-``.py`` file (Dockerfile / compose /
  shell) that references an excluded tier in dotted (``secugent.api``) or slash
  (``secugent/api``) form, or the console UI as ``ui/``, is reported with
  file:line + the matched tier;
* **no false-positive on exempt boundary docs** — README / OPEN_CORE /
  ``docs/security/**`` and the boundary machinery (manifest / runbook / extract
  script) legitimately NAME the tiers and must NOT trip;
* **packaging de-selection + ``#`` comments are not references** — a
  ``pyproject``-style ``exclude = [..., "secugent.enterprise*"]`` glob and a
  commented-out tier name are inert, so an in-scope config file carrying only
  those stays green (this is why ``pyproject.toml`` / CI ``*.yml`` need no
  exemption, keeping a REAL future entry-point reference fail-closed);
* **lock-step** — the scan patterns cover EVERY tier in
  ``FORBIDDEN_IMPORT_PREFIXES`` (no drift);
* **scenario regression** — the REAL curated public set contains no excluded-tier
  reference and the whole gate exits 0 (both in-process and as the CLI).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_public_release import (
    _TIER_REF_EXEMPT_FILES,
    _TIER_REF_PATTERNS,
    FORBIDDEN_IMPORT_PREFIXES,
    _is_tier_ref_scan_target,
    _strip_hash_comment,
    _tier_ref_reasons,
    load_manifest,
    main,
    public_files,
    scan_forbidden_content,
)

# tests/release/test_*.py -> tests/release -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "release" / "public_manifest.yaml"
GATE_SCRIPT = REPO_ROOT / "scripts" / "check_public_release.py"

# The dotted enterprise/D1 tiers (everything with a dot). ``ui`` is exercised
# separately because it is matched only in its ``ui/`` slash form.
_DOTTED_TIERS = [p for p in FORBIDDEN_IMPORT_PREFIXES if "." in p]


def _write(root: Path, rel: str, text: str) -> Path:
    """Create ``root/rel`` (with parents) and return the path."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _tier_violations(violations: list[str]) -> list[str]:
    """Keep only the excluded-tier-reference violations (ignore prose/secret)."""
    return [v for v in violations if "excluded-tier reference" in v]


# --------------------------------------------------------------------------- #
# (red) a synthetic shipped non-.py artifact referencing an excluded tier fails.
# --------------------------------------------------------------------------- #
def test_tier_ref_dockerfile_dotted_reference_is_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(red) a Dockerfile ``CMD`` that boots ``secugent.api.main`` must be flagged.

    This is the exact leak the gap allowed: a public image entrypoint importing an
    EXCLUDED tier that is not shipped, so the container cannot boot. Import-closure
    never sees it (not a ``.py``); this new scan catches it fail-closed.
    """
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    dockerfile = _write(
        tmp_path,
        "deploy/Dockerfile",
        'FROM python:3.11-slim\nCMD ["uvicorn", "secugent.api.main:create_app"]\n',
    )
    violations = _tier_violations(scan_forbidden_content([dockerfile]))
    assert any("secugent.api" in v and "deploy/Dockerfile:2" in v for v in violations), violations


def test_tier_ref_compose_slash_image_is_violation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """(red) a compose ``image: secugent/api:...`` (slash form + image tag) fails."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    compose = _write(
        tmp_path,
        "docker-compose.yml",
        "services:\n  api:\n    image: secugent/api:0.1.0\n",
    )
    violations = _tier_violations(scan_forbidden_content([compose]))
    assert any("secugent/api" in v and "docker-compose.yml:3" in v for v in violations), violations


def test_tier_ref_shell_script_reference_is_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(red) a shell entrypoint invoking an excluded tier module fails."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    script = _write(
        tmp_path,
        "deploy/entrypoint.sh",
        "#!/usr/bin/env bash\npython -m secugent.cost.accounting --serve\n",
    )
    violations = _tier_violations(scan_forbidden_content([script]))
    assert any("secugent.cost" in v and "deploy/entrypoint.sh:2" in v for v in violations), violations


@pytest.mark.parametrize("tier", sorted(_DOTTED_TIERS))
@pytest.mark.parametrize("form", ["dotted", "slash"])
def test_tier_ref_every_dotted_tier_both_forms_caught(
    tier: str, form: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each excluded ``secugent.*`` tier is caught in BOTH dotted and slash form."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    ref = f"{tier}.main" if form == "dotted" else f"{tier.replace('.', '/')}/main"
    # deploy/ is NOT exempt; a .yml there is an executable/consumed artifact.
    leaked = _write(tmp_path, "deploy/stack.yml", f"cmd:\n  - run {ref}\n")
    violations = _tier_violations(scan_forbidden_content([leaked]))
    assert any(tier in v and "deploy/stack.yml:2" in v for v in violations), (
        tier,
        form,
        violations,
    )


def test_tier_ref_ui_slash_form_is_caught(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The top-level console UI is caught as the ``ui/`` path segment."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    dockerfile = _write(tmp_path, "Dockerfile.ui", "FROM node:20\nCOPY ui/dist /app\n")
    violations = _tier_violations(scan_forbidden_content([dockerfile]))
    assert any("(tier ui)" in v and "Dockerfile.ui:2" in v for v in violations), violations


def test_tier_ref_ui_does_not_false_positive_on_gui_or_bare_word(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ui`` matches only as a bounded ``ui/`` segment — ``gui/`` / ``build-ui/`` /
    a bare ``ui`` word must NOT trip."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    clean = _write(
        tmp_path,
        "deploy/stack.yml",
        "notes:\n  - build the ui here\n  - COPY gui/dist /app\n  - build-ui/out\n",
    )
    assert _tier_violations(scan_forbidden_content([clean])) == []


# --------------------------------------------------------------------------- #
# no false-positive: exempt boundary docs + boundary machinery may NAME tiers.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "rel",
    [
        "README.md",
        "docs/OPEN_CORE.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "docs/security/threat_model.md",
    ],
)
def test_tier_ref_exempt_boundary_doc_not_flagged(
    rel: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A boundary-describing doc that NAMES the tiers to explain the open-core
    split (``secugent.api``, ``secugent/enterprise/``) must NOT be flagged — it is
    prose, not an executable reference."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    doc = _write(
        tmp_path,
        rel,
        "# Open Core boundary\n\n"
        "The Enterprise tiers `secugent/enterprise/`, `secugent/api/`, "
        "`secugent.cost` are NOT shipped in Core.\n",
    )
    assert _tier_violations(scan_forbidden_content([doc])) == []


@pytest.mark.parametrize(
    "rel",
    [
        "release/public_manifest.yaml",
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        "scripts/extract_public_repo.sh",
        ".gitignore",
    ],
)
def test_tier_ref_boundary_machinery_not_flagged(
    rel: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The boundary machinery (manifest exclude list / runbook leak-scan / extract
    script) and VCS metadata legitimately enumerate ``secugent/<tier>/`` paths and
    must NOT trip this scan."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    body = (
        "exclude:\n"
        '  - "secugent/enterprise/**"\n'
        '  - "secugent/api/**"\n'
        '  - "ui/**"\n'
        "git log --all -- secugent/cost/\n"
    )
    machinery = _write(tmp_path, rel, body)
    assert _tier_violations(scan_forbidden_content([machinery])) == []


# --------------------------------------------------------------------------- #
# packaging de-selection + comment tails are NOT references (keeps pyproject / CI
# green WITHOUT whole-file exemption, so a real reference there still fails).
# --------------------------------------------------------------------------- #
def test_tier_ref_glob_deselection_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A packaging ``exclude = [..., "secugent.enterprise*"]`` glob de-SELECTS the
    tier (trailing ``*``) — it is not a reference and must NOT trip, even in an
    in-scope (non-exempt) ``.toml``."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    pkg = _write(
        tmp_path,
        "packaging/build.toml",
        '[tool.setuptools.packages.find]\nexclude = ["ui*", "secugent.enterprise*"]\n',
    )
    assert _tier_violations(scan_forbidden_content([pkg])) == []


def test_tier_ref_comment_tail_stripped_but_directive_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``#`` comment tier name is inert (stripped); a directive BEFORE any ``#``
    is still caught — exactly one violation, on the executable line."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    yml = _write(
        tmp_path,
        "deploy/stack.yml",
        "# was: image: secugent/api:old\nservices:\n  api:\n    image: secugent/api:1.0  # prod tag\n",
    )
    violations = _tier_violations(scan_forbidden_content([yml]))
    assert len(violations) == 1, violations
    assert "deploy/stack.yml:4" in violations[0], violations


def test_tier_ref_longer_name_and_left_boundary_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Precise boundaries: ``secugent.apis`` (longer name) and ``mysecugent/api``
    (longer left word) must NOT match; a real ``secugent.api.`` reference must."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    clean = _write(
        tmp_path,
        "deploy/stack.yml",
        "notes:\n  - secugent.apis is a different name\n  - mysecugent/apixyz\n",
    )
    assert _tier_violations(scan_forbidden_content([clean])) == []
    leaked = _write(tmp_path, "deploy/other.yml", "run: secugent.api.main\n")
    assert _tier_violations(scan_forbidden_content([leaked])) != []


# --------------------------------------------------------------------------- #
# scope predicate + Python is out of scope (closure governs it).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "rel",
    [
        "deploy/Dockerfile",
        "Dockerfile.ui",
        "docker-compose.yml",
        "deploy/run.sh",
        "config/models.yaml",
        "requirements.txt",
        "Makefile",  # extensionless
        "deploy/app.env",
    ],
)
def test_tier_ref_scope_includes_non_python_artifacts(rel: str) -> None:
    assert _is_tier_ref_scan_target(rel) is True


@pytest.mark.parametrize(
    "rel",
    [
        "secugent/core/regulations.py",  # .py -> import-closure governs it
        "README.md",  # exempt boundary doc
        "docs/OPEN_CORE.md",  # exempt boundary doc
        "docs/security/threat_model.md",  # exempt prefix
        "release/public_manifest.yaml",  # boundary machinery
        "release/PUBLIC_RELEASE_RUNBOOK.md",  # boundary machinery
        "scripts/extract_public_repo.sh",  # boundary machinery
        ".gitignore",  # VCS metadata
        ".gitattributes",  # VCS metadata
    ],
)
def test_tier_ref_scope_excludes_python_and_exempt_files(rel: str) -> None:
    assert _is_tier_ref_scan_target(rel) is False


def test_tier_ref_python_file_not_scanned_for_tiers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``.py`` importing an excluded tier is NOT this scan's job (import-closure
    catches it); the tier-ref scan must add no violation for a ``.py``."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    py = _write(tmp_path, "secugent/x.py", "import secugent.api.main\n")
    assert _tier_violations(scan_forbidden_content([py])) == []


# --------------------------------------------------------------------------- #
# lock-step + determinism + report format.
# --------------------------------------------------------------------------- #
def test_tier_ref_patterns_cover_every_forbidden_prefix() -> None:
    """The scan patterns cover EVERY tier in ``FORBIDDEN_IMPORT_PREFIXES`` — the
    same deny-set the import-closure gate uses, so the two never drift."""
    covered = {tier for tier, _patterns in _TIER_REF_PATTERNS}
    assert covered == set(FORBIDDEN_IMPORT_PREFIXES)


def test_tier_ref_exempt_set_never_includes_executable_artifacts() -> None:
    """Defence: the whole-file exempt set must not contain an executable/consumed
    artifact (``pyproject.toml``, a CI ``*.yml``, a ``*.sh`` other than the extract
    script) — those must stay fail-closed."""
    assert "pyproject.toml" not in _TIER_REF_EXEMPT_FILES
    assert ".github/workflows/secugent.yml" not in _TIER_REF_EXEMPT_FILES
    shipped_sh = {f for f in _TIER_REF_EXEMPT_FILES if f.endswith(".sh")}
    assert shipped_sh == {"scripts/extract_public_repo.sh"}, shipped_sh


def test_tier_ref_reasons_deterministic() -> None:
    """``_tier_ref_reasons`` is a pure function — 100 calls on the same input are
    byte-identical (the gate must be reproducible; hits are sorted by the caller)."""
    text = "run secugent.api.main\nimage: secugent/cost:1\nCOPY ui/dist /app\n"
    baseline = _tier_ref_reasons("deploy/stack.yml", text)
    assert baseline, "expected the fixture to produce hits"
    for _ in range(100):
        assert _tier_ref_reasons("deploy/stack.yml", text) == baseline


def test_tier_ref_report_names_file_line_and_tier(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A violation is locatable: it carries the tier, the matched text, and
    ``{file}:{line}``."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    f = _write(tmp_path, "deploy/x.yml", "a:\nb:\n  run secugent.api.main\n")
    (v,) = _tier_violations(scan_forbidden_content([f]))
    assert "secugent.api" in v and "deploy/x.yml:3" in v


def test_strip_hash_comment_only_for_hash_formats() -> None:
    """``#`` is stripped for hash-comment formats (yaml/toml/sh/env/Dockerfile) but
    NOT for markdown (a ``#`` there is a heading, not a comment)."""
    assert _strip_hash_comment("image: x  # note", "deploy/stack.yml") == "image: x  "
    assert _strip_hash_comment("RUN x  # note", "Dockerfile") == "RUN x  "
    # Markdown heading is preserved verbatim (no stripping).
    assert _strip_hash_comment("# secugent.api guide", "docs/guide.md") == "# secugent.api guide"


# --------------------------------------------------------------------------- #
# scenario regression: the REAL curated public set is clean + the gate exits 0.
# --------------------------------------------------------------------------- #
def test_tier_ref_real_public_tree_has_no_excluded_tier_reference() -> None:
    """The shipped public set references no excluded tier in any non-.py file (the
    resynced tree removed the deploy artifacts that leaked ``secugent.api``)."""
    manifest = load_manifest(MANIFEST_PATH)
    files = public_files(manifest, REPO_ROOT)
    violations = _tier_violations(scan_forbidden_content(files))
    assert violations == [], violations


def test_tier_ref_gate_exits_zero_on_current_repo() -> None:
    """The whole gate (including the new scan) exits 0 on the current curated set."""
    assert main([str(MANIFEST_PATH)]) == 0


def test_tier_ref_gate_cli_subprocess_exits_zero() -> None:
    """Regression (requirement 5c): the CLI ``python scripts/check_public_release.py``
    exits 0 on the resynced tree. Subprocess so it exercises the real entrypoint."""
    result = subprocess.run(  # noqa: S603 - sys.executable + fixed script path, no untrusted input
        [sys.executable, str(GATE_SCRIPT)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK: public set is closed" in result.stdout, result.stdout
