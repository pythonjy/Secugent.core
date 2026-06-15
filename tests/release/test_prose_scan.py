# SPDX-License-Identifier: Apache-2.0
"""Prose-token leak gate (CHG-2) — deterministic-module test suite.

``scan_forbidden_content`` previously scanned only file NAMES for internal
artifacts and text BODIES for secrets, so a public document whose *path* is
clean (CHANGELOG.md, the runbook) could still name-drop the private source tree
in its prose and the gate would stay green (fail-open). This module pins the
strengthened prose gate:

* **unit / red injection** — a planted ``Project_Secugent`` (and each other
  forbidden token) in the BODY of a shipped public document is reported with the
  file + line, while a clean document and an out-of-scope source file are not.
* **allowlist is tight** — the two boundary-machinery files
  (``release/public_manifest.yaml`` and ``release/PUBLIC_RELEASE_RUNBOOK.md``),
  which MUST name the excluded paths, are not tripped; nothing else is exempt.
* **scenario regression** — the REAL curated public tree passes the prose gate
  (no remaining internal token leaked into shipped prose).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_public_release import (
    _FORBIDDEN_PROSE_SUBSTRINGS,
    _PROSE_SCAN_ALLOWLIST,
    _is_prose_scan_target,
    load_manifest,
    public_files,
    scan_forbidden_content,
)

# tests/release/test_*.py -> tests/release -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "release" / "public_manifest.yaml"


def _write(root: Path, rel: str, text: str) -> Path:
    """Create ``root/rel`` (with parents) and return the path."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# red injection: a planted internal token in shipped prose must be caught.
# --------------------------------------------------------------------------- #
def test_prose_planted_project_secugent_in_changelog_is_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(red) plant ``Project_Secugent`` in CHANGELOG.md body -> must be flagged.

    The path ``CHANGELOG.md`` is perfectly legitimate; the leak is the BODY line
    that name-drops the private source tree. The old name-only scan missed this.
    """
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    leaked = _write(
        tmp_path,
        "CHANGELOG.md",
        "# Changelog\n\n## v0.1.0\n- extracted from D:/Project_Secugent\n",
    )
    violations = scan_forbidden_content([leaked])
    assert any("Project_Secugent" in v and "CHANGELOG.md:4" in v for v in violations), violations


@pytest.mark.parametrize("token", sorted(_FORBIDDEN_PROSE_SUBSTRINGS))
def test_prose_each_forbidden_token_is_caught(
    token: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every token in the deny-list trips the gate when planted in a doc body."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    leaked = _write(tmp_path, "docs/OPEN_CORE.md", f"line one\nsee {token} here\nlast\n")
    violations = scan_forbidden_content([leaked])
    assert any(repr(token) in v and "docs/OPEN_CORE.md:2" in v for v in violations), (
        token,
        violations,
    )


def test_prose_clean_document_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A genuinely clean public document yields zero prose violations."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    clean = _write(
        tmp_path,
        "README.md",
        "# SecuGent Core\n\nAn open-core trust & control plane for agents.\n",
    )
    assert scan_forbidden_content([clean]) == []


# --------------------------------------------------------------------------- #
# allowlist: boundary-machinery files that MUST name excluded paths are exempt.
# --------------------------------------------------------------------------- #
def test_prose_allowlisted_manifest_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``release/public_manifest.yaml`` names ``Review/**`` etc. by design."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    manifest = _write(
        tmp_path,
        "release/public_manifest.yaml",
        'exclude:\n  - "Review/**"\n  - "docs/specs/**"\n  - "BDP_REFORMED/**"\n',
    )
    assert scan_forbidden_content([manifest]) == []


def test_prose_allowlisted_runbook_is_not_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The runbook documents ``git log -- docs/specs/`` leak-check commands."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    runbook = _write(
        tmp_path,
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        'git log --all -- "docs/specs/"\ngit log --all -- BDP_REFORMED\n',
    )
    assert scan_forbidden_content([runbook]) == []


def test_prose_allowlist_is_tight() -> None:
    """The allowlist is exactly the two boundary-machinery files — nothing else.

    A broad allowlist would re-open the fail-open; pin the membership so an
    accidental widening (e.g. exempting all of ``release/``) is caught.
    """
    assert _PROSE_SCAN_ALLOWLIST == frozenset(
        {"release/public_manifest.yaml", "release/PUBLIC_RELEASE_RUNBOOK.md"}
    )


def test_prose_allowlisted_changelog_would_still_be_scanned() -> None:
    """Defence: a NON-allowlisted root document stays in the prose-scan scope.

    Guards against someone widening the allowlist to cover CHANGELOG.md (the very
    file CHG-2 leaked through).
    """
    assert "CHANGELOG.md" not in _PROSE_SCAN_ALLOWLIST
    assert _is_prose_scan_target("CHANGELOG.md") is True


# --------------------------------------------------------------------------- #
# scope: which files the prose gate scans (docs/ release/ root; .md/.txt/.rst/.yaml)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "rel",
    [
        "CHANGELOG.md",
        "README.md",
        "docs/OPEN_CORE.md",
        "release/RELEASE_NOTES_v0.1.0.md",
        "docs/notes.txt",
        "docs/guide.rst",
        "release/meta.yaml",
    ],
)
def test_prose_scope_includes_curated_documents(rel: str) -> None:
    assert _is_prose_scan_target(rel) is True


@pytest.mark.parametrize(
    "rel",
    [
        "secugent/core/regulations.py",  # code text, not prose
        "pyproject.toml",  # config text, not a .md/.txt/.rst/.yaml doc
        "scripts/check_public_release.py",  # defines the tokens; out of scope
        "tests/release/test_prose_scan.py",  # this very file mentions the tokens
        "secugent/fixtures/sample.yaml",  # source-tree yaml is out of scope
        "release/public_manifest.yaml",  # allowlisted boundary machinery
    ],
)
def test_prose_scope_excludes_non_documents(rel: str) -> None:
    assert _is_prose_scan_target(rel) is False


# --------------------------------------------------------------------------- #
# scenario regression: the REAL curated public tree leaks no internal prose token.
# --------------------------------------------------------------------------- #
def test_prose_real_public_tree_has_no_token_leak() -> None:
    """The shipped public set passes the strengthened prose gate (exit-0 path)."""
    manifest = load_manifest(MANIFEST_PATH)
    files = public_files(manifest, REPO_ROOT)
    violations = scan_forbidden_content(files)
    leaked_prose = [v for v in violations if "internal token" in v]
    assert leaked_prose == [], leaked_prose
