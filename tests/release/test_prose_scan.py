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
* **per-file exemption is token-scoped, never whole-file** — the three
  boundary-machinery files (``release/public_manifest.yaml``,
  ``release/PUBLIC_RELEASE_RUNBOOK.md``, ``scripts/extract_public_repo.sh``) may
  carry ONLY their legitimately-needed category tokens; a planted
  ``Project_Secugent`` in any of them STILL fails closed (the gap the adversarial
  review found in the old whole-file allowlist).
* **BDP_0 family** — ``BDP_05`` (and ``BDP_01``…) in a normal shipped doc is
  caught, while the boundary-machinery files that legitimately reference it are
  not self-tripped.
* **scenario regression** — the REAL curated public tree leaks no never-exempt
  private-path token (``Project_Secugent``) into shipped prose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_public_release import (
    _FORBIDDEN_PROSE_SUBSTRINGS,
    _NEVER_EXEMPT_PROSE_SUBSTRINGS,
    _PROSE_ALLOWED_TOKENS_BY_FILE,
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
# per-file exemption: boundary-machinery files may carry ONLY their category
# tokens — and are STILL scanned (Project_Secugent there fails closed).
# --------------------------------------------------------------------------- #
def test_prose_exempt_manifest_category_tokens_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``release/public_manifest.yaml`` names ``Review/**`` / ``BDP_05`` by design."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    manifest = _write(
        tmp_path,
        "release/public_manifest.yaml",
        "# BDP_05 item 2\n"
        'exclude:\n  - "Review/**"\n  - "docs/specs/**"\n'
        '  - "BDP_REFORMED/**"\n  - "DEPLOY_PROGRESS.md"\n',
    )
    assert scan_forbidden_content([manifest]) == []


def test_prose_exempt_runbook_category_tokens_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runbook documents ``git log -- docs/specs/`` leak-check commands + BDP_05."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    runbook = _write(
        tmp_path,
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        "BDP_05 항목\n"
        'git log --all -- "docs/specs/"\n'
        "git log --all -- BDP_REFORMED\n"
        "git log --all -- DEPLOY_PROGRESS.md\n",
    )
    assert scan_forbidden_content([runbook]) == []


def test_prose_exempt_extract_script_category_tokens_not_flagged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``.sh`` extract script (under scripts/) is now scanned but exempts its
    category tokens — symmetric with the manifest/runbook, no longer escaping by
    virtue of the ``.sh`` suffix alone."""
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    script = _write(
        tmp_path,
        "scripts/extract_public_repo.sh",
        '# BDP_05 항목 3\nLEAK_SCAN_PATHS=(\n  "BDP_REFORMED"\n  "DEPLOY_PROGRESS.md"\n)\n',
    )
    # In scope (boundary-machinery), yet clean for its allowed tokens.
    assert _is_prose_scan_target("scripts/extract_public_repo.sh") is True
    assert scan_forbidden_content([script]) == []


# --------------------------------------------------------------------------- #
# (red) per-file exemption is TOKEN-scoped, not whole-file: Project_Secugent in
# a boundary-machinery file STILL fails closed (the gap the review found).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "rel",
    [
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        "release/public_manifest.yaml",
        "scripts/extract_public_repo.sh",
    ],
)
def test_prose_planted_project_secugent_in_exempt_file_still_flagged(
    rel: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(red) plant ``Project_Secugent`` into a boundary-machinery file body.

    The old WHOLE-FILE allowlist skipped these files entirely, so this leak passed
    silently. The per-token exemption must STILL flag it (Project_Secugent is
    never legitimate), even on a line that ALSO carries an allowed category token.
    """
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    # Line 1: an allowed token (must NOT trip). Line 2: a genuine private-path leak
    # alongside an allowed token (the allowed token must NOT mask the leak).
    leaked = _write(
        tmp_path,
        rel,
        "exclude Review/**\n# extracted from D:/Project_Secugent (Review/ tree)\n",
    )
    violations = scan_forbidden_content([leaked])
    assert any("Project_Secugent" in v and f"{rel}:2" in v for v in violations), violations
    # The allowed category token on the same/other line must NOT itself be flagged.
    assert not any("'Review/'" in v for v in violations), violations


def test_prose_never_exempt_set_is_project_secugent_only() -> None:
    """Pin the never-exempt set: only the private source-repo dir name.

    Widening per-file allowed sets must never be able to suppress this token; the
    membership is pinned so an accidental change is caught.
    """
    assert _NEVER_EXEMPT_PROSE_SUBSTRINGS == ("Project_Secugent",)
    # And it is a real member of the denylist (so the scan looks for it at all).
    assert "Project_Secugent" in _FORBIDDEN_PROSE_SUBSTRINGS


# --------------------------------------------------------------------------- #
# (red) BDP_0 family: BDP_05 in a NORMAL shipped doc is caught.
# --------------------------------------------------------------------------- #
def test_prose_bdp05_in_normal_doc_is_violation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """(red) ``BDP_05`` in a non-exempt shipped document body must be flagged.

    ``BDP_0`` (added to the denylist) is broader than ``BDP_REFORMED`` and catches
    the numbered internal process-artifact names that currently ship in some docs
    (removed by the strategy-scrub step). A normal doc has no exemption.
    """
    import scripts.check_public_release as mod

    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    leaked = _write(
        tmp_path,
        "docs/OPEN_CORE.md",
        "# Open Core\n\nTier table (BDP_05 항목 1 — 확정)\n",
    )
    violations = scan_forbidden_content([leaked])
    assert any("'BDP_0'" in v and "docs/OPEN_CORE.md:3" in v for v in violations), violations


def test_prose_bdp0_is_in_denylist() -> None:
    """The ``BDP_0`` family token is in the prose denylist (broader than BDP_REFORMED)."""
    assert "BDP_0" in _FORBIDDEN_PROSE_SUBSTRINGS


# --------------------------------------------------------------------------- #
# per-file map shape + tightness.
# --------------------------------------------------------------------------- #
def test_prose_per_file_map_is_exactly_the_three_boundary_files() -> None:
    """The exemption map is exactly the three boundary-machinery files.

    A broader map would re-open the fail-open; pin membership so an accidental
    widening (e.g. exempting all of ``release/``) is caught.
    """
    assert set(_PROSE_ALLOWED_TOKENS_BY_FILE) == {
        "release/public_manifest.yaml",
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        "scripts/extract_public_repo.sh",
    }


def test_prose_no_exempt_file_allows_project_secugent() -> None:
    """No per-file allowed set may include the never-exempt private-path token."""
    for rel, allowed in _PROSE_ALLOWED_TOKENS_BY_FILE.items():
        assert "Project_Secugent" not in allowed, rel


def test_prose_changelog_is_scanned_with_zero_tolerance() -> None:
    """Defence: a NON-exempt root document stays in the prose-scan scope.

    Guards against someone adding CHANGELOG.md (the very file CHG-2 leaked through)
    to the per-file map.
    """
    assert "CHANGELOG.md" not in _PROSE_ALLOWED_TOKENS_BY_FILE
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
        # The three boundary-machinery files are now IN scope (scanned with their
        # per-token exemption) rather than skipped wholesale.
        "release/public_manifest.yaml",
        "release/PUBLIC_RELEASE_RUNBOOK.md",
        "scripts/extract_public_repo.sh",
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
        "scripts/gen_sbom.py",  # source code under scripts/, not boundary machinery
    ],
)
def test_prose_scope_excludes_non_documents(rel: str) -> None:
    assert _is_prose_scan_target(rel) is False


# --------------------------------------------------------------------------- #
# scenario regression: the REAL curated public tree leaks no NEVER-EXEMPT private-
# path token. (BDP_0 family is still present in some shipped docs RIGHT NOW —
# OPEN_CORE.md / TRUST_PROOF.md — and is removed by the strategy-scrub step; this
# gate change must be correct without weakening, so we assert the invariant that
# holds today AND after the scrub: no Project_Secugent leak.)
# --------------------------------------------------------------------------- #
def test_prose_real_public_tree_has_no_never_exempt_leak() -> None:
    """The shipped public set leaks no ``Project_Secugent`` into shipped prose.

    This is the always-true invariant (the private source-repo dir name has zero
    legitimate public use anywhere). We do NOT assert zero ``BDP_0`` violations
    here: the broadened denylist intentionally flags the ``BDP_05`` references that
    still ship in ``docs/OPEN_CORE.md`` / ``docs/security/TRUST_PROOF.md`` until the
    next strategy-scrub step removes them — making the gate fail on those now is
    correct, not a regression to suppress.
    """
    manifest = load_manifest(MANIFEST_PATH)
    files = public_files(manifest, REPO_ROOT)
    violations = scan_forbidden_content(files)
    never_exempt_leaks = [
        v
        for v in violations
        if "internal token" in v and any(f"'{tok}'" in v for tok in _NEVER_EXEMPT_PROSE_SUBSTRINGS)
    ]
    assert never_exempt_leaks == [], never_exempt_leaks


def test_prose_real_public_tree_boundary_files_are_clean() -> None:
    """The three boundary-machinery files leak NO forbidden prose token at all.

    They are now scanned (not skipped wholesale), with their per-token exemption.
    A clean result proves (a) they carry only their legitimately-needed category
    tokens and (b) the exemption is wired for each — including the ``.sh`` script
    that previously escaped scanning entirely.
    """
    boundary = [
        REPO_ROOT / "release" / "public_manifest.yaml",
        REPO_ROOT / "release" / "PUBLIC_RELEASE_RUNBOOK.md",
        REPO_ROOT / "scripts" / "extract_public_repo.sh",
    ]
    present = [p for p in boundary if p.is_file()]
    assert present, "expected at least one boundary-machinery file to exist"
    violations = [v for v in scan_forbidden_content(present) if "internal token" in v]
    assert violations == [], violations
