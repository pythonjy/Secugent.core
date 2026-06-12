# SPDX-License-Identifier: Apache-2.0
"""Governance + release-notes artifact existence gate (BDP_05 / deploy T1).

The public manifest's ``include`` list promises governance files and the runbook
(§6.3) references the release notes. A drift where the manifest/runbook reference
a file that does not exist silently skips it during snapshot extraction and breaks
the public repo's CONTRIBUTING → CODE_OF_CONDUCT link. These tests pin that every
promised governance/release artifact actually exists on disk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]

_REQUIRED_FILES = [
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "release/RELEASE_NOTES_v0.1.0.md",
]


@pytest.mark.parametrize("rel_path", _REQUIRED_FILES)
def test_required_governance_file_exists(rel_path: str) -> None:
    target = _REPO_ROOT / rel_path
    assert target.is_file(), f"required governance/release artifact missing: {rel_path}"


def test_release_notes_mention_version() -> None:
    notes = (_REPO_ROOT / "release" / "RELEASE_NOTES_v0.1.0.md").read_text(encoding="utf-8")
    assert "0.1.0" in notes, "RELEASE_NOTES_v0.1.0.md must reference the 0.1.0 version"


def test_changelog_has_v010_section() -> None:
    changelog = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "[0.1.0]" in changelog, "CHANGELOG.md must contain a '## [0.1.0]' release section"


def test_release_notes_ships_in_public_set() -> None:
    """Runbook §6.3 runs ``gh release create --notes-file release/RELEASE_NOTES_v0.1.0.md``
    from inside the extracted repo, so the notes file MUST be in the public set —
    otherwise extraction silently drops it and the documented publish step fails.
    """
    import sys

    scripts_dir = str(_REPO_ROOT / "scripts")
    added = scripts_dir not in sys.path
    if added:
        sys.path.insert(0, scripts_dir)
    try:
        import check_public_release  # type: ignore[import-untyped]  # dynamic, untyped scripts/

        manifest = check_public_release.load_manifest(_REPO_ROOT / "release" / "public_manifest.yaml")
        assert check_public_release.is_public_path("release/RELEASE_NOTES_v0.1.0.md", manifest), (
            "release/RELEASE_NOTES_v0.1.0.md is not selected by the manifest; runbook §6.3 "
            "references it from inside the extracted repo and would fail."
        )
    finally:
        if added:
            sys.path.remove(scripts_dir)
