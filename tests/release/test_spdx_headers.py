# SPDX-License-Identifier: Apache-2.0
"""SPDX-License-Identifier header gate for the public Core .py file set.

Every Python file selected by ``release/public_manifest.yaml`` MUST carry a
``# SPDX-License-Identifier: Apache-2.0`` comment in its first five lines.
This gates drift: any future file added to the public set without the header
causes this test to fail immediately (fail-closed).

Apache-2.0 §4(a) source-header requirement — OSS public release invariant W-06.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

# tests/release/test_spdx_headers.py -> tests/release -> tests -> repo root.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _REPO_ROOT / "release" / "public_manifest.yaml"

_SPDX_MARKER = "SPDX-License-Identifier: Apache-2.0"

# Number of lines from the top of each file to scan for the SPDX marker.
_SCAN_LINES = 5


def _load_public_py_files() -> list[Path]:
    """Return every public .py file selected by the release manifest.

    The ``scripts/`` directory is not an installed package; we add it to
    sys.path transiently so the import works without ``pip install -e .``
    changes.  The import is dynamic (scripts/ is untyped), so the ``type:
    ignore`` below is both necessary and intentional.
    """
    scripts_dir = str(_REPO_ROOT / "scripts")
    added = scripts_dir not in sys.path
    if added:
        sys.path.insert(0, scripts_dir)
    try:
        import check_public_release  # type: ignore[import-untyped]  # dynamic, untyped scripts/

        manifest = check_public_release.load_manifest(_MANIFEST_PATH)
        all_files: list[Path] = list(check_public_release.public_files(manifest, _REPO_ROOT))
        return [f for f in all_files if f.suffix == ".py"]
    finally:
        if added:
            sys.path.remove(scripts_dir)


def _has_spdx_header(path: Path) -> bool:
    """Return True if any of the first *_SCAN_LINES* lines contains the marker."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return False
    for line in content.splitlines()[:_SCAN_LINES]:
        if _SPDX_MARKER in line:
            return True
    return False


# ---------------------------------------------------------------------------
# Gate test: every public .py must have the SPDX header
# ---------------------------------------------------------------------------


def test_all_public_py_files_have_spdx_header() -> None:
    """Fail if any public .py file is missing ``SPDX-License-Identifier: Apache-2.0``
    in its first five lines.

    This is a drift-prevention gate: once W-06 is fixed, any future public
    .py added without the header will cause this test to fail immediately,
    making the omission visible in CI before release.
    """
    py_files = _load_public_py_files()
    assert py_files, "public_files() returned no .py files — manifest misconfiguration?"

    violations: list[str] = []
    for path in py_files:
        if not _has_spdx_header(path):
            violations.append(str(path.relative_to(_REPO_ROOT).as_posix()))

    assert not violations, (
        f"{len(violations)} public .py file(s) missing "
        f"'# SPDX-License-Identifier: Apache-2.0' in the first {_SCAN_LINES} lines:\n"
        + "\n".join(f"  {v}" for v in sorted(violations))
    )


def test_public_py_file_set_is_nonempty() -> None:
    """Sanity: the manifest must select at least some .py files."""
    py_files = _load_public_py_files()
    assert len(py_files) > 50, (
        f"Expected >50 public .py files, got {len(py_files)} — manifest may be misconfigured"
    )


def test_no_public_py_has_crlf_line_endings() -> None:
    """Byte-level guard: public .py must be LF-only (repo .gitattributes ``eol=lf``).

    The SPDX-insertion tooling rewrote files in Windows text mode, flipping every
    line LF->CRLF. ``git diff`` hid this (``eol=lf`` normalizes both sides), and
    ``splitlines()``-based checks treat CRLF/LF identically — so the flip passed
    every existing gate. The snapshot extractor copies working-tree bytes via
    ``cp``, so CRLF here would leak into the public repo. This byte check fails
    closed on any CR.
    """
    py_files = _load_public_py_files()
    crlf = [str(p.relative_to(_REPO_ROOT).as_posix()) for p in py_files if b"\r\n" in p.read_bytes()]
    assert not crlf, f"{len(crlf)} public .py file(s) contain CRLF line endings (must be LF):\n" + "\n".join(
        f"  {c}" for c in sorted(crlf)
    )


def test_all_public_py_parse_cleanly() -> None:
    """Syntactic integrity: prepending the SPDX header must not break any file.

    Catches a header inserted before ``from __future__ import`` or in a position
    that turns a module docstring into a plain comment / raises SyntaxError.
    """
    py_files = _load_public_py_files()
    errors: list[str] = []
    for path in py_files:
        try:
            ast.parse(path.read_bytes())
        except SyntaxError as exc:  # pragma: no cover - failure path asserts below
            errors.append(f"{path.relative_to(_REPO_ROOT).as_posix()}: {exc}")
    assert not errors, "public .py file(s) failed to parse after SPDX insertion:\n" + "\n".join(errors)


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (["# SPDX-License-Identifier: Apache-2.0", "x = 1"], True),
        (["#!/usr/bin/env python3", "# SPDX-License-Identifier: Apache-2.0"], True),
        (["x = 1", "y = 2", "", "# SPDX-License-Identifier: Apache-2.0"], True),
        (["x = 1"], False),
        ([], False),
        (["# Apache-2.0 license"], False),  # not the canonical SPDX form
    ],
)
def test_has_spdx_header_unit(lines: list[str], expected: bool, tmp_path: Path) -> None:
    """Unit-test the _has_spdx_header() predicate directly."""
    f = tmp_path / "test.py"
    f.write_text("\n".join(lines), encoding="utf-8")
    assert _has_spdx_header(f) is expected
