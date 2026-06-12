# SPDX-License-Identifier: Apache-2.0
"""Regression test: extract_public_repo.sh --dry-run resolves paths correctly.

W-02 회귀 테스트: scripts/extract_public_repo.sh가 POSIX 경로 문자열을
python 내부에 삽입하지 않고 cwd() 기반으로 repo_root를 얻도록 수정됐다.
이 테스트는 --dry-run 모드에서 exit 0 + secugent/__init__.py 포함을 검증한다.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_dry_run_exits_zero_and_includes_init_py() -> None:
    """--dry-run は exit 0 で終了し, stdout に secugent/__init__.py を含む."""
    bash_exe = shutil.which("bash")
    if bash_exe is None:
        pytest.skip("bash not available on this platform")

    result = subprocess.run(  # noqa: S603
        [bash_exe, "scripts/extract_public_repo.sh", "--dry-run"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode == 0, (
        f"extract_public_repo.sh --dry-run exited with code {result.returncode}.\n"
        f"stderr:\n{result.stderr}\n"
        f"stdout:\n{result.stdout}"
    )
    assert "secugent/__init__.py" in result.stdout, (
        "secugent/__init__.py not found in --dry-run output.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


def test_real_snapshot_extraction_copies_all_public_files(tmp_path: Path) -> None:
    """Run a REAL (non-dry-run) snapshot extraction and assert files are copied.

    Regression for the Windows CRLF false-pass: --dry-run never exercises the
    extract read-loop, so a CRLF-contaminated file list (win32 python3 text-mode
    stdout) skipped every file (0 copied, exit 1) while the dry-run test stayed
    green. This test runs the read-loop end-to-end so that class of bug fails CI.
    """
    bash_exe = shutil.which("bash")
    if bash_exe is None:
        pytest.skip("bash not available on this platform")
    git_exe = shutil.which("git")
    if git_exe is None:
        pytest.skip("git not available on this platform")

    out_dir = tmp_path / "secugent-core"
    result = subprocess.run(  # noqa: S603
        [bash_exe, "scripts/extract_public_repo.sh", "--mode", "snapshot", "--out", str(out_dir)],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert result.returncode == 0, (
        f"real snapshot extraction failed (rc={result.returncode}).\n"
        f"stderr:\n{result.stderr}\nstdout:\n{result.stdout}"
    )
    # 0-copied failure would leave secugent/__init__.py absent (and rc!=0 above).
    assert (out_dir / "secugent" / "__init__.py").is_file(), (
        "extracted repo is missing secugent/__init__.py — the read-loop copied 0 files."
    )
    # Snapshot must be a single-commit repo (Invariant I7 — no history leak).
    rev = subprocess.run(  # noqa: S603
        [git_exe, "-C", str(out_dir), "rev-list", "--count", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert rev.stdout.strip() == "1", (
        f"expected a single-commit snapshot (I7), got {rev.stdout.strip()!r} commits"
    )
