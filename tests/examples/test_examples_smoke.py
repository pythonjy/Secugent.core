# SPDX-License-Identifier: Apache-2.0
"""Smoke tests for ``examples/`` (Invariant I3).

Every example directory must ship a runnable ``run.py`` that exits 0 with no API
key and no network — no dead examples. Each is executed as an isolated
subprocess so an example crash can never poison the test process, and so we
exercise the exact ``python examples/<dir>/run.py`` path a new user would type.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLES_DIR = _REPO_ROOT / "examples"

# The example directories item 3 ships. Listed explicitly (not globbed) so adding
# a new example without a smoke test is a visible, deliberate change.
_EXAMPLE_DIRS = ["quickstart", "policy_demo", "langchain_demo"]


def _keyless_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)  # I1: prove key-less
    env.pop("SECUGENT_ENV", None)
    env["PYTHONUTF8"] = "1"  # Korean output must not crash on cp949 consoles
    return env


def test_examples_dir_exists() -> None:
    assert _EXAMPLES_DIR.is_dir()


@pytest.mark.parametrize("example", _EXAMPLE_DIRS)
def test_example_has_runnable_script_and_readme(example: str) -> None:
    """Each example ships a run.py + a README (no dead examples)."""
    d = _EXAMPLES_DIR / example
    assert (d / "run.py").is_file(), f"{example} missing run.py"
    assert (d / "README.md").is_file(), f"{example} missing README.md"


@pytest.mark.parametrize("example", _EXAMPLE_DIRS)
def test_example_runs_with_zero_exit(example: str) -> None:
    """I3 — `python examples/<dir>/run.py` exits 0, key-less, no network."""
    script = _EXAMPLES_DIR / example / "run.py"
    proc = subprocess.run(  # noqa: S603  — args are sys.executable + an in-repo script path, not untrusted input
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_keyless_env(),
        cwd=str(_REPO_ROOT),
        timeout=120,
    )
    assert proc.returncode == 0, f"{example} exited {proc.returncode}: {proc.stderr}"
    assert proc.stdout.strip(), f"{example} produced no output"
