# SPDX-License-Identifier: Apache-2.0
"""Gate: public-Core hard runtime imports must be declared in [project.dependencies].

A standalone ``pip install secugent`` of the open-core public repo must be
self-contained. Regression for the prometheus_client gap (I8/I9): secugent/
observability/metrics.py imports ``prometheus_client`` at module top and the
DETERMINISTIC approval.py pulls ``APPROVAL_WAIT`` from it, but the dependency was
undeclared — ``secugent demo`` raised ModuleNotFoundError on a fresh install while
the source environment (which had it globally) stayed green.

The runbook §5 fresh-venv install is the comprehensive G5 check; this test pins
the specific class cheaply so CI catches an undeclared core runtime dependency.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]

# PEP 503-normalised distribution names that public-Core modules import at module
# top (non-lazy) and therefore MUST be installed by ``pip install secugent``.
_REQUIRED_CORE_DEPS = frozenset(
    {
        "prometheus-client",
        "pydantic",
        "fastapi",
        "structlog",
        "jsonschema",
        "tenacity",
        "pyyaml",
        "anthropic",
        "httpx",
        "aiosmtplib",
        "websockets",
    }
)

_VERSION_OPS = (">=", "==", "<=", "~=", "!=", ">", "<")


def _declared_dist_names() -> set[str]:
    """Return the PEP 503-normalised distribution names in [project.dependencies]."""
    data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps: list[str] = data["project"]["dependencies"]
    names: set[str] = set()
    for spec in deps:
        name = spec.split(";")[0].split("[")[0]  # drop env markers + extras
        for op in _VERSION_OPS:
            name = name.split(op)[0]
        names.add(name.strip().lower().replace("_", "-"))
    return names


def test_public_core_runtime_deps_are_declared() -> None:
    declared = _declared_dist_names()
    missing = sorted(d for d in _REQUIRED_CORE_DEPS if d not in declared)
    assert not missing, (
        "public Core imports these distributions at module top but pyproject "
        "[project.dependencies] does not declare them — a standalone "
        f"`pip install secugent` would ModuleNotFoundError: {missing}"
    )
