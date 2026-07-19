# SPDX-License-Identifier: Apache-2.0
"""SBOM pollution regression tests.

Verifies that ``scripts/gen_sbom.py`` emits a deterministic, closure-scoped
CycloneDX SBOM — not a dump of the whole dev-venv site-packages.

Three invariant classes tested:

(a) **Pollution gate**: known-unrelated dev-venv packages do NOT appear in
    the generated SBOM components list.
(b) **Root metadata**: the root component carries the correct version (from
    ``pyproject.toml``) and the correct SPDX license expression.
(c) **Byte reproducibility**: two successive ``build_sbom()`` calls produce
    identical ``serialize()`` output (determinism contract).

Korean fixture: '테스트_보안패키지' (fictional package name used in
``_has_extra_marker`` / ``_normalize_name`` unit checks — §C-3).
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Import the script under test.  It lives in scripts/ (excluded from the
# installed package) so we add that directory to sys.path transiently.
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"


def _import_gen_sbom() -> object:  # type: ignore[return]  # dynamic import
    added = str(_SCRIPTS_DIR) not in sys.path
    if added:
        sys.path.insert(0, str(_SCRIPTS_DIR))
    try:
        import importlib

        return importlib.import_module("gen_sbom")
    finally:
        if added:
            sys.path.remove(str(_SCRIPTS_DIR))


_gen_sbom = _import_gen_sbom()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build() -> dict:  # type: ignore[type-arg]
    """Call build_sbom() with the repository root explicitly supplied."""
    return _gen_sbom.build_sbom(repo_root=_REPO_ROOT)  # type: ignore[attr-defined]


def _component_names(sbom: dict) -> set[str]:  # type: ignore[type-arg]
    return {c["name"].lower() for c in sbom["components"]}


# ---------------------------------------------------------------------------
# (a) Pollution gate
# ---------------------------------------------------------------------------

# Packages that should never appear in secugent's dependency closure.
# These are common dev / data-science / unrelated packages that are sometimes
# installed in the same Python environment but are not declared in
# pyproject.toml [project.dependencies].
_KNOWN_UNRELATED = {
    "yfinance",
    "discord.py",
    "discordpy",
    "pandas",
    "matplotlib",
    "flask",
    "django",
    "openai",
    "langchain",
    "torch",
    "tensorflow",
    "numpy",
    "scipy",
    "black",  # dev formatter, NOT a runtime dep
    "jupyter",
    "notebook",
    "ipython",
    "coverage",  # dev tool
    "hypothesis",  # dev / test
    "ruff",  # dev linter
    "mypy",  # dev type-checker
    "pytest",  # dev test runner
    "pytest-asyncio",
    "pytest-cov",
    "pytest-timeout",
}


def test_sbom_excludes_known_unrelated_packages() -> None:
    """(a) SBOM must not include dev-venv-only or unrelated packages."""
    sbom = _build()
    names = _component_names(sbom)
    polluted = sorted(_KNOWN_UNRELATED & names)
    assert not polluted, (
        f"SBOM contains {len(polluted)} known-unrelated package(s) — "
        f"gen_sbom.py may still be enumerating all site-packages:\n" + "\n".join(f"  {p}" for p in polluted)
    )


def test_sbom_includes_declared_core_deps() -> None:
    """(a) Closure sanity: known core deps MUST appear in the SBOM."""
    sbom = _build()
    names = _component_names(sbom)
    # These are always in [project.dependencies] and always installed.
    required = {"pydantic", "fastapi", "anthropic", "httpx", "structlog"}
    missing = sorted(required - names)
    assert not missing, (
        "SBOM is missing declared core dep(s) — closure resolver may be broken:\n"
        + "\n".join(f"  {m}" for m in missing)
    )


# ---------------------------------------------------------------------------
# (b) Root component metadata
# ---------------------------------------------------------------------------


def test_sbom_root_version_matches_pyproject() -> None:
    """(b) Root component version must equal pyproject.toml project.version."""
    with (_REPO_ROOT / "pyproject.toml").open("rb") as fh:
        expected_version = tomllib.load(fh)["project"]["version"]

    sbom = _build()
    actual_version = sbom["metadata"]["component"]["version"]
    assert actual_version == expected_version, (
        f"SBOM root version '{actual_version}' != pyproject.toml '{expected_version}'. "
        "gen_sbom._self_version() must read from pyproject.toml, not the installed package."
    )


def test_sbom_root_license_is_apache_spdx() -> None:
    """(b) Root component must carry the correct Apache-2.0 SPDX license expression."""
    sbom = _build()
    component = sbom["metadata"]["component"]
    licenses = component.get("licenses", [])
    assert licenses, "Root component 'licenses' field is missing or empty."
    # Must have at least one license entry with id == "Apache-2.0"
    ids = [lic.get("license", {}).get("id", "") for lic in licenses]
    assert "Apache-2.0" in ids, (
        f"Root component license IDs {ids!r} do not contain 'Apache-2.0'. "
        "Update _SECUGENT_LICENSE_SPDX or metadata_block in build_sbom()."
    )


# ---------------------------------------------------------------------------
# (c) Byte reproducibility
# ---------------------------------------------------------------------------


def test_sbom_is_byte_reproducible() -> None:
    """(c) Two successive build_sbom()+serialize() calls must produce identical bytes.

    This verifies the determinism contract: sorted components, fixed field order,
    no timestamp by default.  A CI reproduction job can diff two runs byte-for-byte.
    """
    run1 = _gen_sbom.serialize(_build())  # type: ignore[attr-defined]
    run2 = _gen_sbom.serialize(_build())  # type: ignore[attr-defined]
    assert run1 == run2, (
        "SBOM is NOT byte-reproducible across two successive calls.\n"
        "Check for: non-sorted components, volatile fields, timestamp leakage."
    )


# ---------------------------------------------------------------------------
# Unit tests for internal helpers (§C-3 Korean fixture)
# ---------------------------------------------------------------------------


def test_normalize_name_korean_lookalike() -> None:
    """_normalize_name must handle unusual characters without crashing.

    Korean fixture: '테스트_보안패키지' contains underscores which
    _normalize_name converts to dashes (PEP 503 canonicalization).
    """
    normalize = _gen_sbom._normalize_name  # type: ignore[attr-defined]
    assert normalize("테스트_보안패키지") == "테스트-보안패키지"
    # Standard cases
    assert normalize("PyYAML") == "pyyaml"
    assert normalize("typing_extensions") == "typing-extensions"
    assert normalize("anthropic") == "anthropic"


def test_has_extra_marker_detection() -> None:
    """_has_extra_marker must correctly identify extra-conditional requirements."""
    detect = _gen_sbom._has_extra_marker  # type: ignore[attr-defined]
    assert detect('httpx ; extra == "dev"')
    assert detect("pytest; extra=='test'")
    assert not detect("pydantic>=2.6")
    assert not detect('httpx ; python_version >= "3.11"')
    assert not detect("anyio")


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("pydantic>=2.6", "pydantic"),
        ("uvicorn[standard]>=0.27", "uvicorn"),
        ("PyYAML>=6.0; python_version>='3.11'", "pyyaml"),
        ("anthropic>=0.40.0", "anthropic"),
        ("prometheus_client>=0.20", "prometheus-client"),
    ],
)
def test_parse_pep508_name(spec: str, expected: str) -> None:
    """_parse_pep508_name must return the bare normalised distribution name."""
    parse = _gen_sbom._parse_pep508_name  # type: ignore[attr-defined]
    normalize = _gen_sbom._normalize_name  # type: ignore[attr-defined]
    assert normalize(parse(spec)) == expected
