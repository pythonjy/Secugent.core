# SPDX-License-Identifier: Apache-2.0
"""Generate a deterministic CycloneDX 1.5 JSON SBOM (BDP Phase 1 item 2).

Why: an SBOM ("of what is this built?") is a baseline trust requirement for a
security product — it lets an external party fix dependency versions and audit
the supply chain. We emit it from the *installed* distributions via
``importlib.metadata`` (pure stdlib + ``json``); no heavy SBOM library is added
(BDP non-scope: "DO NOT add a heavy new dependency").

**DA-H7 fix**: The previous implementation enumerated ALL installed distributions
in the active virtual environment, causing SBOM pollution with ~16+ unrelated
packages (yfinance, discord, etc.) that are not part of secugent's dependency
closure.  The fixed implementation resolves the *transitive closure* of the
dependencies declared in ``pyproject.toml`` via ``importlib.metadata``
``Requires-Dist``, not the whole site-packages.  Extra-specific requirements
(``; extra == "dev"`` etc.) are intentionally excluded — optional extras vary by
deployment and are tracked separately.

Determinism (so a CI reproduction job can diff two runs byte-for-byte): components
are sorted by ``(name, version)``, the field order within each object is fixed,
and the only volatile field (``metadata.timestamp``) is **omitted by default**.
Pass ``--timestamp`` to include a wall-clock timestamp when you explicitly want a
dated artifact (it then stops being byte-reproducible, by design).

Usage::

    python scripts/gen_sbom.py                 # -> sbom.json (deterministic)
    python scripts/gen_sbom.py --output o.json # custom path
    python scripts/gen_sbom.py --timestamp     # include a (non-deterministic) timestamp
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"

# SPDX expression for the secugent public-core package (Apache-2.0 open-core,
# matching the LICENSE file at the repository root).
_SECUGENT_LICENSE_SPDX = "Apache-2.0"

# Version specifier operators — used to strip the version part from a PEP 508
# requirement specifier when extracting the distribution name.
_VERSION_OPS = (">=", "<=", "!=", "==", "~=", ">", "<")


# ---------------------------------------------------------------------------
# PEP 508 / PEP 503 helpers
# ---------------------------------------------------------------------------


def _parse_pep508_name(spec: str) -> str:
    """Extract the bare distribution name from a PEP 508 requirement string.

    Strips environment markers (``; python_version >= "3.11"``), extras
    (``uvicorn[standard]``), and version specifiers (``>=0.27``).
    """
    # Drop environment markers
    spec = spec.split(";")[0].strip()
    # Drop extras bracket
    spec = spec.split("[")[0].strip()
    # Drop version specifiers
    for op in _VERSION_OPS:
        spec = spec.split(op)[0].strip()
    return spec.strip()


def _normalize_name(name: str) -> str:
    """PEP 503 canonical distribution name (lower-case, runs of [-_.] → -)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _has_extra_marker(req_str: str) -> bool:
    """Return True if *req_str* is conditional on a specific extra being selected.

    We intentionally skip extra-specific requirements when building the core
    closure — they are optional deployment-time dependencies that vary per
    installation (dev, pg, vault, aws, obs, …).
    """
    marker_part = req_str.split(";")[-1] if ";" in req_str else ""
    return "extra ==" in marker_part or "extra==" in marker_part


# ---------------------------------------------------------------------------
# Transitive closure resolver
# ---------------------------------------------------------------------------


def _load_pyproject_deps(repo_root: Path) -> list[str]:
    """Return the raw PEP 508 specifier strings from ``[project.dependencies]``."""
    with (repo_root / "pyproject.toml").open("rb") as fh:
        data = tomllib.load(fh)
    deps: list[str] = data["project"]["dependencies"]
    return deps


def _resolve_dep_closure(
    root_specs: list[str],
    *,
    installed: dict[str, metadata.Distribution] | None = None,
) -> set[str]:
    """BFS transitive closure of PEP 503-normalised distribution names.

    Starting from the names in *root_specs* (PEP 508 strings from
    ``pyproject.toml``), follows each distribution's ``Requires-Dist``
    recursively, skipping:

    * Requirements that carry an ``extra ==`` marker (optional extras).
    * Distributions not present in the current Python environment (silently
      skipped — optional extras may be absent on a slim install).

    Returns a ``set[str]`` of PEP 503 normalised names (lower-case, dashes).
    """
    if installed is None:
        installed = {_normalize_name(d.metadata["Name"] or ""): d for d in metadata.distributions()}

    todo: set[str] = set()
    for spec in root_specs:
        todo.add(_normalize_name(_parse_pep508_name(spec)))

    closed: set[str] = set()
    while todo:
        name = todo.pop()
        if name in closed:
            continue
        closed.add(name)
        dist = installed.get(name)
        if dist is None:
            continue  # not installed in this environment (optional extra dep)
        for req_str in dist.metadata.get_all("Requires-Dist") or []:
            if _has_extra_marker(req_str):
                continue  # skip optional-extra deps
            req_name = _normalize_name(_parse_pep508_name(req_str))
            if req_name not in closed:
                todo.add(req_name)

    return closed


# ---------------------------------------------------------------------------
# SBOM component builders
# ---------------------------------------------------------------------------


def _purl(name: str, version: str) -> str:
    """Package URL (purl) for a PyPI distribution (spec: pkg:pypi/name@version)."""
    return f"pkg:pypi/{name.lower()}@{version}"


def _license_entries(dist: metadata.Distribution) -> list[dict[str, Any]]:
    """Best-effort license extraction from distribution metadata.

    Reads the ``License`` field then any ``Classifier: License :: ...`` lines.
    Returns CycloneDX ``licenses`` entries (``{"license": {"name": ...}}``);
    empty when nothing is declared (we never fabricate a license).
    """
    meta = dist.metadata
    names: list[str] = []
    for declared in meta.get_all("License") or []:
        cleaned = declared.strip()
        if cleaned and cleaned.upper() != "UNKNOWN" and cleaned not in names:
            names.append(cleaned)
    for classifier in meta.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            tail = classifier.split("::")[-1].strip()
            if tail and tail not in names:
                names.append(tail)
    return [{"license": {"name": name}} for name in sorted(set(names))]


def _component(dist: metadata.Distribution) -> dict[str, Any]:
    """One CycloneDX ``component`` object with a fixed, stable field order."""
    names = dist.metadata.get_all("Name") or []
    name = names[0] if names else "unknown"
    version = dist.version or "0"
    component: dict[str, Any] = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": _purl(name, version),
    }
    licenses = _license_entries(dist)
    if licenses:
        component["licenses"] = licenses
    return component


def _iter_closure_distributions(
    closure: set[str],
    installed: dict[str, metadata.Distribution],
) -> Iterable[metadata.Distribution]:
    """Yield distributions whose normalised name is in *closure*."""
    for norm_name in closure:
        dist = installed.get(norm_name)
        if dist is not None:
            yield dist


# ---------------------------------------------------------------------------
# Version / license for the root component (secugent itself)
# ---------------------------------------------------------------------------


def _self_version(repo_root: Path) -> str:
    """Read the version directly from ``pyproject.toml``.

    This is intentionally NOT ``importlib.metadata.version("secugent")``
    because that call returns the *installed* package version, which may be
    stale (``0.0.0+local`` on an editable install built from an older wheel, or
    ``0.0.1`` from a previous release on PyPI) and does NOT reflect the version
    declared in the source tree.  Reading ``pyproject.toml`` always returns the
    authoritative in-tree version (DA-H7 fix).
    """
    with (repo_root / "pyproject.toml").open("rb") as fh:
        data = tomllib.load(fh)
    return str(data["project"]["version"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_sbom(
    *,
    include_timestamp: bool = False,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Build the CycloneDX 1.5 document as a plain dict (deterministic ordering).

    *repo_root* defaults to the repository root (two directories above this
    script).  Pass an explicit path in tests so the function does not depend on
    filesystem layout at import time.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]

    # Build a lookup table of all installed distributions once.
    installed: dict[str, metadata.Distribution] = {
        _normalize_name(d.metadata["Name"] or ""): d for d in metadata.distributions()
    }

    root_specs = _load_pyproject_deps(repo_root)
    closure = _resolve_dep_closure(root_specs, installed=installed)

    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for dist in _iter_closure_distributions(closure, installed):
        component = _component(dist)
        # De-duplicate by (name, version): editable/namespace installs can
        # surface the same distribution twice; a stable key keeps output
        # reproducible.
        seen[(component["name"].lower(), component["version"])] = component

    components = [seen[key] for key in sorted(seen)]

    root_version = _self_version(repo_root)
    metadata_block: dict[str, Any] = {
        "component": {
            "type": "application",
            "name": "secugent",
            "version": root_version,
            "licenses": [{"license": {"id": _SECUGENT_LICENSE_SPDX}}],
        }
    }
    if include_timestamp:
        metadata_block["timestamp"] = datetime.now(tz=UTC).isoformat()

    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": metadata_block,
        "components": components,
    }


def serialize(sbom: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, compact-but-readable, trailing newline."""
    return json.dumps(sbom, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gen_sbom",
        description="Generate a deterministic CycloneDX 1.5 SBOM from the project dep closure.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("sbom.json"),
        help="output path (default: sbom.json)",
    )
    parser.add_argument(
        "--timestamp",
        action="store_true",
        help="include a wall-clock timestamp (makes the artifact non-reproducible)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    sbom = build_sbom(include_timestamp=args.timestamp)
    payload = serialize(sbom)
    args.output.write_text(payload, encoding="utf-8")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    print(f"wrote {len(sbom['components'])} components to {args.output} (sha256 {digest[:16]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
