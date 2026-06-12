# SPDX-License-Identifier: Apache-2.0
"""Generate a deterministic CycloneDX 1.5 JSON SBOM (BDP Phase 1 item 2).

Why: an SBOM ("of what is this built?") is a baseline trust requirement for a
security product — it lets an external party fix dependency versions and audit
the supply chain. We emit it from the *installed* distributions via
``importlib.metadata`` (pure stdlib + ``json``); no heavy SBOM library is added
(BDP non-scope: "DO NOT add a heavy new dependency").

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
from collections.abc import Iterable
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"


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
    # ``get_all`` is the email.message-backed accessor in the typeshed stub and
    # returns ``None`` (not an implicit-None KeyError) for an absent header.
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


def _iter_distributions() -> Iterable[metadata.Distribution]:
    return metadata.distributions()


def build_sbom(*, include_timestamp: bool = False) -> dict[str, Any]:
    """Build the CycloneDX 1.5 document as a plain dict (deterministic ordering)."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for dist in _iter_distributions():
        component = _component(dist)
        # De-duplicate by (name, version): editable/namespace installs can surface
        # the same distribution twice; a stable key keeps the output reproducible.
        seen[(component["name"].lower(), component["version"])] = component

    components = [seen[key] for key in sorted(seen)]

    metadata_block: dict[str, Any] = {
        "component": {
            "type": "application",
            "name": "secugent",
            "version": _self_version(),
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


def _self_version() -> str:
    try:
        return metadata.version("secugent")
    except metadata.PackageNotFoundError:
        return "0.0.0+local"


def serialize(sbom: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, compact-but-readable, trailing newline."""
    return json.dumps(sbom, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gen_sbom",
        description="Generate a deterministic CycloneDX 1.5 SBOM from installed deps.",
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
