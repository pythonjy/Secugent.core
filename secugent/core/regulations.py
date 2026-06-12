# SPDX-License-Identifier: Apache-2.0
"""REGULATIONS schema + loader.

Per SECURITY_CONTRACT §8 the regulations module owns *parsing and schema
validation only*. The matching logic lives in
:mod:`secugent.core.mechanical_oversight` so that the deterministic checks can
be unit-tested without touching disk.

Four rule categories per master prompt PHASE 1:

* :class:`BannedPath`     — glob patterns of forbidden file paths
* :class:`DomainPolicy`   — allow/deny list with subdomain + IP controls
* :class:`BannedCommand`  — regex patterns of forbidden commands
* :class:`DataLabel`      — labelled data classes (confidential/public/...)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secugent.core.contracts import ActionType, RegulationVersion
from secugent.tools.connectors.base import ConnectorPolicy

__all__ = [
    "BannedPath",
    "ConnectorPolicy",
    "DomainPolicy",
    "BannedCommand",
    "DataLabel",
    "Regulations",
    "RegulationsLoadError",
    "load_regulations",
    "load_regulations_from_dict",
]


Severity = Literal["low", "medium", "high", "critical"]


# ---------------------------------------------------------------------------
# Rule models
# ---------------------------------------------------------------------------


class BannedPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=64)
    pattern: str = Field(..., min_length=1, max_length=1024)
    actions: list[ActionType] = Field(default_factory=list)
    severity: Severity = "high"
    hard_block: bool = True
    description: str | None = None

    @field_validator("actions")
    @classmethod
    def _no_unknown(cls, v: list[ActionType]) -> list[ActionType]:
        if "unknown" in v:
            raise ValueError("actions cannot include 'unknown'")
        return v


class DomainPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = "default-domain-policy"
    mode: Literal["allow_list", "deny_list"] = "allow_list"
    domains: list[str] = Field(default_factory=list)
    allow_subdomains: bool = True
    block_ip_literal: bool = True
    block_punycode: bool = True
    hard_block: bool = True
    description: str | None = None

    @field_validator("domains")
    @classmethod
    def _no_empty(cls, v: list[str]) -> list[str]:
        cleaned: list[str] = []
        for d in v:
            d2 = d.strip().rstrip(".").lower()
            if not d2:
                raise ValueError("domain entries cannot be empty")
            cleaned.append(d2)
        return cleaned


class BannedCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=64)
    pattern: str = Field(..., min_length=1, max_length=1024)  # regex
    severity: Severity = "high"
    hard_block: bool = True
    description: str | None = None


class DataLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, max_length=64)
    label: str = Field(..., min_length=1, max_length=64)
    path_patterns: list[str] = Field(default_factory=list)
    allowed_actions: list[ActionType] = Field(default_factory=list)
    severity: Severity = "medium"
    hard_block: bool = False
    description: str | None = None


class Regulations(BaseModel):
    """Root model — exactly what is persisted to ``REGULATIONS.json``."""

    model_config = ConfigDict(extra="forbid")

    version: str = Field(..., min_length=1, max_length=64)
    banned_paths: list[BannedPath] = Field(default_factory=list)
    domain_policy: DomainPolicy | None = None
    banned_commands: list[BannedCommand] = Field(default_factory=list)
    data_labels: list[DataLabel] = Field(default_factory=list)
    # P2 (§A-3 P2-4): per-connector REGULATIONS slice, keyed by connector name.
    # Absent in a legacy document ⇒ empty dict (backward-compatible). The
    # tenant_loader merges these strengthen-only (additive allowlists).
    connector_policies: dict[str, ConnectorPolicy] = Field(default_factory=dict)

    def checksum(self) -> str:
        raw = self.model_dump_json(exclude_none=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def to_version_record(self, source: str) -> RegulationVersion:
        return RegulationVersion(
            version=self.version,
            checksum=self.checksum(),
            source=source,
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class RegulationsLoadError(Exception):
    """Raised on any regulations load/parse/validation failure.

    Per fail-closed rule §2.1, the caller must NOT execute steps when this is
    raised — load failures are treated as a hard block.
    """


def load_regulations(path: str | Path) -> Regulations:
    """Read and validate a REGULATIONS file from disk."""
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegulationsLoadError(f"cannot read regulations file {p}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegulationsLoadError(f"regulations file {p} not valid JSON: {exc}") from exc
    return load_regulations_from_dict(data, source=str(p))


def load_regulations_from_dict(data: Any, *, source: str = "<dict>") -> Regulations:
    if not isinstance(data, dict):
        raise RegulationsLoadError(f"regulations payload must be an object (source={source})")
    try:
        return Regulations.model_validate(data)
    except ValidationError as exc:
        raise RegulationsLoadError(f"regulations schema validation failed: {exc}") from exc
