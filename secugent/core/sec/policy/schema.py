# SPDX-License-Identifier: Apache-2.0
"""Policy DSL schema (EM-03).

The *authoritative* expression of a policy is this reviewable, signed document —
not LLM output. ``PolicyDoc`` is deny-by-default; rules match against a
normalized :class:`Effect` (EM-01) and a :class:`DataLabel` (EM-02).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secugent.core.sec.effects import EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import TenantId

__all__ = ["Match", "Rule", "PolicyDoc"]


class Match(BaseModel):
    """Conditions a rule matches on. All specified fields must hold (AND)."""

    model_config = ConfigDict(extra="forbid")

    kind: EffectKind | None = None
    # fnmatch against the EM-01 canonical effect.target. NOTE: ``*`` spans ``/``
    # (a glob is NOT segment-anchored), so "c:/data/*" also matches
    # "c:/data/sub/x" — author allow-rules narrowly.
    target_glob: str | None = None
    sink_class: SinkClass | None = None
    min_label: DataLabel | None = None  # rule applies only when label >= min_label


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=64)
    effect: Literal["allow", "deny", "hard_block"]
    match: Match
    rationale: str = Field(..., min_length=1, max_length=1024)  # required for audit/review

    @field_validator("id", "rationale")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        # min_length=1 still admits whitespace-only; id/rationale feed the audit
        # log (audit) and must be meaningful.
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be blank/whitespace-only")
        return stripped


class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(..., min_length=1, max_length=64)
    tenant_id: str  # a valid TenantId, or the literal "_base"
    default: Literal["deny"] = "deny"  # deny-by-default is fixed
    rules: list[Rule] = Field(default_factory=list)

    @field_validator("tenant_id")
    @classmethod
    def _valid_tenant(cls, value: str) -> str:
        if value == "_base":
            return value
        TenantId(value)  # raises ValueError on malformed tenant id
        return value
