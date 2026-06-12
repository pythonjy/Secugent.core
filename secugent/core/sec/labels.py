# SPDX-License-Identifier: Apache-2.0
"""Information-flow label lattice + egress decision (EM-02).

A coarse, totally-ordered classification lattice (``PUBLIC < INTERNAL_USE <
CONFIDENTIAL < SECRET``) lets the system express *context* — data sensitivity ×
destination — as a **deterministic** rule ("anything above ``max_external`` may
not leave through an EXTERNAL sink") rather than a probabilistic judgement.

This ``DataLabel`` (the egress lattice) is deliberately **distinct** from
:class:`secugent.core.regulations.DataLabel` (the mechanical-oversight
classification model). They are complementary, not a replacement: this module
governs egress; ``regulations.DataLabel`` governs path/action oversight. To keep
that separation clean, this module does **not** import ``regulations`` — the
key↔lattice mapping validators below operate on plain strings.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

from secugent.core.sec.effects import SinkClass

__all__ = [
    "DataLabel",
    "merge",
    "LabelDecision",
    "may_egress",
    "LabelMappingError",
    "DEFAULT_LABEL_MAP",
    "resolve_label",
    "validate_label_keys",
]


class DataLabel(IntEnum):
    """Total-order classification lattice; integer comparison is deterministic."""

    PUBLIC = 0
    INTERNAL_USE = 1
    CONFIDENTIAL = 2
    SECRET = 3


def _coerce(label: DataLabel) -> DataLabel:
    """Coerce/validate to a real lattice member; out-of-lattice ⇒ ValueError.

    Defense-in-depth: a future persistent ``LabelStore`` backend may hand back a
    bare ``int`` — never let an out-of-lattice value flow through a decision.
    """
    return DataLabel(int(label))


def merge(*labels: DataLabel) -> DataLabel:
    """Least upper bound (max) of ``labels`` — conservative. Empty ⇒ PUBLIC."""
    return max((_coerce(label) for label in labels), default=DataLabel.PUBLIC)


@dataclass(frozen=True, slots=True)
class LabelDecision:
    """Deterministic egress verdict with an auditable reason (no score)."""

    allow: bool
    reason: str
    label: DataLabel
    sink_class: SinkClass


def may_egress(label: DataLabel, sink: SinkClass, *, max_external: DataLabel) -> LabelDecision:
    """Decide whether ``label`` may leave through ``sink``.

    Only EXTERNAL sinks are gated by the lattice: a label exceeding
    ``max_external`` is denied (``max_external`` is the inclusive ceiling — a
    label *equal* to it may egress). INTERNAL / LOCAL_SANDBOX sinks are not
    external egress and are allowed here (other gates still apply upstream).
    """
    label = _coerce(label)
    max_external = _coerce(max_external)
    if sink is not SinkClass.EXTERNAL:
        return LabelDecision(allow=True, reason="sink_not_external", label=label, sink_class=sink)
    if label > max_external:
        return LabelDecision(allow=False, reason="label_exceeds_external_sink", label=label, sink_class=sink)
    return LabelDecision(allow=True, reason="label_within_external_max", label=label, sink_class=sink)


# --------------------------------------------------------------------------- #
# REGULATIONS classification key ↔ lattice mapping (string-only; no regulations import)
# --------------------------------------------------------------------------- #


class LabelMappingError(Exception):
    """Raised when a REGULATIONS classification key has no lattice mapping."""


DEFAULT_LABEL_MAP: dict[str, DataLabel] = {
    # English
    "public": DataLabel.PUBLIC,
    "internal": DataLabel.INTERNAL_USE,
    "internal_use": DataLabel.INTERNAL_USE,
    "confidential": DataLabel.CONFIDENTIAL,
    "secret": DataLabel.SECRET,
    # Korean (한국 엔터프라이즈 분류 체계)
    "공개": DataLabel.PUBLIC,
    "대내": DataLabel.INTERNAL_USE,
    "내부": DataLabel.INTERNAL_USE,
    "대외비": DataLabel.CONFIDENTIAL,
    "기밀": DataLabel.SECRET,
}


def _normalize_key(label: str) -> str:
    """NFC-normalize + strip + lower so NFD-decomposed input (e.g. some macOS
    sources) resolves identically to the NFC map keys."""
    return unicodedata.normalize("NFC", label.strip()).lower()


def resolve_label(label: str, *, mapping: dict[str, DataLabel] = DEFAULT_LABEL_MAP) -> DataLabel:
    """Map a REGULATIONS classification key to a lattice level (case-insensitive)."""
    try:
        return mapping[_normalize_key(label)]
    except KeyError as exc:
        raise LabelMappingError(f"unmapped classification key: {label!r}") from exc


def validate_label_keys(labels: Iterable[str], *, mapping: dict[str, DataLabel] = DEFAULT_LABEL_MAP) -> None:
    """Raise :class:`LabelMappingError` if any key lacks a lattice mapping.

    Intended for boot-time verification that a tenant's REGULATIONS classification
    keys line up 1:1 with the lattice (fail-closed → boot refused on mismatch).
    """
    unknown = sorted({lbl for lbl in labels if _normalize_key(lbl) not in mapping})
    if unknown:
        raise LabelMappingError(f"unmapped classification keys: {unknown}")
