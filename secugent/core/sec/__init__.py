# SPDX-License-Identifier: Apache-2.0
"""Deterministic Effect Mediation core (``secugent.core.sec``).

Pure, side-effect-free primitives shared by every EM unit.
"""

from __future__ import annotations

from secugent.core.sec.canonicalize import (
    AmbiguousEffectError,
    canonicalize_command,
    canonicalize_path,
    canonicalize_url,
)
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.label_store import InMemoryLabelStore, LabelStore
from secugent.core.sec.labels import (
    DEFAULT_LABEL_MAP,
    DataLabel,
    LabelDecision,
    LabelMappingError,
    may_egress,
    merge,
    resolve_label,
    validate_label_keys,
)
from secugent.core.sec.reversibility import (
    ActionManifest,
    ManifestRegistry,
    ReversibilityClass,
)
from secugent.core.sec.taint import (
    AuditSink,
    LabelDowngradeError,
    TaintContext,
    downgrade,
)

__all__ = [
    # canonicalize
    "AmbiguousEffectError",
    "canonicalize_path",
    "canonicalize_url",
    "canonicalize_command",
    # effects
    "Effect",
    "EffectKind",
    "SinkClass",
    # reversibility
    "ReversibilityClass",
    "ActionManifest",
    "ManifestRegistry",
    # labels (EM-02)
    "DataLabel",
    "merge",
    "LabelDecision",
    "may_egress",
    "LabelMappingError",
    "DEFAULT_LABEL_MAP",
    "resolve_label",
    "validate_label_keys",
    "LabelStore",
    "InMemoryLabelStore",
    "TaintContext",
    "AuditSink",
    "LabelDowngradeError",
    "downgrade",
]
