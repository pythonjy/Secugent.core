# SPDX-License-Identifier: Apache-2.0
"""G-M3 — property-based invariants for the strengthen-only ``data_labels`` merge.

Mandatory testable invariant on TWO unambiguous axes (spec §3.2):

    for every rule_id r present in base:
        merged[r].severity_rank >= base[r].severity_rank      (no downgrade)
        base[r].hard_block ⇒ merged[r].hard_block             (no hard_block removal)

and: any relaxation input → always raises :class:`RegulationsSchemaError`.

The ``allowed_actions`` subset guard is also a strengthen direction (a wider
allowlist is more permissive — see ``mechanical_oversight._match_data_label``),
exercised here as part of the relaxation-always-raises property.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import ActionType
from secugent.core.regulations import DataLabel, Severity
from secugent.regulations.tenant_loader import (
    _SEVERITY_RANK,
    RegulationsLoader,
    RegulationsSchemaError,
)

_SEVERITIES: list[Severity] = ["low", "medium", "high", "critical"]
_ACTIONS: list[ActionType] = ["file_read", "file_write", "http_get", "connector_action"]


def _label(
    rule_id: str,
    severity: Severity,
    hard_block: bool,
    allowed_actions: list[ActionType],
) -> DataLabel:
    return DataLabel(
        rule_id=rule_id,
        label="lbl",
        path_patterns=["*/x/*"],
        allowed_actions=allowed_actions,
        severity=severity,
        hard_block=hard_block,
    )


_label_strategy = st.builds(
    _label,
    rule_id=st.sampled_from(["r0", "r1", "r2"]),
    severity=st.sampled_from(_SEVERITIES),
    hard_block=st.booleans(),
    allowed_actions=st.lists(st.sampled_from(_ACTIONS), max_size=4, unique=True),
)


def _dedup_by_rule_id(labels: list[DataLabel]) -> list[DataLabel]:
    seen: dict[str, DataLabel] = {}
    for lbl in labels:
        seen[lbl.rule_id] = lbl
    return list(seen.values())


# --------------------------------------------------------------------------- #
# Invariant: a STRENGTHENED override always succeeds and preserves the 2 axes.
# --------------------------------------------------------------------------- #


@given(base=st.lists(_label_strategy, max_size=3))
@settings(max_examples=200)
def test_self_merge_is_identity_on_axes(base: list[DataLabel]) -> None:
    base = _dedup_by_rule_id(base)
    merged = RegulationsLoader._merge_data_labels(base, base)
    by_id = {m.rule_id: m for m in merged}
    for b in base:
        m = by_id[b.rule_id]
        assert _SEVERITY_RANK[m.severity] >= _SEVERITY_RANK[b.severity]
        assert (not b.hard_block) or m.hard_block


@given(base=st.lists(_label_strategy, max_size=3), data=st.data())
@settings(max_examples=300)
def test_strengthening_preserves_axes(base: list[DataLabel], data: st.DataObject) -> None:
    base = _dedup_by_rule_id(base)
    override: list[DataLabel] = []
    for b in base:
        # Strengthen: severity >= base, hard_block kept-or-added, allowed_actions
        # a subset of base's (or empty when base is empty).
        hi = data.draw(
            st.sampled_from([s for s in _SEVERITIES if _SEVERITY_RANK[s] >= _SEVERITY_RANK[b.severity]])
        )
        hb = data.draw(st.booleans()) or b.hard_block
        if b.allowed_actions:
            subset = data.draw(
                st.lists(st.sampled_from(b.allowed_actions), max_size=len(b.allowed_actions), unique=True)
            )
        else:
            subset = []
        override.append(_label(b.rule_id, hi, hb, subset))

    merged = RegulationsLoader._merge_data_labels(base, override)
    by_id = {m.rule_id: m for m in merged}
    for b in base:
        m = by_id[b.rule_id]
        assert _SEVERITY_RANK[m.severity] >= _SEVERITY_RANK[b.severity]
        assert (not b.hard_block) or m.hard_block


# --------------------------------------------------------------------------- #
# Invariant: relaxation on ANY axis always raises.
# --------------------------------------------------------------------------- #


@given(
    severity=st.sampled_from(["medium", "high", "critical"]),
    lower=st.sampled_from(_SEVERITIES),
)
@settings(max_examples=200)
def test_severity_downgrade_always_raises(severity: Severity, lower: Severity) -> None:
    if _SEVERITY_RANK[lower] >= _SEVERITY_RANK[severity]:
        return  # not a downgrade
    base = [_label("r", severity, hard_block=False, allowed_actions=[])]
    override = [_label("r", lower, hard_block=False, allowed_actions=[])]
    with pytest.raises(RegulationsSchemaError):
        RegulationsLoader._merge_data_labels(base, override)


@given(severity=st.sampled_from(_SEVERITIES))
@settings(max_examples=100)
def test_hard_block_removal_always_raises(severity: Severity) -> None:
    base = [_label("r", severity, hard_block=True, allowed_actions=[])]
    override = [_label("r", severity, hard_block=False, allowed_actions=[])]
    with pytest.raises(RegulationsSchemaError):
        RegulationsLoader._merge_data_labels(base, override)


@given(
    base_actions=st.lists(st.sampled_from(_ACTIONS), min_size=1, max_size=3, unique=True),
    extra=st.sampled_from(_ACTIONS),
)
@settings(max_examples=200)
def test_allowed_actions_widening_always_raises(base_actions: list[ActionType], extra: ActionType) -> None:
    if extra in base_actions:
        return  # not a widening
    base = [_label("r", "high", hard_block=True, allowed_actions=base_actions)]
    override = [_label("r", "high", hard_block=True, allowed_actions=[*base_actions, extra])]
    with pytest.raises(RegulationsSchemaError):
        RegulationsLoader._merge_data_labels(base, override)


# --------------------------------------------------------------------------- #
# Invariant: path_patterns must be a SUPERSET for shared rule_ids.
#
# SG-20260606-01: ``_match_data_label`` raises only when a pattern matches, so
# MORE patterns ⇒ MORE protection. Removing any pattern always raises; a
# superset (or equal set) always passes and never drops a base pattern.
# --------------------------------------------------------------------------- #

_PATTERNS: list[str] = ["*/p0/*", "*/p1/*", "*/p2/*", "*/p3/*"]


def _label_paths(rule_id: str, path_patterns: list[str]) -> DataLabel:
    return DataLabel(
        rule_id=rule_id,
        label="lbl",
        path_patterns=path_patterns,
        allowed_actions=[],
        severity="high",
        hard_block=True,
    )


@given(
    base_paths=st.lists(st.sampled_from(_PATTERNS), min_size=1, max_size=4, unique=True),
    override_paths=st.lists(st.sampled_from(_PATTERNS), max_size=4, unique=True),
)
@settings(max_examples=400)
def test_path_patterns_non_superset_always_raises(base_paths: list[str], override_paths: list[str]) -> None:
    base = [_label_paths("r", base_paths)]
    override = [_label_paths("r", override_paths)]
    if set(override_paths) >= set(base_paths):
        # superset (or equal) ⇒ accepted AND no base pattern is dropped.
        merged = RegulationsLoader._merge_data_labels(base, override)
        assert set(merged[0].path_patterns) >= set(base_paths)
    else:
        with pytest.raises(RegulationsSchemaError):
            RegulationsLoader._merge_data_labels(base, override)


@given(
    base=st.lists(_label_strategy, max_size=3),
    extra=st.sampled_from(_PATTERNS),
)
@settings(max_examples=200)
def test_path_patterns_superset_preserved_for_shared_ids(base: list[DataLabel], extra: str) -> None:
    base = _dedup_by_rule_id(base)
    # Build a strengthening override that keeps every base pattern plus one more
    # (superset) while leaving the other axes identical (no relaxation).
    override = [
        DataLabel(
            rule_id=b.rule_id,
            label=b.label,
            path_patterns=[*b.path_patterns, extra],  # superset
            allowed_actions=b.allowed_actions,
            severity=b.severity,
            hard_block=b.hard_block,
        )
        for b in base
    ]
    merged = RegulationsLoader._merge_data_labels(base, override)
    by_id = {m.rule_id: m for m in merged}
    for b in base:
        assert set(by_id[b.rule_id].path_patterns) >= set(b.path_patterns)
