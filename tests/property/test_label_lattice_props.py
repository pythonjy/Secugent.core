# SPDX-License-Identifier: Apache-2.0
"""EM-02 — Hypothesis property tests for the DataLabel lattice laws."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from secugent.core.sec.effects import SinkClass
from secugent.core.sec.labels import DataLabel, may_egress, merge

_LABELS = st.sampled_from(list(DataLabel))


@given(a=_LABELS, b=_LABELS)
def test_merge_commutative(a: DataLabel, b: DataLabel) -> None:
    assert merge(a, b) is merge(b, a)


@given(a=_LABELS, b=_LABELS, c=_LABELS)
def test_merge_associative(a: DataLabel, b: DataLabel, c: DataLabel) -> None:
    assert merge(merge(a, b), c) is merge(a, merge(b, c))


@given(a=_LABELS)
def test_merge_idempotent(a: DataLabel) -> None:
    assert merge(a, a) is a


@given(a=_LABELS)
def test_public_is_identity(a: DataLabel) -> None:
    assert merge(a, DataLabel.PUBLIC) is a


@given(a=_LABELS, b=_LABELS)
def test_merge_never_below_inputs(a: DataLabel, b: DataLabel) -> None:
    m = merge(a, b)
    assert m >= a and m >= b


@given(label=_LABELS, max_external=_LABELS)
def test_egress_monotonic_in_label(label: DataLabel, max_external: DataLabel) -> None:
    # External egress is allowed iff the label does not exceed max_external —
    # a higher label is never more permissive.
    decision = may_egress(label, SinkClass.EXTERNAL, max_external=max_external)
    assert decision.allow is (label <= max_external)
