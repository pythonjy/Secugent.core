# SPDX-License-Identifier: Apache-2.0
"""Property-based invariants for the Rule of Two engine (deterministic, §B-4a).

The action_type × context flag space is small but the invariants are sharp:

  * **HITL equivalence (I-4)**: ``len(classify_axes(x)) >= 3 ⟺ requires_hitl(...)``.
  * **determinism (I-1)**: equal inputs always yield an equal frozenset.
  * **purity (I-2)**: classification never mutates the input Step.
  * **audit stability (I-3)**: ``axes_to_audit`` is sorted, deduped, value-only.
  * **bounded cardinality**: at most 3 axes ever (there are exactly 3 axes).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import ActionType, Step
from secugent.core.rule_of_two import (
    Axis,
    RuleOfTwoContext,
    axes_to_audit,
    classify_axes,
    requires_hitl,
)
from secugent.core.tenancy import TenantId

_ACTION_TYPES: list[ActionType] = [
    "file_read",
    "file_write",
    "http_get",
    "desktop",
    "compute",
    "connector_action",
    "unknown",
]


def _step(action_type: ActionType, target: str | None) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type=action_type,
        target=target,
    )


_contexts = st.builds(
    RuleOfTwoContext,
    untrusted_input=st.booleans(),
    sensitive=st.booleans(),
    declares_external_comm=st.booleans(),
)
_steps = st.builds(
    _step,
    action_type=st.sampled_from(_ACTION_TYPES),
    target=st.one_of(st.none(), st.text(max_size=24)),
)


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_hitl_iff_three_axes(step: Step, ctx: RuleOfTwoContext) -> None:
    axes = classify_axes(step, ctx)
    assert requires_hitl(axes) == (len(axes) >= 3)


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_classification_is_deterministic(step: Step, ctx: RuleOfTwoContext) -> None:
    assert classify_axes(step, ctx) == classify_axes(step, ctx)


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_at_most_three_axes(step: Step, ctx: RuleOfTwoContext) -> None:
    axes = classify_axes(step, ctx)
    assert len(axes) <= 3
    assert axes <= frozenset(Axis)


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_classification_does_not_mutate_step(step: Step, ctx: RuleOfTwoContext) -> None:
    before = step.model_dump()
    classify_axes(step, ctx)
    assert step.model_dump() == before


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_audit_is_sorted_value_only(step: Step, ctx: RuleOfTwoContext) -> None:
    axes = classify_axes(step, ctx)
    audit = axes_to_audit(axes)
    assert audit == sorted(audit)
    assert len(audit) == len(set(audit))
    assert set(audit) == {a.value for a in axes}


@settings(max_examples=400)
@given(step=_steps, ctx=_contexts)
def test_explicit_flags_are_monotone(step: Step, ctx: RuleOfTwoContext) -> None:
    # Turning every flag ON can only ADD axes (never remove) — the context flags
    # are purely additive overlays on the action-type baseline.
    base = classify_axes(step, ctx)
    forced = classify_axes(
        step,
        RuleOfTwoContext(
            untrusted_input=ctx.untrusted_input or True,
            sensitive=ctx.sensitive or True,
            declares_external_comm=ctx.declares_external_comm or True,
        ),
    )
    assert base <= forced
