# SPDX-License-Identifier: Apache-2.0
"""Rule of Two 3-axis isolation engine — unit tests (deterministic, §B-4a).

Exhaustive 0/1/2/3-axis combinations + boundary. The classifier is a PURE
function of (Step, RuleOfTwoContext); these tests pin the axis derivation table
and the HITL boundary at exactly 3 axes (§A-2 architecture principle 1).
"""

from __future__ import annotations

import pytest

from secugent.core.contracts import ActionType, Step
from secugent.core.rule_of_two import (
    Axis,
    RuleOfTwoContext,
    axes_to_audit,
    classify_axes,
    requires_hitl,
)
from secugent.core.tenancy import TenantId


def _step(
    action_type: ActionType, *, target: str | None = None, context: dict[str, object] | None = None
) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type=action_type,
        target=target,
        context=context or {},
    )


# --------------------------------------------------------------------------- #
# Axis enum string values — must match §C-2 audit schema exactly.
# --------------------------------------------------------------------------- #


def test_axis_string_values_match_audit_schema() -> None:
    assert Axis.UNTRUSTED_INPUT.value == "untrusted_input"
    assert Axis.SENSITIVE_ACCESS.value == "sensitive_access"
    assert Axis.EXTERNAL_COMM.value == "external_comm"


def test_axis_is_str() -> None:
    # StrEnum members are usable as plain strings (audit payloads are JSON).
    assert Axis.EXTERNAL_COMM == "external_comm"
    assert sorted([Axis.EXTERNAL_COMM, Axis.UNTRUSTED_INPUT]) == [
        "external_comm",
        "untrusted_input",
    ]


# --------------------------------------------------------------------------- #
# 0-axis: read-only compute with no flags ⇒ no axes.
# --------------------------------------------------------------------------- #


def test_compute_no_context_zero_axes() -> None:
    axes = classify_axes(_step("compute"))
    assert axes == frozenset()
    assert requires_hitl(axes) is False
    assert axes_to_audit(axes) == []


def test_http_get_alone_is_only_external_comm() -> None:
    # http_get is egress (axis ③) but NOT sensitive-access by itself.
    axes = classify_axes(_step("http_get", target="https://example.com/a"))
    assert axes == frozenset({Axis.EXTERNAL_COMM})


# --------------------------------------------------------------------------- #
# 1-axis combinations.
# --------------------------------------------------------------------------- #


def test_file_read_is_sensitive_access_only() -> None:
    # file_read touches a sensitive system surface but is not state-changing.
    axes = classify_axes(_step("file_read", target="C:/data/x"))
    assert axes == frozenset({Axis.SENSITIVE_ACCESS})
    assert requires_hitl(axes) is False


def test_untrusted_only_via_context() -> None:
    axes = classify_axes(_step("compute"), RuleOfTwoContext(untrusted_input=True))
    assert axes == frozenset({Axis.UNTRUSTED_INPUT})


# --------------------------------------------------------------------------- #
# 2-axis combinations — Rule of Two NOT violated (no HITL forced by axes).
# --------------------------------------------------------------------------- #


def test_file_write_is_sensitive_and_external() -> None:
    # file_write is both sensitive-access (②) AND state-changing (③) but only 2 axes.
    axes = classify_axes(_step("file_write", target="C:/data/out"))
    assert axes == frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})
    assert requires_hitl(axes) is False


def test_connector_action_is_sensitive_and_external() -> None:
    # connector_action generalizes the legacy single-axis carve-out: it is both
    # axis ② (touches a connected system) and axis ③ (external comm) — 2 axes.
    axes = classify_axes(_step("connector_action", target="kakaowork.post_message"))
    assert axes == frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})
    assert requires_hitl(axes) is False


def test_http_get_plus_untrusted_is_two_axes() -> None:
    axes = classify_axes(
        _step("http_get", target="https://example.com"),
        RuleOfTwoContext(untrusted_input=True),
    )
    assert axes == frozenset({Axis.UNTRUSTED_INPUT, Axis.EXTERNAL_COMM})
    assert requires_hitl(axes) is False


# --------------------------------------------------------------------------- #
# 3-axis — Rule of Two VIOLATED ⇒ HITL forced.
# --------------------------------------------------------------------------- #


def test_three_axes_force_hitl() -> None:
    axes = classify_axes(
        _step("connector_action", target="kakaowork.post_message"),
        RuleOfTwoContext(untrusted_input=True),
    )
    assert axes == frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})
    assert requires_hitl(axes) is True
    assert axes_to_audit(axes) == [
        "external_comm",
        "sensitive_access",
        "untrusted_input",
    ]


def test_file_write_plus_untrusted_forces_hitl() -> None:
    # untrusted source + sensitive file write (which is also egress) ⇒ all 3 axes.
    axes = classify_axes(
        _step("file_write", target="C:/data/out"),
        RuleOfTwoContext(untrusted_input=True),
    )
    assert requires_hitl(axes) is True


def test_explicit_flags_can_force_three_axes_on_compute() -> None:
    # A pure-compute step can still trip all three axes via explicit declarations.
    axes = classify_axes(
        _step("compute"),
        RuleOfTwoContext(untrusted_input=True, sensitive=True, declares_external_comm=True),
    )
    assert requires_hitl(axes) is True


# --------------------------------------------------------------------------- #
# requires_hitl boundary — exactly at 3.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("axes", "expected"),
    [
        (frozenset(), False),
        (frozenset({Axis.UNTRUSTED_INPUT}), False),
        (frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM}), False),
        (
            frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM}),
            True,
        ),
    ],
)
def test_requires_hitl_boundary(axes: frozenset[Axis], expected: bool) -> None:
    assert requires_hitl(axes) is expected


# --------------------------------------------------------------------------- #
# Context plumbing.
# --------------------------------------------------------------------------- #


def test_context_none_equals_all_false() -> None:
    step = _step("file_read", target="C:/x")
    assert classify_axes(step) == classify_axes(step, None)
    assert classify_axes(step, RuleOfTwoContext()) == classify_axes(step, None)


def test_sensitive_flag_adds_axis_to_http_get() -> None:
    # http_get is normally only external_comm; an explicit sensitive label adds ②.
    axes = classify_axes(
        _step("http_get", target="https://example.com"),
        RuleOfTwoContext(sensitive=True),
    )
    assert axes == frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})


def test_declares_external_comm_adds_axis_to_file_read() -> None:
    # file_read is normally only sensitive-access; explicit egress declaration adds ③.
    axes = classify_axes(
        _step("file_read", target="C:/x"),
        RuleOfTwoContext(declares_external_comm=True),
    )
    assert axes == frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})


# --------------------------------------------------------------------------- #
# RuleOfTwoContext.from_step — deny-by-default extraction from Step.context.
# --------------------------------------------------------------------------- #


def test_from_step_extracts_nested_rule_of_two_block() -> None:
    step = _step(
        "compute",
        context={
            "rule_of_two": {
                "untrusted_input": True,
                "sensitive": True,
                "declares_external_comm": True,
            }
        },
    )
    ctx = RuleOfTwoContext.from_step(step)
    assert ctx == RuleOfTwoContext(untrusted_input=True, sensitive=True, declares_external_comm=True)


def test_from_step_extracts_flat_keys() -> None:
    step = _step("compute", context={"untrusted_input": True, "sensitive": True})
    ctx = RuleOfTwoContext.from_step(step)
    assert ctx.untrusted_input is True
    assert ctx.sensitive is True
    assert ctx.declares_external_comm is False


def test_from_step_non_bool_values_are_false_deny_by_default() -> None:
    # Only an explicit ``is True`` counts — truthy-but-not-True is deny-by-default.
    step = _step(
        "compute",
        context={"untrusted_input": "yes", "sensitive": 1, "declares_external_comm": [1]},
    )
    ctx = RuleOfTwoContext.from_step(step)
    assert ctx == RuleOfTwoContext()


def test_from_step_empty_context_is_all_false() -> None:
    assert RuleOfTwoContext.from_step(_step("compute")) == RuleOfTwoContext()


def test_from_step_non_dict_rule_of_two_block_ignored() -> None:
    step = _step("compute", context={"rule_of_two": "nope"})
    assert RuleOfTwoContext.from_step(step) == RuleOfTwoContext()


@pytest.mark.parametrize("axis", ["untrusted_input", "sensitive", "declares_external_comm"])
def test_top_level_axis_flag_not_cleared_by_nested_false(axis: str) -> None:
    # Monotonicity (I1) / deny-by-default (I3): a flat top-level ``<axis>=True``
    # declaration must NEVER be cleared by a nested ``rule_of_two: {<axis>: False}``.
    # The boolean flags are OR-combined across the flat and nested locations the
    # same way provenance taint is — declarations can only ADD an axis, never drop
    # a HITL-forcing one. (Mirrors the provenance non-clearing invariant.)
    step = _step("compute", context={axis: True, "rule_of_two": {axis: False}})
    ctx = RuleOfTwoContext.from_step(step)
    assert getattr(ctx, axis) is True


@pytest.mark.parametrize("axis", ["untrusted_input", "sensitive", "declares_external_comm"])
def test_nested_axis_flag_not_cleared_by_flat_false(axis: str) -> None:
    # Symmetric: a nested ``<axis>=True`` must NOT be cleared by a flat ``False``.
    step = _step("compute", context={axis: False, "rule_of_two": {axis: True}})
    ctx = RuleOfTwoContext.from_step(step)
    assert getattr(ctx, axis) is True


def test_classify_with_step_context_via_from_step() -> None:
    # End-to-end: a connector_action with an untrusted-input flag in Step.context.
    step = _step(
        "connector_action",
        target="kakaowork.post_message",
        context={"rule_of_two": {"untrusted_input": True}},
    )
    axes = classify_axes(step, RuleOfTwoContext.from_step(step))
    assert requires_hitl(axes) is True


# --------------------------------------------------------------------------- #
# axes_to_audit stability.
# --------------------------------------------------------------------------- #


def test_axes_to_audit_is_sorted_and_stable() -> None:
    axes = frozenset({Axis.EXTERNAL_COMM, Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS})
    assert axes_to_audit(axes) == [
        "external_comm",
        "sensitive_access",
        "untrusted_input",
    ]
    # Idempotent / order-independent: rebuilding from a different insertion order
    # yields the identical list.
    axes2 = frozenset({Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM, Axis.UNTRUSTED_INPUT})
    assert axes_to_audit(axes2) == axes_to_audit(axes)


# --------------------------------------------------------------------------- #
# Determinism: same (step, context) → same classification, 100 runs (§B-4a).
# --------------------------------------------------------------------------- #


def test_classify_axes_determinism_100_runs() -> None:
    step = _step(
        "connector_action",
        target="kakaowork.post_message",
        context={"params": {"channel": "사내-공지"}},
    )
    ctx = RuleOfTwoContext(untrusted_input=True, sensitive=True)
    expected = classify_axes(step, ctx)
    for _ in range(100):
        assert classify_axes(step, ctx) == expected
        assert requires_hitl(classify_axes(step, ctx)) is True
        assert axes_to_audit(classify_axes(step, ctx)) == axes_to_audit(expected)


def test_classify_axes_does_not_mutate_step() -> None:
    # I-2 purity: classification must not mutate the input Step or its context.
    step = _step(
        "connector_action", target="kakaowork.post_message", context={"params": {"channel": "사내-공지"}}
    )
    before = step.model_dump()
    classify_axes(step, RuleOfTwoContext(untrusted_input=True))
    assert step.model_dump() == before
