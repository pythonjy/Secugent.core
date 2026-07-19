# SPDX-License-Identifier: Apache-2.0
"""DA-M4 §B-4a triple for the deterministic ``rule_of_two_axes`` stamp.

``axes_for_steps`` (secugent.core.rule_of_two) is the pure function an
:class:`ApprovalScope` stamps into its immutable ``rule_of_two_axes`` field at
approval-creation time, and the HITL approve/reject emitters read back verbatim
into the §C-2 audit payload. This file covers the deterministic-module triple
required by CLAUDE.md §B-4a:

* unit — axis union over steps, honest empty, provenance-aware classification;
* property (hypothesis) — emitted axes are a deterministic, sorted/unique
  function of the steps, and equal the axes that justified the approval;
* 100x determinism — same step set → byte-identical axes AND scope serialization.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import hypothesis.strategies as st
from hypothesis import given, settings

from secugent.core.contracts import _RULE_OF_TWO_AXIS_TOKENS, ApprovalScope, Step
from secugent.core.provenance import TaintSource
from secugent.core.rule_of_two import (
    Axis,
    RuleOfTwoContext,
    axes_for_steps,
    axes_to_audit,
    classify_axes,
)

_FIXED_EXPIRY = datetime(2026, 1, 1, tzinfo=UTC)

# Every ActionType except "unknown" (Step rejects "unknown").
_AXIS_ACTION_TYPES = [
    "file_read",
    "file_write",
    "http_get",
    "desktop",
    "compute",
    "connector_action",
]


def _step(action_type: str, *, context: dict[str, object] | None = None) -> Step:
    return Step(
        tenant_id="legacy-default",
        run_id="r-da-m4",
        actor="sub:x",
        action_type=action_type,  # type: ignore[arg-type]
        context=context or {},
    )


# --------------------------------------------------------------------------- #
# 1. Unit
# --------------------------------------------------------------------------- #


def test_empty_step_set_is_honest_empty() -> None:
    assert axes_for_steps([]) == ()


def test_single_compute_step_has_no_axes() -> None:
    # compute is neither egress nor sensitive nor untrusted ⇒ honest empty.
    assert axes_for_steps([_step("compute")]) == ()


def test_single_file_read_is_sensitive_only() -> None:
    assert axes_for_steps([_step("file_read")]) == ("sensitive_access",)


def test_connector_with_untrusted_pii_trips_all_three() -> None:
    step = _step(
        "connector_action",
        context={"rule_of_two": {"untrusted_input": True, "sensitive": True}},
    )
    assert axes_for_steps([step]) == (
        "external_comm",
        "sensitive_access",
        "untrusted_input",
    )


def test_union_over_multiple_steps() -> None:
    # http_get (external) + file_read (sensitive) + untrusted-tainted http_get.
    tainted = _step(
        "http_get",
        context={"provenance": {"source": "web_fetch"}},
    )
    steps = [_step("http_get"), _step("file_read"), tainted]
    assert axes_for_steps(steps) == (
        "external_comm",
        "sensitive_access",
        "untrusted_input",
    )


def test_provenance_taint_activates_axis_one() -> None:
    # A web_fetch-derived input auto-activates axis ① with no explicit flag.
    step = _step("compute", context={"provenance": {"source": "web_fetch"}})
    assert "untrusted_input" in axes_for_steps([step])


def test_axes_tokens_are_canonical() -> None:
    step = _step(
        "connector_action",
        context={"rule_of_two": {"untrusted_input": True, "sensitive": True}},
    )
    for token in axes_for_steps([step]):
        assert token in _RULE_OF_TWO_AXIS_TOKENS


# --------------------------------------------------------------------------- #
# 2. Property (hypothesis)
# --------------------------------------------------------------------------- #


@st.composite
def _random_step(draw: st.DrawFn) -> Step:
    action_type = draw(st.sampled_from(_AXIS_ACTION_TYPES))
    rot: dict[str, object] = {}
    if draw(st.booleans()):
        rot["untrusted_input"] = True
    if draw(st.booleans()):
        rot["sensitive"] = True
    if draw(st.booleans()):
        rot["declares_external_comm"] = True
    if draw(st.booleans()):
        rot["provenance"] = {
            "source": draw(st.sampled_from([t.value for t in TaintSource])),
            "parent_tainted": draw(st.booleans()),
        }
    context: dict[str, object] = {"rule_of_two": rot} if rot else {}
    return _step(action_type, context=context)


@given(steps=st.lists(_random_step(), max_size=6))
@settings(max_examples=200)
def test_axes_equal_recomputed_union(steps: list[Step]) -> None:
    union: set[Axis] = set()
    for s in steps:
        union |= classify_axes(s, RuleOfTwoContext.from_step(s))
    expected = tuple(axes_to_audit(frozenset(union)))
    assert axes_for_steps(steps) == expected


@given(steps=st.lists(_random_step(), max_size=6))
@settings(max_examples=200)
def test_axes_are_sorted_unique_canonical(steps: list[Step]) -> None:
    axes = axes_for_steps(steps)
    assert list(axes) == sorted(set(axes))  # sorted + de-duplicated
    assert set(axes) <= _RULE_OF_TWO_AXIS_TOKENS


@given(steps=st.lists(_random_step(), max_size=6))
@settings(max_examples=200)
def test_scope_emits_exactly_the_axes_that_justified_it(steps: list[Step]) -> None:
    # An approval's stamped axes equal the axes that justified it (no drift via
    # the validator's normalization, since axes_for_steps is already normalized).
    expected = axes_for_steps(steps)
    scope = ApprovalScope(
        tenant_id="legacy-default",
        run_id="r-da-m4",
        step_ids=[s.id for s in steps],
        max_risk=70,
        expires_at=_FIXED_EXPIRY,
        rule_of_two_axes=expected,
    )
    assert scope.rule_of_two_axes == expected


# --------------------------------------------------------------------------- #
# 3. 100x determinism (same input → identical output)
# --------------------------------------------------------------------------- #


def test_axes_for_steps_deterministic_100x() -> None:
    steps = [
        _step("connector_action", context={"rule_of_two": {"untrusted_input": True}}),
        _step("file_read"),
        _step("http_get", context={"provenance": {"source": "connector_response"}}),
    ]
    first = axes_for_steps(steps)
    for _ in range(100):
        assert axes_for_steps(steps) == first


def test_scope_serialization_deterministic_100x() -> None:
    step = _step(
        "connector_action",
        context={"rule_of_two": {"untrusted_input": True, "sensitive": True}},
    )

    def _make() -> bytes:
        scope = ApprovalScope(
            tenant_id="legacy-default",
            run_id="r-da-m4",
            plan_id="p-da-m4",
            step_ids=[step.id],
            max_risk=70,
            expires_at=_FIXED_EXPIRY,
            rule_of_two_axes=axes_for_steps([step]),
        )
        return json.dumps(scope.model_dump(mode="json"), sort_keys=True).encode()

    first = _make()
    for _ in range(100):
        assert _make() == first
