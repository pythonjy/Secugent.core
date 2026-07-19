# SPDX-License-Identifier: Apache-2.0
"""Provenance taint producer — unit + property + determinism (§B-4a, BDP_02 항목 5).

This is the deterministic axis① (``untrusted_input``) producer. The three
obligations of a deterministic-core module are exercised here:

* **unit** — the truth table of :func:`is_untrusted` / :func:`derive_taint`,
  the action-type → taint-source mapping (:func:`taint_source_for_action`
  exhaustive truth-table over all ActionType values × untrusted_file flag),
  plus the live web-fetch derivation that turns axis① on through
  :meth:`RuleOfTwoContext.from_step`.
* **property (hypothesis)** — MONOTONICITY (I1): taint only ever turns ON. Every
  descendant of a tainted parent is tainted; no derivation clears taint.
  Additionally: determinism + deny-by-default of ``taint_source_for_action``.
* **determinism (100x)** — identical ``(step, provenance)`` ⇒ identical
  ``frozenset[Axis]`` (I2): ``distinct_outputs == 1``. Also 100x for
  ``taint_source_for_action`` itself.
"""

from __future__ import annotations

import typing
from typing import cast

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import ActionType, Step
from secugent.core.provenance import TaintSource, derive_taint, is_untrusted, taint_source_for_action
from secugent.core.rule_of_two import (
    Axis,
    RuleOfTwoContext,
    classify_axes,
    requires_hitl,
)
from secugent.core.tenancy import TenantId

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_ALL_SOURCES: list[TaintSource] = list(TaintSource)
_UNTRUSTED_SOURCES: list[TaintSource] = [s for s in TaintSource if s is not TaintSource.USER_DIRECT]


def _step(
    action_type: ActionType,
    *,
    target: str | None = None,
    context: dict[str, object] | None = None,
) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type=action_type,
        target=target,
        context=context or {},
    )


def _prov(source: str | None, *, parent_tainted: bool = False) -> dict[str, object]:
    block: dict[str, object] = {"parent_tainted": parent_tainted}
    if source is not None:
        block["source"] = source
    return {"provenance": block}


# --------------------------------------------------------------------------- #
# is_untrusted — truth table.
# --------------------------------------------------------------------------- #


def test_user_direct_is_trusted() -> None:
    assert is_untrusted(TaintSource.USER_DIRECT) is False


def test_every_non_user_direct_source_is_untrusted() -> None:
    for source in _UNTRUSTED_SOURCES:
        assert is_untrusted(source) is True


def test_taint_source_string_values_are_stable() -> None:
    # Wire-stable values: provenance metadata is JSON-serialized into Step.context.
    assert TaintSource.WEB_FETCH.value == "web_fetch"
    assert TaintSource.CONNECTOR_RESPONSE.value == "connector_response"
    assert TaintSource.FILE_UNTRUSTED.value == "file_untrusted"
    assert TaintSource.USER_DIRECT.value == "user_direct"


# --------------------------------------------------------------------------- #
# derive_taint — propagation rules.
# --------------------------------------------------------------------------- #


def test_untrusted_source_taints_clean_parent() -> None:
    assert derive_taint(False, TaintSource.WEB_FETCH) is True
    assert derive_taint(False, TaintSource.CONNECTOR_RESPONSE) is True
    assert derive_taint(False, TaintSource.FILE_UNTRUSTED) is True


def test_trusted_source_does_not_taint_clean_parent() -> None:
    assert derive_taint(False, TaintSource.USER_DIRECT) is False


def test_none_source_on_clean_parent_stays_clean() -> None:
    # Ambiguous/absent source must not invent taint, but also must not clear it.
    assert derive_taint(False, None) is False


def test_tainted_parent_stays_tainted_for_every_source() -> None:
    # I1 monotone: a tainted parent can never be cleared, regardless of source.
    for source in _ALL_SOURCES:
        assert derive_taint(True, source) is True
    assert derive_taint(True, None) is True


def test_trusted_source_cannot_clear_existing_taint() -> None:
    # I3 deny-by-default: even an explicitly trusted source never clears taint.
    assert derive_taint(True, TaintSource.USER_DIRECT) is True


# --------------------------------------------------------------------------- #
# Live producer through RuleOfTwoContext.from_step.
# --------------------------------------------------------------------------- #


def test_web_fetch_provenance_activates_axis1() -> None:
    step = _step("compute", context=_prov("web_fetch"))
    ctx = RuleOfTwoContext.from_step(step)
    assert ctx.untrusted_input is True


def test_connector_response_provenance_activates_axis1() -> None:
    step = _step("compute", context=_prov("connector_response"))
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_user_direct_provenance_does_not_activate_axis1() -> None:
    step = _step("compute", context=_prov("user_direct"))
    assert RuleOfTwoContext.from_step(step).untrusted_input is False


def test_parent_tainted_provenance_propagates_even_with_trusted_source() -> None:
    # A derivation chain: parent was tainted upstream, this hop reads user_direct.
    step = _step("compute", context=_prov("user_direct", parent_tainted=True))
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_no_provenance_block_does_not_auto_activate() -> None:
    # Edge 5.7: no provenance meta ⇒ no auto-taint (explicit declaration only).
    step = _step("compute", context={"unrelated": 1})
    assert RuleOfTwoContext.from_step(step).untrusted_input is False


def test_unknown_source_string_is_deny_by_default_no_clear() -> None:
    # Edge 5.7: ambiguous source string never clears an inherited taint.
    step = _step("compute", context=_prov("totally-unknown", parent_tainted=True))
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_unknown_source_string_on_clean_parent_does_not_invent_taint() -> None:
    step = _step("compute", context=_prov("totally-unknown", parent_tainted=False))
    assert RuleOfTwoContext.from_step(step).untrusted_input is False


def test_explicit_true_still_wins_over_absent_provenance() -> None:
    # Backward compat: explicit untrusted_input=True with no provenance still on.
    step = _step("compute", context={"untrusted_input": True})
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_explicit_false_but_untrusted_provenance_adds_taint() -> None:
    # OR-combine: explicit absent/False + untrusted provenance ⇒ tainted.
    step = _step("compute", context={"untrusted_input": False, **_prov("web_fetch")})
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_provenance_nested_under_rule_of_two_block() -> None:
    step = _step("compute", context={"rule_of_two": {"provenance": {"source": "web_fetch"}}})
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_truthy_non_true_parent_tainted_is_deny_by_default_false() -> None:
    # External truthy-non-True must be treated as False (cannot silently enable).
    step = _step("compute", context=_prov(None))  # parent_tainted=False, no source
    # Now inject a truthy-non-True parent_tainted value.
    step = _step("compute", context={"provenance": {"parent_tainted": "yes"}})
    assert RuleOfTwoContext.from_step(step).untrusted_input is False


def test_non_dict_provenance_block_is_ignored() -> None:
    step = _step("compute", context={"provenance": "nope"})
    assert RuleOfTwoContext.from_step(step).untrusted_input is False


def test_source_as_taint_source_instance_is_accepted() -> None:
    # Defensive: a provenance source supplied as a TaintSource enum member (not a
    # serialized string) is still recognized — covers the in-process producer path.
    step = _step("compute", context={"provenance": {"source": TaintSource.WEB_FETCH}})
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_source_as_non_string_non_enum_is_deny_by_default() -> None:
    # An integer / arbitrary object source is ambiguous ⇒ no auto-taint on a clean
    # parent, and (deny-by-default) cannot clear an inherited taint.
    clean = _step("compute", context={"provenance": {"source": 123}})
    assert RuleOfTwoContext.from_step(clean).untrusted_input is False
    inherited = _step("compute", context={"provenance": {"source": 123, "parent_tainted": True}})
    assert RuleOfTwoContext.from_step(inherited).untrusted_input is True


# --------------------------------------------------------------------------- #
# Regression (finding 1/3): flat + nested provenance are OR-combined — a clean /
# trusted / empty provenance block in EITHER location can never clear the other's
# taint (monotonicity / deny-by-default hole: nested used to REPLACE flat).
# --------------------------------------------------------------------------- #


def test_top_level_untrusted_not_cleared_by_nested_trusted_provenance() -> None:
    # Flat says web_fetch (untrusted); nested says user_direct (trusted). The OR
    # must keep axis① ON — the nested trusted block must NOT clear the flat taint.
    step = _step(
        "compute",
        context={
            "provenance": {"source": "web_fetch"},
            "rule_of_two": {"provenance": {"source": "user_direct"}},
        },
    )
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_top_level_untrusted_not_cleared_by_nested_empty_provenance() -> None:
    # An EMPTY nested provenance block (no source, parent_tainted absent) must not
    # shadow a genuine top-level untrusted taint.
    step = _step(
        "compute",
        context={
            "provenance": {"source": "web_fetch"},
            "rule_of_two": {"provenance": {}},
        },
    )
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


def test_nested_untrusted_not_cleared_by_flat_trusted_provenance() -> None:
    # Symmetric: untrusted in nested, trusted in flat ⇒ still tainted.
    step = _step(
        "compute",
        context={
            "provenance": {"source": "user_direct"},
            "rule_of_two": {"provenance": {"source": "web_fetch"}},
        },
    )
    assert RuleOfTwoContext.from_step(step).untrusted_input is True


@given(
    flat_source=st.sampled_from(_ALL_SOURCES) | st.none(),
    nested_source=st.sampled_from(_ALL_SOURCES) | st.none(),
    flat_parent=st.booleans(),
    nested_parent=st.booleans(),
    add_nested=st.booleans(),
)
def test_property_adding_nested_provenance_never_reduces_taint(
    flat_source: TaintSource | None,
    nested_source: TaintSource | None,
    flat_parent: bool,
    nested_parent: bool,
    add_nested: bool,
) -> None:
    # Build a step with ONLY a flat provenance block, then add/alter a nested
    # provenance block. The resolved axis① bit must be monotone non-decreasing:
    # adding or altering a nested block can never turn an existing taint OFF.
    flat_block: dict[str, object] = {"parent_tainted": flat_parent}
    if flat_source is not None:
        flat_block["source"] = flat_source.value
    base_ctx: dict[str, object] = {"provenance": flat_block}
    before = RuleOfTwoContext.from_step(_step("compute", context=base_ctx)).untrusted_input

    nested_block: dict[str, object] = {"parent_tainted": nested_parent}
    if nested_source is not None:
        nested_block["source"] = nested_source.value
    combined_ctx: dict[str, object] = {**base_ctx}
    if add_nested:
        combined_ctx["rule_of_two"] = {"provenance": nested_block}
    after = RuleOfTwoContext.from_step(_step("compute", context=combined_ctx)).untrusted_input

    # Monotone: after >= before (a True taint can never become False).
    assert after or not before


# --------------------------------------------------------------------------- #
# Axis-level live derivation: web_fetch + sensitive + external ⇒ 3 axes.
# --------------------------------------------------------------------------- #


def test_web_fetch_derived_three_axes_force_hitl() -> None:
    step = _step(
        "connector_action",
        target="kakaowork.post_message",
        context={"rule_of_two": {"sensitive": True}, **_prov("web_fetch")},
    )
    axes = classify_axes(step, RuleOfTwoContext.from_step(step))
    assert axes == frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})
    assert requires_hitl(axes) is True


# --------------------------------------------------------------------------- #
# Property (hypothesis): MONOTONICITY (I1).
# --------------------------------------------------------------------------- #

_source_strategy = st.sampled_from(_ALL_SOURCES) | st.none()


@given(source=_source_strategy)
def test_property_tainted_parent_never_clears(source: TaintSource | None) -> None:
    # I1: a tainted parent stays tainted under any single derivation hop.
    assert derive_taint(True, source) is True


@given(sources=st.lists(_source_strategy, min_size=1, max_size=12))
def test_property_descendant_of_tainted_chain_stays_tainted(
    sources: list[TaintSource | None],
) -> None:
    # Fold an arbitrary derivation chain starting from a tainted root: every
    # descendant must remain tainted (monotone — taint never clears).
    tainted = True
    for source in sources:
        tainted = derive_taint(tainted, source)
        assert tainted is True


@given(sources=st.lists(_source_strategy, min_size=1, max_size=12))
def test_property_chain_with_one_untrusted_source_ends_tainted(
    sources: list[TaintSource | None],
) -> None:
    # If ANY hop in the chain reads an untrusted source, the result is tainted
    # (monotone ON + deny-by-default never clears it afterwards).
    has_untrusted = any(s is not None and is_untrusted(s) for s in sources)
    tainted = False
    for source in sources:
        tainted = derive_taint(tainted, source)
    assert tainted is has_untrusted


@given(parent=st.booleans(), source=_source_strategy)
def test_property_derive_is_monotone_in_parent(parent: bool, source: TaintSource | None) -> None:
    # Output is >= parent (deny-by-default: a clean parent may turn ON, a tainted
    # parent stays ON). Encoded as: if parent True ⇒ result True.
    result = derive_taint(parent, source)
    if parent:
        assert result is True


# --------------------------------------------------------------------------- #
# Determinism (100x): same (step, provenance) ⇒ identical frozenset[Axis].
# --------------------------------------------------------------------------- #


def test_provenance_axes_determinism_100_runs() -> None:
    step = _step(
        "connector_action",
        target="kakaowork.post_message",
        context={"rule_of_two": {"sensitive": True}, **_prov("web_fetch", parent_tainted=True)},
    )
    outputs = {classify_axes(step, RuleOfTwoContext.from_step(step)) for _ in range(100)}
    assert len(outputs) == 1  # distinct_outputs == 1
    only = next(iter(outputs))
    assert only == frozenset({Axis.UNTRUSTED_INPUT, Axis.SENSITIVE_ACCESS, Axis.EXTERNAL_COMM})


def test_derive_taint_determinism_100_runs() -> None:
    outputs = {derive_taint(False, TaintSource.WEB_FETCH) for _ in range(100)}
    assert outputs == {True}


# --------------------------------------------------------------------------- #
# taint_source_for_action — exhaustive truth-table (§B-4a unit).
# --------------------------------------------------------------------------- #

# All ActionType values covered explicitly (deny-by-default invariant I4).


def test_http_get_always_returns_web_fetch() -> None:
    # http_get is definitionally an untrusted external source (§A-2 근거).
    assert taint_source_for_action("http_get", {}) is TaintSource.WEB_FETCH
    assert taint_source_for_action("http_get", {"irrelevant": 1}) is TaintSource.WEB_FETCH


def test_connector_action_always_returns_connector_response() -> None:
    # connector_action (external connector) is definitionally untrusted (§A-2 근거).
    assert taint_source_for_action("connector_action", {}) is TaintSource.CONNECTOR_RESPONSE
    assert (
        taint_source_for_action("connector_action", {"untrusted_file": True})
        is TaintSource.CONNECTOR_RESPONSE
    )


def test_file_read_with_explicit_untrusted_flag_returns_file_untrusted() -> None:
    # Only an explicit boolean True flag taints file_read (I4 false-positive guard).
    assert taint_source_for_action("file_read", {"untrusted_file": True}) is TaintSource.FILE_UNTRUSTED


def test_file_read_without_flag_returns_none() -> None:
    # Plain config read MUST NOT taint (I4 — no false positives).
    assert taint_source_for_action("file_read", {}) is None
    assert taint_source_for_action("file_read", {"unrelated": True}) is None


def test_file_read_truthy_non_true_flag_is_deny_by_default_none() -> None:
    # I3 deny-by-default: "yes" / 1 / ["x"] are truthy but not `is True`.
    assert taint_source_for_action("file_read", {"untrusted_file": "yes"}) is None
    assert taint_source_for_action("file_read", {"untrusted_file": 1}) is None
    assert taint_source_for_action("file_read", {"untrusted_file": ["x"]}) is None


def test_file_write_returns_none() -> None:
    # Output action — not an untrusted input source (I4).
    assert taint_source_for_action("file_write", {}) is None
    assert taint_source_for_action("file_write", {"untrusted_file": True}) is None


def test_desktop_returns_none() -> None:
    # Desktop action — not an untrusted input source (I4).
    assert taint_source_for_action("desktop", {}) is None


def test_compute_returns_none() -> None:
    # Compute — not an untrusted input source (I4).
    assert taint_source_for_action("compute", {}) is None


def test_unknown_returns_none() -> None:
    # Unknown action type — deny-by-default, no taint invented (I3/I4).
    assert taint_source_for_action("unknown", {}) is None


# --------------------------------------------------------------------------- #
# taint_source_for_action — hypothesis: determinism + deny-by-default (§B-4a property).
# --------------------------------------------------------------------------- #

_ALL_ACTION_TYPES: list[ActionType] = [
    "file_read",
    "file_write",
    "http_get",
    "desktop",
    "compute",
    "connector_action",
    "unknown",
]


@given(
    action_type=st.sampled_from(_ALL_ACTION_TYPES),
    untrusted_file_flag=st.one_of(st.just(True), st.just(False), st.just(None)),
)
@settings(max_examples=200)
def test_property_taint_source_for_action_deterministic(
    action_type: ActionType,
    untrusted_file_flag: bool | None,
) -> None:
    """Same (action_type, context) always returns identical TaintSource | None."""
    ctx: dict[str, object] = {}
    if untrusted_file_flag is not None:
        ctx["untrusted_file"] = untrusted_file_flag
    result1 = taint_source_for_action(action_type, ctx)
    result2 = taint_source_for_action(action_type, ctx)
    assert result1 is result2, f"{action_type=} {ctx=}: got {result1!r} then {result2!r}"


@given(action_type=st.sampled_from(_ALL_ACTION_TYPES))
@settings(max_examples=200)
def test_property_taint_source_for_action_deny_by_default_non_true(
    action_type: ActionType,
) -> None:
    """A truthy-but-not-True untrusted_file value must never activate file_read taint."""
    result = taint_source_for_action(action_type, {"untrusted_file": "yes"})
    # "yes" is truthy but not `is True`, so it must not trigger FILE_UNTRUSTED.
    assert result is not TaintSource.FILE_UNTRUSTED or action_type != "file_read"


# --------------------------------------------------------------------------- #
# taint_source_for_action — 100x determinism run (§B-4a결정성 100회).
# --------------------------------------------------------------------------- #


def test_taint_source_for_action_determinism_100_runs() -> None:
    """taint_source_for_action is identical 100x for every action type × flag combo."""
    cases: list[tuple[ActionType, dict[str, object], TaintSource | None]] = [
        ("http_get", {}, TaintSource.WEB_FETCH),
        ("connector_action", {}, TaintSource.CONNECTOR_RESPONSE),
        ("file_read", {"untrusted_file": True}, TaintSource.FILE_UNTRUSTED),
        ("file_read", {}, None),
        ("file_write", {}, None),
        ("desktop", {}, None),
        ("compute", {}, None),
        ("unknown", {}, None),
    ]
    for action_type, ctx, expected in cases:
        outputs = {taint_source_for_action(action_type, ctx) for _ in range(100)}
        assert outputs == {expected}, (
            f"{action_type=} {ctx=}: expected {{expected!r}} but got {outputs!r} over 100 runs"
        )


# --------------------------------------------------------------------------- #
# REV-2 regression: exhaustiveness guard + type-narrowing (§B-3 / §B-4a).
#
# These tests must remain GREEN after `taint_source_for_action` is narrowed to
# `action_type: ActionType` and the if-chain is replaced with a `match` +
# `assert_never`. They confirm the mapping covers EVERY ActionType member and
# that the parameter signature is narrowed (not `str`).
# --------------------------------------------------------------------------- #


def test_rev2_every_action_type_member_is_handled_and_mapping_is_exact() -> None:
    """REV-2: every ActionType member maps to the correct TaintSource or None.

    Exhaustiveness guard: if a future ActionType is added without updating
    taint_source_for_action the match + assert_never will fail mypy/CI (not
    silently return None). This test pins the exact expected mapping so that
    drift in either direction (new member unhandled, or an existing member's
    taint changed unexpectedly) is caught at test time.
    """
    # get_args returns the Literal members at runtime.
    all_members: tuple[str, ...] = typing.get_args(ActionType)
    assert set(all_members) == {
        "file_read",
        "file_write",
        "http_get",
        "desktop",
        "compute",
        "connector_action",
        "unknown",
    }, "ActionType member set changed — update this test AND taint_source_for_action"

    expected_mapping: dict[str, TaintSource | None] = {
        "http_get": TaintSource.WEB_FETCH,
        "connector_action": TaintSource.CONNECTOR_RESPONSE,
        # file_read without the explicit flag → None (flag-gated; tested separately)
        "file_read": None,
        "file_write": None,
        "desktop": None,
        "compute": None,
        "unknown": None,
    }
    for member in all_members:
        # typing.get_args returns str at runtime; cast confirms these are valid ActionType members.
        result = taint_source_for_action(cast("ActionType", member), {})
        assert result == expected_mapping[member], (
            f"ActionType {member!r}: expected {expected_mapping[member]!r}, got {result!r}"
        )


def test_rev2_taint_source_for_action_accepts_action_type_literal() -> None:
    """REV-2: signature narrowed to ActionType — mypy must accept ActionType values.

    This test can only exercise runtime behaviour (passing an ActionType value
    must not raise); the compile-time narrowing is verified by mypy in the gate.
    The test is here to document the intent and catch a regression if the param
    is widened back to str.
    """
    # All valid ActionType values — must not raise at runtime.
    for at in typing.get_args(ActionType):
        # typing.get_args returns str; cast confirms these are valid ActionType members.
        result = taint_source_for_action(cast("ActionType", at), {})
        assert result is None or isinstance(result, TaintSource)
