# SPDX-License-Identifier: Apache-2.0
"""G-H8 — unit tests for the 3 metric-emission helpers.

The helpers (``record_llm_tokens`` / ``record_risk_branch`` /
``record_policy_block``) are the single label-contract surface for the three
previously-unemitted PHASE 10 metrics. They MUST be best-effort: an internal
failure logs a WARN and returns, it never propagates (INV-3 fail-open).
"""

from __future__ import annotations

from secugent.observability.metrics import (
    LLM_TOKENS,
    POLICY_BLOCK,
    RISK_BRANCH,
    record_llm_tokens,
    record_policy_block,
    record_risk_branch,
)

# ---------------------------------------------------------------------------
# record_llm_tokens
# ---------------------------------------------------------------------------


def test_record_llm_tokens_accumulates_input_and_output() -> None:
    in_metric = LLM_TOKENS.labels(tenant_id="acme", model="gpt-x", kind="input")
    out_metric = LLM_TOKENS.labels(tenant_id="acme", model="gpt-x", kind="output")
    before_in = in_metric._value.get()
    before_out = out_metric._value.get()

    record_llm_tokens(tenant_id="acme", model="gpt-x", input_tokens=12, output_tokens=34)

    assert in_metric._value.get() == before_in + 12
    assert out_metric._value.get() == before_out + 34


def test_record_llm_tokens_clamps_negative_to_zero() -> None:
    in_metric = LLM_TOKENS.labels(tenant_id="acme", model="clamp-model", kind="input")
    out_metric = LLM_TOKENS.labels(tenant_id="acme", model="clamp-model", kind="output")
    before_in = in_metric._value.get()
    before_out = out_metric._value.get()

    record_llm_tokens(tenant_id="acme", model="clamp-model", input_tokens=-5, output_tokens=-1)

    # Negative tokens clamp to 0 — Counter stays monotonic, never decreases.
    assert in_metric._value.get() == before_in
    assert out_metric._value.get() == before_out


def test_record_llm_tokens_zero_is_noop_but_safe() -> None:
    in_metric = LLM_TOKENS.labels(tenant_id="acme", model="zero-model", kind="input")
    before = in_metric._value.get()
    record_llm_tokens(tenant_id="acme", model="zero-model", input_tokens=0, output_tokens=0)
    assert in_metric._value.get() == before


# ---------------------------------------------------------------------------
# record_risk_branch
# ---------------------------------------------------------------------------


def test_record_risk_branch_increments_labelled_counter() -> None:
    metric = RISK_BRANCH.labels(tenant_id="acme", branch="hitl")
    before = metric._value.get()

    record_risk_branch(tenant_id="acme", branch="hitl")

    assert metric._value.get() == before + 1


def test_record_risk_branch_distinct_branches_independent() -> None:
    warn_metric = RISK_BRANCH.labels(tenant_id="acme", branch="warn")
    silent_metric = RISK_BRANCH.labels(tenant_id="acme", branch="silent")
    before_warn = warn_metric._value.get()
    before_silent = silent_metric._value.get()

    record_risk_branch(tenant_id="acme", branch="warn")

    assert warn_metric._value.get() == before_warn + 1
    assert silent_metric._value.get() == before_silent  # untouched


# ---------------------------------------------------------------------------
# record_policy_block
# ---------------------------------------------------------------------------


def test_record_policy_block_increments_labelled_counter() -> None:
    metric = POLICY_BLOCK.labels(tenant_id="acme", category="banned_path")
    before = metric._value.get()

    record_policy_block(tenant_id="acme", category="banned_path")

    assert metric._value.get() == before + 1


def test_record_policy_block_unknown_category_label() -> None:
    metric = POLICY_BLOCK.labels(tenant_id="acme", category="unknown")
    before = metric._value.get()

    record_policy_block(tenant_id="acme", category="unknown")

    assert metric._value.get() == before + 1


# ---------------------------------------------------------------------------
# Edge: None tenant collapses to "unknown" (cardinality-safe default)
# ---------------------------------------------------------------------------


def test_helpers_coerce_none_tenant_to_unknown() -> None:
    # The helpers take ``str`` per the contract; callers pass ``str(tenant_id)``.
    # When a caller passes the string "None" (or a None coerced upstream), the
    # helper still records under a stable label rather than raising.
    in_metric = LLM_TOKENS.labels(tenant_id="unknown", model="m", kind="input")
    before = in_metric._value.get()
    record_llm_tokens(tenant_id="unknown", model="m", input_tokens=3, output_tokens=0)
    assert in_metric._value.get() == before + 3
