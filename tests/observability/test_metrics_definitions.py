# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — Prometheus metric definition snapshot.

The names/labels/HELP text of these 6 metrics are an external contract for
Grafana dashboards and Prometheus alert rules; renaming them silently would
break the dashboards. We pin the definitions with a snapshot test.
"""

from __future__ import annotations

from secugent.observability.metrics import (
    APPROVAL_WAIT,
    HITL_BACKLOG,
    LLM_TOKENS,
    POLICY_BLOCK,
    RISK_BRANCH,
    RUN_LATENCY,
    init_metrics,
    metrics_snapshot,
)


def test_run_latency_definition() -> None:
    assert RUN_LATENCY._name == "secugent_run_latency_seconds"
    assert tuple(RUN_LATENCY._labelnames) == ("tenant_id", "terminal_state")


def test_approval_wait_definition() -> None:
    assert APPROVAL_WAIT._name == "secugent_approval_wait_seconds"
    assert tuple(APPROVAL_WAIT._labelnames) == ("tenant_id", "risk_band")


def test_hitl_backlog_definition() -> None:
    assert HITL_BACKLOG._name == "secugent_hitl_backlog"
    assert tuple(HITL_BACKLOG._labelnames) == ("tenant_id",)


def test_llm_tokens_definition() -> None:
    # prometheus_client.Counter strips ``_total`` from ``_name`` (the suffix
    # is appended only in the exposition format).
    assert LLM_TOKENS._name == "secugent_llm_tokens"
    assert tuple(LLM_TOKENS._labelnames) == ("tenant_id", "model", "kind")


def test_risk_branch_definition() -> None:
    assert RISK_BRANCH._name == "secugent_risk_branch"
    assert tuple(RISK_BRANCH._labelnames) == ("tenant_id", "branch")


def test_policy_block_definition() -> None:
    assert POLICY_BLOCK._name == "secugent_policy_block"
    assert tuple(POLICY_BLOCK._labelnames) == ("tenant_id", "category")


def test_snapshot_contains_all_metrics() -> None:
    """Single snapshot ensures none get accidentally removed."""
    snap = metrics_snapshot()
    names = {entry["exposed_name"] for entry in snap}
    assert names == {
        "secugent_run_latency_seconds",
        "secugent_approval_wait_seconds",
        "secugent_hitl_backlog",
        "secugent_llm_tokens_total",
        "secugent_risk_branch_total",
        "secugent_policy_block_total",
    }


def test_init_metrics_returns_registry() -> None:
    registry = init_metrics()
    assert registry is not None


def test_render_prometheus_exposition() -> None:
    from prometheus_client import generate_latest

    init_metrics()
    RUN_LATENCY.labels(tenant_id="acme", terminal_state="completed").observe(0.5)
    body = generate_latest()
    assert b"secugent_run_latency_seconds" in body
    assert b'tenant_id="acme"' in body
    assert b'terminal_state="completed"' in body
