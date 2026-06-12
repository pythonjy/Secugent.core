# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — Prometheus metric registry.

Six metrics power the Grafana ``secugent_overview`` dashboard:

* run latency (Histogram, labels: tenant_id, terminal_state)
* approval wait (Histogram, labels: tenant_id, risk_band)
* HITL backlog (Gauge, labels: tenant_id)
* LLM tokens (Counter, labels: tenant_id, model, kind)
* RISKANALYZER branch outcome (Counter, labels: tenant_id, branch)
* policy block (Counter, labels: tenant_id, category)

Names/labels are an *external* contract — see
``deploy/prometheus/alerts/secugent.yml`` and the dashboard JSON. Tests in
``tests/observability/test_metrics_definitions.py`` keep this honest.
"""

from __future__ import annotations

from typing import Any

from prometheus_client import REGISTRY as _DEFAULT_REGISTRY
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

__all__ = [
    "APPROVAL_WAIT",
    "HITL_BACKLOG",
    "LLM_TOKENS",
    "POLICY_BLOCK",
    "RISK_BRANCH",
    "RUN_LATENCY",
    "init_metrics",
    "metrics_snapshot",
]


# Histogram bucket boundaries (seconds) — chosen for typical agent workloads.
_LATENCY_BUCKETS: tuple[float, ...] = (
    0.1,
    0.5,
    1,
    2.5,
    5,
    10,
    30,
    60,
    120,
    300,
    600,
)


RUN_LATENCY = Histogram(
    "secugent_run_latency_seconds",
    "Pipeline latency from enqueue to terminal state",
    labelnames=("tenant_id", "terminal_state"),
    buckets=_LATENCY_BUCKETS,
)

APPROVAL_WAIT = Histogram(
    "secugent_approval_wait_seconds",
    "Duration spent in AWAITING_APPROVAL before a human decision",
    labelnames=("tenant_id", "risk_band"),
    buckets=_LATENCY_BUCKETS,
)

HITL_BACKLOG = Gauge(
    "secugent_hitl_backlog",
    "Pending HITL approvals per tenant",
    labelnames=("tenant_id",),
)

LLM_TOKENS = Counter(
    "secugent_llm_tokens_total",
    "LLM input/output tokens consumed",
    labelnames=("tenant_id", "model", "kind"),
)

RISK_BRANCH = Counter(
    "secugent_risk_branch_total",
    "RISKANALYZER decision branch (auto/hitl/block)",
    labelnames=("tenant_id", "branch"),
)

POLICY_BLOCK = Counter(
    "secugent_policy_block_total",
    "Mechanical Oversight policy block events",
    labelnames=("tenant_id", "category"),
)


# ---------------------------------------------------------------------------
# BDP_02 item 7 — opt-in adoption telemetry is intentionally NOT a Prometheus
# metric. It lives entirely in-memory / sink-only in
# ``secugent.observability.telemetry.TelemetryCollector`` (default-off). A
# global Prometheus counter would (a) auto-register on the default REGISTRY at
# import time and leak HELP/TYPE metadata onto ``/metrics`` even with opt-in OFF
# (contradicting Invariant I1 "nothing created"), and (b) be a second,
# never-incremented source of truth forked from the collector's own counter.
# Both are avoided by having no telemetry collector here. Do NOT re-add one.
# ---------------------------------------------------------------------------


def init_metrics(registry: CollectorRegistry | None = None) -> CollectorRegistry:
    """Return the global Prometheus registry.

    Idempotent: passing ``registry=None`` returns the default registry where
    the six metrics above were already registered at module import.
    """
    return registry or _DEFAULT_REGISTRY


def metrics_snapshot() -> list[dict[str, Any]]:
    """Return a stable snapshot of the six PHASE 10 metrics (for tests).

    ``exposed_name`` is the name as it appears in the Prometheus exposition
    format. ``prometheus_client`` strips ``_total`` from Counter ``_name`` —
    we restore it here so the snapshot matches Grafana / alert rule strings.
    """
    out: list[dict[str, Any]] = []
    for m in (
        RUN_LATENCY,
        APPROVAL_WAIT,
        HITL_BACKLOG,
        LLM_TOKENS,
        RISK_BRANCH,
        POLICY_BLOCK,
    ):
        exposed = m._name + "_total" if m._type == "counter" else m._name
        out.append(
            {
                "name": m._name,
                "exposed_name": exposed,
                "type": m._type,
                "labels": tuple(m._labelnames),
            }
        )
    return out
