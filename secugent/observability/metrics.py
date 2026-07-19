# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — Prometheus metric registry.

Eight metrics power the Grafana ``secugent_overview`` dashboard:

* run latency (Histogram, labels: tenant_id, terminal_state)
* approval wait (Histogram, labels: tenant_id, risk_band)
* HITL backlog (Gauge, labels: tenant_id)
* LLM tokens (Counter, labels: tenant_id, model, kind)
* RISKANALYZER branch outcome (Counter, labels: tenant_id, branch)
* policy block (Counter, labels: tenant_id, category)
* cost quota exceeded (Counter, labels: tenant_id, period) — COST-02
* cost quota utilization (Gauge, labels: tenant_id, period) — COST-02

Names/labels are an *external* contract — see
``deploy/prometheus/alerts/secugent.yml`` and the dashboard JSON. Tests in
``tests/observability/test_metrics_definitions.py`` keep this honest.

This module is PUBLIC (ships in the ``secugent-core`` OSS set) and must NEVER
import the private ``secugent.cost`` tier (import-closure I2). The cost_* helpers
below take only primitives and are CALLED from ``secugent.cost.accounting`` — the
private side imports this public module, never the reverse.
"""

from __future__ import annotations

import logging
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
    "COST_QUOTA_EXCEEDED",
    "COST_QUOTA_UTILIZATION",
    "HITL_BACKLOG",
    "LLM_TOKENS",
    "POLICY_BLOCK",
    "RISK_BRANCH",
    "RUN_LATENCY",
    "init_metrics",
    "metrics_snapshot",
    "record_cost_quota_exceeded",
    "record_cost_utilization",
    "record_llm_tokens",
    "record_policy_block",
    "record_risk_branch",
]

_logger = logging.getLogger(__name__)


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
    "RISKANALYZER decision branch (silent/warn/hitl)",
    labelnames=("tenant_id", "branch"),
)

POLICY_BLOCK = Counter(
    "secugent_policy_block_total",
    "Mechanical Oversight policy block events",
    labelnames=("tenant_id", "category"),
)

# COST-02 — cost-quota observability. ``period`` is the quota window the value
# refers to (``day`` / ``month``), a finite Literal so label cardinality stays
# bounded. HONESTY CAVEAT: exactly like ``secugent_llm_tokens_total`` today, both
# cost_* series move only on ACCRUED spend — the durable cost already written to
# the ledger from external / prior-run accounting. They do NOT yet reflect
# live in-run metering (that lands with COST-01); until then they track the same
# accrued snapshot the quota gate decides on, not a running in-flight tally.
COST_QUOTA_EXCEEDED = Counter(
    "secugent_cost_quota_exceeded_total",
    "Cost-quota refusals: a run blocked because accrued spend hit the cap",
    labelnames=("tenant_id", "period"),
)

COST_QUOTA_UTILIZATION = Gauge(
    "secugent_cost_quota_utilization",
    "Accrued/budget ratio per quota window (0..>1; >=1 means at/over cap)",
    labelnames=("tenant_id", "period"),
)


# ---------------------------------------------------------------------------
# Opt-in adoption telemetry is intentionally NOT a Prometheus
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
    the eight metrics above were already registered at module import.
    """
    return registry or _DEFAULT_REGISTRY


def metrics_snapshot() -> list[dict[str, Any]]:
    """Return a stable snapshot of the eight PHASE 10 / COST-02 metrics (for tests).

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
        COST_QUOTA_EXCEEDED,
        COST_QUOTA_UTILIZATION,
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


# ---------------------------------------------------------------------------
# G-H8 — emission helpers (single label-contract surface)
#
# These wrap the three previously-unemitted PHASE 10 counters. They centralise
# the label contract (so call sites cannot drift) and are *best-effort*: an
# internal failure logs a WARN and returns. A metric emission must NEVER change
# a product decision or abort an execution flow (INV-3 fail-open). They are pure
# side effects invoked at the *consumption* boundary — never inside the
# deterministic decision core.
# ---------------------------------------------------------------------------


def record_llm_tokens(*, tenant_id: str, model: str, input_tokens: int, output_tokens: int) -> None:
    """Accumulate input/output LLM tokens into :data:`LLM_TOKENS`.

    Negative token counts are clamped to 0 so the Counter stays monotonic
    (a buggy/garbled accounting value can never make the series decrease).
    Best-effort: any failure is logged at WARN and swallowed (INV-3).
    """
    try:
        LLM_TOKENS.labels(tenant_id=tenant_id, model=model, kind="input").inc(max(0, input_tokens))
        LLM_TOKENS.labels(tenant_id=tenant_id, model=model, kind="output").inc(max(0, output_tokens))
    except Exception as exc:  # noqa: BLE001 - observability must not break the caller
        _logger.warning("record_llm_tokens failed (best-effort, ignored): %s", exc)


def record_risk_branch(*, tenant_id: str, branch: str) -> None:
    """Increment :data:`RISK_BRANCH` for one RISKANALYZER decision.

    ``branch`` is the ``RiskDecision`` literal (``silent`` / ``warn`` / ``hitl``).
    Best-effort: any failure is logged at WARN and swallowed (INV-3).
    """
    try:
        RISK_BRANCH.labels(tenant_id=tenant_id, branch=branch).inc()
    except Exception as exc:  # noqa: BLE001 - observability must not break the caller
        _logger.warning("record_risk_branch failed (best-effort, ignored): %s", exc)


def record_policy_block(*, tenant_id: str, category: str) -> None:
    """Increment :data:`POLICY_BLOCK` for one Mechanical Oversight hard block.

    ``category`` is the matched :class:`~secugent.core.contracts.Violation`'s
    ``category`` — a finite ``ViolationCategory`` Literal, never free text, so
    label cardinality stays bounded. The helper accepts a bare ``str`` so
    non-typed callers can pass a known-safe constant; typed callers forward the
    Violation's category directly. Best-effort, never raises (INV-3).
    """
    try:
        POLICY_BLOCK.labels(tenant_id=tenant_id, category=category).inc()
    except Exception as exc:  # noqa: BLE001 - observability must not break the caller
        _logger.warning("record_policy_block failed (best-effort, ignored): %s", exc)


def record_cost_quota_exceeded(*, tenant_id: str, period: str) -> None:
    """Increment :data:`COST_QUOTA_EXCEEDED` for one cost-quota refusal (COST-02).

    ``period`` is the quota window that tripped (``day`` / ``month``). Emitted at
    the cost-accounting boundary when a run is blocked because accrued spend hit
    the cap — NOT live in-run metering (that lands with COST-01). Best-effort: any
    failure is logged at WARN and swallowed so a metric error can never abort the
    quota decision (INV-3 fail-open).
    """
    try:
        COST_QUOTA_EXCEEDED.labels(tenant_id=tenant_id, period=period).inc()
    except Exception as exc:  # noqa: BLE001 - observability must not break the caller
        _logger.warning("record_cost_quota_exceeded failed (best-effort, ignored): %s", exc)


def record_cost_utilization(*, tenant_id: str, period: str, ratio: float) -> None:
    """Set :data:`COST_QUOTA_UTILIZATION` to the accrued/budget ratio (COST-02).

    ``ratio`` is ``accrued / budget`` for the ``period`` window (``day`` /
    ``month``); ``>=1`` means at/over cap. A negative ``ratio`` is clamped to 0 so
    the gauge never reports a nonsensical sub-zero utilization from a buggy/garbled
    accounting value. Reflects ACCRUED spend only, not live in-run metering
    (COST-01). Best-effort: any failure is logged at WARN and swallowed (INV-3).
    """
    try:
        COST_QUOTA_UTILIZATION.labels(tenant_id=tenant_id, period=period).set(max(0.0, ratio))
    except Exception as exc:  # noqa: BLE001 - observability must not break the caller
        _logger.warning("record_cost_utilization failed (best-effort, ignored): %s", exc)
