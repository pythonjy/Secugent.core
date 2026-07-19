# SPDX-License-Identifier: Apache-2.0
"""G-H8 (INV-4) — alert rules ↔ metric registry contract.

Every ``secugent_*`` metric name referenced by an alert expr in
``deploy/prometheus/alerts/secugent.yml`` must resolve to a metric that
actually exists in :func:`secugent.observability.metrics.metrics_snapshot`.
This catches *dead alerts* — a rule whose query target is never emitted (the
exact failure mode G-H8 fixes for ``secugent_risk_branch_total`` and
``secugent_policy_block_total``).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from secugent.observability.metrics import metrics_snapshot

_ALERTS_PATH = Path(__file__).resolve().parents[2] / "deploy" / "prometheus" / "alerts" / "secugent.yml"

# A PromQL metric reference: ``secugent_foo_total`` possibly followed by a
# Prometheus-synthesised suffix (``_bucket`` / ``_count`` / ``_sum``) that the
# client derives from a Histogram and is NOT a separately-registered series.
_METRIC_RE = re.compile(r"secugent_[a-z0-9_]+")
_HISTOGRAM_SUFFIXES = ("_bucket", "_count", "_sum")


def _referenced_metric_names() -> set[str]:
    text = _ALERTS_PATH.read_text(encoding="utf-8")
    rules = yaml.safe_load(text)
    names: set[str] = set()
    for group in rules["groups"]:
        for rule in group["rules"]:
            expr = rule.get("expr", "")
            for raw in _METRIC_RE.findall(expr):
                # Strip a Histogram-derived suffix back to the exposed series
                # name (``secugent_run_latency_seconds_bucket`` →
                # ``secugent_run_latency_seconds``). Counters expose ``_total``
                # directly (kept as-is) — it is part of the real series name.
                base = raw
                for suffix in _HISTOGRAM_SUFFIXES:
                    if base.endswith(suffix):
                        base = base[: -len(suffix)]
                        break
                names.add(base)
    return names


def test_alerts_file_exists_and_has_rules() -> None:
    assert _ALERTS_PATH.exists(), f"alerts file missing: {_ALERTS_PATH}"
    assert _referenced_metric_names(), "no secugent_* metrics referenced by any alert"


def test_every_alerted_metric_exists_in_registry() -> None:
    """INV-4: no dead alerts — every referenced metric is registered + exposed."""
    exposed = {m["exposed_name"] for m in metrics_snapshot()}
    # Histograms expose the bare series name (without ``_total``); Counters
    # expose ``_total``. The snapshot already restores ``_total`` for counters,
    # so the exposed set is the right contract surface to match against.
    exposed_with_histogram_base = set(exposed)
    for m in metrics_snapshot():
        if m["type"] == "histogram":
            # ``exposed_name`` for a histogram is the bare name (no suffix); the
            # alert references ``..._bucket`` which we already stripped to bare.
            exposed_with_histogram_base.add(m["exposed_name"])

    referenced = _referenced_metric_names()
    missing = {
        name
        for name in referenced
        if name not in exposed_with_histogram_base
        # A counter's exposed name already carries ``_total``; the alert also
        # references ``..._total`` so it matches directly.
    }
    assert not missing, (
        f"dead alert(s): referenced metric(s) {sorted(missing)} are not in the "
        f"registry exposed set {sorted(exposed_with_histogram_base)}"
    )


def test_two_previously_dead_alerts_are_now_backed() -> None:
    """The two G-H8 target series are referenced AND registered."""
    referenced = _referenced_metric_names()
    exposed = {m["exposed_name"] for m in metrics_snapshot()}
    assert "secugent_risk_branch_total" in referenced
    assert "secugent_policy_block_total" in referenced
    assert "secugent_risk_branch_total" in exposed
    assert "secugent_policy_block_total" in exposed
