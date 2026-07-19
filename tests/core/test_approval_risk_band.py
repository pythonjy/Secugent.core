# SPDX-License-Identifier: Apache-2.0
"""G-H8 — ``approval._risk_band`` derivation + APPROVAL_WAIT real-band emission.

``approval.py`` is a §B-4a deterministic module (95% line-coverage gate). The
new pure helper ``_risk_band`` maps a scope's ``max_risk`` (0-100) to a coarse
band the APPROVAL_WAIT histogram labels with. Tests cover every branch and the
boundary values, plus a ``hypothesis`` property that the mapping is total and
only ever returns the three documented bands.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from secugent.core.approval import ApprovalService, _risk_band
from secugent.core.contracts import ApprovalScope
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId
from secugent.observability.metrics import APPROVAL_WAIT

# ---------------------------------------------------------------------------
# _risk_band — branch coverage (thresholds: <34 low, <67 medium, else high)
# ---------------------------------------------------------------------------


def test_risk_band_low_lower_boundary() -> None:
    assert _risk_band(0) == "low"


def test_risk_band_low_upper_boundary() -> None:
    # 33 < 34 → still "low"; 34 crosses into "medium".
    assert _risk_band(33) == "low"


def test_risk_band_medium_lower_boundary() -> None:
    assert _risk_band(34) == "medium"


def test_risk_band_medium_upper_boundary() -> None:
    # 66 < 67 → "medium"; 67 crosses into "high".
    assert _risk_band(66) == "medium"


def test_risk_band_high_lower_boundary() -> None:
    assert _risk_band(67) == "high"


def test_risk_band_high_upper_boundary() -> None:
    assert _risk_band(100) == "high"


@given(st.integers(min_value=0, max_value=100))
def test_risk_band_total_and_closed_set(max_risk: int) -> None:
    """Property: ``_risk_band`` is total over the valid 0-100 range and returns
    only one of the three documented bands."""
    band = _risk_band(max_risk)
    assert band in {"low", "medium", "high"}


@given(st.integers(min_value=0, max_value=100))
def test_risk_band_monotonic_non_decreasing(max_risk: int) -> None:
    """Property: band severity is non-decreasing in ``max_risk``."""
    order = {"low": 0, "medium": 1, "high": 2}
    if max_risk > 0:
        assert order[_risk_band(max_risk)] >= order[_risk_band(max_risk - 1)]


# ---------------------------------------------------------------------------
# Integration: APPROVAL_WAIT now labels with the derived band (not "unknown")
# ---------------------------------------------------------------------------


def _hist_count(metric: object) -> float:
    """Read a Histogram child's observation count via its samples (the public
    ``_count`` attribute is not exposed on the child object)."""
    for sample in metric._child_samples():  # type: ignore[attr-defined]
        if sample.name == "_count":
            return float(sample.value)
    return 0.0


def _scope(max_risk: int) -> ApprovalScope:
    return ApprovalScope(
        tenant_id=TenantId("acme"),
        run_id="r-band",
        plan_id=None,
        step_ids=[],
        allowed_action_types=["file_read"],
        max_risk=max_risk,
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
    )


def test_approval_wait_uses_derived_high_band_on_grant(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "band_grant.db")
    svc = ApprovalService(store)
    approval = svc.request_approval(actor="head:planner", scope=_scope(80))

    high_metric = APPROVAL_WAIT.labels(tenant_id="acme", risk_band="high")
    before_high = high_metric._sum.get()
    unknown_metric = APPROVAL_WAIT.labels(tenant_id="acme", risk_band="unknown")
    before_unknown = unknown_metric._sum.get()

    before_high_count = _hist_count(high_metric)
    svc.grant(approval.id)

    # The high band saw an observation; the legacy "unknown" band did NOT.
    assert high_metric._sum.get() >= before_high
    assert _hist_count(high_metric) == before_high_count + 1
    assert unknown_metric._sum.get() == before_unknown
    store.close()


def test_approval_wait_uses_derived_low_band_on_reject(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "band_reject.db")
    svc = ApprovalService(store)
    approval = svc.request_approval(actor="head:planner", scope=_scope(10))

    low_metric = APPROVAL_WAIT.labels(tenant_id="acme", risk_band="low")
    before_count = _hist_count(low_metric)

    svc.reject(approval.id)

    assert _hist_count(low_metric) == before_count + 1
    store.close()
