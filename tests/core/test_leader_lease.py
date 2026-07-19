# SPDX-License-Identifier: Apache-2.0
"""Durable leader-lease decision logic (unit + property, no Postgres).

The SQL primitives (``acquire_leader_lease`` / ``renew_leader_lease`` /
``assert_leader_lease``) are thin wrappers over the PURE decision
:func:`secugent.core.event_store_pg._decide_leader_acquisition`, which is fully
property-testable without a database. The key safety invariant (INV-C1-4):

    two distinct workers can NEVER both hold a live (non-expired) leader lease.

A real-Postgres 2-worker fence is the skip-gated ``tests/integration/
test_pg_single_writer``. §C-3 scenario: KB국민은행 HA pods electing one writer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.event_store_base import LeaderLease
from secugent.core.event_store_pg import _decide_leader_acquisition

_NOW = datetime(2026, 3, 31, 9, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# unit — the four decision branches
# --------------------------------------------------------------------------- #


def test_grant_when_no_existing_lease() -> None:
    granted, fence = _decide_leader_acquisition(existing=None, now=_NOW, worker_id="kb-bank-pod-a")
    assert granted is True
    assert fence == 1


def test_takeover_when_existing_lease_expired() -> None:
    existing = ("kb-bank-pod-a", _NOW - timedelta(seconds=1), 7)  # expired
    granted, fence = _decide_leader_acquisition(existing=existing, now=_NOW, worker_id="kb-bank-pod-b")
    assert granted is True
    assert fence == 8  # monotonic bump


def test_refresh_when_same_worker_holds_live_lease() -> None:
    existing = ("kb-bank-pod-a", _NOW + timedelta(seconds=30), 3)
    granted, fence = _decide_leader_acquisition(existing=existing, now=_NOW, worker_id="kb-bank-pod-a")
    assert granted is True
    assert fence == 4


def test_reject_when_other_worker_holds_live_lease() -> None:
    existing = ("kb-bank-pod-a", _NOW + timedelta(seconds=30), 5)
    granted, fence = _decide_leader_acquisition(existing=existing, now=_NOW, worker_id="kb-bank-pod-b")
    assert granted is False
    assert fence == 5  # unchanged — the incumbent keeps the lock


def test_boundary_expiry_is_inclusive_expired() -> None:
    """``expires_at == now`` counts as EXPIRED (``<=``) so a lease never lingers a
    tick past its TTL and block a takeover."""
    existing = ("kb-bank-pod-a", _NOW, 1)
    granted, _ = _decide_leader_acquisition(existing=existing, now=_NOW, worker_id="kb-bank-pod-b")
    assert granted is True


def test_leader_lease_is_expired_helper() -> None:
    lease = LeaderLease(
        worker_id="w", lock_key=1, acquired_at=_NOW, expires_at=_NOW + timedelta(seconds=10), fence_token=1
    )
    assert lease.is_expired(_NOW) is False
    assert lease.is_expired(_NOW + timedelta(seconds=10)) is True  # boundary == expired
    assert lease.is_expired(_NOW + timedelta(seconds=11)) is True


# --------------------------------------------------------------------------- #
# property — mutual exclusion + monotonic fence (INV-C1-4)
# --------------------------------------------------------------------------- #

_WORKERS = st.sampled_from(["kb-bank-pod-a", "kb-bank-pod-b", "kb-bank-pod-c"])
_OFFSETS = st.integers(min_value=-120, max_value=120)
_FENCES = st.integers(min_value=0, max_value=10_000)


@settings(max_examples=300)
@given(holder=_WORKERS, expires_offset=_OFFSETS, fence=_FENCES, worker=_WORKERS)
def test_a_different_worker_only_wins_when_incumbent_expired(
    holder: str, expires_offset: int, fence: int, worker: str
) -> None:
    """Mutual exclusion: a DIFFERENT worker is granted ONLY if the incumbent's
    lease was already expired at ``now`` — never while it is live."""
    expires_at = _NOW + timedelta(seconds=expires_offset)
    granted, new_fence = _decide_leader_acquisition(
        existing=(holder, expires_at, fence), now=_NOW, worker_id=worker
    )
    if granted and worker != holder:
        assert expires_at <= _NOW, "a different worker won while the incumbent lease was still live"
    if not granted:
        # Rejection happens ONLY for a live lease held by another worker.
        assert worker != holder and expires_at > _NOW
    # Monotonic fence on every grant over an existing row.
    if granted:
        assert new_fence == fence + 1 and new_fence > fence


@settings(max_examples=200)
@given(
    events=st.lists(
        st.tuples(_WORKERS, _OFFSETS, st.integers(min_value=1, max_value=60)), min_size=1, max_size=20
    )
)
def test_simulated_election_never_has_two_live_leaders(events: list[tuple[str, int, int]]) -> None:
    """Replay a sequence of acquisition attempts against a single in-memory row;
    at no point do two distinct workers simultaneously hold a live lease."""
    row: tuple[str, datetime, int] | None = None
    for worker, when_offset, ttl in events:
        now = _NOW + timedelta(seconds=when_offset)
        granted, fence = _decide_leader_acquisition(existing=row, now=now, worker_id=worker)
        if granted:
            # The incumbent (if any and different) MUST have been expired at ``now``.
            if row is not None and row[0] != worker:
                assert row[1] <= now
            row = (worker, now + timedelta(seconds=ttl), fence)
    # The terminal row is internally consistent (a single holder).
    assert row is None or isinstance(row[0], str)
