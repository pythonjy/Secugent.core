# SPDX-License-Identifier: Apache-2.0
"""Property-based invariants for the HA lease + recovery driver.

Two §B-10 invariants are exercised over arbitrary input:

* LEADER-SINGLETON — for any interleaving of acquire/renew/release across
  multiple workers, at most one worker holds a given run's (unexpired) lease at
  a time. Verified on :class:`InMemoryLeaseManager`, the reference backend the
  PG/SQLite managers must match.
* RECOVERY-IDEMPOTENCY — for any set of stale runs, applying ``run_recovery``
  once vs twice yields identical final states and never double-enqueues.
"""

from __future__ import annotations

from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.core.event_store_base import LeaseLostError
from secugent.orchestrator.lease import InMemoryLeaseManager
from secugent.orchestrator.recovery import run_recovery
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunRecord,
    RunState,
)

# A small worker / run alphabet keeps interleavings dense (more contention).
_WORKERS = ["w0", "w1", "w2"]
_RUNS = ["run-a", "run-b"]
_STATES = list(RunState)

_lease_ops = st.lists(
    st.tuples(
        st.sampled_from(["acquire", "renew", "release"]),
        st.sampled_from(_RUNS),
        st.sampled_from(_WORKERS),
    ),
    min_size=0,
    max_size=40,
)


@given(ops=_lease_ops)
@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_leader_singleton_invariant(ops: list[tuple[str, str, str]]) -> None:
    """At most one worker ever holds a given run's unexpired lease."""
    mgr = InMemoryLeaseManager()
    # Long TTL so nothing expires mid-sequence — we test mutual exclusion, not
    # expiry reclamation (covered in the contract tests).
    ttl = 3600
    holders: dict[str, str] = {}

    for op, run_id, worker in ops:
        if op == "acquire":
            try:
                await mgr.acquire_run(run_id, worker, ttl)
            except LeaseLostError:
                # Held by someone else → our model must agree it is held by !=worker.
                assert holders.get(run_id) not in (None, worker)
                continue
            holders[run_id] = worker
        elif op == "renew":
            try:
                await mgr.renew(run_id, worker, ttl)
            except LeaseLostError:
                assert holders.get(run_id) != worker
                continue
            assert holders.get(run_id) == worker
        else:  # release
            await mgr.release(run_id, worker)
            if holders.get(run_id) == worker:
                holders.pop(run_id, None)

        # INVARIANT: the manager's view of each held run has exactly one holder,
        # and it matches our independent model.
        for r in _RUNS:
            stale = await mgr.list_stale()
            # Anything not stale and present is singly-held by construction
            # (dict can't hold two values for one key); cross-check our model.
            if r in holders and r not in stale:
                # Re-acquiring by the recorded holder must succeed (idempotent),
                # proving no other worker secretly owns it.
                await mgr.acquire_run(r, holders[r], ttl)


_run_specs = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=9),  # run index → unique id
        st.sampled_from(_STATES),
    ),
    min_size=0,
    max_size=12,
    unique_by=lambda t: t[0],
)


async def _build_store(specs: list[tuple[int, RunState]]) -> tuple[InMemoryRunStateStore, list[RunRecord]]:
    store = InMemoryRunStateStore()
    records: list[RunRecord] = []
    for idx, state in specs:
        run_id = f"run-{idx}"
        await store.create(run_id, "명령", {"tenant": "kr-public"})
        if state is not RunState.PENDING:
            await store.update_state(run_id, state)
        rec = await store.get(run_id)
        assert rec is not None
        records.append(rec)
    return store, records


@given(specs=_run_specs)
@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_recovery_idempotent_and_no_double_enqueue(
    specs: list[tuple[int, RunState]],
) -> None:
    store, snapshot = await _build_store(specs)
    enqueued: list[str] = []
    events: list[tuple[str, str, dict[str, Any]]] = []

    async def enqueue(record: RunRecord) -> None:
        enqueued.append(record.run_id)
        # Mimic real resume: advance out of the resumable set.
        await store.update_state(record.run_id, RunState.EXECUTING)

    async def publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        events.append((run_id, topic, payload))

    await run_recovery(snapshot, state_store=store, enqueue=enqueue, publish_event=publish)
    enqueued_after_first = list(enqueued)
    states_after_first = {r.run_id: (await store.get(r.run_id)).state for r in snapshot}  # type: ignore[union-attr]

    await run_recovery(snapshot, state_store=store, enqueue=enqueue, publish_event=publish)
    states_after_second = {r.run_id: (await store.get(r.run_id)).state for r in snapshot}  # type: ignore[union-attr]

    # IDEMPOTENCY: no extra enqueue, identical final states.
    assert enqueued == enqueued_after_first
    assert states_after_first == states_after_second


@given(specs=_run_specs)
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_recovery_report_partitions_all_runs(
    specs: list[tuple[int, RunState]],
) -> None:
    """Every input run appears in exactly one report bucket; buckets are sorted."""
    store, snapshot = await _build_store(specs)

    async def enqueue(record: RunRecord) -> None:
        return None

    async def publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        return None

    report = await run_recovery(snapshot, state_store=store, enqueue=enqueue, publish_event=publish)

    all_ids = {r.run_id for r in snapshot}
    bucketed = list(report.resumed) + list(report.failed) + list(report.skipped)
    assert sorted(bucketed) == sorted(all_ids)
    assert len(bucketed) == len(all_ids)  # no run in two buckets
    assert list(report.resumed) == sorted(report.resumed)
    assert list(report.failed) == sorted(report.failed)
    assert list(report.skipped) == sorted(report.skipped)
