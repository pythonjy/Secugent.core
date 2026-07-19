# SPDX-License-Identifier: Apache-2.0
"""Single-writer fence + tenant second-guard (no Postgres).

Both guards are pure policy checks that run BEFORE any SQL, so they are unit-tested
against a bare ``PgEventStore`` (built via ``__new__`` to skip the engine) and a
fake async connection — no driver, no DB. The full INSERT path is exercised only
by the infra-gated ``tests/integration/test_pg_event_store.py`` (skipped without
``DATABASE_URL``).
"""

from __future__ import annotations

from typing import Any

import pytest

from secugent.core.event_store import EventStoreError
from secugent.core.event_store_base import LeaderLostError
from secugent.core.event_store_pg import PgEventStore
from secugent.core.tenancy import TenantId, set_current_tenant
from secugent.deploy.airgap import HaWriterArbiter
from secugent.orchestrator.lease import InMemoryLeaseManager

_KB = TenantId("kb-fin")
_GOV = TenantId("mois-gov")


class _GrantGuard:
    async def assert_writer(self, worker_id: str) -> None:
        return None


class _DenyGuard:
    async def assert_writer(self, worker_id: str) -> None:
        raise LeaderLostError(f"worker {worker_id!r} is not the writer; write denied")


class _FakeConn:
    """Records ``execute`` calls; the guard must raise BEFORE the first call."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def execute(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(args)


def _bare_store() -> PgEventStore:
    """A ``PgEventStore`` without a real engine (guards need no DB)."""
    store = PgEventStore.__new__(PgEventStore)
    store._writer_guard = None
    store._worker_id = None
    store._leader_lease = None  # durable-lease fence (disarmed in guard tests)
    return store


# --- INV-C1-4: single-writer fence ----------------------------------- #


async def test_assert_writer_noop_when_unwired() -> None:
    store = _bare_store()
    await store._assert_writer()  # no guard ⇒ no-op (dev/single-node unchanged)


async def test_assert_writer_rejects_non_leader() -> None:
    store = _bare_store()
    store.set_writer_guard(_DenyGuard(), "worker-2")
    with pytest.raises(LeaderLostError):
        await store._assert_writer()


async def test_assert_writer_allows_leader() -> None:
    store = _bare_store()
    store.set_writer_guard(_GrantGuard(), "worker-1")
    await store._assert_writer()  # leader ⇒ proceeds


# --- INV-C1-4: REAL arbiter coverage (not a hardcoded fake) ----------- #
#
# The _GrantGuard/_DenyGuard fakes above only prove that PgEventStore._assert_writer
# plumbs through to guard.assert_writer — they CANNOT reveal whether the wired
# object (HaWriterArbiter + LeaseManager.is_leader) actually distinguishes a leader
# from a standby. These tests wire the REAL HaWriterArbiter over a REAL lease whose
# is_leader honors worker_id, so the assertion reflects the wired object's behaviour.


async def test_real_arbiter_over_worker_aware_lease_fences_non_leader() -> None:
    # InMemoryLeaseManager.is_leader HONORS worker_id (the single-node + test
    # backend). With the REAL arbiter, the leader proceeds and a DIFFERENT worker
    # (a standby that also armed the guard) fails closed — genuine single-writer.
    lease = InMemoryLeaseManager()
    assert await lease.try_acquire_leader("worker-1") is True  # worker-1 is the writer
    arbiter = HaWriterArbiter(lease)

    leader_store = _bare_store()
    leader_store.set_writer_guard(arbiter, "worker-1")
    await leader_store._assert_writer()  # the real leader proceeds

    standby_store = _bare_store()
    standby_store.set_writer_guard(arbiter, "worker-2")  # NOT the writer
    with pytest.raises(LeaderLostError):
        await standby_store._assert_writer()  # real arbiter + real is_leader rejects


class _WorkerAgnosticLease(InMemoryLeaseManager):
    """Faithfully models ``PgEventStore.is_leader`` (event_store_pg.py:627): it
    reports whether the advisory lock is held by ANY session, IGNORING ``worker_id``
    (and the real PG lock rides a non-durable pooled connection). Subclasses the
    real InMemory manager so it still satisfies the full ``LeaseManager`` protocol;
    only ``is_leader`` drops the per-worker check to reproduce the PG limitation."""

    async def is_leader(self, worker_id: str) -> bool:  # noqa: ARG002 - worker_id IGNORED (PG behaviour)
        return self._leader_worker is not None


async def test_pg_style_worker_agnostic_lease_cannot_fence_standby() -> None:
    # HONEST REGRESSION (finding #3): the wired fence is only as strong as the
    # lease's is_leader. The PgLeaseManager advisory-lock is_leader IGNORES
    # worker_id and is non-durable, so over it the REAL HaWriterArbiter CANNOT tell
    # a standby from the leader — a non-leader's assert_writer does NOT raise. This
    # is asserted explicitly (not papered over): the advisory-lock PG backend is
    # PROVISIONED, not the live cross-process single-writer fence. The live PG fence
    # needs a durable per-worker lease (TTL+heartbeat row or a dedicated long-lived
    # connection), which is STAGED (spec §3.4); the live request path still persists
    # to SQLite today, so this is not an active breakage. The InMemory/SQLite lease
    # backends DO honor worker_id (test above), which is what single-node + tests use.
    lease = _WorkerAgnosticLease()
    assert await lease.try_acquire_leader("worker-1") is True  # the lock is "held"
    arbiter = HaWriterArbiter(lease)

    standby_store = _bare_store()
    standby_store.set_writer_guard(arbiter, "worker-2")  # a DIFFERENT (non-leader) worker
    # Over a worker_id-agnostic lease the fence does NOT reject the standby — this
    # documents and locks in the known PG limitation rather than hiding it.
    await standby_store._assert_writer()


# --- Request-scoped tenant second-guard over FORCE RLS --------------- #


async def test_bind_tenant_mismatch_fails_closed() -> None:
    conn = _FakeConn()
    with set_current_tenant(_GOV):
        with pytest.raises(EventStoreError, match="tenant context mismatch"):
            await PgEventStore._bind_tenant(conn, str(_KB))
    # Fail-closed BEFORE binding app.tenant_id — no SQL executed.
    assert conn.calls == []


async def test_bind_tenant_match_binds() -> None:
    conn = _FakeConn()
    with set_current_tenant(_KB):
        await PgEventStore._bind_tenant(conn, str(_KB))
    assert len(conn.calls) == 1  # set_config executed


async def test_bind_tenant_unbound_context_allows() -> None:
    """Background/scheduler writes have no bound context ⇒ RLS alone applies."""
    conn = _FakeConn()
    await PgEventStore._bind_tenant(conn, str(_KB))
    assert len(conn.calls) == 1


async def test_bind_tenant_owner_sentinel_exempt() -> None:
    """The "" owner/cross-tenant read (list_pending_approvals(tenant=None)) is
    exempt even with a bound context — it must not false-trip the guard."""
    conn = _FakeConn()
    with set_current_tenant(_GOV):
        await PgEventStore._bind_tenant(conn, "")
    assert len(conn.calls) == 1
