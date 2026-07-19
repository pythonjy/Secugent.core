# SPDX-License-Identifier: Apache-2.0
"""Thin async adapter over the sync SQLite :class:`EventStore`.

Why this exists
---------------
The :class:`secugent.core.event_store_base.AsyncEventStore` protocol is the
forward-looking (HA, PG) interface. The whole live request/audit/STEER path,
however, still drives the *synchronous* :class:`secugent.core.event_store.EventStore`
(the initial tier keeps live traffic on SQLite — the async cutover is the next
tier). This adapter lets the *same* SQLite store satisfy the async protocol so that:

* the shared contract-equivalence suite can prove SQLite ≡ PG behaviour in CI
  (no Postgres required), and
* Stage 2 has a ready seam: swap ``SqliteAsyncEventStore`` for ``PgChainedEventStore``
  at the boundary without re-deriving the contract.

The underlying :class:`EventStore` is ``RLock``-guarded and therefore
thread-safe, so each call is dispatched to a worker thread via
:func:`asyncio.to_thread`. The protocol/sync name + argument differences
(``append``↔``append_event``, ``query``↔``list_events``, keyword ``run_id``
positional vs keyword) are mapped here, in one place.

HA lease primitives are intentionally not implemented — SQLite has no advisory
locks; the protocol documents these as PG-only and callers must use a
:class:`secugent.core.event_store_pg.PgEventStore` for leasing. Calling one here
raises :class:`NotImplementedError` (fail-closed, never a silent no-op).
"""

from __future__ import annotations

import asyncio

from secugent.core.contracts import Approval, Event, Run
from secugent.core.event_store import EventStore
from secugent.core.event_store_base import RunLease
from secugent.core.tenancy import TenantId

__all__ = ["SqliteAsyncEventStore"]


class SqliteAsyncEventStore:
    """Async :class:`AsyncEventStore` facade over a sync :class:`EventStore`.

    Implements the CRUD half of the protocol by delegating to the wrapped
    synchronous store on a worker thread. The HA-lease half raises
    :class:`NotImplementedError` (SQLite has no advisory locks).
    """

    def __init__(self, inner: EventStore) -> None:
        self._inner = inner

    @property
    def inner(self) -> EventStore:
        return self._inner

    # ------------------------------------------------------------------ #
    # Event log
    # ------------------------------------------------------------------ #

    async def append(self, event: Event) -> None:
        await asyncio.to_thread(self._inner.append_event, event)

    async def query(
        self,
        *,
        tenant_id: TenantId,
        run_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        return await asyncio.to_thread(
            lambda: self._inner.list_events(tenant_id=str(tenant_id), run_id=run_id, limit=limit)
        )

    # ------------------------------------------------------------------ #
    # Run lifecycle
    # ------------------------------------------------------------------ #

    async def upsert_run(self, run: Run) -> None:
        await asyncio.to_thread(self._inner.upsert_run, run)

    async def get_run(self, *, tenant_id: TenantId, run_id: str) -> Run | None:
        return await asyncio.to_thread(lambda: self._inner.get_run(run_id, tenant_id=str(tenant_id)))

    # ------------------------------------------------------------------ #
    # Approvals
    # ------------------------------------------------------------------ #

    async def save_approval(self, approval: Approval) -> None:
        await asyncio.to_thread(self._inner.save_approval, approval)

    async def get_approval(self, *, tenant_id: TenantId, approval_id: str) -> Approval | None:
        return await asyncio.to_thread(
            lambda: self._inner.get_approval(approval_id, tenant_id=str(tenant_id))
        )

    async def list_pending_approvals(self, *, tenant_id: TenantId | None = None) -> list[Approval]:
        scoped = str(tenant_id) if tenant_id is not None else None
        return await asyncio.to_thread(lambda: self._inner.list_pending_approvals(tenant_id=scoped))

    # ------------------------------------------------------------------ #
    # HA primitives — PG-only; SQLite cannot provide advisory locks.
    # ------------------------------------------------------------------ #

    async def try_acquire_leader(self, worker_id: str, *, lock_key: int) -> bool:
        raise NotImplementedError("SQLite backend has no advisory leader lock — use PgEventStore")

    async def is_leader(self, worker_id: str, *, lock_key: int) -> bool:
        raise NotImplementedError("SQLite backend has no advisory leader lock — use PgEventStore")

    async def release_leader(self, worker_id: str, *, lock_key: int) -> None:
        raise NotImplementedError("SQLite backend has no advisory leader lock — use PgEventStore")

    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        raise NotImplementedError("SQLite backend has no run leases — use PgEventStore")

    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        raise NotImplementedError("SQLite backend has no run leases — use PgEventStore")

    async def release_lease(self, *, run_id: str, worker_id: str) -> None:
        raise NotImplementedError("SQLite backend has no run leases — use PgEventStore")

    async def list_stale_leases(self) -> list[str]:
        raise NotImplementedError("SQLite backend has no run leases — use PgEventStore")
