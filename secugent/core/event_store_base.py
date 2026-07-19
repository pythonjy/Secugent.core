# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — async :class:`EventStore` Protocol + HA lease primitives.

Why a parallel async protocol while the existing SQLite class stays sync?

* PHASE 0~9 callers (HEAD/SUB/Dispatcher/Steer/Evolution + 290+ tests) all
  use the sync :class:`secugent.core.event_store.EventStore`. Rewiring all
  call sites to ``await`` would be a 2nd big sweep right after PHASE 9's.
* PHASE 10's new orchestration paths (lease/recovery, PG backend) are async
  by nature. We model them with a dedicated Protocol here and let the new
  PG implementation conform to it.
* Step 7 onwards (PHASE 11/12) can gradually migrate the sync sites; until
  then the two interfaces co-exist.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from secugent.core.contracts import (
    Approval,
    Event,
    Run,
)
from secugent.core.tenancy import TenantId

__all__ = [
    "AsyncEventStore",
    "LeaderLease",
    "LeaseLostError",
    "LeaderLostError",
    "RunLease",
]


# ---------------------------------------------------------------------------
# HA lease types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunLease:
    run_id: str
    worker_id: str
    acquired_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class LeaderLease:
    """A DURABLE per-worker leader lease (DA-C1 B2 — the live single-writer fence).

    Unlike the session-scoped ``pg_advisory_lock`` (which rides a pooled
    connection that is RETURNED to the pool, so it is NOT durably held for the
    caller — see ``PgEventStore.try_acquire_leader``), this lease is a persistent
    ``leader_leases`` row with a TTL: a crashed leader's lease EXPIRES and another
    worker can take over, while the stale leader fails its next ``_assert_writer``
    with :class:`LeaderLostError` (deny-by-default — never two simultaneous
    durable writers, INV-C1-4). ``fence_token`` increases monotonically on every
    (re)acquisition so a write authorised under an older leadership epoch is
    rejected on renew.
    """

    worker_id: str
    lock_key: int
    acquired_at: datetime
    expires_at: datetime
    fence_token: int

    def is_expired(self, now: datetime) -> bool:
        """True iff the lease's TTL has elapsed at ``now`` (``expires_at <= now``)."""
        return self.expires_at <= now


class LeaseLostError(RuntimeError):
    """Raised when a worker that lost its lease tries to mutate state."""


class LeaderLostError(RuntimeError):
    """Raised when the orchestrator-leader role moves to another worker."""


# ---------------------------------------------------------------------------
# Async EventStore protocol
# ---------------------------------------------------------------------------


class AsyncEventStore(Protocol):
    """Async, tenant-aware, HA-aware event/run/approval store."""

    # event log
    async def append(self, event: Event) -> None: ...
    async def query(
        self,
        *,
        tenant_id: TenantId,
        run_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]: ...

    # run lifecycle
    async def upsert_run(self, run: Run) -> None: ...
    async def get_run(self, *, tenant_id: TenantId, run_id: str) -> Run | None: ...

    # approvals
    async def save_approval(self, approval: Approval) -> None: ...
    async def get_approval(self, *, tenant_id: TenantId, approval_id: str) -> Approval | None: ...
    async def list_pending_approvals(self, *, tenant_id: TenantId | None = None) -> list[Approval]: ...

    # HA primitives (PG-only — SQLite/InMemory may raise NotImplementedError)
    async def try_acquire_leader(self, worker_id: str, *, lock_key: int) -> bool: ...
    async def is_leader(self, worker_id: str, *, lock_key: int) -> bool: ...
    async def release_leader(self, worker_id: str, *, lock_key: int) -> None: ...
    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease: ...
    async def release_lease(self, *, run_id: str, worker_id: str) -> None: ...
    async def list_stale_leases(self) -> list[str]: ...
