# SPDX-License-Identifier: Apache-2.0
"""DA-C1 store-selection seam + synchronous bridge over the async PG store.

The live request handlers (``api/main.py`` ``post_command`` etc.) are ``async
def`` but call the durable store **synchronously** —
``state_.store.upsert_run(run)`` / ``state_.store.append_event(event)`` — because
the reference store (:class:`secugent.core.event_store.EventStore`, SQLite) is
sync. The production store (:class:`secugent.core.event_store_pg.PgEventStore`)
is **async**. A backend swap therefore cannot be a drop-in.

This module provides:

* :func:`select_live_store` — a pure, config-driven seam. ``DATABASE_URL`` unset
  ⇒ the SQLite store (dev/air-gap default, unchanged); set ⇒ the PG-backed
  bridge. Fully unit-testable with fakes (no infra).
* :class:`SyncPgEventStore` — a thin synchronous facade that drives the async
  :class:`PgChainedEventStore` on a **dedicated** background event loop, so it
  exposes the exact sync methods the live path uses (``upsert_run``,
  ``append_event``, ``append_chained``, ``save_approval``). It mirrors the SQLite
  split: ``append_event`` writes a raw (unchained) event row, ``append_chained``
  writes the §C-2 hash-chained row — so PG parity matches the SQLite reference.

HONEST CONCURRENCY CAVEAT (why the live request-path swap is STAGED, not flipped
on by default): each bridge call blocks the **calling** thread until the PG
round-trip returns (``run_coroutine_threadsafe(...).result()``). The bridge is
deadlock-free — the coroutine runs on a *separate* loop/thread, never the
caller's loop (INV-C1-7) — but if the live request path (which runs ON the
uvicorn event loop) called it, that loop would block for the duration of the PG
write, serialising concurrent requests. Routing the live request path onto PG
therefore needs either (a) an async facade (await the async store directly; the
handlers are already ``async def``) or (b) acceptance of that serialisation,
*plus* a real Postgres to validate end-to-end. Until then SQLite stays the
live default and this bridge is the proven building block for the staged cutover
(migration CLI, background/worker writes, tests).
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeVar

from secugent.core.contracts import Approval, Event, Run
from secugent.core.tenancy import TenantId

if TYPE_CHECKING:
    from secugent.audit.hash_chain import ChainedEventRecord, ChainedEventStore
    from secugent.core.event_store_pg import PgChainedEventStore

__all__ = [
    "AsyncChainedStore",
    "AsyncLiveStore",
    "LiveWriteStore",
    "SyncPgEventStore",
    "select_live_store",
]

_T = TypeVar("_T")

# Wall-clock bound for any single bridged PG call. A wedged backend must not hang
# the caller forever; a timeout surfaces as :class:`TimeoutError` (fail-closed,
# never a silent dropped write). Module-level so a test can shrink it.
_DEFAULT_CALL_TIMEOUT_S: float = 30.0
_THREAD_JOIN_TIMEOUT_S: float = 5.0


class LiveWriteStore(Protocol):
    """The SYNC write surface the live request path calls on the durable store.

    Both :class:`secugent.core.event_store.EventStore` (SQLite, the default) and
    :class:`SyncPgEventStore` (PG bridge) satisfy this structurally, so the seam
    can return either without the call sites knowing which backend is live.
    """

    def upsert_run(self, run: Run) -> None: ...
    def append_event(self, event: Event) -> None: ...


class AsyncChainedStore(Protocol):
    """The async surface :class:`SyncPgEventStore` drives.

    Implemented by :class:`secugent.core.event_store_pg.PgChainedEventStore`;
    a fake satisfies it for unit tests with no Postgres.
    """

    async def upsert_run(self, run: Run) -> None: ...
    async def append(self, event: Event) -> None: ...
    async def save_approval(self, approval: Approval) -> None: ...


class _RawAppendable(Protocol):
    async def append(self, event: Event) -> None: ...


class SyncPgEventStore:
    """Synchronous facade over an async PG chained store, on a dedicated loop.

    The wrapped store's single-writer fence (DA-C1 INV-C1-4) and tenant
    second-guard (DA-M2) live in :class:`PgEventStore`, so every write through
    this bridge is fenced and tenant-bound without the bridge re-deciding policy
    (single source of truth, §A).
    """

    def __init__(
        self,
        chained: PgChainedEventStore,
        *,
        call_timeout_s: float = _DEFAULT_CALL_TIMEOUT_S,
    ) -> None:
        self._chained = chained
        # The raw (unchained) inner store mirrors EventStore.append_event: a plain
        # event row WITHOUT a chain link, for the non-§C-2 events the SQLite live
        # path writes through ``state_.store.append_event``.
        self._raw: _RawAppendable = chained.inner
        self._call_timeout_s = call_timeout_s
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="secugent-pg-bridge",
            daemon=True,
        )
        self._thread.start()

    def _run(self, coro: Coroutine[Any, Any, _T]) -> _T:
        """Submit ``coro`` to the dedicated loop and block for its result.

        Deadlock-free: ``coro`` runs on ``self._loop`` (a different thread), never
        the caller's loop. ``result(timeout)`` raises :class:`TimeoutError` if the
        backend wedges (fail-closed) rather than blocking forever.
        """
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(self._call_timeout_s)

    # -- sync write surface (mirrors EventStore / ChainedEventStore) ------ #

    def upsert_run(self, run: Run) -> None:
        self._run(self._chained.upsert_run(run))

    def append_event(self, event: Event) -> None:
        """Persist a raw (unchained) event row — mirrors ``EventStore.append_event``."""
        self._run(self._raw.append(event))

    def append_chained(self, event: Event) -> None:
        """Persist a §C-2 hash-chained event — mirrors ``ChainedEventStore.append_event``."""
        self._run(self._chained.append(event))

    def save_approval(self, approval: Approval) -> None:
        self._run(self._chained.save_approval(approval))

    def close(self) -> None:
        """Stop the dedicated loop and join its thread (no leaked thread/loop)."""
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=_THREAD_JOIN_TIMEOUT_S)
        if not self._loop.is_closed():
            self._loop.close()


class AsyncLiveStore:
    """Backend-neutral ASYNC durable-store facade for the live (``async def``)
    request/audit/STEER handlers (DA-C1 B3 — the staged successor to
    :class:`SyncPgEventStore`).

    The handlers are already ``async def`` but drive the durable store
    *synchronously* today (``state_.store.append_event(...)``) because the SQLite
    reference store is sync. This facade lets a handler ``await`` the store
    directly, so the eventual PG cutover does NOT serialise the uvicorn loop on a
    cross-thread bridge (the honest-caveat path documented on
    :class:`SyncPgEventStore`): the PG branch awaits the async store on the loop.

    Two branches, ONE surface:

    * ``backend="sqlite"`` (dev / air-gap default): DIRECT sync delegation to the
      SAME cached :class:`ChainedEventStore` and its ``inner`` :class:`EventStore`.
      No thread offload, no re-ordering — each ``async def`` here just wraps the
      identical sync call the handler makes today, so the determinism path and the
      event ORDER are byte-identical (CLAUDE.md §B "행동·순서 동일"). The §C-2
      hash chain stays the single cached decorator (one chain over one DB file).
    * ``backend="postgres"``: ``await`` the async :class:`PgChainedEventStore`
      (which already carries RLS + the DA-M2 tenant second-guard + the DA-C1
      single-writer fence). New behaviour lives ONLY on this branch — so the
      determinism pin, which never traverses the live path, is unaffected.

    NOTE (spec refinement): the SQLite branch takes a :class:`ChainedEventStore`
    (not a bare :class:`EventStore` as the B3 sketch typed it) so that
    ``append_chained``/``verify_chain`` reuse the SINGLE cached audit chain
    (SECURITY_CONTRACT §10.1 — one decorator over one DB file) instead of forking
    a second chain; raw reads/writes go through its ``inner`` store. The read
    methods carry ``tenant_id`` because the PG branch needs it for RLS.

    fail-closed: constructing a backend with its store absent raises; a wrong-
    backend store is never silently substituted (INV-C1-3).
    """

    def __init__(
        self,
        *,
        sqlite: ChainedEventStore | None,
        pg: PgChainedEventStore | None,
        backend: Literal["sqlite", "postgres"],
    ) -> None:
        if backend == "sqlite" and sqlite is None:
            raise ValueError("AsyncLiveStore(backend='sqlite') requires a sqlite ChainedEventStore")
        if backend == "postgres" and pg is None:
            raise ValueError("AsyncLiveStore(backend='postgres') requires a PgChainedEventStore")
        self._sqlite = sqlite
        self._pg = pg
        self._backend: Literal["sqlite", "postgres"] = backend

    @property
    def backend(self) -> Literal["sqlite", "postgres"]:
        """``"sqlite"`` or ``"postgres"`` — the SELECTED live backend (observability)."""
        return self._backend

    def _sq(self) -> ChainedEventStore:
        store = self._sqlite
        if store is None:  # pragma: no cover - __init__ guarantees this on the sqlite branch
            raise RuntimeError("AsyncLiveStore: sqlite store not configured")
        return store

    def _pgs(self) -> PgChainedEventStore:
        store = self._pg
        if store is None:  # pragma: no cover - __init__ guarantees this on the postgres branch
            raise RuntimeError("AsyncLiveStore: pg store not configured")
        return store

    # -- write surface ---------------------------------------------------- #

    async def upsert_run(self, run: Run) -> None:
        if self._backend == "sqlite":
            self._sq().inner.upsert_run(run)
        else:
            await self._pgs().upsert_run(run)

    async def append_event(self, event: Event) -> None:
        """Persist a raw (unchained) event row — mirrors ``EventStore.append_event``."""
        if self._backend == "sqlite":
            self._sq().inner.append_event(event)
        else:
            await self._pgs().inner.append(event)

    async def append_chained(self, event: Event) -> ChainedEventRecord:
        """Persist a §C-2 hash-chained event and return its record."""
        if self._backend == "sqlite":
            return self._sq().append_event(event)
        return await self._pgs().append_chained(event)

    async def save_approval(self, approval: Approval) -> None:
        if self._backend == "sqlite":
            self._sq().inner.save_approval(approval)
        else:
            await self._pgs().save_approval(approval)

    # -- read surface (every method the live handlers use) ---------------- #

    async def list_events(
        self, *, tenant_id: str, run_id: str | None = None, limit: int = 100
    ) -> list[Event]:
        if self._backend == "sqlite":
            return self._sq().inner.list_events(tenant_id=tenant_id, run_id=run_id, limit=limit)
        return await self._pgs().query(tenant_id=TenantId(tenant_id), run_id=run_id, limit=limit)

    async def count_events(self, *, tenant_id: str, run_id: str | None = None) -> int:
        if self._backend == "sqlite":
            return self._sq().inner.count_events(tenant_id=tenant_id, run_id=run_id)
        return await self._pgs().count_events(tenant_id=TenantId(tenant_id), run_id=run_id)

    async def get_run(self, *, tenant_id: str, run_id: str) -> Run | None:
        if self._backend == "sqlite":
            return self._sq().inner.get_run(run_id, tenant_id=tenant_id)
        return await self._pgs().get_run(tenant_id=TenantId(tenant_id), run_id=run_id)

    async def get_event(self, *, tenant_id: str, event_id: str) -> Event | None:
        if self._backend == "sqlite":
            return self._sq().inner.get_event(event_id, tenant_id=tenant_id)
        return await self._pgs().get_event(tenant_id=TenantId(tenant_id), event_id=event_id)

    async def get_approval(self, *, tenant_id: str, approval_id: str) -> Approval | None:
        if self._backend == "sqlite":
            return self._sq().inner.get_approval(approval_id, tenant_id=tenant_id)
        return await self._pgs().get_approval(tenant_id=TenantId(tenant_id), approval_id=approval_id)

    async def list_pending_approvals(self, *, tenant_id: str | None = None) -> list[Approval]:
        if self._backend == "sqlite":
            return self._sq().inner.list_pending_approvals(tenant_id=tenant_id)
        scoped = TenantId(tenant_id) if tenant_id is not None else None
        return await self._pgs().list_pending_approvals(tenant_id=scoped)

    async def verify_chain(self, *, tenant_id: str) -> bool:
        """Walk the §C-2 chain; raise ``AuditChainBrokenError`` on the first break.

        Tenant-scoped (matches both backends' ``verify_chain`` contract); returns
        ``True`` when intact. The PG branch's false-break hazards — JSONB numeric
        re-formatting (``1.50`` → ``1.5``) and ``TIMESTAMPTZ`` microsecond
        truncation — are neutralised by verifying against the STORED canonical
        bytes (``body_canonical``), pinned by the JSONB round-trip test.
        """
        if self._backend == "sqlite":
            return self._sq().verify_chain(tenant_id=tenant_id)
        return await self._pgs().verify_chain(tenant_id=TenantId(tenant_id))


def select_live_store(
    *,
    database_url: str | None,
    sqlite_store: LiveWriteStore,
    pg_bridge_factory: Callable[[], LiveWriteStore],
) -> tuple[LiveWriteStore, str]:
    """Pick the live durable write store from config (DA-C1 seam).

    Pure and side-effect free except for ``pg_bridge_factory()`` (called only on
    the PG branch). Returns ``(store, backend_name)`` where ``backend_name`` is
    ``"sqlite"`` or ``"postgres"`` for logging/observability.

    * ``database_url`` unset/blank ⇒ ``sqlite_store`` (dev/air-gap default;
      unchanged behaviour, so the determinism workflow path is untouched).
    * ``database_url`` set ⇒ ``pg_bridge_factory()`` (the PG-backed bridge).
      Never falls back to SQLite on a PG construction error — the factory's
      exception propagates (fail-closed: the operator believes PG is live,
      INV-C1-3).
    """
    if database_url is not None and database_url.strip():
        bridge: LiveWriteStore = pg_bridge_factory()
        return bridge, "postgres"
    return sqlite_store, "sqlite"
