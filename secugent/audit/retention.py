# SPDX-License-Identifier: Apache-2.0
"""Deterministic 6-month audit retention.

EU AI Act Art.26 and the Korean AI Basic Act require operators to *retain*
machine-generated logs for at least six months. They do not require keeping them
forever, and an unbounded ``events`` table is an operational liability. This
module enforces the retention window **deterministically** while preserving the
tamper-evident append-only hash chain (:mod:`secugent.audit.hash_chain`).

Design:

* :func:`plan` is a **pure** function — given ``now``, the set of sealed days,
  and ``retain_days`` it computes which sealed days are past the retention floor
  and therefore purge candidates. It never touches I/O, so identical inputs
  always yield an identical :class:`RetentionPlan` (100x determinism test).
* :class:`RetentionService.apply` executes the plan with the **archive → verify
  → purge** discipline: a day's events are first *copied* into an
  ``events_archive`` table, the chain is re-verified end-to-end, and the hot
  rows are deleted **only if** verification succeeds. The ``event_chain`` table
  is never mutated, so :meth:`ChainedEventStore.verify_chain` keeps passing —
  archived rows are resolved through the store's live∪archive union read.
* Per-day isolation: a verify failure for one day records an error and skips
  that day's purge (fail-closed integrity) without aborting the whole pass
  (availability), mirroring the daily Merkle sealer's per-tenant isolation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Protocol

__all__ = [
    "DayRetentionOutcome",
    "RetentionPlan",
    "RetentionResult",
    "RetentionService",
    "ChainedStoreRetentionAdapter",
    "SealedDaysProvider",
    "plan",
    "wire_retention_hook",
]

_LOG = logging.getLogger("secugent.audit.retention")

DEFAULT_RETAIN_DAYS = 180  # ≈ 6 months — EU AI Act Art.26 / Korean AI Act floor.


# --------------------------------------------------------------------------- #
# Pure planning
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RetentionPlan:
    """The deterministic result of :func:`plan`.

    ``purge_days`` are sealed days strictly older than ``retain_days`` (safe to
    archive+purge). ``retained_sealed_days`` are sealed days still inside the
    window (must be kept). Both are sorted ascending and de-duplicated.
    """

    now: date
    retain_days: int
    purge_days: tuple[date, ...]
    retained_sealed_days: tuple[date, ...]


def plan(
    *,
    now: date,
    sealed_days: Iterable[date],
    retain_days: int = DEFAULT_RETAIN_DAYS,
) -> RetentionPlan:
    """Compute the retention plan. PURE — no I/O, deterministic.

    A sealed day ``d`` is a purge candidate iff ``(now - d).days > retain_days``.
    Days not in ``sealed_days`` are never candidates (an unsealed day may still
    receive late events, and purging it would break the chain). ``retain_days``
    must be ``>= 0``; a negative window is rejected fail-fast.
    """
    if retain_days < 0:
        raise ValueError(f"retain_days must be >= 0, got {retain_days}")

    unique_sealed = sorted(set(sealed_days))
    purge: list[date] = []
    retained: list[date] = []
    for day in unique_sealed:
        age = (now - day).days
        if age > retain_days:
            purge.append(day)
        else:
            retained.append(day)
    return RetentionPlan(
        now=now,
        retain_days=retain_days,
        purge_days=tuple(purge),
        retained_sealed_days=tuple(retained),
    )


# --------------------------------------------------------------------------- #
# Store contract
# --------------------------------------------------------------------------- #


class _ArchivableChainStore(Protocol):
    """Structural view of the store bits the retention service drives.

    These are **synchronous** methods (bare ``int``/``bool`` returns). The
    in-tree implementation is :class:`ChainedStoreRetentionAdapter`, which wraps
    a hash-chained SQLite store (delegating archive/purge to its inner SQLite
    store and verify to the chain) — that adapter satisfies this Protocol.

    The PG store (:class:`secugent.core.event_store_pg.PgEventStore`) does NOT
    satisfy this Protocol: its ``archive_day``/``purge_day``/``is_day_archived``
    (and the PG chain's ``verify_chain``) are ``async def`` coroutines, and its
    ``verify_chain`` takes a :class:`~secugent.core.tenancy.TenantId`, not a bare
    ``str``. A live-PG retention path therefore requires a separate async
    retention service (or an awaiting adapter that drives the coroutines from a
    sync context) and is deferred to the Stage 2+ live-PG cutover — it is not
    plugged into this synchronous :class:`RetentionService`.
    """

    def archive_day(self, *, tenant_id: str, day: date) -> int: ...
    def purge_day(self, *, tenant_id: str, day: date) -> int: ...
    def is_day_archived(self, *, tenant_id: str, day: date) -> bool: ...
    def verify_chain(self, *, tenant_id: str) -> bool: ...


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DayRetentionOutcome:
    """Per-(day, tenant) result of :meth:`RetentionService.apply`."""

    day: date
    tenant_id: str
    archived_count: int
    verified: bool
    purged: bool
    purged_count: int
    error: str | None


@dataclass(frozen=True)
class RetentionResult:
    """Aggregate result of one :meth:`RetentionService.apply` pass."""

    outcomes: tuple[DayRetentionOutcome, ...]
    archived_total: int
    purged_total: int


def _skip(day: date, tenant_id: str, archived_count: int, error: str) -> DayRetentionOutcome:
    """Build a verify-failed outcome (archive kept, purge skipped — I4)."""
    return DayRetentionOutcome(
        day=day,
        tenant_id=tenant_id,
        archived_count=archived_count,
        verified=False,
        purged=False,
        purged_count=0,
        error=error,
    )


class RetentionService:
    """Execute a :class:`RetentionPlan` with archive → verify → purge."""

    def __init__(
        self,
        *,
        store: _ArchivableChainStore,
        tenant_ids: Sequence[str],
    ) -> None:
        self._store = store
        self._tenant_ids = list(tenant_ids)

    async def apply(self, plan_: RetentionPlan) -> RetentionResult:
        """Archive, verify, then purge every purge-candidate day per tenant.

        Verify-gated purge (I4): a day is only purged when its archive copy is
        complete AND :meth:`verify_chain` still passes. A verify failure records
        the error on that day's outcome and skips its purge — the hot rows stay,
        so integrity is never traded for cleanup. Unexpected store-level
        exceptions (e.g. a dropped DB connection) propagate, as they invalidate
        the whole pass.
        """
        outcomes: list[DayRetentionOutcome] = []
        archived_total = 0
        purged_total = 0
        for tenant_id in self._tenant_ids:
            for day in plan_.purge_days:
                outcome = self._apply_day(tenant_id=tenant_id, day=day)
                outcomes.append(outcome)
                archived_total += outcome.archived_count
                purged_total += outcome.purged_count
        return RetentionResult(
            outcomes=tuple(outcomes),
            archived_total=archived_total,
            purged_total=purged_total,
        )

    def _apply_day(self, *, tenant_id: str, day: date) -> DayRetentionOutcome:
        archived_count = self._store.archive_day(tenant_id=tenant_id, day=day)
        # Verify gate: archive must be complete AND the chain must still link.
        if not self._store.is_day_archived(tenant_id=tenant_id, day=day):
            msg = "archive incomplete — purge skipped"
            _LOG.error("retention: tenant=%r day=%s %s", tenant_id, day.isoformat(), msg)
            return _skip(day, tenant_id, archived_count, msg)
        try:
            verified = self._store.verify_chain(tenant_id=tenant_id)
        except Exception as exc:  # noqa: BLE001 - downgrade tamper to per-day skip
            _LOG.error(
                "retention: tenant=%r day=%s verify raised — purge skipped",
                tenant_id,
                day.isoformat(),
                exc_info=True,
            )
            return _skip(day, tenant_id, archived_count, f"verify_chain raised: {exc}")
        if not verified:
            return _skip(
                day,
                tenant_id,
                archived_count,
                "verify_chain returned False — purge skipped",
            )
        purged_count = self._store.purge_day(tenant_id=tenant_id, day=day)
        return DayRetentionOutcome(
            day=day,
            tenant_id=tenant_id,
            archived_count=archived_count,
            verified=True,
            purged=True,
            purged_count=purged_count,
            error=None,
        )


# --------------------------------------------------------------------------- #
# SQLite adapter — bundle a ChainedEventStore into the retention contract
# --------------------------------------------------------------------------- #


class _SqliteArchiveStore(Protocol):
    def archive_day(self, *, tenant_id: str, day: date) -> int: ...
    def purge_day(self, *, tenant_id: str, day: date) -> int: ...
    def is_day_archived(self, *, tenant_id: str, day: date) -> bool: ...


class _Verifiable(Protocol):
    def verify_chain(self, *, tenant_id: str) -> bool: ...


class ChainedStoreRetentionAdapter:
    """Adapt a hash-chained SQLite store to :class:`_ArchivableChainStore`.

    The chain decorator owns ``verify_chain`` but delegates durable storage to
    an inner :class:`secugent.core.event_store.EventStore` that carries the
    archive/purge primitives. This adapter wires the two without editing the
    chain module, so production can build
    ``RetentionService(store=ChainedStoreRetentionAdapter(chain), ...)``.
    """

    def __init__(self, chain: _Verifiable, *, archive_store: _SqliteArchiveStore) -> None:
        self._chain = chain
        self._archive = archive_store

    def archive_day(self, *, tenant_id: str, day: date) -> int:
        return self._archive.archive_day(tenant_id=tenant_id, day=day)

    def purge_day(self, *, tenant_id: str, day: date) -> int:
        return self._archive.purge_day(tenant_id=tenant_id, day=day)

    def is_day_archived(self, *, tenant_id: str, day: date) -> bool:
        return self._archive.is_day_archived(tenant_id=tenant_id, day=day)

    def verify_chain(self, *, tenant_id: str) -> bool:
        return self._chain.verify_chain(tenant_id=tenant_id)


# --------------------------------------------------------------------------- #
# Integration hook — exposed for the API/scheduler wiring lane (no main.py edit)
# --------------------------------------------------------------------------- #


SealedDaysProvider = Callable[[], Iterable[date]]


def wire_retention_hook(
    *,
    service: RetentionService,
    sealed_days: SealedDaysProvider,
    retain_days: int = DEFAULT_RETAIN_DAYS,
    runner: Callable[[Coroutine[Any, Any, RetentionResult]], object] = asyncio.run,
    now_fn: Callable[[], date] = lambda: datetime.now(tz=UTC).date(),
) -> Callable[[date], None]:
    """Build a sync retention hook for :class:`DailyMerkleScheduler`.

    The scheduler loop is synchronous; this closure adapts the async
    :meth:`RetentionService.apply` for it. On each seal it (re)reads the current
    set of sealed days via ``sealed_days`` (so freshly sealed days enter the
    candidate set), plans against ``now_fn()``/``retain_days`` and applies. The
    integration lane mounts the returned callable as the scheduler's
    ``retention_hook`` — it must never edit ``secugent/api/main.py`` itself.

    ``retain_days`` is validated **here, at wire/boot time** (must be an ``int``
    ``>= 0``). A misconfigured (negative) window would otherwise only raise later
    inside the per-seal hook, where :class:`DailyMerkleScheduler` swallows per-seal
    errors by design — so retention would silently never run. This is a
    compliance-critical path (EU AI Act Art.26), so we fail fast at construction.
    """
    if not isinstance(retain_days, int) or isinstance(retain_days, bool):
        raise ValueError(f"retain_days must be an int, got {type(retain_days).__name__}")
    if retain_days < 0:
        raise ValueError(f"retain_days must be >= 0, got {retain_days}")

    def _hook(_sealed_day: date) -> None:
        retention_plan = plan(
            now=now_fn(),
            sealed_days=sealed_days(),
            retain_days=retain_days,
        )
        if not retention_plan.purge_days:
            return
        # ``apply`` is a coroutine; ``runner`` (asyncio.run by default) drives it
        # to completion from this synchronous scheduler thread.
        runner(service.apply(retention_plan))

    return _hook
