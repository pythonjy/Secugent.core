# SPDX-License-Identifier: Apache-2.0
"""In-memory fakes mirroring the async PG chained store — NO Postgres.

These let the DA-C1 seam, sync bridge, and migration be unit-tested deterministically
on every host. The chain math uses the REAL
:mod:`secugent.audit.hash_chain` functions (``canonical``/``stored_view``/
``compute_chain_hash``/``GENESIS``), so a fake chain reproduces the SQLite/PG chain
byte-identically — the migration's tail-hash equality check is therefore meaningful
against the fake.
"""

from __future__ import annotations

import asyncio

from secugent.audit.hash_chain import (
    GENESIS,
    AuditChainBrokenError,
    ChainedEventRecord,
    canonical,
    compute_chain_hash,
    stored_view,
)
from secugent.core.contracts import Approval, Event, Run
from secugent.core.tenancy import TenantId


class FakeAsyncRaw:
    """Mirror of ``PgEventStore`` (the ``.inner`` raw store): unchained appends."""

    def __init__(self) -> None:
        self.events: dict[str, Event] = {}
        self.append_calls = 0

    async def append(self, event: Event) -> None:
        self.append_calls += 1
        self.events[event.id] = event

    async def get_event(self, *, tenant_id: TenantId, event_id: str) -> Event | None:
        # Mirror PgEventStore.get_event: tenant-scoped (RLS + explicit WHERE).
        ev = self.events.get(event_id)
        if ev is None or str(ev.tenant_id) != str(tenant_id):
            return None
        return ev


class FakeAsyncPgChain:
    """Mirror of ``PgChainedEventStore`` for unit tests (in-memory, real hashing).

    Set ``fail_verify=True`` to simulate a PG-side chain break (the migration must
    then abort fail-closed). ``slow_append_s`` injects latency so the sync bridge's
    per-call timeout can be exercised.
    """

    def __init__(self, *, fail_verify: bool = False, slow_append_s: float = 0.0) -> None:
        self.inner = FakeAsyncRaw()
        self.runs: dict[str, Run] = {}
        self.approvals: dict[str, Approval] = {}
        self._chains: dict[str, list[ChainedEventRecord]] = {}
        self.fail_verify = fail_verify
        self.slow_append_s = slow_append_s

    async def upsert_run(self, run: Run) -> None:
        self.runs[run.id] = run

    async def append(self, event: Event) -> None:
        await self.append_chained(event)

    async def append_chained(self, event: Event) -> ChainedEventRecord:
        """Mirror ``PgChainedEventStore.append_chained`` — chained append + record."""
        if self.slow_append_s:
            await asyncio.sleep(self.slow_append_s)
        tenant = str(event.tenant_id)
        stored = stored_view(event)
        body = canonical(stored)
        chain = self._chains.setdefault(tenant, [])
        if not chain:
            prev_hash, seq = GENESIS, 0
        else:
            prev_hash, seq = chain[-1].event_hash, chain[-1].seq + 1
        event_hash = compute_chain_hash(prev_hash, body)
        record = ChainedEventRecord(event=stored, seq=seq, prev_hash=prev_hash, event_hash=event_hash)
        chain.append(record)
        # Mirror the atomic event-row write that rides the chained append.
        await self.inner.append(stored)
        return record

    async def save_approval(self, approval: Approval) -> None:
        self.approvals[approval.id] = approval

    # -- read surface (mirrors PgChainedEventStore delegation) -------------- #

    async def query(self, *, tenant_id: TenantId, run_id: str | None = None, limit: int = 100) -> list[Event]:
        rows = [rec.event for rec in self._chains.get(str(tenant_id), [])]
        if run_id is not None:
            rows = [e for e in rows if e.run_id == run_id]
        return list(reversed(rows))[:limit]  # newest-first, like the real store

    async def count_events(self, *, tenant_id: TenantId, run_id: str | None = None) -> int:
        rows = [rec.event for rec in self._chains.get(str(tenant_id), [])]
        if run_id is not None:
            rows = [e for e in rows if e.run_id == run_id]
        return len(rows)

    async def get_run(self, *, tenant_id: TenantId, run_id: str) -> Run | None:
        run = self.runs.get(run_id)
        if run is None or str(run.tenant_id) != str(tenant_id):
            return None
        return run

    async def get_event(self, *, tenant_id: TenantId, event_id: str) -> Event | None:
        return await self.inner.get_event(tenant_id=tenant_id, event_id=event_id)

    async def get_approval(self, *, tenant_id: TenantId, approval_id: str) -> Approval | None:
        approval = self.approvals.get(approval_id)
        if approval is None or str(approval.scope.tenant_id) != str(tenant_id):
            return None
        return approval

    async def list_pending_approvals(self, *, tenant_id: TenantId | None = None) -> list[Approval]:
        out = [
            a
            for a in self.approvals.values()
            if a.status == "pending" and (tenant_id is None or str(a.scope.tenant_id) == str(tenant_id))
        ]
        return out

    async def read_chain(self, *, tenant_id: TenantId) -> list[ChainedEventRecord]:
        return list(self._chains.get(str(tenant_id), []))

    async def verify_chain(self, *, tenant_id: TenantId) -> bool:
        if self.fail_verify:
            raise AuditChainBrokenError(f"injected PG chain break for {tenant_id}")
        last = GENESIS
        for rec in self._chains.get(str(tenant_id), []):
            body = canonical(stored_view(rec.event))
            if rec.prev_hash != last or rec.event_hash != compute_chain_hash(last, body):
                raise AuditChainBrokenError(f"chain break at seq={rec.seq}")
            last = rec.event_hash
        return True
