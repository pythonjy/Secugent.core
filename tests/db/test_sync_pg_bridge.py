# SPDX-License-Identifier: Apache-2.0
"""DA-C1 — SyncPgEventStore bridge unit tests (fake async store, no Postgres).

Proves the sync facade drives the async store on a DEDICATED loop/thread:
writes land, the call is deadlock-free, a wedged backend times out (fail-closed),
and an underlying error propagates (never a silent dropped write).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from secugent.core.contracts import Approval, ApprovalScope, Event, Run
from secugent.core.tenancy import TenantId
from secugent.db.store_facade import SyncPgEventStore
from tests.db._fakes import FakeAsyncPgChain

_TENANT = TenantId("kb-fin")


def _event(evt_type: str = "plan.created") -> Event:
    return Event(tenant_id=_TENANT, actor="head:planner", type=evt_type, severity="info")


def _run() -> Run:
    return Run(tenant_id=_TENANT, goal="대외비 파일 접근 검토", status="planning")


def _approval() -> Approval:
    scope = ApprovalScope(
        tenant_id=_TENANT,
        run_id="run-1",
        expires_at=datetime.now(tz=UTC) + timedelta(hours=1),
    )
    return Approval(
        actor="human:admin",
        scope=scope,
        expires_at=scope.expires_at,
        nonce="nonce-abc",
    )


def test_bridge_routes_writes_to_async_store() -> None:
    fake = FakeAsyncPgChain()
    bridge = SyncPgEventStore(fake)
    try:
        run = _run()
        bridge.upsert_run(run)
        bridge.append_event(_event("command.received"))  # raw, unchained
        bridge.append_chained(_event("plan.created"))  # §C-2 chained
        bridge.save_approval(_approval())
    finally:
        bridge.close()

    assert run.id in fake.runs
    # append_event → raw inner; append_chained → chain + the atomic inner row.
    assert fake.inner.append_calls == 2
    chain = fake._chains[str(_TENANT)]
    assert len(chain) == 1  # only the chained append builds a chain link
    assert len(fake.approvals) == 1


def test_bridge_runs_on_a_separate_thread_and_cleans_up() -> None:
    """The work must run on the bridge's OWN thread/loop, never the caller's
    (INV-C1-7 no nested loop / deadlock), and close() must reclaim both."""
    import threading

    seen: dict[str, int] = {}

    class _Recording(FakeAsyncPgChain):
        async def upsert_run(self, run: Run) -> None:
            seen["worker_thread"] = threading.get_ident()
            seen["worker_loop"] = id(asyncio.get_running_loop())
            await super().upsert_run(run)

    fake = _Recording()
    bridge = SyncPgEventStore(fake)
    caller_thread = threading.get_ident()
    try:
        bridge.upsert_run(_run())
    finally:
        bridge.close()

    assert seen["worker_thread"] != caller_thread
    assert seen["worker_loop"] == id(bridge._loop)
    # close() reclaims the loop + thread (no leak across app restarts/tests).
    assert bridge._loop.is_closed()
    assert not bridge._thread.is_alive()


def test_bridge_times_out_on_a_wedged_backend() -> None:
    """A backend that never returns must surface a TimeoutError (fail-closed),
    not hang the caller forever."""
    fake = FakeAsyncPgChain(slow_append_s=5.0)
    bridge = SyncPgEventStore(fake, call_timeout_s=0.05)
    try:
        with pytest.raises(TimeoutError):
            bridge.append_chained(_event())
    finally:
        bridge.close()


def test_bridge_propagates_underlying_error() -> None:
    """An async-store failure must propagate (no silently dropped write)."""

    class _Boom(FakeAsyncPgChain):
        async def upsert_run(self, run: Run) -> None:
            raise RuntimeError("durable write failed")

    bridge = SyncPgEventStore(_Boom())
    try:
        with pytest.raises(RuntimeError, match="durable write failed"):
            bridge.upsert_run(_run())
    finally:
        bridge.close()
