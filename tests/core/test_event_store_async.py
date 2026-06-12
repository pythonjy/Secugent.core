# SPDX-License-Identifier: Apache-2.0
"""Stage 1 (G-C9) — SqliteAsyncEventStore delegation unit tests.

Pins the *adapter contract*: every async method maps to the right sync
``EventStore`` method with the right argument names/positions, and the HA-lease
methods fail closed with :class:`NotImplementedError` (SQLite has no advisory
locks). Behaviour parity with PG is covered separately by the shared contract
suite; here we assert the wiring in isolation with a recording fake.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from secugent.core.contracts import Approval, ApprovalScope, Event, Run
from secugent.core.event_store_async import SqliteAsyncEventStore
from secugent.core.tenancy import TenantId

T = TenantId("financial-kr")


class _RecordingStore:
    """Records each sync EventStore call as ``(method, args, kwargs)``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.run_result: Run | None = None
        self.approval_result: Approval | None = None
        self.events_result: list[Event] = []
        self.pending_result: list[Approval] = []

    def append_event(self, event: Event) -> None:
        self.calls.append(("append_event", (event,), {}))

    def list_events(self, **kwargs: Any) -> list[Event]:
        self.calls.append(("list_events", (), kwargs))
        return self.events_result

    def upsert_run(self, run: Run) -> None:
        self.calls.append(("upsert_run", (run,), {}))

    def get_run(self, run_id: str, **kwargs: Any) -> Run | None:
        self.calls.append(("get_run", (run_id,), kwargs))
        return self.run_result

    def save_approval(self, approval: Approval) -> None:
        self.calls.append(("save_approval", (approval,), {}))

    def get_approval(self, approval_id: str, **kwargs: Any) -> Approval | None:
        self.calls.append(("get_approval", (approval_id,), kwargs))
        return self.approval_result

    def list_pending_approvals(self, **kwargs: Any) -> list[Approval]:
        self.calls.append(("list_pending_approvals", (), kwargs))
        return self.pending_result


def _event() -> Event:
    return Event(tenant_id=T, actor="head", type="plan.created", payload={"a": 1})


def _run() -> Run:
    return Run(tenant_id=T, goal="분기 마감", status="planning")


def _approval() -> Approval:
    now = datetime.now(tz=UTC)
    scope = ApprovalScope(tenant_id=T, run_id="r1", expires_at=now + timedelta(hours=1))
    return Approval(actor="human:심사역", scope=scope, expires_at=now + timedelta(hours=1), nonce="n1")


async def test_append_delegates_to_append_event() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]  # duck-typed sync store fake
    ev = _event()
    await store.append(ev)
    assert rec.calls == [("append_event", (ev,), {})]


async def test_query_maps_to_list_events_with_str_tenant() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    await store.query(tenant_id=T, run_id="r1", limit=7)
    name, _args, kwargs = rec.calls[0]
    assert name == "list_events"
    assert kwargs == {"tenant_id": "financial-kr", "run_id": "r1", "limit": 7}
    assert isinstance(kwargs["tenant_id"], str)


async def test_query_returns_inner_result() -> None:
    rec = _RecordingStore()
    rec.events_result = [_event()]
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    out = await store.query(tenant_id=T)
    assert out == rec.events_result


async def test_upsert_run_delegates() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    run = _run()
    await store.upsert_run(run)
    assert rec.calls == [("upsert_run", (run,), {})]


async def test_get_run_maps_positional_id_and_keyword_tenant() -> None:
    rec = _RecordingStore()
    rec.run_result = _run()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    out = await store.get_run(tenant_id=T, run_id="r1")
    name, args, kwargs = rec.calls[0]
    assert name == "get_run"
    assert args == ("r1",)  # run_id is positional in the sync API
    assert kwargs == {"tenant_id": "financial-kr"}
    assert out is rec.run_result


async def test_save_approval_delegates() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    apv = _approval()
    await store.save_approval(apv)
    assert rec.calls == [("save_approval", (apv,), {})]


async def test_get_approval_maps_positional_id_and_keyword_tenant() -> None:
    rec = _RecordingStore()
    rec.approval_result = _approval()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    out = await store.get_approval(tenant_id=T, approval_id="apv_1")
    name, args, kwargs = rec.calls[0]
    assert name == "get_approval"
    assert args == ("apv_1",)
    assert kwargs == {"tenant_id": "financial-kr"}
    assert out is rec.approval_result


async def test_list_pending_with_tenant_passes_str() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    await store.list_pending_approvals(tenant_id=T)
    assert rec.calls == [("list_pending_approvals", (), {"tenant_id": "financial-kr"})]


async def test_list_pending_without_tenant_passes_none() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    await store.list_pending_approvals()
    assert rec.calls == [("list_pending_approvals", (), {"tenant_id": None})]


async def test_inner_property_returns_wrapped_store() -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    # ``inner`` is typed ``EventStore``; compare as plain objects since the fake
    # is duck-typed (the production type is enforced by mypy at real call sites).
    assert store.inner is rec  # type: ignore[comparison-overlap]


@pytest.mark.parametrize(
    "coro_factory",
    [
        lambda s: s.try_acquire_leader("w1", lock_key=1),
        lambda s: s.release_leader("w1", lock_key=1),
        lambda s: s.acquire_run_lease(run_id="r1", worker_id="w1", ttl_seconds=60),
        lambda s: s.renew_lease(run_id="r1", worker_id="w1", ttl_seconds=60),
        lambda s: s.release_lease(run_id="r1", worker_id="w1"),
        lambda s: s.list_stale_leases(),
    ],
)
async def test_ha_lease_methods_fail_closed(coro_factory: Any) -> None:
    rec = _RecordingStore()
    store = SqliteAsyncEventStore(rec)  # type: ignore[arg-type]
    with pytest.raises(NotImplementedError):
        await coro_factory(store)
