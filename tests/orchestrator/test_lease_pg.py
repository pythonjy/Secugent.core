# SPDX-License-Identifier: Apache-2.0
"""G-C8 — PgLeaseManager adapter: Protocol→PG method/arg mapping.

The adapter performs zero SQL; it only renames methods and converts the
positional :class:`LeaseManager` Protocol arguments into the keyword-only
arguments the PG event store expects. These tests assert that delegation with a
*fake* PG store. A real-PG round-trip is DB-gated (skipped without DATABASE_URL).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from secugent.core.event_store_base import LeaseLostError, RunLease
from secugent.orchestrator.lease import PgLeaseManager


class _FakePgStore:
    """Records every lease-primitive call + its kwargs for delegation asserts."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.leader_result = True
        self.stale_result: list[str] = ["run-stale-1", "run-stale-2"]
        self.raise_on_acquire: Exception | None = None

    def _lease(self, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        now = datetime.now(tz=UTC)
        return RunLease(
            run_id=run_id,
            worker_id=worker_id,
            acquired_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    async def try_acquire_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        self.calls.append(("try_acquire_leader", {"worker_id": worker_id, "lock_key": lock_key}))
        return self.leader_result

    async def is_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        self.calls.append(("is_leader", {"worker_id": worker_id, "lock_key": lock_key}))
        return self.leader_result

    async def release_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> None:
        self.calls.append(("release_leader", {"worker_id": worker_id, "lock_key": lock_key}))

    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        self.calls.append(
            ("acquire_run_lease", {"run_id": run_id, "worker_id": worker_id, "ttl_seconds": ttl_seconds})
        )
        if self.raise_on_acquire is not None:
            raise self.raise_on_acquire
        return self._lease(run_id, worker_id, ttl_seconds)

    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        self.calls.append(
            ("renew_lease", {"run_id": run_id, "worker_id": worker_id, "ttl_seconds": ttl_seconds})
        )
        return self._lease(run_id, worker_id, ttl_seconds)

    async def release_lease(self, *, run_id: str, worker_id: str) -> None:
        self.calls.append(("release_lease", {"run_id": run_id, "worker_id": worker_id}))

    async def list_stale_leases(self) -> list[str]:
        self.calls.append(("list_stale_leases", {}))
        return self.stale_result


async def test_acquire_run_maps_to_acquire_run_lease_with_kwargs() -> None:
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    lease = await mgr.acquire_run("run-1", "worker-A", 60)

    assert store.calls == [
        ("acquire_run_lease", {"run_id": "run-1", "worker_id": "worker-A", "ttl_seconds": 60})
    ]
    assert isinstance(lease, RunLease)
    assert lease.run_id == "run-1"
    assert lease.worker_id == "worker-A"


async def test_renew_maps_to_renew_lease_with_kwargs() -> None:
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    await mgr.renew("run-2", "worker-B", 30)

    assert store.calls == [("renew_lease", {"run_id": "run-2", "worker_id": "worker-B", "ttl_seconds": 30})]


async def test_release_maps_to_release_lease_with_kwargs() -> None:
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    await mgr.release("run-3", "worker-C")

    assert store.calls == [("release_lease", {"run_id": "run-3", "worker_id": "worker-C"})]


async def test_list_stale_maps_to_list_stale_leases() -> None:
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    result = await mgr.list_stale()

    assert store.calls == [("list_stale_leases", {})]
    assert result == ["run-stale-1", "run-stale-2"]


async def test_leader_passthrough_uses_pg_default_lock_key() -> None:
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    ok = await mgr.try_acquire_leader("worker-A")
    await mgr.release_leader("worker-A")

    assert ok is True
    # The adapter must NOT pass lock_key — the PG default (0xDEADBEEF) stands.
    assert store.calls == [
        ("try_acquire_leader", {"worker_id": "worker-A", "lock_key": 0xDEADBEEF}),
        ("release_leader", {"worker_id": "worker-A", "lock_key": 0xDEADBEEF}),
    ]


async def test_is_leader_passthrough_uses_pg_default_lock_key() -> None:
    """is_leader 도 lock_key 를 넘기지 않고 PG 기본(0xDEADBEEF)을 사용한다 (비-acquiring 조회)."""
    store = _FakePgStore()
    mgr = PgLeaseManager(store)

    ok = await mgr.is_leader("worker-A")

    assert ok is True
    assert store.calls == [("is_leader", {"worker_id": "worker-A", "lock_key": 0xDEADBEEF})]


async def test_lease_lost_error_propagates_unchanged() -> None:
    store = _FakePgStore()
    store.raise_on_acquire = LeaseLostError("held by worker-X")
    mgr = PgLeaseManager(store)

    with pytest.raises(LeaseLostError, match="held by worker-X"):
        await mgr.acquire_run("run-9", "worker-A", 60)


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="real-PG round-trip requires DATABASE_URL (DB-gated)",
)
async def test_real_pg_round_trip() -> None:  # pragma: no cover - DB-gated
    from secugent.core.event_store_pg import PgEventStore

    store = PgEventStore(os.environ["DATABASE_URL"])
    mgr = PgLeaseManager(store)
    lease = await mgr.acquire_run("run-pg-rt", "worker-rt", 60)
    assert lease.worker_id == "worker-rt"
    await mgr.release("run-pg-rt", "worker-rt")
