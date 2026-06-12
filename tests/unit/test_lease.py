# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — LeaseManager contract tests (InMemory + SQLite)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from secugent.orchestrator.lease import (
    InMemoryLeaseManager,
    LeaseLostError,
    SQLiteLeaseManager,
)

# ---------------------------------------------------------------------------
# Shared contract — both backends must behave identically.
# ---------------------------------------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def lease_manager(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        yield InMemoryLeaseManager()
        return
    mgr = SQLiteLeaseManager(tmp_path / "lease.db")
    try:
        yield mgr
    finally:
        mgr.close()


async def test_acquire_then_release(lease_manager) -> None:
    lease = await lease_manager.acquire_run("run-1", "worker-A", ttl_seconds=60)
    assert lease.run_id == "run-1"
    assert lease.worker_id == "worker-A"
    await lease_manager.release("run-1", "worker-A")


async def test_acquire_blocks_other_worker(lease_manager) -> None:
    await lease_manager.acquire_run("run-2", "worker-A", ttl_seconds=60)
    with pytest.raises(LeaseLostError):
        await lease_manager.acquire_run("run-2", "worker-B", ttl_seconds=60)


async def test_renew_only_by_holder(lease_manager) -> None:
    await lease_manager.acquire_run("run-3", "worker-A", ttl_seconds=60)
    await lease_manager.renew("run-3", "worker-A", ttl_seconds=60)
    with pytest.raises(LeaseLostError):
        await lease_manager.renew("run-3", "worker-B", ttl_seconds=60)


async def test_expired_lease_can_be_claimed_by_anyone(lease_manager) -> None:
    await lease_manager.acquire_run("run-4", "worker-A", ttl_seconds=0)
    # Sleep a hair so wall-clock advances past expiry.
    await asyncio.sleep(0.01)
    lease = await lease_manager.acquire_run("run-4", "worker-B", ttl_seconds=60)
    assert lease.worker_id == "worker-B"


async def test_list_stale_returns_expired(lease_manager) -> None:
    await lease_manager.acquire_run("run-5", "worker-A", ttl_seconds=0)
    await asyncio.sleep(0.01)
    stale = await lease_manager.list_stale()
    assert "run-5" in stale


async def test_leader_election_single_holder(lease_manager) -> None:
    ok_a = await lease_manager.try_acquire_leader("worker-A")
    ok_b = await lease_manager.try_acquire_leader("worker-B")
    assert ok_a is True
    assert ok_b is False
    await lease_manager.release_leader("worker-A")
    ok_b_after = await lease_manager.try_acquire_leader("worker-B")
    assert ok_b_after is True


async def test_leader_release_by_non_holder_no_effect(lease_manager) -> None:
    await lease_manager.try_acquire_leader("worker-A")
    await lease_manager.release_leader("worker-B")  # different worker
    ok_c = await lease_manager.try_acquire_leader("worker-C")
    assert ok_c is False  # A still holds the lock


async def test_is_leader_is_read_only_and_accurate(lease_manager) -> None:
    """is_leader 는 보유자만 True 이고, 조회만으로 빈 슬롯을 점유하지 않는다."""
    # 빈 슬롯: 임의 worker 조회는 False 이며 슬롯은 비어 있어야 한다.
    assert await lease_manager.is_leader("worker-A") is False
    # 조회가 점유하지 않았으므로 worker-A 가 정상적으로 리더가 될 수 있다.
    assert await lease_manager.try_acquire_leader("worker-A") is True
    assert await lease_manager.is_leader("worker-A") is True
    # 비-보유자 조회는 False 이고, 그 조회가 슬롯을 빼앗지 않는다.
    assert await lease_manager.is_leader("worker-B") is False
    assert await lease_manager.is_leader("worker-A") is True
