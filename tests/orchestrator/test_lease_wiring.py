# SPDX-License-Identifier: Apache-2.0
"""resolve_lease_manager + recover_open_runs boot hooks.

resolve_lease_manager is a fail-closed router (HA off by default; in-memory only
in dev; pg requires a compatible store). recover_open_runs is the lifespan hook
that drives boot recovery; list_open_runs is a mandatory RunStateStore member.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from secugent.config import OrchestratorConfig
from secugent.core.event_store_base import RunLease
from secugent.orchestrator.lease import (
    InMemoryLeaseManager,
    PgLeaseManager,
    SQLiteLeaseManager,
)
from secugent.orchestrator.recovery import RecoveryReport
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunRecord,
    RunState,
)
from secugent.orchestrator.wiring import (
    LeaseConfigError,
    recover_open_runs,
    resolve_lease_manager,
)


def _ha_cfg(*, enabled: bool, backend: str = "", db_path: str = "data/x.db") -> OrchestratorConfig:
    cfg = OrchestratorConfig(run_state_db_path=db_path)
    cfg.ha_enabled = enabled  # type: ignore[attr-defined]  # optional HA flag (config lane)
    if backend:
        cfg.ha_backend = backend  # type: ignore[attr-defined]
    return cfg


# --------------------------------------------------------------------------- #
# resolve_lease_manager
# --------------------------------------------------------------------------- #


def test_ha_disabled_returns_none() -> None:
    assert resolve_lease_manager(OrchestratorConfig(), None, is_dev=True) is None


def test_ha_disabled_flag_false_returns_none() -> None:
    cfg = _ha_cfg(enabled=False, backend="pg")
    assert resolve_lease_manager(cfg, object(), is_dev=False) is None


def test_memory_backend_dev_returns_inmemory() -> None:
    cfg = _ha_cfg(enabled=True, backend="memory")
    mgr = resolve_lease_manager(cfg, None, is_dev=True)
    assert isinstance(mgr, InMemoryLeaseManager)


def test_memory_backend_prod_fails_closed() -> None:
    cfg = _ha_cfg(enabled=True, backend="memory")
    with pytest.raises(LeaseConfigError, match="dev-only"):
        resolve_lease_manager(cfg, None, is_dev=False)


def test_sqlite_backend_returns_sqlite(tmp_path: Any) -> None:
    cfg = _ha_cfg(enabled=True, backend="sqlite", db_path=str(tmp_path / "l.db"))
    mgr = resolve_lease_manager(cfg, None, is_dev=False)
    assert isinstance(mgr, SQLiteLeaseManager)
    mgr.close()


def test_sqlite_backend_empty_path_fails() -> None:
    cfg = _ha_cfg(enabled=True, backend="sqlite", db_path="")
    with pytest.raises(LeaseConfigError, match="non-empty"):
        resolve_lease_manager(cfg, None, is_dev=True)


def test_pg_backend_wraps_compatible_store() -> None:
    cfg = _ha_cfg(enabled=True, backend="pg")
    mgr = resolve_lease_manager(cfg, _FakePgStore(), is_dev=False)
    assert isinstance(mgr, PgLeaseManager)


def test_pg_backend_incompatible_store_fails() -> None:
    cfg = _ha_cfg(enabled=True, backend="pg")
    with pytest.raises(LeaseConfigError, match="lease primitives"):
        resolve_lease_manager(cfg, object(), is_dev=False)


def test_unknown_backend_fails() -> None:
    cfg = _ha_cfg(enabled=True, backend="redis")
    with pytest.raises(LeaseConfigError, match="unknown ha_backend"):
        resolve_lease_manager(cfg, None, is_dev=True)


def test_backend_falls_back_to_run_state_backend() -> None:
    # No ha_backend set → uses run_state_backend ("memory" default).
    cfg = _ha_cfg(enabled=True)
    mgr = resolve_lease_manager(cfg, None, is_dev=True)
    assert isinstance(mgr, InMemoryLeaseManager)


class _FakePgStore:
    async def try_acquire_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        return True

    async def is_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> bool:
        return True

    async def release_leader(self, worker_id: str, *, lock_key: int = 0xDEADBEEF) -> None:
        return None

    async def acquire_run_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        now = datetime.now(tz=UTC)
        return RunLease(
            run_id=run_id,
            worker_id=worker_id,
            acquired_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

    async def renew_lease(self, *, run_id: str, worker_id: str, ttl_seconds: int) -> RunLease:
        return await self.acquire_run_lease(run_id=run_id, worker_id=worker_id, ttl_seconds=ttl_seconds)

    async def release_lease(self, *, run_id: str, worker_id: str) -> None:
        return None

    async def list_stale_leases(self) -> list[str]:
        return []


# --------------------------------------------------------------------------- #
# recover_open_runs
# --------------------------------------------------------------------------- #


class _FakeOrch:
    def __init__(self) -> None:
        self.resumed: list[str] = []

    async def resume(self, record: RunRecord) -> None:
        self.resumed.append(record.run_id)


async def test_recover_open_runs_drives_recovery() -> None:
    # F12: list_open_runs is mandatory on RunStateStore — use the store directly.
    store = InMemoryRunStateStore()
    await store.create("r-pending", "감사", {})
    await store.create("r-exec", "감사", {})
    await store.update_state("r-exec", RunState.EXECUTING)
    await store.create("r-done", "감사", {})
    await store.update_state("r-done", RunState.COMPLETED)

    orch = _FakeOrch()
    events: list[tuple[str, str, dict[str, Any]]] = []

    async def publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        events.append((run_id, topic, payload))

    report = await recover_open_runs(orch, store, publish)  # type: ignore[arg-type]

    assert report.resumed == ("r-pending",)
    assert report.failed == ("r-exec",)
    # r-done is terminal so list_open_runs never surfaces it → not in report.
    assert "r-done" not in report.skipped
    assert orch.resumed == ["r-pending"]
    failed_rec = await store.get("r-exec")
    assert failed_rec is not None and failed_rec.state is RunState.FAILED


async def test_recover_open_runs_empty_store_is_noop() -> None:
    store = InMemoryRunStateStore()
    orch = _FakeOrch()

    async def publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        return None

    report = await recover_open_runs(orch, store, publish)  # type: ignore[arg-type]
    assert report == RecoveryReport(resumed=(), failed=(), skipped=())


async def test_recover_skips_run_held_by_another_worker() -> None:
    """F9 (LEADER-SINGLETON): a run whose lease is held (non-expired) by ANOTHER
    worker must NOT be failed-out / resumed by a booting node's recovery."""
    store = InMemoryRunStateStore()
    # node-A's live, lease-held EXECUTING run.
    await store.create("r-held", "감사", {})
    await store.update_state("r-held", RunState.EXECUTING)
    # an orphaned PENDING run no one holds — booting node-B may resume it.
    await store.create("r-free", "감사", {})

    lease = InMemoryLeaseManager()
    await lease.acquire_run("r-held", "node-A", 60)  # node-A owns r-held

    orch = _FakeOrch()
    events: list[tuple[str, str, dict[str, Any]]] = []

    async def publish(run_id: str, topic: str, payload: dict[str, Any]) -> None:
        events.append((run_id, topic, payload))

    report = await recover_open_runs(
        orch,
        store,
        publish,
        lease_manager=lease,
        worker_id="node-B",
    )  # type: ignore[arg-type]

    # node-B did NOT fail node-A's held run (no state mutation), and skipped it.
    held = await store.get("r-held")
    assert held is not None and held.state is RunState.EXECUTING
    assert "r-held" in report.skipped
    assert "r-held" not in report.failed
    # the free run is still recoverable by node-B.
    assert report.resumed == ("r-free",)
