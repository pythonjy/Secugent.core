# SPDX-License-Identifier: Apache-2.0
"""G-C7 — resolve_run_state_store: durable run-state store wiring.

Deterministic/critical module (CLAUDE.md §B-4a): unit + property-based
(hypothesis) + scenario regression + a 100x same-input-same-output determinism
test. The resolver is a pure routing function: same (cfg, is_dev) -> same store
*type* + same sqlite path, with no clock/random/env dependency in the decision.

Fail-closed invariant: production (is_dev=False) + memory backend must RAISE,
never silently fall back to in-memory (SECURITY_CONTRACT: deny-by-default).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.config import OrchestratorConfig
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunState,
    RunStateStore,
    SQLiteRunStateStore,
)
from secugent.orchestrator.wiring import (
    RunStateConfigError,
    resolve_run_state_store,
)


def _sqlite_cfg(path: str) -> OrchestratorConfig:
    return OrchestratorConfig(run_state_backend="sqlite", run_state_db_path=path)


# --------------------------------------------------------------------------- #
# Unit — backend x is_dev matrix
# --------------------------------------------------------------------------- #


def test_memory_in_dev_returns_inmemory_store() -> None:
    cfg = OrchestratorConfig(run_state_backend="memory")
    store = resolve_run_state_store(cfg, is_dev=True)
    assert isinstance(store, InMemoryRunStateStore)
    assert isinstance(store, RunStateStore)


def test_memory_in_prod_raises_fail_closed() -> None:
    cfg = OrchestratorConfig(run_state_backend="memory")
    with pytest.raises(RunStateConfigError):
        resolve_run_state_store(cfg, is_dev=False)


def test_unconfigured_none_in_dev_returns_inmemory_store() -> None:
    # F8/F13: None = unconfigured → behaves like the dev-default memory store.
    cfg = OrchestratorConfig(run_state_backend=None)
    store = resolve_run_state_store(cfg, is_dev=True)
    assert isinstance(store, InMemoryRunStateStore)


def test_unconfigured_none_in_prod_raises_fail_closed() -> None:
    # F8/F13: the resolver still refuses an unconfigured/in-memory store in prod;
    # the boot path upgrades None → sqlite BEFORE reaching the resolver.
    cfg = OrchestratorConfig(run_state_backend=None)
    with pytest.raises(RunStateConfigError):
        resolve_run_state_store(cfg, is_dev=False)


def test_explicit_memory_in_prod_still_raises() -> None:
    # F13: an EXPLICIT prod "memory" is honoured verbatim → fail-fast (the old
    # default-comparison guard silently upgraded it instead, a dead fail path).
    cfg = OrchestratorConfig(run_state_backend="memory")
    with pytest.raises(RunStateConfigError):
        resolve_run_state_store(cfg, is_dev=False)


def test_sqlite_in_dev_returns_sqlite_store(tmp_path: Path) -> None:
    cfg = _sqlite_cfg(str(tmp_path / "runs.db"))
    store = resolve_run_state_store(cfg, is_dev=True)
    assert isinstance(store, SQLiteRunStateStore)
    assert isinstance(store, RunStateStore)
    store.close()


def test_sqlite_in_prod_returns_sqlite_store(tmp_path: Path) -> None:
    # SQLite is durable -> allowed in production (this is the whole point of G-C7).
    cfg = _sqlite_cfg(str(tmp_path / "prod.db"))
    store = resolve_run_state_store(cfg, is_dev=False)
    assert isinstance(store, SQLiteRunStateStore)
    store.close()


def test_sqlite_uses_configured_db_path(tmp_path: Path) -> None:
    path = str(tmp_path / "nested" / "runs.db")
    cfg = _sqlite_cfg(path)
    store = resolve_run_state_store(cfg, is_dev=True)
    assert isinstance(store, SQLiteRunStateStore)
    # The resolver passes the path through unmodified; the store creates the dir.
    assert Path(path).parent.is_dir()
    store.close()


def test_sqlite_memory_path_allowed(tmp_path: Path) -> None:
    cfg = _sqlite_cfg(":memory:")
    store = resolve_run_state_store(cfg, is_dev=False)
    assert isinstance(store, SQLiteRunStateStore)
    store.close()


def test_sqlite_empty_path_raises(tmp_path: Path) -> None:
    cfg = _sqlite_cfg("")
    with pytest.raises(RunStateConfigError):
        resolve_run_state_store(cfg, is_dev=True)


# --------------------------------------------------------------------------- #
# pg + unknown backends — fail-fast, never silent
# --------------------------------------------------------------------------- #


def test_pg_backend_raises_not_implemented() -> None:
    # "pg" is not in the Literal; inject it directly to exercise the defensive
    # branch (a future PgRunStateStore must be added before pg is usable).
    cfg = OrchestratorConfig()
    object.__setattr__(cfg, "run_state_backend", "pg")
    with pytest.raises(NotImplementedError) as exc:
        resolve_run_state_store(cfg, is_dev=True)
    assert "PG run-state deferred" in str(exc.value)


def test_unknown_backend_raises_config_error() -> None:
    cfg = OrchestratorConfig()
    object.__setattr__(cfg, "run_state_backend", "redis")
    with pytest.raises(RunStateConfigError):
        resolve_run_state_store(cfg, is_dev=True)


def test_config_error_message_has_no_path_leak() -> None:
    # Error gives a backend/mode hint but must not echo the configured db path
    # (avoid leaking on-disk layout via a boot error). Korean fixture (§C-3).
    cfg = replace(
        OrchestratorConfig(run_state_backend="memory"),
        run_state_db_path="/금융/비밀/runs.db",
    )
    with pytest.raises(RunStateConfigError) as exc:
        resolve_run_state_store(cfg, is_dev=False)
    assert "/금융/비밀/runs.db" not in str(exc.value)


# --------------------------------------------------------------------------- #
# Property-based (hypothesis) — fail-closed never yields a store
# --------------------------------------------------------------------------- #


@settings(max_examples=200, deadline=None)
@given(is_dev=st.booleans())
def test_prop_memory_store_only_in_dev(is_dev: bool) -> None:
    cfg = OrchestratorConfig(run_state_backend="memory")
    if is_dev:
        assert isinstance(resolve_run_state_store(cfg, is_dev=is_dev), InMemoryRunStateStore)
    else:
        with pytest.raises(RunStateConfigError):
            resolve_run_state_store(cfg, is_dev=is_dev)


@settings(max_examples=100, deadline=None)
@given(
    backend=st.sampled_from(["redis", "postgres", "", "MEMORY", "SQLite", "file"]),
    is_dev=st.booleans(),
)
def test_prop_unknown_backend_never_returns_store(backend: str, is_dev: bool) -> None:
    cfg = OrchestratorConfig()
    object.__setattr__(cfg, "run_state_backend", backend)
    with pytest.raises((RunStateConfigError, NotImplementedError)):
        resolve_run_state_store(cfg, is_dev=is_dev)


# --------------------------------------------------------------------------- #
# Scenario regression — the boot path both call sites take
# --------------------------------------------------------------------------- #


async def test_scenario_sqlite_store_is_usable_after_resolution(tmp_path: Path) -> None:
    """End-to-end: resolver hands back a working durable store the orchestrator
    can immediately create/update runs against (한국어 픽스처, §C-3)."""
    cfg = _sqlite_cfg(str(tmp_path / "scenario.db"))
    store = resolve_run_state_store(cfg, is_dev=False)
    assert isinstance(store, SQLiteRunStateStore)
    await store.create("run-시나리오", "배포 승인", {"테넌트": "kbank"})
    await store.update_state("run-시나리오", RunState.AWAITING_APPROVAL)
    rec = await store.get("run-시나리오")
    assert rec is not None
    assert rec.state is RunState.AWAITING_APPROVAL
    store.close()


# --------------------------------------------------------------------------- #
# Determinism — identical (cfg, is_dev) -> identical decision, 100 runs
# --------------------------------------------------------------------------- #


def _decision_projection(cfg: OrchestratorConfig, is_dev: bool) -> object:
    """Wall-clock-independent projection of the resolver decision."""
    try:
        store = resolve_run_state_store(cfg, is_dev=is_dev)
    except RunStateConfigError:
        return ("error", "config")
    except NotImplementedError:
        return ("error", "not_implemented")
    store_type = type(store).__name__
    if isinstance(store, SQLiteRunStateStore):
        store.close()
    return ("store", store_type)


def test_resolver_deterministic_100_runs(tmp_path: Path) -> None:
    cases: list[tuple[OrchestratorConfig, bool]] = [
        (OrchestratorConfig(run_state_backend="memory"), True),
        (OrchestratorConfig(run_state_backend="memory"), False),
        (_sqlite_cfg(":memory:"), True),
        (_sqlite_cfg(":memory:"), False),
    ]
    pg_cfg = OrchestratorConfig()
    object.__setattr__(pg_cfg, "run_state_backend", "pg")
    cases.append((pg_cfg, True))

    expected = [_decision_projection(cfg, is_dev) for cfg, is_dev in cases]
    for _ in range(100):
        got = [_decision_projection(cfg, is_dev) for cfg, is_dev in cases]
        assert got == expected
