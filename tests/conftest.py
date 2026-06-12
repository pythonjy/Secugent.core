# SPDX-License-Identifier: Apache-2.0
"""Shared pytest fixtures for SecuGent.

Per the master prompt §5, conftest must expose at minimum:

- mock_human_approve
- mock_human_reject
- mock_llm_client
- regulations_engine
- temp_event_bus
- temp_event_store
- approval_service

Some of these depend on modules that arrive in later PHASEs; their fixtures
are conditionally available (skipped if the dependency is not installed yet).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from secugent.core.approval import ApprovalService
from secugent.core.contracts import (
    Approval,
    ApprovalScope,
    Run,
    Step,
)
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

#: Default tenant used by legacy tests that pre-date PHASE 9 (multitenancy).
#: New tests should pass an explicit tenant_id; this constant exists so
#: factory fixtures here have one canonical value to inject.
DEFAULT_TEST_TENANT = TenantId("legacy-default")


# ---------------------------------------------------------------------------
# Event store / approval service
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_event_store(tmp_path: Path) -> Iterator[EventStore]:
    db_path = tmp_path / "secugent.db"
    store = EventStore(db_path)
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def approval_service(temp_event_store: EventStore) -> ApprovalService:
    return ApprovalService(temp_event_store)


# ---------------------------------------------------------------------------
# Human-in-the-loop simulation
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_human_approve(approval_service: ApprovalService) -> Callable[[str], Approval]:
    """Return a callable that grants an approval by id."""

    def _approve(approval_id: str, reason: str = "test-approve") -> Approval:
        return approval_service.grant(approval_id, reason=reason)

    return _approve


@pytest.fixture
def mock_human_reject(approval_service: ApprovalService) -> Callable[[str], Approval]:
    """Return a callable that rejects an approval by id."""

    def _reject(approval_id: str, reason: str = "test-reject") -> Approval:
        return approval_service.reject(approval_id, reason=reason)

    return _reject


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_run() -> Run:
    return Run(tenant_id=DEFAULT_TEST_TENANT, goal="ingest report and email summary")


@pytest.fixture
def sample_step(sample_run: Run) -> Step:
    return Step(
        tenant_id=sample_run.tenant_id,
        run_id=sample_run.id,
        plan_id=None,
        actor="sub:researcher",
        action_type="file_read",
        target="D:/data/report.csv",
        context={"reason": "sample"},
    )


def _scope_for_step(step: Step, max_risk: int = 80) -> ApprovalScope:
    return ApprovalScope(
        tenant_id=step.tenant_id,
        run_id=step.run_id,
        plan_id=step.plan_id,
        step_ids=[step.id],
        allowed_action_types=[step.action_type],
        max_risk=max_risk,
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
    )


@pytest.fixture
def make_scope() -> Callable[..., ApprovalScope]:
    """Factory fixture for building :class:`ApprovalScope` instances."""

    def _make(step: Step, *, max_risk: int = 80) -> ApprovalScope:
        return _scope_for_step(step, max_risk=max_risk)

    return _make


# ---------------------------------------------------------------------------
# Stubs that real PHASEs will swap out
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm_client() -> Any:
    """Return a deterministic stand-in for the LLM client.

    PHASE 2 will replace this with a richer :class:`MockLLMClient`. For now
    we keep an in-test stub so PHASE 0 fixtures don't depend on PHASE 2 code.
    """

    class _Stub:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []
            self.responses: list[str] = []

        def queue(self, text: str) -> None:
            self.responses.append(text)

        def generate(self, **kwargs: Any) -> str:
            self.calls.append(kwargs)
            if not self.responses:
                return "{}"
            return self.responses.pop(0)

    return _Stub()


@pytest.fixture
def regulations_engine() -> Any:
    """Lazy import so PHASE 0 tests can run before PHASE 1 lands."""
    try:
        from secugent.core.regulations import load_regulations
    except ImportError:
        pytest.skip("regulations engine not available until PHASE 1")
    return load_regulations


@pytest.fixture
def temp_event_bus() -> Any:
    """Placeholder — populated in PHASE 5 when EventBus is implemented."""
    try:
        from secugent.core.event_bus import EventBus
    except ImportError:
        pytest.skip("event bus not available until PHASE 5")
    return EventBus()
