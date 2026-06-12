# SPDX-License-Identifier: Apache-2.0
"""Background orchestrator package.

The orchestrator drives the SecuGent pipeline:

    command.received → HEAD plan → (Plan Review Gate) → Dispatcher
        → SUB exec → REPORTING → run.completed

without requiring client polling. POST /command enqueues, the orchestrator
runs the pipeline in the background, and the API surfaces progress through
``GET /runs/{id}`` and ``GET /runs/{id}/events`` (SSE).
"""

from secugent.orchestrator.events import OrchestratorEventType
from secugent.orchestrator.runner import (
    OrchestratorStoppedError,
    RunOrchestrator,
    SubFactory,
)
from secugent.orchestrator.state import (
    InMemoryRunStateStore,
    RunEvent,
    RunRecord,
    RunState,
    RunStateStore,
    SQLiteRunStateStore,
)

__all__ = [
    "InMemoryRunStateStore",
    "OrchestratorEventType",
    "OrchestratorStoppedError",
    "RunEvent",
    "RunOrchestrator",
    "RunRecord",
    "RunState",
    "RunStateStore",
    "SQLiteRunStateStore",
    "SubFactory",
]
