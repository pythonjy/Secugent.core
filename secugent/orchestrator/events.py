# SPDX-License-Identifier: Apache-2.0
"""Event topic constants for the orchestrator."""

from __future__ import annotations

from typing import Final


class OrchestratorEventType:
    """Stringly-typed event topics used by :class:`RunOrchestrator`.

    Names mirror the Mermaid diagrams in ``SecuGent_Flowcharts.html`` so that
    UI panels can subscribe with the same vocabulary.
    """

    COMMAND_RECEIVED: Final[str] = "command.received"

    PLAN_CREATED: Final[str] = "plan.created"
    PLAN_AWAITING_APPROVAL: Final[str] = "plan.awaiting_approval"
    PLAN_APPROVED: Final[str] = "plan.approved"
    PLAN_REJECTED: Final[str] = "plan.rejected"
    PLAN_AMENDED: Final[str] = "plan.amended"

    DISPATCHER_ROUTED: Final[str] = "dispatcher.routed"

    SUB_STARTED: Final[str] = "sub.started"
    SUB_STEP: Final[str] = "sub.step"
    SUB_COMPLETED: Final[str] = "sub.completed"
    SUB_FAILED: Final[str] = "sub.failed"

    RUN_COMPLETED: Final[str] = "run.completed"
    RUN_FAILED: Final[str] = "run.failed"
    RUN_CANCELLED: Final[str] = "run.cancelled"

    # PHASE 8 — adapter-layer specific failure topic. Lets UI/audit
    # distinguish "HEAD/Dispatcher adapter raised" from generic run failures.
    RUN_FAILED_ADAPTER: Final[str] = "run.failed.adapter"

    # Crash-recovery handover topic. Emitted by the boot recovery driver
    # for every non-skip decision (resume / fail_worker_lost) so the run's audit
    # ribbon records *why* ownership moved. This is an orchestrator event-ribbon
    # topic, NOT a §C-2 audit ``gate`` enum value.
    RUN_HANDOVER: Final[str] = "run.handover"


__all__ = ["OrchestratorEventType"]
