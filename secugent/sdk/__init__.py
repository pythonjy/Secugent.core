# SPDX-License-Identifier: Apache-2.0
"""SecuGent embed SDK — wrap your existing agents/tools in SecuGent oversight.

BDP_02 item 4. This is the **framework-neutral** public embed surface (§A-2.3):
SI/vendors wrap their existing agents/tools so every action passes the SecuGent
trust loop (REGULATIONS deny-by-default → Rule of Two → forced HITL → §C-2 audit)
*without* SecuGent owning their agent runtime — the OEM/licensing premise.

Public surface (re-exported here):

* :func:`~secugent.sdk.decorators.require_oversight` — decorate a sync/async
  callable so its action is gated before it runs.
* :class:`~secugent.sdk.middleware.OversightMiddleware` — a callable/ASGI
  middleware that gates every request through the same core path.
* :func:`~secugent.sdk.middleware.wrap_tool` — gate a single tool callable.
* :class:`~secugent.sdk.gate.OversightGate` — the one object that composes the
  core decision (every surface above calls it; it never re-decides — I1).
* :class:`~secugent.sdk.gate.OversightBlocked` — raised on a fail-closed HITL deny
  (a REGULATIONS violation raises the core
  :class:`~secugent.core.contracts.HardBlockException`).

The SDK is **Core (Apache-2.0)** and depends only on ``secugent.core`` /
``secugent.agents`` primitives — one-directional (SDK → core), never the reverse.
LangChain is an **optional extra**: it is deliberately NOT imported here so
``import secugent.sdk`` works with langchain absent (I3). The LangChain adapter
lives in :mod:`secugent.orchestrator.adapters_langchain` and lazy-imports it.
"""

from __future__ import annotations

from secugent.orchestrator.adapters import DispatcherAdapter, HeadPlannerAdapter
from secugent.sdk.decorators import require_oversight
from secugent.sdk.gate import (
    AuditSink,
    ChainedEventStoreAuditSink,
    OversightBlocked,
    OversightDecision,
    OversightGate,
    build_step,
)
from secugent.sdk.middleware import OversightMiddleware, wrap_tool

__all__ = [
    "AuditSink",
    # Durable, tamper-evident §C-2 sink (ChainedEventStore-backed) — the production
    # audit writer (in-memory sinks are for tests/examples only).
    "ChainedEventStoreAuditSink",
    # Orchestrator adapters (defined in secugent.orchestrator.adapters; re-exported
    # here as the public embed-SDK surface for wiring the real HEAD/Dispatcher).
    "DispatcherAdapter",
    "HeadPlannerAdapter",
    "OversightBlocked",
    "OversightDecision",
    "OversightGate",
    "OversightMiddleware",
    "build_step",
    "require_oversight",
    "wrap_tool",
]
