# SPDX-License-Identifier: Apache-2.0
"""In-process pub/sub Event Bus with WebSocket broadcast support.

The bus is a *display + input channel* only — the
durable source of truth is :class:`secugent.core.event_store.EventStore`.
Callers are expected to:

1. ``store.append_event(e)``  → may raise EventStoreError (fail-closed)
2. ``await bus.publish(e)``   → fan-out to subscribers; failures here are
                                  non-fatal (logged and ignored).

The bus is async-first so it can plug into FastAPI's WebSocket lifecycle in
:mod:`secugent.api.ws`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from secugent.core.contracts import Event
from secugent.core.logger import redact

__all__ = ["EventBus", "Subscription"]

_logger = logging.getLogger("secugent.event_bus")


@dataclass
class Subscription:
    queue: asyncio.Queue[dict[str, Any]]
    run_filter: str | None = None
    _id: int = 0

    async def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        while True:
            yield await self.queue.get()


class EventBus:
    """Simple fan-out bus. Subscribers receive a redacted dict per event."""

    def __init__(self) -> None:
        self._subs: dict[int, Subscription] = {}
        self._lock = asyncio.Lock()
        self._next_id = 0

    # ------------------------------------------------------------------ #
    # Subscribe / unsubscribe
    # ------------------------------------------------------------------ #

    async def subscribe(
        self,
        *,
        run_filter: str | None = None,
        maxsize: int = 256,
    ) -> Subscription:
        async with self._lock:
            self._next_id += 1
            sub = Subscription(
                queue=asyncio.Queue(maxsize=maxsize),
                run_filter=run_filter,
                _id=self._next_id,
            )
            self._subs[sub._id] = sub
            return sub

    async def unsubscribe(self, sub: Subscription) -> None:
        async with self._lock:
            self._subs.pop(sub._id, None)

    # ------------------------------------------------------------------ #
    # Publish
    # ------------------------------------------------------------------ #

    async def publish(self, event: Event) -> None:
        payload = self._serialise(event)
        # Snapshot subs under the lock; deliver outside the lock to avoid
        # head-of-line blocking on a slow consumer.
        async with self._lock:
            targets = list(self._subs.values())
        for sub in targets:
            if sub.run_filter is not None and sub.run_filter != event.run_id:
                continue
            try:
                sub.queue.put_nowait(payload)
            except asyncio.QueueFull:
                _logger.warning("event_bus: dropping event for slow subscriber %s", sub._id)

    @staticmethod
    def _serialise(event: Event) -> dict[str, Any]:
        body = event.model_dump(mode="json")
        body["payload"] = redact(body.get("payload", {}))
        return body

    # ------------------------------------------------------------------ #
    # Inspection
    # ------------------------------------------------------------------ #

    @property
    def subscriber_count(self) -> int:
        return len(self._subs)
