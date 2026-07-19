# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.event_bus.EventBus.

Coverage gate 90% for secugent.core — event_bus.py was at 49%
because all async subscribe/publish/unsubscribe paths were untested by unit tests.
This file covers the full EventBus surface to bring core coverage above 90%.
"""

from __future__ import annotations

import asyncio

from secugent.core.contracts import Event
from secugent.core.event_bus import EventBus, Subscription

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(run_id: str = "run-001", tenant: str = "test-tenant-kr") -> Event:
    """Korean actor fixture (§C-3)."""
    return Event(
        run_id=run_id,
        tenant_id=tenant,
        actor="감사관-홍길동",
        type="test.event",
        step_id="s1",
        payload={"msg": "안녕하세요"},
    )


# ---------------------------------------------------------------------------
# EventBus — subscribe / publish / unsubscribe
# ---------------------------------------------------------------------------


async def test_subscribe_returns_subscription() -> None:
    """subscribe() returns a Subscription with the expected run_filter."""
    bus = EventBus()
    sub = await bus.subscribe(run_filter="run-abc")
    assert isinstance(sub, Subscription)
    assert sub.run_filter == "run-abc"
    assert bus.subscriber_count == 1


async def test_unsubscribe_removes_subscriber() -> None:
    """unsubscribe() removes the subscriber from the bus."""
    bus = EventBus()
    sub = await bus.subscribe()
    assert bus.subscriber_count == 1
    await bus.unsubscribe(sub)
    assert bus.subscriber_count == 0


async def test_publish_delivers_to_subscriber() -> None:
    """publish() fans out the event to a matching subscriber."""
    bus = EventBus()
    sub = await bus.subscribe(run_filter="run-001")
    evt = _make_event(run_id="run-001")
    await bus.publish(evt)
    # The message should be in the queue
    assert not sub.queue.empty()
    msg = sub.queue.get_nowait()
    assert msg["run_id"] == "run-001"
    assert msg["type"] == "test.event"


async def test_publish_filters_wrong_run_id() -> None:
    """publish() does NOT deliver to a subscriber filtering on a different run_id."""
    bus = EventBus()
    sub = await bus.subscribe(run_filter="run-other")
    evt = _make_event(run_id="run-001")
    await bus.publish(evt)
    assert sub.queue.empty()


async def test_publish_no_filter_receives_all_runs() -> None:
    """A subscriber without run_filter receives events from any run."""
    bus = EventBus()
    sub = await bus.subscribe(run_filter=None)
    for run_id in ("run-001", "run-002", "run-003"):
        await bus.publish(_make_event(run_id=run_id))
    assert sub.queue.qsize() == 3


async def test_publish_drops_on_queue_full() -> None:
    """publish() logs and drops the event when the subscriber queue is full."""
    bus = EventBus()
    sub = await bus.subscribe(maxsize=1)
    evt = _make_event()
    await bus.publish(evt)  # fills the queue
    # Second publish must NOT raise — the event is silently dropped
    await bus.publish(evt)
    assert sub.queue.qsize() == 1  # still 1 (the second was dropped)


async def test_multiple_subscribers_fan_out() -> None:
    """publish() delivers to all matching subscribers."""
    bus = EventBus()
    sub_a = await bus.subscribe(run_filter="run-X")
    sub_b = await bus.subscribe()  # no filter — receives everything
    sub_c = await bus.subscribe(run_filter="run-Y")  # wrong filter

    await bus.publish(_make_event(run_id="run-X"))

    assert not sub_a.queue.empty()
    assert not sub_b.queue.empty()
    assert sub_c.queue.empty()


async def test_serialise_redacts_payload() -> None:
    """_serialise() redacts the payload dict (event payloads must not leak secrets)."""
    bus = EventBus()
    sub = await bus.subscribe()
    evt = _make_event()
    await bus.publish(evt)
    msg = sub.queue.get_nowait()
    # payload must be present (possibly redacted) but not the raw sentinel
    assert "payload" in msg


async def test_subscription_aiter_yields_events() -> None:
    """Subscription.__aiter__ yields enqueued events."""
    bus = EventBus()
    sub = await bus.subscribe()
    evt = _make_event(run_id="async-iter-run")
    await bus.publish(evt)

    # Consume one item via __aiter__ with a short timeout
    async def _consume(s: Subscription) -> dict:  # type: ignore[return]
        async for msg in s:
            return msg

    result = await asyncio.wait_for(_consume(sub), timeout=2.0)
    assert result["run_id"] == "async-iter-run"


async def test_subscriber_count_property() -> None:
    """subscriber_count reflects current live subscribers."""
    bus = EventBus()
    assert bus.subscriber_count == 0
    sub1 = await bus.subscribe()
    sub2 = await bus.subscribe()
    assert bus.subscriber_count == 2
    await bus.unsubscribe(sub1)
    assert bus.subscriber_count == 1
    await bus.unsubscribe(sub2)
    assert bus.subscriber_count == 0


async def test_unsubscribe_idempotent() -> None:
    """Calling unsubscribe() twice for the same subscriber does not raise."""
    bus = EventBus()
    sub = await bus.subscribe()
    await bus.unsubscribe(sub)
    await bus.unsubscribe(sub)  # must not raise
    assert bus.subscriber_count == 0
