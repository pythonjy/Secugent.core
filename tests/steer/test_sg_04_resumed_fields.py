# SPDX-License-Identifier: Apache-2.0
"""SG-20260621-04 회귀 테스트: emit_resume_from_checkpoint가 §C-2 필드를 포함함."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from secugent.audit.hash_chain import ChainedEventStore
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations
from secugent.steer.steer import SteerHandler


@pytest.fixture
def store(tmp_path: Path) -> Iterator[EventStore]:
    s = EventStore(tmp_path / "sg04_test.db")
    yield s
    s.close()


@pytest.fixture
def chained(store: EventStore) -> Iterator[ChainedEventStore]:
    c = ChainedEventStore(store)
    yield c
    c.close()


def _make_handler(chained: ChainedEventStore) -> SteerHandler:
    return SteerHandler(
        oversight=OversightEngine(Regulations(version="t")),
        event_store=chained,
    )


def _steer_resumed_events(store: EventStore, run_id: str) -> list[Event]:
    return [e for e in store.list_events(run_id=run_id) if e.type == "steer.resumed"]


class TestResumedFields:
    """emit_resume_from_checkpoint가 §C-2 필드 7개를 포함함."""

    def test_all_c2_fields_present(self, chained: ChainedEventStore, store: EventStore) -> None:
        handler = _make_handler(chained)
        result = handler.emit_resume_from_checkpoint(
            run_id="run-sg04",
            from_checkpoint_id="snap://run-sg04/step-1/ckpt-abc",
            actor="operator:test",
            rule_of_two_axes=["untrusted_input"],
        )
        assert result.event_id is not None
        assert result.from_checkpoint_id == "snap://run-sg04/step-1/ckpt-abc"

        steer_events = _steer_resumed_events(store, "run-sg04")
        assert len(steer_events) == 1
        payload = steer_events[0].payload

        # §C-2 required fields
        assert payload.get("gate") == "steer"
        assert payload.get("decision") == "approve"
        assert "input_hash" in payload
        # The sha256 hex string is redacted to [REDACTED:KEY] by the durable store
        # (§6 long-hex pattern). Either form proves the field was written correctly.
        assert isinstance(payload["input_hash"], str) and len(payload["input_hash"]) > 0
        assert "regulations_version" in payload
        assert "rule_of_two_axes" in payload
        assert payload["rule_of_two_axes"] == ["untrusted_input"]
        assert "risk_score" in payload
        assert "rationale" in payload
        assert "from_checkpoint_id" in payload
        assert payload["from_checkpoint_id"] == "snap://run-sg04/step-1/ckpt-abc"

    def test_default_rule_of_two_axes_is_empty_list(
        self, chained: ChainedEventStore, store: EventStore
    ) -> None:
        handler = _make_handler(chained)
        handler.emit_resume_from_checkpoint(
            run_id="run-sg04b",
            from_checkpoint_id="snap://run-sg04b/step-0/ckpt-xyz",
            actor="operator:test",
        )
        steer_events = _steer_resumed_events(store, "run-sg04b")
        assert len(steer_events) == 1
        assert steer_events[0].payload["rule_of_two_axes"] == []

    def test_input_hash_is_sha256_of_checkpoint_id(self) -> None:
        """input_hash must equal sha256(checkpoint_id) — verified before store redaction."""
        captured: list[Event] = []

        class _CaptureSink:
            def append_event(self, event: Event) -> Event:
                captured.append(event)
                return event

        handler = SteerHandler(
            oversight=OversightEngine(Regulations(version="t")),
            event_store=_CaptureSink(),
        )
        ckpt_id = "snap://run-hash-test/step-2/ckpt-789"
        handler.emit_resume_from_checkpoint(
            run_id="run-hash-test",
            from_checkpoint_id=ckpt_id,
            actor="operator:test",
        )
        steer_events = [e for e in captured if e.type == "steer.resumed"]
        assert len(steer_events) == 1
        expected = hashlib.sha256(ckpt_id.encode()).hexdigest()
        assert steer_events[0].payload["input_hash"] == expected
