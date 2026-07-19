# SPDX-License-Identifier: Apache-2.0
"""Broker.dispatch refuses write-class effects with no content.

A write-class effect (FILE_WRITE / NET_SEND / CONNECTOR_ACTION) submitted with no
explicit ``content`` AND no ``step.context["content"]`` previously fell through to
``content_bytes=None`` and was silently submitted — a fail-OPEN gap (the broker
would "write nothing" without flagging the missing payload). This regression suite
pins the fail-closed contract: such a dispatch must raise (the broker's existing
``EgressDeniedError`` family), read/list effects must keep allowing ``None``, and a
present payload must still succeed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from secugent.core.contracts import Event, Step
from secugent.core.sec.policy import Match, PolicyDoc, Rule, compile_policy
from secugent.core.tenancy import TenantId
from secugent.io.broker import (
    EgressBroker,
    EgressDeniedError,
    EgressRequest,
)


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[EgressRequest] = []

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        self.calls.append(request)
        return b"executed"


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


def _allow_all() -> Any:
    return compile_policy(
        PolicyDoc(
            version="1",
            tenant_id="_base",
            rules=[Rule(id="a", effect="allow", match=Match(), rationale="allow all")],
        )
    )


def _broker(tmp_path: Path) -> tuple[EgressBroker, _RecordingTransport]:
    transport = _RecordingTransport()
    broker = EgressBroker(
        policy=_allow_all(),
        audit_store=_RecordingAudit(),
        transport=transport,
        sandbox_roots=[str(tmp_path)],
    )
    return broker, transport


def _write_step(tmp_path: Path) -> Step:
    # 한국어 픽스처: 금융 감사보고서 산출물 쓰기 단계 (tenant_id는 ASCII 제약을 따른다).
    return Step(
        tenant_id=TenantId("kookmin-bank"),
        run_id="r1",
        actor="sub:보고서작성",
        action_type="file_write",
        target=str(tmp_path / "감사보고서.txt"),
    )


def _read_step(tmp_path: Path) -> Step:
    return Step(
        tenant_id=TenantId("kookmin-bank"),
        run_id="r1",
        actor="sub:보고서작성",
        action_type="file_read",
        target=str(tmp_path / "원본.txt"),
    )


def test_dispatch_write_effect_content_none_is_rejected(tmp_path: Path) -> None:
    broker, transport = _broker(tmp_path)
    with pytest.raises(EgressDeniedError) as exc:
        broker.dispatch(_write_step(tmp_path))  # no content arg, no step.context content
    # fail-closed: the transport is never reached and the reason names the gap
    assert "content" in str(exc.value)
    assert transport.calls == []


def test_dispatch_read_effect_content_none_is_allowed(tmp_path: Path) -> None:
    broker, transport = _broker(tmp_path)
    result = broker.dispatch(_read_step(tmp_path))  # read needs no payload
    assert result.ok is True
    assert len(transport.calls) == 1
    assert transport.calls[0].content is None


def test_dispatch_write_effect_content_present_succeeds(tmp_path: Path) -> None:
    broker, transport = _broker(tmp_path)
    result = broker.dispatch(_write_step(tmp_path), content="결산 데이터")
    assert result.ok is True
    assert len(transport.calls) == 1
    assert transport.calls[0].content == "결산 데이터".encode()


def test_dispatch_write_effect_content_from_step_context_succeeds(tmp_path: Path) -> None:
    step = _write_step(tmp_path)
    step.context["content"] = "컨텍스트 페이로드"
    broker, transport = _broker(tmp_path)
    result = broker.dispatch(step)  # payload carried via step.context
    assert result.ok is True
    assert transport.calls[0].content == "컨텍스트 페이로드".encode()


def test_dispatch_write_effect_empty_bytes_is_allowed(tmp_path: Path) -> None:
    # An *explicit* empty payload is a legitimate "truncate to zero" write; only a
    # missing (None) payload is the fail-closed case.
    broker, transport = _broker(tmp_path)
    result = broker.dispatch(_write_step(tmp_path), content=b"")
    assert result.ok is True
    assert transport.calls[0].content == b""
