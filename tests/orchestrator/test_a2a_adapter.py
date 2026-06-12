# SPDX-License-Identifier: Apache-2.0
"""A2A collaboration adapter — unit tests (RED first).

``A2APlannerAdapter`` / ``A2ADispatcherAdapter`` delegate plan/dispatch to a
*remote* A2A agent over HTTP JSON, implementing the orchestrator's
``PlannerProtocol`` / ``DispatcherProtocol`` so a remote agent is transparently
usable. fail-closed retry (transient only) + strict Pydantic validation.

Korean enterprise fixture (§C-3): a remote A2A 에이전트 goal in Korean.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from secugent.orchestrator.a2a_adapter import (
    A2AAgentConfig,
    A2ADispatcherAdapter,
    A2AHttpResponse,
    A2APlannerAdapter,
)
from secugent.orchestrator.errors import (
    DispatcherResultMalformed,
    PlannerFailedError,
)
from secugent.orchestrator.runner import PlanLike

# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #

_FAST = {"max_attempts": 3, "wait_initial": 0.0, "wait_max": 0.0}


def _config(**kw: Any) -> A2AAgentConfig:
    base = {"base_url": "https://a2a.example.test", "agent_id": "remote-1", "timeout_sec": 5.0}
    base.update(_FAST)
    base.update(kw)
    return A2AAgentConfig(**base)  # type: ignore[arg-type]


_PLAN_BODY = {
    "plan_id": "plan_remote_1",
    "summary": "원격 에이전트가 작성한 계획",
    "steps": [{"id": "s1"}, {"id": "s2"}],
}

_DISPATCH_BODY = {
    "steps_executed": 2,
    "outputs": [{"actor": "remote", "step_id": "s1", "payload": {"k": "v"}}],
    "redactions": [],
    "subs": {"remote": {"status": "completed", "completed_steps": 2}},
    "partial_failure": False,
    "failure_reason": None,
}


@dataclass
class _Resp:
    status: int
    body: Any


class _FakeTransport:
    """Yields queued responses (or raises queued exceptions) per call."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict[str, Any],
        timeout_sec: float,
    ) -> A2AHttpResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "json_body": json_body,
                "timeout_sec": timeout_sec,
            }
        )
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return A2AHttpResponse(status=item.status, body=item.body)


# --------------------------------------------------------------------------- #
# Planner — happy path
# --------------------------------------------------------------------------- #


async def test_planner_returns_planlike() -> None:
    transport = _FakeTransport([_Resp(200, _PLAN_BODY)])
    adapter = A2APlannerAdapter(_config(), secret_value="bearer-tok", http_transport=transport)
    plan = await adapter.plan(run_id="run1", command="명령", context={})
    assert isinstance(plan, PlanLike)
    assert plan.id == "plan_remote_1"
    assert plan.summary == "원격 에이전트가 작성한 계획"
    assert len(plan.steps) == 2
    call = transport.calls[0]
    assert call["headers"]["Authorization"] == "Bearer bearer-tok"
    assert call["json_body"]["run_id"] == "run1"
    assert call["json_body"]["command"] == "명령"


async def test_planner_sends_to_plan_endpoint() -> None:
    transport = _FakeTransport([_Resp(200, _PLAN_BODY)])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    await adapter.plan(run_id="r", command="c", context={"x": 1})
    assert transport.calls[0]["url"].endswith("/agents/remote-1/plan")
    assert transport.calls[0]["method"] == "POST"


# --------------------------------------------------------------------------- #
# Planner — fail-closed invariants
# --------------------------------------------------------------------------- #


async def test_planner_empty_secret_rejected() -> None:
    transport = _FakeTransport([_Resp(200, _PLAN_BODY)])
    adapter = A2APlannerAdapter(_config(), secret_value="", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})
    assert transport.calls == []  # never called


async def test_planner_4xx_permanent_failure_no_retry() -> None:
    transport = _FakeTransport([_Resp(403, {"error": "forbidden"})])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})
    assert len(transport.calls) == 1  # no retry on 4xx


async def test_planner_5xx_retries_then_succeeds() -> None:
    transport = _FakeTransport([_Resp(503, {}), _Resp(200, _PLAN_BODY)])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    plan = await adapter.plan(run_id="r", command="c", context={})
    assert plan.id == "plan_remote_1"
    assert len(transport.calls) == 2


async def test_planner_5xx_exhausted_fails_closed() -> None:
    transport = _FakeTransport([_Resp(500, {}), _Resp(500, {}), _Resp(500, {})])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})
    assert len(transport.calls) == 3


async def test_planner_timeout_retries() -> None:
    transport = _FakeTransport([TimeoutError("slow"), _Resp(200, _PLAN_BODY)])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    plan = await adapter.plan(run_id="r", command="c", context={})
    assert plan.id == "plan_remote_1"
    assert len(transport.calls) == 2


async def test_planner_malformed_body_fails() -> None:
    # extra/unknown field violates strict schema → permanent fail
    transport = _FakeTransport([_Resp(200, {"plan_id": "p", "summary": "s", "steps": [], "bogus": 1})])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})
    assert len(transport.calls) == 1  # malformed is not transient


async def test_planner_non_dict_body_fails() -> None:
    transport = _FakeTransport([_Resp(200, ["not", "a", "dict"])])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})


async def test_planner_empty_plan_rejected() -> None:
    transport = _FakeTransport([_Resp(200, {"plan_id": "p", "summary": "s", "steps": []})])
    adapter = A2APlannerAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})


# --------------------------------------------------------------------------- #
# Dispatcher — happy path
# --------------------------------------------------------------------------- #


def _planlike() -> PlanLike:
    return PlanLike(id="plan_remote_1", summary="원격 계획", steps=[{"id": "s1"}, {"id": "s2"}])


async def test_dispatcher_returns_result_dict() -> None:
    transport = _FakeTransport([_Resp(200, _DISPATCH_BODY)])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    result = await adapter.dispatch(run_id="r", plan=_planlike())
    assert result["steps_executed"] == 2
    assert result["partial_failure"] is False
    assert result["subs"]["remote"]["completed_steps"] == 2
    call = transport.calls[0]
    assert call["url"].endswith("/agents/remote-1/dispatch")
    assert call["headers"]["Authorization"] == "Bearer t"
    assert call["json_body"]["plan_id"] == "plan_remote_1"


async def test_dispatcher_partial_failure_surfaced() -> None:
    body = {**_DISPATCH_BODY, "partial_failure": True, "failure_reason": "sub_error: remote:blocked"}
    transport = _FakeTransport([_Resp(200, body)])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    result = await adapter.dispatch(run_id="r", plan=_planlike())
    assert result["partial_failure"] is True
    assert result["failure_reason"] == "sub_error: remote:blocked"


# --------------------------------------------------------------------------- #
# Dispatcher — fail-closed invariants
# --------------------------------------------------------------------------- #


async def test_dispatcher_empty_secret_rejected() -> None:
    transport = _FakeTransport([_Resp(200, _DISPATCH_BODY)])
    adapter = A2ADispatcherAdapter(_config(), secret_value="", http_transport=transport)
    with pytest.raises(DispatcherResultMalformed):
        await adapter.dispatch(run_id="r", plan=_planlike())
    assert transport.calls == []


async def test_dispatcher_4xx_permanent() -> None:
    transport = _FakeTransport([_Resp(400, {})])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(DispatcherResultMalformed):
        await adapter.dispatch(run_id="r", plan=_planlike())
    assert len(transport.calls) == 1


async def test_dispatcher_5xx_retries_then_succeeds() -> None:
    transport = _FakeTransport([_Resp(502, {}), _Resp(200, _DISPATCH_BODY)])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    result = await adapter.dispatch(run_id="r", plan=_planlike())
    assert result["steps_executed"] == 2
    assert len(transport.calls) == 2


async def test_dispatcher_timeout_exhausted_fails() -> None:
    transport = _FakeTransport([TimeoutError(), TimeoutError(), TimeoutError()])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(DispatcherResultMalformed):
        await adapter.dispatch(run_id="r", plan=_planlike())
    assert len(transport.calls) == 3


async def test_dispatcher_malformed_body_fails() -> None:
    transport = _FakeTransport([_Resp(200, {"unexpected": True})])
    adapter = A2ADispatcherAdapter(_config(), secret_value="t", http_transport=transport)
    with pytest.raises(DispatcherResultMalformed):
        await adapter.dispatch(run_id="r", plan=_planlike())


async def test_dispatcher_no_transport_fails_closed() -> None:
    adapter = A2ADispatcherAdapter(_config(), secret_value="t")
    with pytest.raises(DispatcherResultMalformed):
        await adapter.dispatch(run_id="r", plan=_planlike())


async def test_planner_no_transport_fails_closed() -> None:
    adapter = A2APlannerAdapter(_config(), secret_value="t")
    with pytest.raises(PlannerFailedError):
        await adapter.plan(run_id="r", command="c", context={})
