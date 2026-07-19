# SPDX-License-Identifier: Apache-2.0
"""A2A (Agent-to-Agent) collaboration adapter (P1, §A-3 P1-3).

Delegates planning / dispatch to a *remote* A2A agent over HTTP JSON, while
implementing the orchestrator's existing
:class:`secugent.orchestrator.runner.PlannerProtocol` /
:class:`secugent.orchestrator.runner.DispatcherProtocol`. A remote agent is
therefore a drop-in for the local ``HeadPlannerAdapter`` / ``DispatcherAdapter``
— the :class:`~secugent.orchestrator.runner.RunOrchestrator` does not know or
care whether planning happened in-process or on a peer agent.

We adopt the A2A standard (A-2 원칙 4 "독자 프로토콜 금지 → MCP/A2A 채택")
instead of inventing a SecuGent-specific RPC.

Fail-closed posture (mirrors ``adapters.py``):

* **Empty credential** → fail *before* any network call.
* **HTTP 4xx** → permanent failure (no retry — the request is wrong).
* **HTTP 5xx / timeout / network** → transient → tenacity retry; exhausted
  retries become a terminal failure.
* **Malformed body** (non-dict, schema violation, ``extra`` field) → permanent.
* **Empty plan** (zero steps) → permanent (a remote agent that returns no work
  is treated as a planning failure, not a no-op success).

Terminal failures are surfaced as the same two types the orchestrator already
catches: :class:`PlannerFailedError` (planner path) and
:class:`DispatcherResultMalformed` (dispatcher path) — so no orchestrator
change is required.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from tenacity import (
    RetryError,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from secugent.orchestrator.errors import (
    DispatcherResultMalformed,
    PlannerFailedError,
    PlannerTransientError,
)
from secugent.orchestrator.runner import PlanLike
from secugent.tools.connectors.transport import guard_url_host

if TYPE_CHECKING:
    import httpx

__all__ = [
    "A2AAgentConfig",
    "A2ADispatcherAdapter",
    "A2AHttpResponse",
    "A2APlannerAdapter",
    "A2ASettings",
    "A2ATransport",
    "HttpxA2ATransport",
    "build_a2a_transport",
]


_T = TypeVar("_T")


@dataclass(frozen=True)
class A2AHttpResponse:
    """Minimal HTTP response the transport returns: status + parsed JSON body."""

    status: int
    body: Any


class A2ATransport(Protocol):
    """Async seam performing one HTTP request to the remote A2A agent.

    Implementations wrap a real client; tests inject a fake. The callable must
    *raise* on transport failure (timeout / network) — the adapter classifies a
    raised exception as transient.
    """

    async def __call__(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict[str, Any],
        timeout_sec: float,
    ) -> A2AHttpResponse: ...


@dataclass(frozen=True)
class A2AAgentConfig:
    """Static description of a remote A2A agent endpoint."""

    base_url: str
    agent_id: str
    max_attempts: int = 3
    wait_initial: float = 0.5
    wait_max: float = 4.0
    timeout_sec: float = 30.0

    def __post_init__(self) -> None:
        if not self.base_url or not self.base_url.strip():
            raise ValueError("A2AAgentConfig.base_url must be a non-empty URL")
        if not self.agent_id or not self.agent_id.strip():
            raise ValueError("A2AAgentConfig.agent_id must be a non-empty id")
        if self.max_attempts < 1:
            raise ValueError("A2AAgentConfig.max_attempts must be >= 1")
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def endpoint(self, suffix: str) -> str:
        return f"{self.base_url}/agents/{self.agent_id}/{suffix}"


# --------------------------------------------------------------------------- #
# Strict response schemas (system boundary — §B-8)
# --------------------------------------------------------------------------- #


class _A2APlanResponse(BaseModel):
    """Remote plan response — strict (``extra='forbid'``)."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(..., min_length=1)
    summary: str
    steps: list[dict[str, Any]] = Field(default_factory=list)


class _A2ADispatchResponse(BaseModel):
    """Remote dispatch response — strict, shaped for ``runner._summarise_results``."""

    model_config = ConfigDict(extra="forbid")

    steps_executed: int = Field(..., ge=0)
    outputs: list[dict[str, Any]] = Field(default_factory=list)
    redactions: list[str] = Field(default_factory=list)
    subs: dict[str, dict[str, Any]] = Field(default_factory=dict)
    partial_failure: bool = False
    failure_reason: str | None = None


# --------------------------------------------------------------------------- #
# Shared transport classification
# --------------------------------------------------------------------------- #


class _RemoteTransientError(PlannerTransientError):
    """5xx / timeout / network failure — retryable for both planner & dispatcher."""


class _RemotePermanentError(Exception):
    """4xx / malformed / empty — never retried."""


async def _request(
    transport: A2ATransport,
    *,
    url: str,
    secret_value: str,
    json_body: dict[str, Any],
    timeout_sec: float,
) -> dict[str, Any]:
    """Perform one request and return the validated dict body.

    Raises :class:`_RemoteTransientError` (5xx / timeout / network) or
    :class:`_RemotePermanentError` (4xx / non-dict body). Schema validation of
    the dict is left to the caller (planner vs dispatcher schema differ).
    """
    headers = {"Authorization": f"Bearer {secret_value}", "Content-Type": "application/json"}
    try:
        awaitable: Awaitable[A2AHttpResponse] = transport(
            method="POST",
            url=url,
            headers=headers,
            json_body=json_body,
            timeout_sec=timeout_sec,
        )
        response = await awaitable
    except (_RemoteTransientError, _RemotePermanentError):
        raise
    except Exception as exc:  # timeout / network → transient
        raise _RemoteTransientError(f"a2a transport error: {type(exc).__name__}") from exc

    status = response.status
    if status >= 500:
        raise _RemoteTransientError(f"a2a remote returned {status}")
    if status >= 400:
        raise _RemotePermanentError(f"a2a remote returned {status}")
    if not isinstance(response.body, dict):
        raise _RemotePermanentError(f"a2a remote body is not an object ({type(response.body).__name__})")
    return response.body


async def _retry_async(
    config: A2AAgentConfig,
    coro_factory: Callable[[], Awaitable[_T]],
) -> _T:
    """Drive ``coro_factory`` through a tenacity retry on transient errors.

    Retries only on :class:`_RemoteTransientError` (5xx / timeout / network).
    A :class:`_RemotePermanentError` (4xx / malformed / empty) propagates on the
    first attempt. ``reraise=True`` lets the final transient surface so the
    caller can wrap it into the terminal type. Shared by both adapters so the
    planner and dispatcher use one retry policy.
    """
    for attempt in Retrying(
        stop=stop_after_attempt(config.max_attempts),
        wait=wait_exponential(multiplier=1.0, min=config.wait_initial, max=config.wait_max),
        retry=retry_if_exception_type(_RemoteTransientError),
        reraise=True,
    ):
        with attempt:
            return await coro_factory()
    raise AssertionError("unreachable: Retrying with reraise=True returns or raises")  # pragma: no cover


# --------------------------------------------------------------------------- #
# Planner adapter
# --------------------------------------------------------------------------- #


class A2APlannerAdapter:
    """Implements ``PlannerProtocol`` by delegating to a remote A2A agent."""

    def __init__(
        self,
        config: A2AAgentConfig,
        *,
        secret_value: str,
        http_transport: A2ATransport | None = None,
    ) -> None:
        self._config = config
        self._secret = secret_value
        self._transport = http_transport

    async def plan(self, *, run_id: str, command: str, context: dict[str, Any]) -> PlanLike:
        if not self._secret:
            raise PlannerFailedError("planning_error: a2a missing credential")
        if self._transport is None:
            raise PlannerFailedError("planning_error: a2a planner has no transport configured")

        body = {"run_id": run_id, "command": command, "context": dict(context)}
        try:
            return await _retry_async(self._config, lambda: self._plan_once(body))
        except _RemotePermanentError as exc:
            raise PlannerFailedError(f"planning_error: a2a_permanent: {exc}") from exc
        except _RemoteTransientError as exc:
            raise PlannerFailedError(f"planning_error: a2a_transient_exhausted: {exc}") from exc
        except RetryError as exc:  # pragma: no cover - tenacity safety net
            raise PlannerFailedError(f"planning_error: a2a_retry_error: {exc}") from exc

    async def _plan_once(self, body: dict[str, Any]) -> PlanLike:
        assert self._transport is not None  # guarded in plan()
        raw = await _request(
            self._transport,
            url=self._config.endpoint("plan"),
            secret_value=self._secret,
            json_body=body,
            timeout_sec=self._config.timeout_sec,
        )
        try:
            parsed = _A2APlanResponse.model_validate(raw)
        except ValidationError as exc:
            raise _RemotePermanentError(f"a2a plan response invalid: {exc.error_count()} error(s)") from exc
        if not parsed.steps:
            raise _RemotePermanentError("a2a plan has zero steps")
        return PlanLike(
            id=parsed.plan_id,
            summary=parsed.summary,
            steps=list(parsed.steps),
            raw=parsed.model_dump(),
        )


# --------------------------------------------------------------------------- #
# Dispatcher adapter
# --------------------------------------------------------------------------- #


class A2ADispatcherAdapter:
    """Implements ``DispatcherProtocol`` by delegating to a remote A2A agent."""

    def __init__(
        self,
        config: A2AAgentConfig,
        *,
        secret_value: str,
        http_transport: A2ATransport | None = None,
    ) -> None:
        self._config = config
        self._secret = secret_value
        self._transport = http_transport

    async def dispatch(self, *, run_id: str, plan: PlanLike) -> dict[str, Any]:
        if not self._secret:
            raise DispatcherResultMalformed("a2a missing credential")
        if self._transport is None:
            raise DispatcherResultMalformed("a2a dispatcher has no transport configured")

        body = {
            "run_id": run_id,
            "plan_id": plan.id,
            "summary": plan.summary,
            "steps": list(plan.steps),
        }
        try:
            return await _retry_async(self._config, lambda: self._dispatch_once(body))
        except _RemotePermanentError as exc:
            raise DispatcherResultMalformed(f"a2a_permanent: {exc}") from exc
        except _RemoteTransientError as exc:
            raise DispatcherResultMalformed(f"a2a_transient_exhausted: {exc}") from exc
        except RetryError as exc:  # pragma: no cover - tenacity safety net
            raise DispatcherResultMalformed(f"a2a_retry_error: {exc}") from exc

    async def _dispatch_once(self, body: dict[str, Any]) -> dict[str, Any]:
        assert self._transport is not None  # guarded in dispatch()
        raw = await _request(
            self._transport,
            url=self._config.endpoint("dispatch"),
            secret_value=self._secret,
            json_body=body,
            timeout_sec=self._config.timeout_sec,
        )
        try:
            parsed = _A2ADispatchResponse.model_validate(raw)
        except ValidationError as exc:
            raise _RemotePermanentError(
                f"a2a dispatch response invalid: {exc.error_count()} error(s)"
            ) from exc
        return parsed.model_dump()


# --------------------------------------------------------------------------- #
# Real httpx transport (S5)
# --------------------------------------------------------------------------- #


class A2ASettings(BaseModel):
    """Operator config for the production A2A transport (boot-time).

    ``allow_internal`` is False by default (deny-by-default §A-2.2); set True only
    for a closed-network on-prem peer A2A agent whose endpoint is RFC-1918.
    """

    model_config = ConfigDict(extra="forbid")

    allow_internal: bool = False


class HttpxA2ATransport:
    """Real :class:`A2ATransport` — one httpx request → :class:`A2AHttpResponse`.

    The adapter owns retry + schema validation; this transport only moves bytes:
    it returns the status + parsed JSON body (or the raw text when the body is not
    JSON, so the adapter rejects it as a permanent/malformed failure rather than a
    silent success), and *raises* on timeout / network so the adapter classifies it
    as transient. The SSRF guard (INV-6) runs first; the credential rides only in
    the caller-supplied ``Authorization`` header (INV-5). ``httpx`` is imported
    lazily (INV-8); an injected ``_mock_transport`` lets tests avoid sockets.
    """

    def __init__(
        self,
        *,
        allow_internal: bool = False,
        _mock_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._allow_internal = allow_internal
        self._mock_transport = _mock_transport

    async def __call__(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        json_body: dict[str, Any],
        timeout_sec: float,
    ) -> A2AHttpResponse:
        # SsrfBlocked propagates as-is: the adapter's _request treats any non-
        # transient/permanent raise as transient, so a blocked endpoint fails the
        # attempt (and is retried/exhausted into a terminal failure) — never a
        # silent success.
        guard_url_host(url, allow_internal=self._allow_internal)

        httpx = _import_httpx()
        client_kwargs: dict[str, Any] = {"timeout": timeout_sec}
        if self._mock_transport is not None:
            client_kwargs["transport"] = self._mock_transport
        async with httpx.AsyncClient(**client_kwargs) as client:
            # No try/except here: a timeout / network error must propagate so the
            # adapter's `_request` classifies it as transient (its documented
            # contract). We only translate the BODY shape.
            response = await client.request(method, url, json=json_body, headers=headers)
        try:
            body: Any = response.json()
        except ValueError:
            # Non-JSON 2xx/4xx body → surface the raw text (a non-dict) so the
            # adapter's strict schema validation rejects it as permanent/malformed.
            body = response.text
        return A2AHttpResponse(status=response.status_code, body=body)


def _import_httpx() -> Any:
    """Lazy ``httpx`` import (INV-8: never eager at module import)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise DispatcherResultMalformed(
            "httpx is required for the production A2A transport; install it or inject a transport"
        ) from exc
    return httpx


def build_a2a_transport(settings: A2ASettings) -> HttpxA2ATransport:
    """Materialise the production A2A transport (S5 wire factory).

    The integration step injects the result into :class:`A2APlannerAdapter` /
    :class:`A2ADispatcherAdapter`; this module never reaches ``api/main.py`` itself.
    """
    return HttpxA2ATransport(allow_internal=settings.allow_internal)
