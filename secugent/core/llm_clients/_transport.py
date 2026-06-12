# SPDX-License-Identifier: Apache-2.0
"""Injectable synchronous HTTP transport for domestic LLM adapters.

This module exists so the concrete sovereign-model adapters (EXAONE, HyperCLOVA
X, A.X, Solar) can POST to a vendor endpoint **without** hard-binding to a
specific HTTP library and **without** importing ``httpx`` at import time
(§A model/framework neutrality + closed-network lazy-import discipline).

Design
------
* :class:`HttpResponse` / :class:`HttpTransport` are tiny structural protocols
  (duck-typed). Tests inject a fake transport; production lazily builds an
  ``httpx``-backed one (:func:`default_transport`).
* No control / policy / HITL / taint logic lives here — adapters are pure
  wrappers around :class:`secugent.core.llm_client.LLMClient` and call core for
  any decision. This file only moves bytes.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = [
    "HttpResponse",
    "HttpTransport",
    "TransportError",
    "default_transport",
]


class TransportError(RuntimeError):
    """Raised by a transport when the request never produced a response.

    Covers connect/read timeouts and connection refused/reset. Adapters catch
    this and translate it into :class:`~secugent.core.llm_client.LLMError`
    after exhausting bounded retries. The message is intentionally free of any
    secret/PII (only the failure category, never the request body or api_key).
    """


@runtime_checkable
class HttpResponse(Protocol):
    """Structural view of an HTTP response the adapters rely on."""

    @property
    def status_code(self) -> int: ...

    def json(self) -> Any:
        """Parse the body as JSON. MUST raise ``ValueError`` on non-JSON."""
        ...

    @property
    def text(self) -> str:
        """Raw decoded body (used only for bounded, redacted diagnostics)."""
        ...


@runtime_checkable
class HttpTransport(Protocol):
    """Structural view of the minimal synchronous POST transport.

    A real ``httpx.Client`` satisfies this protocol; tests pass a fake. The
    transport MUST raise :class:`TransportError` (or any exception) on a
    no-response condition so the adapter can retry/fail-closed — it must never
    silently return ``None``.
    """

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse: ...


class _HttpxTransport:
    """Default transport backed by ``httpx`` (imported lazily).

    Constructed only when no transport is injected, so importing the adapters
    (and therefore ``secugent.core``) never requires ``httpx`` to be present.
    """

    def __init__(self) -> None:
        try:
            import httpx  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise TransportError(
                "httpx is required for the default domestic LLM transport; install it or inject a transport"
            ) from exc

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse:
        import httpx

        try:
            with httpx.Client(timeout=timeout) as client:
                return client.post(url, json=json, headers=headers)
        except httpx.TimeoutException as exc:
            raise TransportError("request timed out") from exc
        except httpx.TransportError as exc:
            # Connection refused/reset/DNS — no response received. Do NOT echo
            # the exception text (it can contain the full URL / endpoint host);
            # use a fixed category string.
            raise TransportError("transport failure: no response") from exc


def default_transport() -> HttpTransport:
    """Build the production ``httpx``-backed transport (lazy import)."""
    return _HttpxTransport()
