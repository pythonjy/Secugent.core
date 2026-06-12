# SPDX-License-Identifier: Apache-2.0
"""Single-interface LLM client abstraction.

Per master prompt §1 (technology stack) and §0.7 (모듈 경계 엄수), every LLM
call in SecuGent goes through this module. Production uses the Anthropic SDK;
tests and ``ANTHROPIC_API_KEY``-less environments use the deterministic
:class:`MockLLMClient`.

The interface is intentionally narrow::

    client.generate(
        model="claude-haiku-4-5-20251001",
        system="<system prompt>",
        messages=[{"role": "user", "content": "<user content>"}],
        max_tokens=1024,
        response_format="json",  # advisory hint only
    )

It always returns a single string (the assistant message text).
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from tenacity import (
    RetryError,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

if TYPE_CHECKING:
    from anthropic.types import MessageParam

__all__ = [
    "LLMClient",
    "AnthropicLLMClient",
    "MockLLMClient",
    "LLMError",
    "LLMResponseFormatError",
    "RISK_MODEL_DEFAULT",
    "PLANNER_MODEL_DEFAULT",
    "get_default_client",
]


RISK_MODEL_DEFAULT = os.environ.get("SECUGENT_RISK_MODEL", "claude-haiku-4-5-20251001")
PLANNER_MODEL_DEFAULT = os.environ.get("SECUGENT_PLANNER_MODEL", "claude-opus-4-7")


class LLMError(RuntimeError):
    """Wraps transport/network/SDK errors that survived retries."""


class LLMResponseFormatError(LLMError):
    """Raised when the response cannot be coerced to the requested format.

    Subclasses :class:`LLMError` so that every ``except LLMError`` caller
    (HEAD / STEER / EVOLUTION / RegulationConverter) fails soft uniformly when a
    sovereign adapter raises this from ``generate()`` on a non-JSON / non-object
    / partial body. RiskAnalyzer additionally catches it explicitly to preserve
    its more specific HITL-with-format-reason degradation; that narrower handler
    still runs because it precedes the broad one on a separate call site.
    """


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMClient(ABC):
    """Minimal single-method abstraction.

    Subclasses MUST raise :class:`LLMError` on terminal transport failures so
    callers (RiskAnalyzer / HEAD planner) can route to HITL or fail closed.
    """

    @abstractmethod
    def generate(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        response_format: str | None = None,
    ) -> str:  # pragma: no cover - abstract
        ...


# ---------------------------------------------------------------------------
# Anthropic-backed client
# ---------------------------------------------------------------------------


class AnthropicLLMClient(LLMClient):
    """Thin wrapper around the ``anthropic`` SDK with tenacity retries.

    The SDK is imported lazily so that environments without it (e.g. CI
    without the dependency installed) can still import this module.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        max_attempts: int = 3,
        wait_seconds: float = 1.0,
    ) -> None:
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise LLMError("ANTHROPIC_API_KEY missing; use MockLLMClient instead")
        try:
            import anthropic  # noqa: F401
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise LLMError(f"anthropic SDK not installed: {exc}") from exc
        self._max_attempts = max_attempts
        self._wait_seconds = wait_seconds

    def generate(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        response_format: str | None = None,
    ) -> str:
        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        typed_messages = _to_message_params(messages)

        def _call() -> str:
            response = client.messages.create(
                model=model,
                system=system,
                messages=typed_messages,
                max_tokens=max_tokens,
            )
            return _extract_text(response)

        try:
            for attempt in Retrying(
                stop=stop_after_attempt(self._max_attempts),
                wait=wait_fixed(self._wait_seconds),
                retry=retry_if_exception_type(Exception),
                reraise=True,
            ):
                with attempt:
                    return _call()
        except RetryError as exc:  # pragma: no cover - depends on SDK behaviour
            raise LLMError(f"anthropic call failed after retries: {exc}") from exc
        except Exception as exc:  # pragma: no cover - SDK-specific
            raise LLMError(f"anthropic call failed: {exc}") from exc
        raise LLMError("unreachable")  # pragma: no cover


def _to_message_params(
    messages: list[dict[str, str]],
) -> list[MessageParam]:
    """Convert the public ``list[dict[str, str]]`` into SDK ``MessageParam``.

    The public :meth:`LLMClient.generate` contract accepts plain dicts so the
    abstraction stays SDK-agnostic. The Anthropic SDK requires ``role`` to be
    ``"user"`` or ``"assistant"``; any other role is a caller bug, so we fail
    fast (§B-8) rather than silently coerce.
    """
    out: list[MessageParam] = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role == "user":
            out.append({"role": "user", "content": content})
        elif role == "assistant":
            out.append({"role": "assistant", "content": content})
        else:
            raise LLMError(f"unsupported message role {role!r}; expected 'user' or 'assistant'")
    return out


def _extract_text(response: Any) -> str:
    """Best-effort extract the assistant text from an Anthropic response."""
    # SDK >=0.40 returns a Message with .content list of TextBlock objects.
    content = getattr(response, "content", None)
    if content is None:
        raise LLMError("anthropic response missing .content")
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    if not parts:
        raise LLMError("anthropic response contained no text block")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Mock client
# ---------------------------------------------------------------------------


class MockLLMClient(LLMClient):
    """Deterministic mock for tests and ``ANTHROPIC_API_KEY``-less mode.

    Two modes:

    * Queue mode — caller calls :meth:`queue` with canned strings; ``generate``
      returns them in FIFO order.
    * Programmatic mode — callers can set ``responder`` to a function
      ``(kwargs) -> str`` and drive responses from test logic.

    A :attr:`fail_n` counter lets tests inject transient failures to exercise
    the retry/HITL path.
    """

    def __init__(
        self,
        responses: Iterable[str] | None = None,
        *,
        responder: Any = None,
        fail_n: int = 0,
        exception: BaseException | None = None,
    ) -> None:
        self.queue_: list[str] = list(responses or [])
        self.responder = responder
        self.fail_n = fail_n
        self.exception = exception or LLMError("mock-llm-failure")
        self.calls: list[dict[str, Any]] = []

    def queue(self, text: str) -> None:
        self.queue_.append(text)

    def queue_json(self, payload: dict[str, Any]) -> None:
        self.queue_.append(json.dumps(payload))

    def generate(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        response_format: str | None = None,
    ) -> str:
        self.calls.append(
            {
                "model": model,
                "system": system,
                "messages": messages,
                "max_tokens": max_tokens,
                "response_format": response_format,
            }
        )
        if self.fail_n > 0:
            self.fail_n -= 1
            raise self.exception
        if self.responder is not None:
            return str(self.responder(self.calls[-1]))
        if not self.queue_:
            return "{}"
        return self.queue_.pop(0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_default_client() -> LLMClient:
    """Return an :class:`LLMClient` appropriate for the current environment.

    Resolution order:
    1. ``ANTHROPIC_API_KEY`` present → attempt :class:`AnthropicLLMClient`.
       Construction failure falls through to mock **only in non-production**.
    2. ``SECUGENT_DOMESTIC_MODEL_ENDPOINT`` present → domestic model path.
       - ``SECUGENT_DOMESTIC_MODEL`` selects a concrete sovereign client
         (exaone|hyperclova|ax|solar) → build it (prod and dev), never a Mock.
       - endpoint set but no/unknown model in production → raise
         :class:`LLMError` (fail-closed; no silent Mock).
       - endpoint set but no model in dev/test → :class:`MockLLMClient`.
    3. No key and no domestic endpoint:
       - ``SECUGENT_ENV=production`` → raise :class:`LLMError` (fail-closed).
       - All other environments → return :class:`MockLLMClient` (dev/test).

    The fail-closed guard prevents silent mock usage in production deployments
    where misconfigured credentials would otherwise produce mock responses
    without any visible error.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    domestic_endpoint = os.environ.get("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "").strip()
    is_production = os.environ.get("SECUGENT_ENV", "") == "production"

    if api_key:
        try:
            return AnthropicLLMClient()
        except LLMError:
            # In production, propagate the construction failure; in dev/test,
            # fall back to mock so tests without a real key still work.
            if is_production:
                raise
            return MockLLMClient()

    if domestic_endpoint:
        # Domestic model endpoint configured → honour it.
        # BDP_02 item 10: when a concrete sovereign model is selected via
        # SECUGENT_DOMESTIC_MODEL, build the real adapter (prod AND dev) so
        # closed-network/sovereign deployments get a real model — never a Mock.
        # The registry is imported lazily here so importing this module never
        # pulls the concrete adapters (model-neutral core isolation, §A-2.3).
        domestic_model = os.environ.get("SECUGENT_DOMESTIC_MODEL", "").strip()
        if domestic_model:
            from secugent.core.llm_clients import build_domestic_client

            # Thread the sovereign model id and (optional) auth so a REAL
            # endpoint is not handed a Claude default id with no Authorization
            # header — otherwise every prod request fails closed (401/404). An
            # empty value means "not configured" → the adapter falls back to the
            # per-call model / no-auth (dev/closed-network test gateways).
            domestic_model_id = os.environ.get("SECUGENT_DOMESTIC_MODEL_ID", "").strip() or None
            domestic_api_key = os.environ.get("SECUGENT_DOMESTIC_MODEL_API_KEY", "").strip() or None

            # An unknown/unimplemented model raises LLMError here. In production
            # that is the desired fail-closed boot refusal; in dev/test we also
            # surface it rather than masking a misconfiguration with a Mock.
            return build_domestic_client(
                domestic_model,
                endpoint=domestic_endpoint,
                model_id=domestic_model_id,
                api_key=domestic_api_key,
            )

        # Endpoint set but NO concrete model selected.
        # FIX (High): in production, refuse to silently use MockLLMClient when a
        # domestic endpoint is configured — MockLLMClient returns '{}' for every
        # call, which would defeat all security controls that depend on LLM judgment.
        if is_production:
            raise LLMError(
                "SECUGENT_DOMESTIC_MODEL_ENDPOINT is set but SECUGENT_DOMESTIC_MODEL "
                "selects no concrete client; refusing to boot with MockLLMClient in "
                "production. Set SECUGENT_DOMESTIC_MODEL (exaone|hyperclova|ax|solar) "
                "or use ANTHROPIC_API_KEY instead."
            )
        return MockLLMClient()

    # No API key, no domestic endpoint.
    if is_production:
        raise LLMError(
            "No LLM configured for production. Set ANTHROPIC_API_KEY or configure a domestic model endpoint."
        )
    return MockLLMClient()
