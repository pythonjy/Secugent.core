# SPDX-License-Identifier: Apache-2.0
"""Shared base for domestic/sovereign :class:`LLMClient` adapters.

The four sovereign adapters (EXAONE, HyperCLOVA X, A.X, Solar) share the same
transport / retry / validation / redaction behaviour and differ only in:

* the request **payload shape** (vendor request schema),
* how the **assistant text** is extracted from the response, and
* the **auth headers** the vendor expects.

Those three vendor-specific concerns are template methods; everything else
(input validation, bounded retry, token-limit enforcement, secret redaction,
JSON/format error handling) lives here once (§B-6 single-responsibility, no
copy-paste across adapters).

No control decision is made here. Adapters are model-neutral wrappers around
:class:`~secugent.core.llm_client.LLMClient`; the policy/HITL/taint decisions
stay in ``secugent.core`` and are reached via the abstraction, never re-decided.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Final

from secugent.core.llm_client import LLMClient, LLMError, LLMResponseFormatError

from ._transport import HttpResponse, HttpTransport, TransportError, default_transport

__all__ = ["BaseDomesticLLMClient", "OpenAICompatibleLLMClient"]

# OpenAI-compatible chat-completions sub-path appended to a ``/v1`` base.
_OPENAI_CHAT_PATH: Final[str] = "/chat/completions"

# Bound the retry budget so a flapping endpoint cannot wedge the caller. The
# control layer (RiskAnalyzer / HEAD) fails closed once these are exhausted.
_DEFAULT_MAX_ATTEMPTS: Final[int] = 3

# Defensive cap so a buggy caller cannot request an unbounded generation that
# would blow the token/cost budget on a sovereign endpoint (§B-10).
_MAX_TOKENS_LIMIT: Final[int] = 8192

# Statuses that are worth retrying (transient upstream conditions) vs. those
# that are terminal (auth/permission/bad-request) and must fail fast.
_RETRYABLE_STATUSES: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})


class BaseDomesticLLMClient(LLMClient):
    """Synchronous, injectable-transport base for sovereign-model adapters.

    Subclasses implement :meth:`_endpoint_url`, :meth:`_build_payload`,
    :meth:`_auth_headers`, and :meth:`_extract_text`. They MUST NOT override
    :meth:`generate` — the retry / validation / redaction contract is enforced
    here so every adapter behaves identically at the boundary.
    """

    #: Human-readable vendor label used only in (redacted) error messages.
    vendor: str = "domestic"

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str | None = None,
        model_id: str | None = None,
        timeout: float = 30.0,
        transport: HttpTransport | None = None,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    ) -> None:
        normalized = endpoint.strip()
        if not normalized:
            raise LLMError(f"{self.vendor}: endpoint is required (got empty value)")
        if not normalized.startswith(("http://", "https://")):
            raise LLMError(f"{self.vendor}: endpoint must be an http(s) URL")
        if timeout <= 0:
            raise LLMError(f"{self.vendor}: timeout must be positive")
        if max_attempts < 1:
            raise LLMError(f"{self.vendor}: max_attempts must be >= 1")
        self._endpoint = normalized.rstrip("/")
        # Stored privately; NEVER interpolated into any exception/log message.
        self._api_key = api_key
        # The sovereign model id the endpoint actually serves (e.g.
        # 'exaone-3.5-7.8b-instruct'). When bound, it OVERRIDES the per-call
        # ``model`` arg in ``generate`` so a domestic deployment never forwards a
        # caller's Claude default to a vLLM/CLOVA gateway that would 400/404 it.
        normalized_model_id = model_id.strip() if model_id is not None else None
        self._model_id: str | None = normalized_model_id or None
        self._timeout = timeout
        self._max_attempts = max_attempts
        # Lazily build the real transport only if none was injected, so importing
        # this module never imports httpx.
        self._transport: HttpTransport = transport if transport is not None else default_transport()

    # -- public ABC contract ------------------------------------------------

    def generate(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        response_format: str | None = None,
    ) -> str:
        normalized_messages = self._validate_inputs(system=system, messages=messages, max_tokens=max_tokens)
        # A bound sovereign model id takes precedence over the caller-supplied
        # ``model`` (which is the generic Claude default for cloud callers). On
        # the domestic path the endpoint serves exactly one configured model, so
        # forwarding the caller's id would be rejected upstream.
        effective_model = self._model_id if self._model_id is not None else model
        payload = self._build_payload(
            model=effective_model,
            system=system,
            messages=normalized_messages,
            max_tokens=max_tokens,
        )
        headers = {"Content-Type": "application/json", **self._auth_headers()}
        response = self._post_with_retry(url=self._request_url(), payload=payload, headers=headers)
        return self._parse_response(response)

    def _request_url(self) -> str:
        """Resolve the POST target. Defaults to the configured endpoint.

        Adapters whose vendor exposes a fixed sub-path (e.g. OpenAI-compatible
        ``/chat/completions``) override this to append it deterministically.
        """
        return self._endpoint

    # -- input validation / normalization -----------------------------------

    def _validate_inputs(
        self,
        *,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> list[dict[str, str]]:
        """Validate and normalize caller inputs (§B-8 boundary check).

        Returns the normalized message list. Raises :class:`LLMError` (never
        leaking content) on a contract violation.
        """
        if not isinstance(system, str):  # defensive: callers are typed but external
            raise LLMError(f"{self.vendor}: system prompt must be a string")
        if not messages:
            raise LLMError(f"{self.vendor}: messages must be non-empty")
        if max_tokens <= 0:
            raise LLMError(f"{self.vendor}: max_tokens must be positive")
        if max_tokens > _MAX_TOKENS_LIMIT:
            # Token/cost guard — fail closed rather than silently clamp so the
            # caller learns it exceeded the sovereign-endpoint budget.
            raise LLMError(f"{self.vendor}: max_tokens {max_tokens} exceeds limit {_MAX_TOKENS_LIMIT}")
        normalized: list[dict[str, str]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content")
            if role not in ("user", "assistant"):
                raise LLMError(
                    f"{self.vendor}: unsupported message role {role!r}; expected 'user' or 'assistant'"
                )
            if not isinstance(content, str):
                raise LLMError(f"{self.vendor}: message content must be a string")
            normalized.append({"role": role, "content": content})
        return normalized

    # -- transport / retry --------------------------------------------------

    def _post_with_retry(self, *, url: str, payload: dict[str, Any], headers: dict[str, str]) -> HttpResponse:
        """POST with bounded retry on transient failures; fail-closed otherwise.

        Retries only TransportError (no response) and retryable HTTP statuses.
        Terminal statuses (auth/bad-request) raise immediately. After the
        attempt budget is exhausted, raises :class:`LLMError` — never swallows.
        """
        last_exc: BaseException | None = None
        for _attempt in range(1, self._max_attempts + 1):
            try:
                response = self._transport.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
            except TransportError as exc:
                last_exc = exc
                continue  # transient: retry until budget exhausted
            status = response.status_code
            if status in _RETRYABLE_STATUSES:
                last_exc = LLMError(f"{self.vendor}: transient upstream status {status}")
                continue
            if status == 401 or status == 403:
                # Auth failure is terminal — do NOT echo any header/api_key.
                raise LLMError(f"{self.vendor}: authentication failed (status {status})")
            if status >= 400:
                raise LLMError(f"{self.vendor}: endpoint returned status {status}")
            return response
        raise LLMError(f"{self.vendor}: endpoint failed after {self._max_attempts} attempts") from last_exc

    # -- response parsing ---------------------------------------------------

    def _parse_response(self, response: HttpResponse) -> str:
        """Parse the vendor response into assistant text.

        Non-JSON / malformed / partial responses raise
        :class:`LLMResponseFormatError` (never swallowed, never leaking body).
        """
        try:
            body = response.json()
        except ValueError as exc:
            raise LLMResponseFormatError(f"{self.vendor}: response body was not valid JSON") from exc
        if not isinstance(body, dict):
            raise LLMResponseFormatError(f"{self.vendor}: response JSON was not an object")
        text = self._extract_text(body)
        if not isinstance(text, str) or not text:
            raise LLMResponseFormatError(f"{self.vendor}: response missing assistant text")
        return text

    # -- vendor-specific template methods -----------------------------------

    @abstractmethod
    def _auth_headers(self) -> dict[str, str]:
        """Vendor auth headers built from ``self._api_key`` (never logged)."""

    @abstractmethod
    def _build_payload(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> dict[str, Any]:
        """Build the vendor request body."""

    @abstractmethod
    def _extract_text(self, body: dict[str, Any]) -> str | None:
        """Extract the assistant text from a parsed JSON object.

        Return ``None`` (or "") when the expected field is absent/partial so the
        base raises :class:`LLMResponseFormatError`.
        """


class OpenAICompatibleLLMClient(BaseDomesticLLMClient):
    """Base for vendors that speak the OpenAI ``/v1/chat/completions`` schema.

    EXAONE (vLLM/OpenAI gateway), Upstage Solar, and SKT A.X all expose this
    shape. They differ only in :attr:`vendor` (for redacted diagnostics) and
    optionally auth, so the request/response handling lives here once.
    """

    def _request_url(self) -> str:
        if self._endpoint.endswith(_OPENAI_CHAT_PATH):
            return self._endpoint
        return f"{self._endpoint}{_OPENAI_CHAT_PATH}"

    def _auth_headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        return {"Authorization": f"Bearer {self._api_key}"}

    def _build_payload(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> dict[str, Any]:
        chat_messages: list[dict[str, str]] = [{"role": "system", "content": system}]
        chat_messages.extend(messages)
        return {
            "model": model,
            "messages": chat_messages,
            "max_tokens": max_tokens,
        }

    def _extract_text(self, body: dict[str, Any]) -> str | None:
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            return None
        first = choices[0]
        if not isinstance(first, dict):
            return None
        message = first.get("message")
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        return content if isinstance(content, str) else None
