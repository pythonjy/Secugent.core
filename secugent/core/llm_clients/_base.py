# SPDX-License-Identifier: Apache-2.0
"""Shared base for domestic/sovereign :class:`LLMClient` adapters.

The four sovereign adapters (EXAONE, HyperCLOVA X, A.X, Solar) share the same
transport / retry / validation / redaction behaviour and differ only in:

* the request **payload shape** (vendor request schema),
* how the **assistant text** is extracted from the response, and
* the **auth headers** the vendor expects.

Those three vendor-specific concerns are template methods; everything else
(input validation, bounded retry, token-limit enforcement, secret redaction,
JSON/format error handling) lives here once (single-responsibility, no
copy-paste across adapters).

No control decision is made here. Adapters are model-neutral wrappers around
:class:`~secugent.core.llm_client.LLMClient`; the policy/HITL/taint decisions
stay in ``secugent.core`` and are reached via the abstraction, never re-decided.
"""

from __future__ import annotations

import logging
from abc import abstractmethod
from typing import Any, Final

from secugent.core.llm_client import (
    LLMClient,
    LLMError,
    LLMResponseFormatError,
    UsageEvent,
    UsageObserver,
)

from ._transport import HttpResponse, HttpTransport, TransportError, default_transport

# Public per-spec estimation heuristic shared with ``MockLLMClient`` (~4 chars
# per token) for the fallback when a sovereign endpoint omits provider usage.
_CHARS_PER_TOKEN: Final[int] = 4

__all__ = ["BaseDomesticLLMClient", "OpenAICompatibleLLMClient"]

_logger = logging.getLogger(__name__)

# OpenAI-compatible chat-completions sub-path appended to a ``/v1`` base.
_OPENAI_CHAT_PATH: Final[str] = "/chat/completions"

# The OpenAI ``/v1`` API version segment. The ``/v1`` requirement
# was previously only documented in a comment, so a base endpoint given without it
# produced ``<host>/chat/completions`` (a silent 404). ``_request_url`` now inserts
# this segment when it is absent.
_OPENAI_VERSION_SEG: Final[str] = "/v1"

# Prefixes of hosted cloud model ids (Anthropic / OpenAI / Google). Forwarding one
# of these to a sovereign endpoint 404s — the endpoint serves its OWN model. Used
# to fail fast when no ``SECUGENT_DOMESTIC_MODEL_ID`` override is bound. Sovereign
# selectors (exaone/hyperclova/ax/solar and their served ids) never match these.
_CLOUD_MODEL_PREFIXES: Final[tuple[str, ...]] = (
    "claude",
    "gpt-",
    "gpt3",
    "gpt4",
    "gemini",
    "o1-",
    "o3-",
)


def _is_cloud_model_id(model: str) -> bool:
    """True when ``model`` looks like a hosted cloud (Anthropic/OpenAI/Google) id."""
    return model.strip().lower().startswith(_CLOUD_MODEL_PREFIXES)


# Bound the retry budget so a flapping endpoint cannot wedge the caller. The
# control layer (RiskAnalyzer / HEAD) fails closed once these are exhausted.
_DEFAULT_MAX_ATTEMPTS: Final[int] = 3

# Defensive cap so a buggy caller cannot request an unbounded generation that
# would blow the token/cost budget on a sovereign endpoint.
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
        usage_observer: UsageObserver | None = None,
    ) -> None:
        # COST-01: chain the OPTIONAL usage observer up to the base so the live
        # recorder ``create_app`` installs on a sovereign adapter actually fires
        # (the closed-network-first path). Defaults to ``None`` → the
        # ``generate() -> str`` contract and every existing caller stay unchanged.
        super().__init__(usage_observer=usage_observer)
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
        # fail FAST when no ``SECUGENT_DOMESTIC_MODEL_ID`` override
        # is bound and the caller's per-call ``model`` is a hosted cloud id (the
        # generic Claude/OpenAI default). Forwarding it to a sovereign/closed-network
        # endpoint that serves its OWN model yields a silent 404 after the retry
        # budget; a clear, actionable error at the first call is far better. A real
        # sovereign id (or a bound ``_model_id``) passes through unchanged, so
        # closed-network gateways that ignore the id still work.
        if self._model_id is None and _is_cloud_model_id(effective_model):
            raise LLMError(
                f"{self.vendor}: refusing to forward cloud model id {model!r} to a "
                "sovereign endpoint (would 404) — SECUGENT_DOMESTIC_MODEL_ID is not "
                "set. Set SECUGENT_DOMESTIC_MODEL_ID to the model id this endpoint "
                "serves. 국산(소버린) 엔드포인트에 클라우드 모델 id를 전달할 수 없습니다: "
                "SECUGENT_DOMESTIC_MODEL_ID를 설정하세요."
            )
        payload = self._build_payload(
            model=effective_model,
            system=system,
            messages=normalized_messages,
            max_tokens=max_tokens,
        )
        headers = {"Content-Type": "application/json", **self._auth_headers()}
        response = self._post_with_retry(url=self._request_url(), payload=payload, headers=headers)
        body = self._parse_body(response)
        text = self._extract_assistant_text(body)
        # COST-01 (review fix): emit usage on the SOVEREIGN chokepoint too, so
        # in-run metering (INV-2) is not silently inert on the closed-network
        # path. Emission is fail-open (INV-1) — it runs AFTER a successful text
        # extraction and never raises into ``generate``.
        self._emit_response_usage(
            body,
            effective_model=effective_model,
            system=system,
            messages=normalized_messages,
            output=text,
        )
        return text

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
        """Validate and normalize caller inputs (boundary check).

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

        Retained for backwards-compatibility. ``generate`` now parses the body
        once (so it can also read usage) via :meth:`_parse_body` +
        :meth:`_extract_assistant_text`; this wrapper composes the same two
        steps for any other caller.
        """
        return self._extract_assistant_text(self._parse_body(response))

    def _parse_body(self, response: HttpResponse) -> dict[str, Any]:
        """Decode the response into a JSON object (the shared first half).

        Non-JSON / non-object responses raise :class:`LLMResponseFormatError`
        (never swallowed, never leaking body). Returned to ``generate`` so the
        SAME parsed body backs both text and usage extraction (no double parse).
        """
        try:
            body = response.json()
        except ValueError as exc:
            raise LLMResponseFormatError(f"{self.vendor}: response body was not valid JSON") from exc
        if not isinstance(body, dict):
            raise LLMResponseFormatError(f"{self.vendor}: response JSON was not an object")
        return body

    def _extract_assistant_text(self, body: dict[str, Any]) -> str:
        """Extract validated assistant text from an already-parsed body.

        A missing/empty/partial text raises :class:`LLMResponseFormatError`.
        """
        text = self._extract_text(body)
        if not isinstance(text, str) or not text:
            raise LLMResponseFormatError(f"{self.vendor}: response missing assistant text")
        return text

    # -- usage extraction / emission (COST-01, fail-open) -------------------

    def _emit_response_usage(
        self,
        body: dict[str, Any],
        *,
        effective_model: str,
        system: str,
        messages: list[dict[str, str]],
        output: str,
    ) -> None:
        """Build and emit a :class:`UsageEvent` for a successful generation.

        Uses the vendor's provider usage when the body exposes it (exact=True),
        otherwise a length-based ESTIMATE mirroring ``MockLLMClient`` (exact=
        False, INV-4 honesty). The build itself is wrapped fail-open so a
        malformed usage shape can never abort a returned response; the base
        :meth:`~secugent.core.llm_client.LLMClient._emit_usage` is already
        fail-open against a raising observer (INV-1).
        """
        observer = self.usage_observer
        if observer is None:
            # Nothing installed → skip entirely (the common dev/test path), so a
            # default sovereign client behaves exactly as before (INV-3).
            return
        try:
            event = self._build_usage_event(
                body, effective_model=effective_model, system=system, messages=messages, output=output
            )
        except Exception as exc:  # noqa: BLE001 - metering must never break the call (INV-1)
            _logger.warning("%s: usage extraction failed (best-effort, ignored): %s", self.vendor, exc)
            return
        self._emit_usage(event)

    def _build_usage_event(
        self,
        body: dict[str, Any],
        *,
        effective_model: str,
        system: str,
        messages: list[dict[str, str]],
        output: str,
    ) -> UsageEvent:
        """Provider usage (exact=True) if exposed, else a length estimate."""
        provider = self._extract_usage(body)
        if provider is not None:
            in_tokens, out_tokens = provider
            return UsageEvent(
                model=effective_model,
                input_tokens=max(0, in_tokens),
                output_tokens=max(0, out_tokens),
                exact=True,
            )
        # Length-based ESTIMATE (~4 chars/token), mirroring MockLLMClient so the
        # ledger still accrues in-run on a usage-less sovereign body (INV-2).
        input_chars = len(system) + sum(len(m.get("content", "")) for m in messages)
        return UsageEvent(
            model=effective_model,
            input_tokens=input_chars // _CHARS_PER_TOKEN,
            output_tokens=len(output) // _CHARS_PER_TOKEN,
            exact=False,
        )

    def _extract_usage(self, body: dict[str, Any]) -> tuple[int, int] | None:
        """Read (input_tokens, output_tokens) from a vendor body, or ``None``.

        Base default: no usage exposed (return ``None`` → caller estimates).
        OpenAI-compatible / CLOVA subclasses override with their own shape. A
        partial/garbled usage field returns ``None`` (estimate fallback) rather
        than raising — the emitter is fail-open regardless.
        """
        return None

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
        # ``self._endpoint`` is already stripped + ``rstrip("/")``.
        base = self._endpoint
        if base.endswith(_OPENAI_CHAT_PATH):
            # Caller supplied the full chat-completions URL — honour it verbatim.
            return base
        # ensure the ``/v1`` version segment is present so a bare
        # host base (``https://host``) becomes ``https://host/v1/chat/completions``
        # instead of a silent 404 on ``https://host/chat/completions``. A base that
        # already carries ``/v1`` (as a trailing or interior segment) is left as-is.
        if not (base.endswith(_OPENAI_VERSION_SEG) or f"{_OPENAI_VERSION_SEG}/" in base):
            base = f"{base}{_OPENAI_VERSION_SEG}"
        return f"{base}{_OPENAI_CHAT_PATH}"

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

    def _extract_usage(self, body: dict[str, Any]) -> tuple[int, int] | None:
        """OpenAI usage shape: top-level ``usage.{prompt,completion}_tokens``."""
        return _read_int_pair(body.get("usage"), "prompt_tokens", "completion_tokens")


def _read_int_pair(usage: Any, input_key: str, output_key: str) -> tuple[int, int] | None:
    """Read an (input, output) int pair from a vendor ``usage`` mapping.

    Returns ``None`` (→ the caller falls back to a length estimate) when the
    field is absent, not a mapping, or carries non-int counts — defensive so a
    garbled provider usage shape never raises into the fail-open emitter.
    """
    if not isinstance(usage, dict):
        return None
    in_tokens = usage.get(input_key)
    out_tokens = usage.get(output_key)
    # ``bool`` is an ``int`` subclass — reject it so a stray ``True`` is treated
    # as "unmeasured" rather than counted as 1 token.
    if not isinstance(in_tokens, int) or isinstance(in_tokens, bool):
        return None
    if not isinstance(out_tokens, int) or isinstance(out_tokens, bool):
        return None
    return in_tokens, out_tokens
