# SPDX-License-Identifier: Apache-2.0
"""NAVER HyperCLOVA X adapter (CLOVA Studio chat-completions schema).

Unlike the OpenAI-compatible vendors, NAVER CLOVA Studio uses its own request /
response envelope:

* request body: ``{"messages": [...], "maxTokens": N}`` (camelCase token field),
* successful response: ``{"result": {"message": {"content": "..."}}}``.

This adapter implements that vendor shape directly while reusing the shared
validation / retry / redaction contract from :class:`BaseDomesticLLMClient`.
The request/response schema here is a reasonable typed model of CLOVA Studio;
the load-bearing guarantees are the :class:`LLMClient` contract and the
injectable transport, not byte-exact fidelity to a specific CLOVA revision.
"""

from __future__ import annotations

from typing import Any

from ._base import BaseDomesticLLMClient, _read_int_pair

__all__ = ["HyperClovaLLMClient"]


class HyperClovaLLMClient(BaseDomesticLLMClient):
    """NAVER HyperCLOVA X (CLOVA Studio) chat client."""

    vendor = "hyperclova"

    def _auth_headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        # Modern CLOVA Studio accepts a Bearer test/service API key. The key is
        # only placed in the header value, never logged or echoed in errors.
        return {"Authorization": f"Bearer {self._api_key}"}

    def _build_payload(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> dict[str, Any]:
        clova_messages: list[dict[str, str]] = [{"role": "system", "content": system}]
        clova_messages.extend(messages)
        # ``model`` is carried for parity/observability; CLOVA routes by URL path,
        # but including it keeps the call self-describing without affecting auth.
        return {
            "model": model,
            "messages": clova_messages,
            "maxTokens": max_tokens,
        }

    def _extract_text(self, body: dict[str, Any]) -> str | None:
        result = body.get("result")
        if not isinstance(result, dict):
            return None
        message = result.get("message")
        if not isinstance(message, dict):
            return None
        content = message.get("content")
        return content if isinstance(content, str) else None

    def _extract_usage(self, body: dict[str, Any]) -> tuple[int, int] | None:
        """CLOVA usage shape: ``result.usage.{promptTokens,completionTokens}``.

        A missing ``result``/``usage`` (older/partial CLOVA bodies) returns
        ``None`` so the base falls back to a length estimate (exact=False).
        """
        result = body.get("result")
        if not isinstance(result, dict):
            return None
        return _read_int_pair(result.get("usage"), "promptTokens", "completionTokens")
