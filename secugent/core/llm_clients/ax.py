# SPDX-License-Identifier: Apache-2.0
"""SKT A.X adapter (OpenAI-compatible chat completions).

SKT's A.X family is served behind an OpenAI-compatible gateway in on-prem /
sovereign deployments, so this adapter reuses the shared OpenAI-compatible
request/response handling and only declares its own vendor identity for
redacted diagnostics (model-neutral core).
"""

from __future__ import annotations

from ._base import OpenAICompatibleLLMClient

__all__ = ["AxLLMClient"]


class AxLLMClient(OpenAICompatibleLLMClient):
    """SKT A.X OpenAI-compatible chat client."""

    vendor = "ax"
