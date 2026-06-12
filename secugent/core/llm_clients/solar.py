# SPDX-License-Identifier: Apache-2.0
"""Upstage Solar adapter (OpenAI-compatible chat completions).

Upstage Solar exposes an OpenAI-compatible ``/v1/chat/completions`` API with
Bearer auth. On-prem/sovereign Solar deployments use the same schema, so this
adapter reuses the shared OpenAI-compatible base while keeping its own vendor
identity for redaction/diagnostics.
"""

from __future__ import annotations

from ._base import OpenAICompatibleLLMClient

__all__ = ["SolarLLMClient"]


class SolarLLMClient(OpenAICompatibleLLMClient):
    """Upstage Solar OpenAI-compatible chat client."""

    vendor = "solar"
