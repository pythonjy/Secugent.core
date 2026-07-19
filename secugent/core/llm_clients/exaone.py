# SPDX-License-Identifier: Apache-2.0
"""LG AI EXAONE adapter (OpenAI-compatible chat completions).

EXAONE on-prem serving (e.g. via vLLM / an OpenAI-compatible gateway) speaks the
OpenAI ``/v1/chat/completions`` schema. This adapter targets that shape so an
air-gapped EXAONE deployment plugs into SecuGent's :class:`LLMClient`
abstraction with no core coupling (model-neutral core).
"""

from __future__ import annotations

from ._base import OpenAICompatibleLLMClient

__all__ = ["ExaoneLLMClient"]


class ExaoneLLMClient(OpenAICompatibleLLMClient):
    """EXAONE OpenAI-compatible chat client."""

    vendor = "exaone"
