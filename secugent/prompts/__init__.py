# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 prompt registry + canary routing.

This package supersedes the bare ``secugent/core/prompts`` helper for
PHASE 11+ flows. The PHASE 0-2 system prompts (RISKANALYZER, HEAD planner,
STEER classifier, EVOLUTION analyst) keep using the simple loader until
PHASE 12 migrates them onto :class:`PromptRegistry`.
"""

from secugent.prompts.registry import (
    CanaryConfig,
    Prompt,
    PromptFrontmatter,
    PromptRegistry,
)

__all__ = [
    "CanaryConfig",
    "Prompt",
    "PromptFrontmatter",
    "PromptRegistry",
]
