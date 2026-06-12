# SPDX-License-Identifier: Apache-2.0
"""LLM system prompt assets. Stored as plain Markdown for review/diff."""

from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent


def load_prompt(name: str) -> str:
    """Return the contents of a prompt file by basename (without extension)."""
    path = PROMPTS_DIR / f"{name}.md"
    return path.read_text(encoding="utf-8")
