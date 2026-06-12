# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — prompt registry with deterministic canary routing.

Directory layout::

    prompts/<role>/<name>/v<version>.md

Each file starts with YAML frontmatter (``version``, ``effective_at``,
``deprecated_at``, ``owners``). The :class:`PromptRegistry` resolves the
right version per run by hashing ``run_id`` against
:class:`CanaryConfig.canary_share` — deterministic so the same run sees the
same prompt on retries.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

__all__ = ["CanaryConfig", "Prompt", "PromptFrontmatter", "PromptRegistry"]


_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.DOTALL)


class PromptFrontmatter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    effective_at: datetime
    deprecated_at: datetime | None = None
    owners: list[str]


class Prompt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str
    name: str
    frontmatter: PromptFrontmatter
    body: str


class CanaryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_version: str
    canary_version: str | None = None
    canary_share: float = Field(ge=0.0, le=1.0, default=0.0)


class PromptRegistry:
    """Filesystem-backed registry with per-(role,name) canary config."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._canaries: dict[tuple[str, str], CanaryConfig] = {}

    def set_canary(self, *, role: str, name: str, config: CanaryConfig) -> None:
        self._canaries[(role, name)] = config

    def get(
        self,
        *,
        role: str,
        name: str,
        run_id: str | None = None,
        at: datetime | None = None,
    ) -> Prompt:
        config = self._canaries.get((role, name))
        if config is None:
            raise KeyError(f"no canary config for {role!r}/{name!r}")
        version = self._pick_version(config=config, run_id=run_id)
        path = self._root / role / name / f"v{version}.md"
        if not path.exists():
            raise FileNotFoundError(str(path))
        text = path.read_text(encoding="utf-8")
        frontmatter, body = self._parse(text)
        return Prompt(role=role, name=name, frontmatter=frontmatter, body=body)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _pick_version(*, config: CanaryConfig, run_id: str | None) -> str:
        if config.canary_version is None or config.canary_share <= 0.0:
            return config.active_version
        if config.canary_share >= 1.0:
            return config.canary_version
        if run_id is None:
            return config.active_version
        digest = hashlib.sha256(run_id.encode("utf-8")).digest()
        # First 8 bytes → 64-bit unsigned int → ratio in [0,1)
        n = int.from_bytes(digest[:8], "big")
        ratio = n / 2**64
        return config.canary_version if ratio < config.canary_share else config.active_version

    @staticmethod
    def _parse(text: str) -> tuple[PromptFrontmatter, str]:
        m = _FRONTMATTER_RE.match(text)
        if not m:
            raise ValueError("prompt file missing YAML frontmatter block")
        raw_meta = yaml.safe_load(m.group(1))
        body = m.group(2)
        return PromptFrontmatter.model_validate(raw_meta), body
