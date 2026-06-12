# SPDX-License-Identifier: Apache-2.0
"""Compiled policy + deterministic evaluation (EM-03).

``CompiledPolicy.evaluate`` resolves an effect+label to a :class:`Decision` with
fixed precedence ``hard_block > deny > allow > default(deny)``. Targets match
against the EM-01 canonical ``effect.target`` only — there is no raw string to
bypass.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel

__all__ = ["Decision", "CompiledPolicy", "CompiledRule"]


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: Literal["allow", "deny", "hard_block"]
    rule_id: str | None = None
    rationale: str
    is_deterministic: bool = True


@dataclass(frozen=True)
class CompiledRule:
    """A single compiled rule with an immutable, precomputed matcher."""

    id: str
    effect: Literal["allow", "deny", "hard_block"]
    rationale: str
    kind: EffectKind | None
    target_glob: str | None
    sink_class: SinkClass | None
    min_label: DataLabel | None

    def matches(self, effect: Effect, label: DataLabel) -> bool:
        if self.kind is not None and effect.kind != self.kind:
            return False
        if self.sink_class is not None and effect.sink_class != self.sink_class:
            return False
        if self.min_label is not None and label < self.min_label:
            return False
        if self.target_glob is not None and not fnmatch.fnmatchcase(effect.target, self.target_glob):
            return False
        return True


# Highest-precedence outcome first.
_PRECEDENCE: tuple[Literal["hard_block", "deny", "allow"], ...] = ("hard_block", "deny", "allow")


@dataclass(frozen=True)
class CompiledPolicy:
    """Immutable, signed-and-verified policy ready for deterministic evaluation."""

    doc_hash: str
    rules: tuple[CompiledRule, ...]

    def evaluate(self, effect: Effect, label: DataLabel) -> Decision:
        matched = [rule for rule in self.rules if rule.matches(effect, label)]
        for outcome in _PRECEDENCE:
            for rule in matched:
                if rule.effect == outcome:
                    return Decision(outcome=outcome, rule_id=rule.id, rationale=rule.rationale)
        return Decision(outcome="deny", rule_id=None, rationale="default_deny")
