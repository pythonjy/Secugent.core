# SPDX-License-Identifier: Apache-2.0
"""Policy fixtures = behavior examples that double as regression tests (EM-04).

An admin can't review compiled JSON, but they CAN review "this effect → blocked,
that effect → allowed". A :class:`Fixture` pins an expected outcome for an
effect+label; ``run_fixtures`` checks a compiled policy against them. Every
fixture must pass before a draft may be signed (see ``authoring.sign_off``), and
the approved fixtures become permanent regression tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from secugent.core.sec.effects import Effect
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy.evaluator import CompiledPolicy

__all__ = ["Fixture", "FixtureResult", "FixtureReport", "run_fixtures"]


@dataclass(frozen=True)
class Fixture:
    effect: Effect
    label: DataLabel
    expected: Literal["allow", "deny", "hard_block"]


@dataclass(frozen=True)
class FixtureResult:
    fixture: Fixture
    actual: str
    passed: bool


@dataclass(frozen=True)
class FixtureReport:
    results: tuple[FixtureResult, ...]

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> tuple[FixtureResult, ...]:
        return tuple(r for r in self.results if not r.passed)


def run_fixtures(policy: CompiledPolicy, fixtures: list[Fixture]) -> FixtureReport:
    """Evaluate ``policy`` against each fixture; a fixture fails when the
    compiled outcome differs from its expected outcome."""
    results: list[FixtureResult] = []
    for fixture in fixtures:
        actual = policy.evaluate(fixture.effect, fixture.label).outcome
        results.append(FixtureResult(fixture=fixture, actual=actual, passed=actual == fixture.expected))
    return FixtureReport(results=tuple(results))
