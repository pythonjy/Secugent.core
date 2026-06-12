# SPDX-License-Identifier: Apache-2.0
"""Runtime envelope review gate (EM-08) — SUSPEND → HITL → RESUME / REJECT.

When an effect exceeds the approved envelope at runtime (EM-07 returns
``suspend``), the run is not torn down: only *that effect* is paused and routed
to a human. This is the deterministic state model the orchestrator drives —

    RUNNING --on_suspend--> SUSPENDED --on_approve--> RUNNING (effect proceeds)
                                       --on_reject---> ABORTED

so human attention scales with risk events, not step count. At most one effect
is suspended at a time (the run halts at the boundary until the human decides).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = ["ReviewState", "SuspendedEffect", "EnvelopeGateError", "EnvelopeReviewGate"]


class ReviewState(StrEnum):
    RUNNING = "RUNNING"
    SUSPENDED = "SUSPENDED"  # one offending effect paused, awaiting HITL
    ABORTED = "ABORTED"  # human rejected the offending effect → run halted


class EnvelopeGateError(RuntimeError):
    """Illegal transition (e.g. suspend while already suspended, or decide with
    no pending effect)."""


@dataclass(frozen=True)
class SuspendedEffect:
    """The single effect currently paused at the envelope boundary."""

    reason: str
    effect_fingerprint: str
    action: str


@dataclass
class EnvelopeReviewGate:
    """Deterministic SUSPEND→HITL→RESUME/REJECT state for one run."""

    state: ReviewState = ReviewState.RUNNING
    pending: SuspendedEffect | None = None
    history: list[tuple[str, SuspendedEffect]] = field(default_factory=list)

    def on_suspend(self, *, reason: str, effect_fingerprint: str, action: str) -> SuspendedEffect:
        """Pause the offending effect and await a human decision. Only one effect
        may be suspended at a time (the run halts at this boundary)."""
        if self.state is ReviewState.SUSPENDED:
            raise EnvelopeGateError("already suspended on a pending effect")
        if self.state is ReviewState.ABORTED:
            raise EnvelopeGateError("run already aborted")
        suspended = SuspendedEffect(reason=reason, effect_fingerprint=effect_fingerprint, action=action)
        self.state = ReviewState.SUSPENDED
        self.pending = suspended
        return suspended

    def on_approve(self) -> SuspendedEffect:
        """Human approved the offending effect → it proceeds, run resumes."""
        suspended = self._require_pending()
        self.history.append(("approve", suspended))
        self.state = ReviewState.RUNNING
        self.pending = None
        return suspended

    def on_reject(self, *, reason: str = "") -> SuspendedEffect:
        """Human rejected the offending effect → run halts (ABORTED)."""
        suspended = self._require_pending()
        self.history.append(("reject", suspended))
        self.state = ReviewState.ABORTED
        self.pending = None
        return suspended

    def _require_pending(self) -> SuspendedEffect:
        if self.state is not ReviewState.SUSPENDED or self.pending is None:
            raise EnvelopeGateError("no suspended effect to decide on")
        return self.pending
