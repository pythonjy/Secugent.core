# SPDX-License-Identifier: Apache-2.0
"""Conservative, step-scoped taint propagation + admin downgrade (EM-02).

Within one SUB step, :class:`TaintContext` accumulates the *upper bound* of every
label read, and a step's output inherits that bound — the honest, coarse,
container-level model (no implicit-flow tracking). Only a human admin may
``downgrade`` the effective output label, and every downgrade emits a
``label.downgraded`` audit event.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from secugent.core.sec.labels import DataLabel, merge
from secugent.core.tenancy import Principal

__all__ = ["AuditSink", "TaintContext", "LabelDowngradeError", "downgrade"]


class AuditSink(Protocol):
    """Minimal audit emitter (the real hash-chained store is injected later)."""

    def emit(self, event_type: str, payload: Mapping[str, str]) -> None: ...


class LabelDowngradeError(Exception):
    """Raised when a non-admin principal attempts a label downgrade."""


class TaintContext:
    """Accumulates the upper bound of labels read during one step."""

    def __init__(self) -> None:
        self._observed: DataLabel = DataLabel.PUBLIC
        self._downgraded: DataLabel | None = None

    def observe_read(self, label: DataLabel) -> None:
        """Record a read; the accumulated bound only ever rises."""
        self._observed = merge(self._observed, label)

    @property
    def current(self) -> DataLabel:
        """The accumulated upper bound of everything read (history, immutable)."""
        return self._observed

    def label_for_output(self) -> DataLabel:
        """Label inherited by this step's output: an admin downgrade overrides."""
        return self._downgraded if self._downgraded is not None else self._observed

    def _apply_downgrade(self, to: DataLabel) -> None:
        self._downgraded = to


def downgrade(
    ctx: TaintContext,
    to: DataLabel,
    *,
    approver_principal: Principal,
    audit_sink: AuditSink,
) -> None:
    """Downgrade ``ctx``'s effective output label to ``to`` (admin only).

    ``to`` may not exceed the observed upper bound (``ctx.current``) — this path
    only ever *lowers* sensitivity, never raises it. Non-admin principals are
    rejected with :class:`LabelDowngradeError` and the context is left unchanged.

    The owning tenant of ``ctx`` is the caller's responsibility: this function
    checks only the admin role, not that ``approver_principal.tenant_id`` matches
    the step's tenant (the orchestrator binds tenant context upstream).

    A successful downgrade emits ``label.downgraded`` BEFORE the state change
    (SECURITY_CONTRACT §5: append precedes mutation) — a failing sink leaves the
    context unchanged (fail-closed).
    """
    if approver_principal.role != "admin":
        raise LabelDowngradeError(f"label downgrade requires admin role, got {approver_principal.role!r}")
    observed = ctx.current
    if to > observed:
        raise LabelDowngradeError(f"not a downgrade: target {to.name} exceeds observed {observed.name}")
    previous_effective = ctx.label_for_output()
    audit_sink.emit(
        "label.downgraded",
        {
            "observed": str(int(observed)),
            "from": str(int(previous_effective)),
            "to": str(int(to)),
            "principal": approver_principal.user_id,
            "tenant_id": str(approver_principal.tenant_id),
        },
    )
    ctx._apply_downgrade(to)
