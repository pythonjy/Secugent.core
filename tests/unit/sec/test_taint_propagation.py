# SPDX-License-Identifier: Apache-2.0
"""EM-02 — TaintContext conservative propagation + admin-only downgrade."""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from secugent.core.sec.labels import DataLabel
from secugent.core.sec.taint import (
    LabelDowngradeError,
    TaintContext,
    downgrade,
)
from secugent.core.tenancy import Principal, TenantId


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, str]]] = []

    def emit(self, event_type: str, payload: Mapping[str, str]) -> None:
        self.events.append((event_type, dict(payload)))


def _principal(role: str) -> Principal:
    return Principal(user_id=f"{role}-user", tenant_id=TenantId("acme"), role=role)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# propagation
# --------------------------------------------------------------------------- #


def test_starts_public() -> None:
    ctx = TaintContext()
    assert ctx.current is DataLabel.PUBLIC
    assert ctx.label_for_output() is DataLabel.PUBLIC


def test_observe_read_accumulates_upper_bound() -> None:
    ctx = TaintContext()
    ctx.observe_read(DataLabel.INTERNAL_USE)
    ctx.observe_read(DataLabel.SECRET)
    ctx.observe_read(DataLabel.PUBLIC)
    assert ctx.current is DataLabel.SECRET  # max wins, never decreases


def test_secret_read_is_inherited_by_output() -> None:
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    assert ctx.label_for_output() is DataLabel.SECRET


# --------------------------------------------------------------------------- #
# downgrade (admin only)
# --------------------------------------------------------------------------- #


def test_admin_downgrade_applies_and_audits() -> None:
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    sink = _RecordingSink()
    downgrade(ctx, DataLabel.INTERNAL_USE, approver_principal=_principal("admin"), audit_sink=sink)
    assert ctx.label_for_output() is DataLabel.INTERNAL_USE
    assert ctx.current is DataLabel.SECRET  # observed history is preserved
    assert len(sink.events) == 1
    event_type, payload = sink.events[0]
    assert event_type == "label.downgraded"
    assert payload["observed"] == str(int(DataLabel.SECRET))  # true observed bound
    assert payload["from"] == str(int(DataLabel.SECRET))
    assert payload["to"] == str(int(DataLabel.INTERNAL_USE))


def test_downgrade_above_observed_rejected() -> None:
    # 'downgrade' must only ever LOWER sensitivity — raising above the observed
    # bound is not a downgrade and is refused (context unchanged, no audit).
    ctx = TaintContext()
    ctx.observe_read(DataLabel.PUBLIC)
    sink = _RecordingSink()
    with pytest.raises(LabelDowngradeError):
        downgrade(ctx, DataLabel.SECRET, approver_principal=_principal("admin"), audit_sink=sink)
    assert ctx.label_for_output() is DataLabel.PUBLIC
    assert sink.events == []


def test_non_admin_downgrade_rejected_and_unchanged() -> None:
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    sink = _RecordingSink()
    for role in ("operator", "viewer"):
        with pytest.raises(LabelDowngradeError):
            downgrade(ctx, DataLabel.PUBLIC, approver_principal=_principal(role), audit_sink=sink)
    assert ctx.label_for_output() is DataLabel.SECRET  # unchanged
    assert sink.events == []  # no audit event on rejection


def test_downgrade_not_applied_if_audit_fails() -> None:
    # Audit-first / fail-closed: if the sink raises, the downgrade must NOT stick.
    class _FailingSink:
        def emit(self, event_type: str, payload: Mapping[str, str]) -> None:
            raise RuntimeError("durable audit append failed")

    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    with pytest.raises(RuntimeError):
        downgrade(ctx, DataLabel.PUBLIC, approver_principal=_principal("admin"), audit_sink=_FailingSink())
    assert ctx.label_for_output() is DataLabel.SECRET  # unchanged — fail-closed


def test_downgrade_deterministic_output() -> None:
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    downgrade(ctx, DataLabel.PUBLIC, approver_principal=_principal("admin"), audit_sink=_RecordingSink())
    outs = {ctx.label_for_output() for _ in range(100)}
    assert outs == {DataLabel.PUBLIC}
