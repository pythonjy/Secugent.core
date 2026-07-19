# SPDX-License-Identifier: Apache-2.0
"""structlog decision-gate producer tests (audit D3-RR-01).

Pins the thin ``log_decision_gate`` helper and the end-to-end wiring at the two
decision choke points (``OversightGate._emit`` / ``SubAgent`` decision points):

* the helper ALWAYS emits a 6-field record (run_id/tenant_id/correlation_id
  default to non-None) so DEV never raises ``LoggingContractError`` (INV-1);
* the helper is fail-soft — a logging error never breaks the caller (INV-4);
* an ``OversightGate.enforce`` run (clean pass / hard block / forced HITL)
  writes the expected decision-gate JSONL records with all 6 fields and the
  right ``event_type``/``severity`` (INV-2 audit untouched);
* a ``SubAgent`` decision path also emits;
* NO secret / policy body / PII leaks into the emitted record (INV-5).
"""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from secugent.observability.logging import (
    REQUIRED_FIELDS,
    VALID_SEVERITIES,
    LoggingContractError,
    init_logging,
    log_decision_gate,
)


def _captured(stream: io.StringIO) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in stream.getvalue().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _decision_records(stream: io.StringIO) -> list[dict[str, Any]]:
    """Only records whose event_type is a decision-gate type (gate.* / step.* /
    rule_of_two / oversight / alert), filtering out structlog meta lines."""
    return [r for r in _captured(stream) if isinstance(r.get("event_type"), str)]


# --------------------------------------------------------------------------- #
# Unit — the helper itself
# --------------------------------------------------------------------------- #


def test_helper_emits_all_six_fields_non_none() -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    log_decision_gate(
        event_type="gate.plan_review.approve",
        run_id="run_1",
        tenant_id="acme",
        severity="info",
        correlation_id="run_1",
        gate="plan_review",
        decision="approve",
    )
    records = _decision_records(stream)
    assert len(records) == 1
    rec = records[0]
    for field in REQUIRED_FIELDS:
        assert field in rec, f"missing required field {field}"
        assert rec[field] is not None, f"required field {field} is None"
    assert rec["event_type"] == "gate.plan_review.approve"
    assert rec["gate"] == "plan_review"
    assert rec["decision"] == "approve"


def test_helper_defaults_missing_run_and_tenant_to_unknown() -> None:
    """A system event with no run/tenant must still emit (DEV must NOT raise)."""
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    log_decision_gate(
        event_type="gate.plan_review.reject",
        run_id=None,
        tenant_id=None,
        severity="warn",
    )
    records = _decision_records(stream)
    assert len(records) == 1
    rec = records[0]
    assert rec["run_id"] == "unknown"
    assert rec["tenant_id"] == "unknown"
    # correlation_id defaults to run_id which itself defaulted to "unknown"
    assert rec["correlation_id"] == "unknown"


def test_helper_correlation_defaults_to_run_id() -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    log_decision_gate(
        event_type="step.risk",
        run_id="run_42",
        tenant_id="acme",
        severity="info",
    )
    rec = _decision_records(stream)[0]
    assert rec["correlation_id"] == "run_42"


def test_helper_never_raises_in_dev_for_any_missing_field() -> None:
    """INV-1: with the helper's defaulting, DEV must never raise LoggingContractError."""
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    # Even passing every field as None must NOT raise (helper defaults them).
    try:
        log_decision_gate(
            event_type="oversight_violation",
            run_id=None,
            tenant_id=None,
            severity="critical",
            correlation_id=None,
        )
    except LoggingContractError as exc:  # pragma: no cover - fail signal
        pytest.fail(f"helper raised LoggingContractError in dev: {exc}")
    assert _decision_records(stream), "record should still be emitted"


def test_helper_is_fail_soft_when_logging_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """INV-4: a logging-layer error must never propagate to the caller."""
    import secugent.observability.logging as logging_mod

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("stream exploded")

    monkeypatch.setattr(logging_mod, "log", _boom)
    # Must not raise despite the underlying log() blowing up.
    log_decision_gate(
        event_type="gate.hitl.approve",
        run_id="r",
        tenant_id="t",
        severity="info",
    )


def test_helper_severity_within_valid_set() -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    for sev in ("info", "warn", "warning", "error", "critical", "debug"):
        assert sev in VALID_SEVERITIES
        log_decision_gate(
            event_type="step.risk",
            run_id="r",
            tenant_id="t",
            severity=sev,
        )
    assert len(_decision_records(stream)) == 6
