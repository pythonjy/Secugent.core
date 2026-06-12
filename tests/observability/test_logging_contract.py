# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — structlog contract tests.

Required fields (6): ts, run_id, tenant_id, event_type, severity,
correlation_id. Behaviour:

* dev env: any missing field → ``LoggingContractError``
* prod env: missing → WARN line + fallback ``"unknown-*"``
"""

from __future__ import annotations

import io
import json

import pytest

from secugent.observability.logging import (
    LoggingContractError,
    init_logging,
    log,
)


def _captured(stream: io.StringIO) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in stream.getvalue().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def test_log_with_all_required_fields_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    log(
        event_type="step.completed",
        run_id="run_1",
        tenant_id="acme",
        severity="info",
        correlation_id="corr-1",
        extra_key="value",
    )
    records = _captured(stream)
    assert len(records) == 1
    rec = records[0]
    assert rec["event_type"] == "step.completed"
    assert rec["run_id"] == "run_1"
    assert rec["tenant_id"] == "acme"
    assert rec["correlation_id"] == "corr-1"
    assert rec["severity"] == "info"
    assert rec["extra_key"] == "value"
    assert "ts" in rec  # auto-populated


def test_dev_env_raises_on_missing_field() -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    with pytest.raises(LoggingContractError, match="run_id"):
        log(event_type="step.completed", tenant_id="acme", severity="info", correlation_id="corr-2")


def test_prod_env_falls_back_on_missing_field() -> None:
    stream = io.StringIO()
    init_logging(env="prod", stream=stream)
    log(event_type="step.completed", tenant_id="acme", severity="info", correlation_id="corr-3")
    records = _captured(stream)
    # Must contain the main event line and a WARN log about the contract
    types = [r.get("event_type") for r in records]
    assert "step.completed" in types
    assert any(r.get("severity") == "warning" or r.get("level") == "warning" for r in records)
    main = next(r for r in records if r["event_type"] == "step.completed")
    assert main["run_id"] == "unknown-run"


def test_severity_unknown_rejected_in_dev() -> None:
    stream = io.StringIO()
    init_logging(env="dev", stream=stream)
    with pytest.raises(LoggingContractError, match="severity"):
        log(event_type="x", run_id="r", tenant_id="t", severity="vibes-only", correlation_id="c")


def test_init_logging_idempotent() -> None:
    s1 = io.StringIO()
    s2 = io.StringIO()
    init_logging(env="dev", stream=s1)
    init_logging(env="dev", stream=s2)  # re-init should switch the stream
    log(event_type="step.completed", run_id="r", tenant_id="t", severity="info", correlation_id="c")
    assert _captured(s2)
    assert not _captured(s1)
