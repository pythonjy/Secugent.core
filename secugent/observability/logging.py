# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — structured JSON logging via structlog.

Six fields are required on every emit; missing fields fail closed in dev
(``LoggingContractError``) and fall back with a WARN in prod. This is the
text contract Loki / ELK shippers can rely on.

Why a parallel system to PHASE 0's ``JsonlLogger``? — that one is a durable
audit file. This one is a stdout JSONL stream meant for log shippers. They
co-exist until PHASE 12 e-discovery rationalises both.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Any, Final, Literal, TextIO

import structlog

__all__ = [
    "LoggingContractError",
    "REQUIRED_FIELDS",
    "VALID_SEVERITIES",
    "init_logging",
    "log",
    "log_decision_gate",
]


class LoggingContractError(RuntimeError):
    """Raised in dev when the log call omits a required field."""


REQUIRED_FIELDS: Final[tuple[str, ...]] = (
    "ts",
    "run_id",
    "tenant_id",
    "event_type",
    "severity",
    "correlation_id",
)

VALID_SEVERITIES: Final[frozenset[str]] = frozenset({"debug", "info", "warn", "warning", "error", "critical"})


_ENV: Literal["dev", "prod"] = "dev"
_STREAM: TextIO | None = None
_LOGGER: Any = None


def init_logging(*, env: Literal["dev", "prod"] = "dev", stream: TextIO | None = None) -> None:
    """Configure the global structlog renderer. Idempotent — re-running
    swaps the stream and env (useful in tests).
    """
    global _ENV, _STREAM, _LOGGER
    _ENV = env
    _STREAM = stream

    def _stream_writer(_logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]) -> str:
        import json as _json

        line = _json.dumps(event_dict, ensure_ascii=False, default=str)
        if _STREAM is not None:
            _STREAM.write(line + "\n")
        return line

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            _stream_writer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        cache_logger_on_first_use=False,
    )
    _LOGGER = structlog.get_logger("secugent")


def log(
    event_type: str,
    *,
    run_id: str | None = None,
    tenant_id: str | None = None,
    severity: str = "info",
    correlation_id: str | None = None,
    **extra: Any,
) -> None:
    """Emit a structured log record. Enforces the 6-field contract."""
    if _LOGGER is None:
        init_logging()

    fields = {
        "event_type": event_type,
        "run_id": run_id,
        "tenant_id": tenant_id,
        "severity": severity,
        "correlation_id": correlation_id,
    }

    missing = [name for name, value in fields.items() if value is None]
    if severity not in VALID_SEVERITIES:
        missing.append("severity")

    if missing:
        if _ENV == "dev":
            raise LoggingContractError(f"missing/invalid required fields: {sorted(set(missing))}")
        # prod fallback — emit WARN then continue with placeholders
        _emit_warning(missing)
        for name in missing:
            if name == "severity":
                fields["severity"] = "info"
            else:
                fields[name] = f"unknown-{name.replace('_id', '')}"

    payload: dict[str, Any] = {**fields, **extra}
    assert _LOGGER is not None
    # Always emit at info level — severity is a payload field, not a level.
    _LOGGER.info(payload["event_type"], **payload)


_UNKNOWN: Final[str] = "unknown"


def log_decision_gate(
    *,
    event_type: str,
    run_id: str | None,
    tenant_id: str | None,
    severity: str,
    correlation_id: str | None = None,
    **extra: Any,
) -> None:
    """Emit a decision-gate record on the parallel structlog stream (D3-RR-01).

    A thin, **fail-soft** producer for the §C-2 decision choke points (the SDK
    gate and the SUB agent). It exists so the 6-field JSONL stream — empty until
    now — is populated alongside (never replacing) the durable audit emit.

    Two guarantees the bare :func:`log` does not give the call sites:

    * **Always 6-field (INV-1).** ``run_id`` / ``tenant_id`` / ``correlation_id``
      are defaulted to non-``None`` here (``"unknown"`` / falling back to
      ``run_id``) so a system event with no run/tenant context can never trip the
      DEV ``LoggingContractError``. ``severity`` is clamped into
      :data:`VALID_SEVERITIES` (an unexpected value becomes ``"info"``) for the
      same reason.
    * **Never breaks the caller (INV-4).** A logging-layer failure (stream gone,
      serialisation error) is swallowed: a decision/run must never fail because a
      *parallel observability* emit raised. This is a deliberate, scoped
      ``except`` (§B-8 fail-soft for a pure side-effect), not silent error
      hiding — the durable §C-2 audit chain is the source of truth and is emitted
      independently.

    ``extra`` MUST carry only structural fields (``gate`` / ``decision`` / axis
    labels) — never a policy body, token, command, or PII (INV-5). Callers are
    responsible for not passing sensitive values; this helper does not inspect
    ``extra`` beyond forwarding it.
    """
    resolved_run_id = run_id if run_id is not None else _UNKNOWN
    resolved_tenant_id = tenant_id if tenant_id is not None else _UNKNOWN
    resolved_correlation_id = correlation_id if correlation_id is not None else resolved_run_id
    resolved_severity = severity if severity in VALID_SEVERITIES else "info"
    try:
        log(
            event_type,
            run_id=resolved_run_id,
            tenant_id=resolved_tenant_id,
            severity=resolved_severity,
            correlation_id=resolved_correlation_id,
            **extra,
        )
    except Exception:  # noqa: BLE001 - fail-soft: a parallel log must never break the run (INV-4)
        # Best-effort: the durable §C-2 audit emit is independent and authoritative.
        # We intentionally do not re-raise; observability is a side-effect here.
        return


def _emit_warning(missing: list[str]) -> None:
    assert _LOGGER is not None
    _LOGGER.warning(
        "logging.contract_violation",
        event_type="logging.contract_violation",
        run_id="unknown-run",
        tenant_id="unknown-tenant",
        severity="warning",
        correlation_id="unknown-correlation",
        missing_fields=sorted(set(missing)),
    )
