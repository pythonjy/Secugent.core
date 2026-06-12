# SPDX-License-Identifier: Apache-2.0
"""PHASE 10 — OpenTelemetry tracing + PII span sanitizer.

The :class:`SpanSanitizer` reuses the PHASE 0 `logger.redact_string` /
`redact` patterns (API-key, Bearer, email, KR RRN, large blob) and adds:

* :class:`pydantic.SecretStr` instances → wholesale ``[REDACTED]``
* JWT-shaped triple-segment dot-separated base64 → wholesale ``[REDACTED:JWT]``
* Approval nonce-shaped strings (32+ URL-safe base64 chars) — already caught
  by the API-key pattern from PHASE 0 logger.

The sanitiser is applied transparently in :func:`traced_span` to every
attribute value, and is the same function the future log shipper /
metrics-label scrubber should call.

OTel SDK is initialised lazily via :func:`init_tracing`. The default exporter
is the SDK's :class:`InMemorySpanExporter` so unit tests have a deterministic
sink. When ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set we additionally configure
an OTLP HTTP exporter — the actual collector choice (Honeycomb / Jaeger /
Grafana Cloud) is an operations-time decision.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from pydantic import SecretStr

from secugent.core.logger import redact, redact_string

__all__ = [
    "SpanSanitizer",
    "init_tracing",
    "traced_span",
]

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sanitiser
# ---------------------------------------------------------------------------


_JWT_RE = re.compile(r"\b[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\b")


class SpanSanitizer:
    """Strip secrets from span attribute values.

    Conservative: passes scalars (int/float/bool/None) through unchanged, and
    delegates dict/list/string handling to the PHASE 0 redact helpers so the
    rules stay in one place.
    """

    def sanitise(self, value: Any) -> Any:
        if isinstance(value, SecretStr):
            return "[REDACTED]"
        if isinstance(value, str):
            text = _JWT_RE.sub("[REDACTED:JWT]", value)
            return redact_string(text)
        if isinstance(value, dict):
            return redact(value)
        if isinstance(value, (list, tuple)):
            seq_type = type(value)
            return seq_type(self.sanitise(v) for v in value)
        return value


# ---------------------------------------------------------------------------
# OTel provider
# ---------------------------------------------------------------------------


_TRACER_PROVIDER: Any = None
_IN_MEMORY_EXPORTER: Any = None


def init_tracing(
    *,
    service_name: str = "secugent",
    otlp_endpoint: str | None = None,
    resource_attrs: dict[str, str] | None = None,
    install_in_memory_exporter: bool = True,
) -> Any:
    """Configure the global TracerProvider. Idempotent.

    * Always installs an InMemorySpanExporter (kept on
      :data:`_IN_MEMORY_EXPORTER`) so tests can introspect spans.
    * If ``otlp_endpoint`` or env ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set, the
      OTLP HTTP exporter is also wired (operator's collector choice).
    """
    global _TRACER_PROVIDER, _IN_MEMORY_EXPORTER

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )
    except ImportError:
        # Defense-in-depth: the production image installs the obs extra, but a
        # missing opentelemetry must never brick boot. Mirror the fail-soft
        # behaviour of instrument_fastapi — no tracer provider, app still
        # serves /healthz and /metrics.
        return None

    if _TRACER_PROVIDER is not None:
        return _TRACER_PROVIDER

    attrs = {"service.name": service_name}
    attrs.update(resource_attrs or {})
    provider = TracerProvider(resource=Resource.create(attrs))

    if install_in_memory_exporter:
        _IN_MEMORY_EXPORTER = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(_IN_MEMORY_EXPORTER))

    endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        except ImportError:
            # Operator-time collector library not installed yet — leave the
            # provider with only the in-memory exporter so the app still boots.
            pass

    trace.set_tracer_provider(provider)
    _TRACER_PROVIDER = provider
    return provider


def get_in_memory_exporter() -> Any:
    """Return the in-memory span exporter (for tests)."""
    return _IN_MEMORY_EXPORTER


def reset_tracing() -> None:
    """Clear the in-memory exporter between test cases.

    OpenTelemetry refuses to swap a global TracerProvider once installed
    ("Overriding of current TracerProvider is not allowed"), so we keep
    the provider + exporter installed and just empty the captured span
    buffer between tests.
    """
    global _IN_MEMORY_EXPORTER
    if _IN_MEMORY_EXPORTER is not None:
        try:
            _IN_MEMORY_EXPORTER.clear()
        except Exception as exc:  # pragma: no cover
            _logger.debug("tracing reset clear failed: %s", exc)


# ---------------------------------------------------------------------------
# traced_span context manager
# ---------------------------------------------------------------------------


_SANITIZER = SpanSanitizer()


@contextmanager
def traced_span(
    name: str,
    *,
    run_id: str | None = None,
    tenant_id: str | None = None,
    step_id: str | None = None,
    **extra: Any,
) -> Iterator[Any]:
    """Open a span; sanitise every attribute value."""
    from opentelemetry import trace

    if _TRACER_PROVIDER is None:
        init_tracing()
    tracer = trace.get_tracer("secugent")
    with tracer.start_as_current_span(name) as span:
        if run_id is not None:
            span.set_attribute("secugent.run_id", _stringify(run_id))
        if tenant_id is not None:
            span.set_attribute("secugent.tenant_id", _stringify(tenant_id))
        if step_id is not None:
            span.set_attribute("secugent.step_id", _stringify(step_id))
        for k, v in extra.items():
            span.set_attribute(k, _stringify(_SANITIZER.sanitise(v)))
        yield span


def _stringify(value: Any) -> Any:
    # OTel only accepts str/bool/int/float (and sequences thereof); convert
    # everything else through repr() to keep the span sink simple.
    if isinstance(value, (str, bool, int, float)):
        return value
    return repr(value)


# ---------------------------------------------------------------------------
# Instrumentation hooks (optional dependencies — lazy import)
# ---------------------------------------------------------------------------


def instrument_fastapi(app: Any) -> None:  # pragma: no cover - optional
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(app)


def instrument_httpx_client(client: Any) -> None:  # pragma: no cover - optional
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    except ImportError:
        return
    HTTPXClientInstrumentor().instrument_client(client)


def instrument_sqlalchemy(engine: Any) -> None:  # pragma: no cover - optional
    try:
        from opentelemetry.instrumentation.sqlalchemy import (
            SQLAlchemyInstrumentor,
        )
    except ImportError:
        return
    SQLAlchemyInstrumentor().instrument(engine=engine)
