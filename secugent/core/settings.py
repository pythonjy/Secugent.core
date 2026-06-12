# SPDX-License-Identifier: Apache-2.0
"""Runtime settings (PHASE 8 introduces ``LLMSettings``).

This module is the future home for the broader settings tree (``AppSettings``,
``OIDCSettings``, ``SecretsSettings`` — PHASE 9). For PHASE 8 we ship the
minimal subset needed to:

1. Choose between ``mock`` and ``anthropic`` LLM clients.
2. Refuse to boot when ``anthropic`` is selected without an API key
   (fail-closed, sister behaviour to ``RealDesktopDisabledError``).
"""

from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator

from secugent.core.llm_client import (
    AnthropicLLMClient,
    LLMClient,
    LLMError,
    MockLLMClient,
)

__all__ = [
    "DomesticModel",
    "LLMSettings",
    "TelemetrySettings",
    "resolve_llm_client",
]

# BDP_02 item 7: opt-in adoption telemetry flag. Environment variable name is an
# external contract (operator-facing); the value is parsed leniently to a bool.
TELEMETRY_OPTIN_ENV = "SECUGENT_TELEMETRY_OPTIN"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# BDP_02 item 10: sovereign-model selector. Defined locally (not imported from
# secugent.core.llm_clients) so importing settings does NOT eagerly load the
# concrete adapters — the registry is resolved lazily in resolve_llm_client.
# Must stay in sync with secugent.core.llm_clients.DomesticModel.
DomesticModel = Literal["exaone", "hyperclova", "ax", "solar"]


class LLMSettings(BaseModel):
    """Configuration for the LLM client used by HEAD and RISKANALYZER."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["mock", "anthropic"] = "mock"
    api_key: SecretStr | None = None
    timeout_seconds: float = 30.0
    max_retries: int = 3
    # Korean domestic / sovereign model fields (S8A/S8C).
    # Used for on-premise/airgap deployments with EXAONE, HyperCLOVA X, Solar.
    # ``None`` = not configured (cloud or mock path).
    domestic_model_id: str | None = None
    domestic_model_endpoint: str | None = None
    # BDP_02 item 10: which sovereign adapter to build for the domestic endpoint.
    # ``None`` = no concrete sovereign client selected (mock/cloud path).
    domestic_model: DomesticModel | None = None

    @model_validator(mode="after")
    def _api_key_required_for_anthropic(self) -> LLMSettings:
        if self.mode == "anthropic" and self.api_key is None:
            raise ValueError(
                "LLMSettings.api_key is required when mode='anthropic' "
                "(fail-closed: refusing to boot without credentials)"
            )
        return self

    @model_validator(mode="after")
    def _endpoint_required_for_domestic_model(self) -> LLMSettings:
        if self.domestic_model is not None and not self.domestic_model_endpoint:
            raise ValueError(
                "LLMSettings.domestic_model_endpoint is required when "
                "domestic_model is set (fail-closed: refusing to boot a sovereign "
                "adapter without an endpoint)"
            )
        return self


def resolve_llm_client(settings: LLMSettings) -> LLMClient:
    """Materialise the LLM client described by ``settings``.

    Raises :class:`ValueError` on unknown modes; intentionally hard-fails so
    misconfiguration cannot silently fall through to a permissive default.
    """
    # BDP_02 item 10: a selected sovereign model takes precedence — build the
    # concrete adapter via the registry (imported lazily to keep settings free
    # of any concrete-adapter import). The endpoint is guaranteed present by the
    # model validator above.
    if settings.domestic_model is not None:
        from secugent.core.llm_clients import build_domestic_client

        assert settings.domestic_model_endpoint is not None  # guarded by validator
        api_key = settings.api_key.get_secret_value() if settings.api_key is not None else None
        # Thread ALL configured fields: domestic_model_id binds the sovereign
        # model the endpoint serves (so generate() does not forward a caller's
        # Claude id), and max_retries is honoured here exactly as it is for the
        # anthropic path below (rather than silently using the adapter default).
        return build_domestic_client(
            settings.domestic_model,
            endpoint=settings.domestic_model_endpoint,
            api_key=api_key,
            model_id=settings.domestic_model_id,
            timeout=settings.timeout_seconds,
            max_attempts=settings.max_retries,
        )
    if settings.mode == "mock":
        return MockLLMClient()
    if settings.mode == "anthropic":
        assert settings.api_key is not None  # guarded by validator
        try:
            return AnthropicLLMClient(
                api_key=settings.api_key.get_secret_value(),
                max_attempts=settings.max_retries,
            )
        except LLMError as exc:  # pragma: no cover - env-specific
            raise ValueError(f"cannot construct AnthropicLLMClient: {exc}") from exc
    raise ValueError(f"unknown llm mode: {settings.mode!r}")


class TelemetrySettings(BaseModel):
    """Opt-in adoption telemetry settings (BDP_02 item 7).

    ``opt_in`` is **False by default** (§A privacy, §A-2.6 closed-network first):
    until an operator explicitly enables it, the collector is a complete no-op.
    The flag feeds :class:`secugent.observability.telemetry.TelemetryCollector`.
    """

    model_config = ConfigDict(extra="forbid")

    opt_in: bool = False

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> TelemetrySettings:
        """Build from the ``SECUGENT_TELEMETRY_OPTIN`` environment variable.

        Default-off: unset / unrecognised / falsey values all yield
        ``opt_in=False``. Recognised truthy values are ``1/true/yes/on``
        (case-insensitive).
        """
        env = os.environ if environ is None else environ
        raw = env.get(TELEMETRY_OPTIN_ENV, "").strip().lower()
        return cls(opt_in=raw in _TRUTHY)
