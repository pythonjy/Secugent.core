# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — approved model catalog.

A YAML-backed whitelist. Anything not present is refused at boot or at
runtime (per call) with :class:`UnapprovedModelError`. Reuse of
:data:`secugent.observability.metrics.LLM_TOKENS` happens in
:mod:`secugent.models.router` rather than here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field

from secugent.core.tenancy import TenantId

__all__ = [
    "ModelCard",
    "ModelCatalog",
    "UnapprovedModelError",
    "DomesticProvider",
]


class UnapprovedModelError(RuntimeError):
    """Raised when a non-whitelisted model is requested."""


# FIX (Medium): Separate Literal type for domestic providers so _DOMESTIC_PROVIDERS
# is built from get_args() — typos are caught at type-check time instead of
# silently returning False from is_domestic_model().
DomesticProvider = Literal["local_exaone", "hyperclova", "solar"]

# All provider values; ModelCard.provider is typed as union for clarity.
_AllProviders = Literal["anthropic", "openai", "mock", "local_exaone", "hyperclova", "solar"]


class ModelCard(BaseModel):
    """One approved model. Costs are USD per 1k tokens."""

    model_config = ConfigDict(extra="forbid")

    model_id: str
    provider: _AllProviders
    version: str
    approved_at: datetime
    deprecated_at: datetime | None = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    allowed_tenants: list[TenantId] | Literal["*"] = "*"
    cost_per_input_1k: Decimal = Field(default=Decimal("0"))
    cost_per_output_1k: Decimal = Field(default=Decimal("0"))

    def cost_for(self, *, input_tokens: int, output_tokens: int) -> Decimal:
        return self.cost_per_input_1k * Decimal(input_tokens) / Decimal(
            1000
        ) + self.cost_per_output_1k * Decimal(output_tokens) / Decimal(1000)

    def is_active(self, *, at: datetime | None = None) -> bool:
        now = at or datetime.now(tz=UTC)
        if now < self.approved_at:
            return False
        if self.deprecated_at is not None and now >= self.deprecated_at:
            return False
        return True


@dataclass
class ModelCatalog:
    """In-memory view of the YAML catalog. Immutable after load."""

    cards: list[ModelCard]
    _by_id: dict[str, ModelCard]

    @classmethod
    def load(cls, path: str | Path) -> ModelCatalog:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        raw_cards = data.get("models") or []
        cards = [ModelCard.model_validate(item) for item in raw_cards]
        return cls(cards=cards, _by_id={c.model_id: c for c in cards})

    def all(self) -> list[ModelCard]:
        return list(self.cards)

    def get(self, model_id: str) -> ModelCard:
        card = self._by_id.get(model_id)
        if card is None:
            raise UnapprovedModelError(f"unapproved_model:{model_id}")
        return card

    def is_approved(
        self,
        model_id: str,
        tenant_id: TenantId,
        *,
        at: datetime | None = None,
    ) -> bool:
        card = self._by_id.get(model_id)
        if card is None:
            return False
        if not card.is_active(at=at):
            return False
        if card.allowed_tenants == "*":
            return True
        return tenant_id in card.allowed_tenants

    # FIX (Medium): Build from get_args(DomesticProvider) so additions to either
    # DomesticProvider or this set that don't match are caught at type-check time.
    _DOMESTIC_PROVIDERS: frozenset[str] = frozenset(get_args(DomesticProvider))

    def is_domestic_model(self, model_id: str) -> bool:
        """Return True if *model_id* is a Korean domestic / sovereign model.

        A model is domestic when it is present in the catalog and its
        ``provider`` is one of ``{"local_exaone", "hyperclova", "solar"}``.
        Unknown model IDs return ``False`` (never raise).
        """
        card = self._by_id.get(model_id)
        if card is None:
            return False
        return card.provider in self._DOMESTIC_PROVIDERS
