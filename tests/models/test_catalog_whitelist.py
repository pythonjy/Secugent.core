# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 — model catalog whitelist tests (RED first)."""

from __future__ import annotations

from datetime import UTC
from decimal import Decimal
from pathlib import Path

import pytest

from secugent.core.tenancy import TenantId
from secugent.models.catalog import (
    ModelCatalog,
    UnapprovedModelError,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPO_ROOT / "config" / "models.yaml"


def test_load_default_catalog() -> None:
    catalog = ModelCatalog.load(CATALOG_PATH)
    ids = {card.model_id for card in catalog.all()}
    assert "claude-haiku-4-5-20251001" in ids
    assert "claude-sonnet-4-6" in ids


def test_unapproved_model_lookup_raises() -> None:
    catalog = ModelCatalog.load(CATALOG_PATH)
    with pytest.raises(UnapprovedModelError, match="unapproved_model"):
        catalog.get("gpt-5")


def test_is_approved_for_global_allowlist() -> None:
    catalog = ModelCatalog.load(CATALOG_PATH)
    assert catalog.is_approved("claude-haiku-4-5-20251001", TenantId("acme")) is True


def test_unapproved_for_unknown_model() -> None:
    catalog = ModelCatalog.load(CATALOG_PATH)
    assert catalog.is_approved("evil-model", TenantId("acme")) is False


def test_per_tenant_allowlist(tmp_path: Path) -> None:
    yaml_text = """
models:
  - model_id: scoped-model
    provider: mock
    version: "1.0"
    approved_at: 2026-05-01T00:00:00Z
    risk_level: low
    allowed_tenants: ["acme"]
    cost_per_input_1k: "0"
    cost_per_output_1k: "0"
"""
    path = tmp_path / "models.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    catalog = ModelCatalog.load(path)
    assert catalog.is_approved("scoped-model", TenantId("acme")) is True
    assert catalog.is_approved("scoped-model", TenantId("contoso")) is False


def test_deprecated_card_rejected() -> None:
    from datetime import datetime

    yaml_text = """
models:
  - model_id: old-model
    provider: mock
    version: "0.9"
    approved_at: 2026-01-01T00:00:00Z
    deprecated_at: 2026-05-01T00:00:00Z
    risk_level: low
    allowed_tenants: "*"
    cost_per_input_1k: "0"
    cost_per_output_1k: "0"
"""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(yaml_text)
        path = Path(f.name)
    catalog = ModelCatalog.load(path)
    # at = now (after deprecated_at) → not approved
    assert catalog.is_approved("old-model", TenantId("acme"), at=datetime(2026, 6, 1, tzinfo=UTC)) is False


def test_cost_calculator() -> None:
    catalog = ModelCatalog.load(CATALOG_PATH)
    card = catalog.get("claude-haiku-4-5-20251001")
    cost = card.cost_for(input_tokens=1000, output_tokens=2000)
    expected = Decimal("0.00025") * 1 + Decimal("0.00125") * 2
    assert cost == expected
