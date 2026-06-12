# SPDX-License-Identifier: Apache-2.0
"""EM-02 — InMemoryLabelStore: tagging, conservative default, tenant isolation."""

from __future__ import annotations

from secugent.core.sec.label_store import InMemoryLabelStore
from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import TenantId

_T_A = TenantId("tenant-a")
_T_B = TenantId("tenant-b")


async def test_tag_then_get_roundtrip() -> None:
    store = InMemoryLabelStore()
    await store.tag(_T_A, "file:report.csv", DataLabel.SECRET)
    assert await store.get(_T_A, "file:report.csv") is DataLabel.SECRET


async def test_untagged_returns_conservative_default() -> None:
    store = InMemoryLabelStore()
    assert await store.get(_T_A, "file:never-tagged") is DataLabel.CONFIDENTIAL


async def test_custom_default() -> None:
    store = InMemoryLabelStore(default=DataLabel.SECRET)
    assert await store.get(_T_A, "unknown") is DataLabel.SECRET


async def test_tenant_isolation() -> None:
    store = InMemoryLabelStore()
    await store.tag(_T_A, "shared-id", DataLabel.SECRET)
    # tenant B must NOT see tenant A's label — falls back to the default.
    assert await store.get(_T_B, "shared-id") is DataLabel.CONFIDENTIAL
    assert await store.get(_T_A, "shared-id") is DataLabel.SECRET


async def test_retag_overwrites() -> None:
    store = InMemoryLabelStore()
    await store.tag(_T_A, "c", DataLabel.PUBLIC)
    await store.tag(_T_A, "c", DataLabel.SECRET)
    assert await store.get(_T_A, "c") is DataLabel.SECRET


async def test_get_is_deterministic() -> None:
    store = InMemoryLabelStore()
    await store.tag(_T_A, "c", DataLabel.INTERNAL_USE)
    results = {await store.get(_T_A, "c") for _ in range(100)}
    assert results == {DataLabel.INTERNAL_USE}
