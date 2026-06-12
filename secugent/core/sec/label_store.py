# SPDX-License-Identifier: Apache-2.0
"""Container → label mapping with tenant isolation (EM-02).

Maps an opaque container id (a file, record, or connector payload) to its
:class:`DataLabel`. Untagged containers return a *conservative* default
(``CONFIDENTIAL``) so an unclassified container is never treated as public
(fail-safe). Storage is keyed by ``(tenant_id, container_id)`` so one tenant's
labels are invisible to another.
"""

from __future__ import annotations

from typing import Protocol

from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import TenantId

__all__ = ["LabelStore", "InMemoryLabelStore"]


class LabelStore(Protocol):
    """Async tagging/lookup of container labels, tenant-isolated."""

    async def tag(self, tenant_id: TenantId, container_id: str, label: DataLabel) -> None: ...

    async def get(self, tenant_id: TenantId, container_id: str) -> DataLabel: ...


class InMemoryLabelStore:
    """In-memory :class:`LabelStore`. Persistence backends implement the Protocol."""

    def __init__(self, *, default: DataLabel = DataLabel.CONFIDENTIAL) -> None:
        # Conservative default: an untagged container is treated as CONFIDENTIAL,
        # never PUBLIC. PUBLIC-by-default would be a silent egress hole.
        self._default = default
        self._by_key: dict[tuple[str, str], DataLabel] = {}

    async def tag(self, tenant_id: TenantId, container_id: str, label: DataLabel) -> None:
        self._by_key[(str(tenant_id), container_id)] = label

    async def get(self, tenant_id: TenantId, container_id: str) -> DataLabel:
        return self._by_key.get((str(tenant_id), container_id), self._default)
