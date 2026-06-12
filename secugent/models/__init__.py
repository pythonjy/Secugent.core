# SPDX-License-Identifier: Apache-2.0
"""PHASE 11 model catalog + cascade router.

``ModelCatalog`` / ``ModelCard`` ship in the public OSS Core. ``CascadeRouter`` /
``CircuitOpenError`` live in :mod:`secugent.models.router`, which eagerly imports
the BSL-1.1 Enterprise quota tier (``secugent.cost.accounting``) and is therefore
NOT shipped in the public Core wheel. To keep ``import secugent.models`` working
standalone (Invariant I8 — no ``ModuleNotFoundError: secugent.models.router`` in
the extracted public repo) while preserving the public re-export surface for
Enterprise builds, the router symbols are resolved LAZILY via a PEP 562
``__getattr__``: the cost tier is only touched when a caller actually accesses
``secugent.models.CascadeRouter`` / ``CircuitOpenError``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from secugent.models.catalog import (
    ModelCard,
    ModelCatalog,
    UnapprovedModelError,
)

if TYPE_CHECKING:  # pragma: no cover - typing-only import, no runtime dependency.
    from secugent.models.router import CascadeRouter, CircuitOpenError

__all__ = [
    "CascadeRouter",
    "CircuitOpenError",
    "ModelCard",
    "ModelCatalog",
    "UnapprovedModelError",
]

_LAZY_ROUTER_NAMES = frozenset({"CascadeRouter", "CircuitOpenError"})


def __getattr__(name: str) -> Any:
    """Lazily resolve the Enterprise-coupled router exports (PEP 562).

    ``import secugent.models`` does not load ``secugent.models.router`` (and thus
    never touches the private ``secugent.cost`` tier); only accessing
    ``CascadeRouter`` / ``CircuitOpenError`` triggers the import, and only when
    the cost tier is installed. Any other attribute is a genuine
    ``AttributeError`` (fail-closed — typos are not masked)."""
    if name in _LAZY_ROUTER_NAMES:
        from secugent.models import router as _router

        return getattr(_router, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
