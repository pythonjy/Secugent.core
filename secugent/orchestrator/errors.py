# SPDX-License-Identifier: Apache-2.0
"""Adapter-layer exceptions surfaced by PHASE 8 production wiring.

These types let :class:`secugent.orchestrator.runner.RunOrchestrator`
distinguish *transient retries already exhausted* from *immediate fail-closed*
events without coupling to the underlying ``HeadAgent``/``Dispatcher``
implementation details.

``QuotaExceededError`` is re-exported from :mod:`secugent.cost.accounting` so
callers can import all orchestrator-level errors from one place (S8B). That
re-export is resolved LAZILY (PEP 562 ``__getattr__``) rather than at module
load: ``secugent.cost`` is the BSL-1.1 Enterprise quota-enforcement tier and is
NOT shipped in the public OSS Core wheel, so an eager
``from secugent.cost.accounting import ...`` here would break standalone import
of the public Core (``ModuleNotFoundError: secugent.cost``) and leak the tier
(open-core boundary I2/I8). The three locally-defined planner/dispatcher error
classes below carry no Enterprise dependency, so this module itself is
import-closed and ships in Core; only the optional ``QuotaExceededError`` alias
reaches into the Enterprise tier, and only when a caller actually requests it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing-only import, no runtime dependency.
    from secugent.cost.accounting import QuotaExceededError as QuotaExceededError

__all__ = [
    "DispatcherResultMalformed",
    "PlannerFailedError",
    "PlannerTransientError",
    "QuotaExceededError",
]


def __getattr__(name: str) -> Any:
    """Lazily resolve the optional ``QuotaExceededError`` re-export (PEP 562).

    Importing ``secugent.orchestrator.errors`` does not touch the Enterprise cost
    tier; only ``errors.QuotaExceededError`` triggers the load, and only when the
    quota tier is actually installed. Any other attribute is a genuine
    ``AttributeError`` (fail-closed — we do not mask typos)."""
    if name == "QuotaExceededError":
        from secugent.cost.accounting import QuotaExceededError as _QuotaExceededError

        return _QuotaExceededError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class PlannerTransientError(Exception):
    """Raised by :class:`HeadPlannerAdapter` internally to drive tenacity.

    Production callers should not see this directly; the adapter converts a
    final exhausted transient into a :class:`PlannerFailedError` so the
    orchestrator only needs to catch one fail-closed type.
    """


class PlannerFailedError(Exception):
    """Terminal planner failure.

    Wraps both *exhausted transient retries* and any *non-transient* error
    from the underlying ``HeadAgent``. Message convention: starts with
    ``planning_error:`` so the orchestrator can surface a consistent
    ``failure_reason``.
    """


class DispatcherResultMalformed(Exception):
    """Dispatcher returned an unexpected (e.g. ``None``) shape.

    Treated as fail-closed: the run is marked ``RunState.FAILED`` with reason
    ``dispatch_result_malformed`` so operators can investigate the underlying
    invariant violation.
    """
