# SPDX-License-Identifier: Apache-2.0
"""Action reversibility classification (EM-01).

Declares, per action, whether its effect can be rolled back, only compensated,
or is irreversible. STEER (EM-09) uses this to decide what intervention is even
*possible*. Unregistered actions classify as the most conservative class,
``IRREVERSIBLE`` (fail-closed) — STEER must then treat them as "catch before
commit", never "undo after".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

__all__ = ["ReversibilityClass", "ActionManifest", "ManifestRegistry"]

_log = logging.getLogger("secugent.core.sec.reversibility")


class ReversibilityClass(StrEnum):
    REVERSIBLE = "reversible"  # snapshot rollback possible (e.g. sandbox file write)
    COMPENSATABLE = "compensatable"  # no undo, but a compensating action exists
    IRREVERSIBLE = "irreversible"  # external send / payment / publish — unrecoverable


@dataclass(frozen=True)
class ActionManifest:
    """Static declaration of one action's reversibility.

    A ``COMPENSATABLE`` action *must* name its ``compensating_action``; any other
    class *must not* — invalid combinations cannot be constructed.
    """

    action: str
    reversibility: ReversibilityClass
    compensating_action: str | None = None

    def __post_init__(self) -> None:
        if not self.action or not self.action.strip():
            raise ValueError("action must be a non-empty string")
        if self.reversibility is ReversibilityClass.COMPENSATABLE:
            if not self.compensating_action:
                raise ValueError("COMPENSATABLE action requires a compensating_action")
        elif self.compensating_action is not None:
            raise ValueError("compensating_action is only valid for COMPENSATABLE actions")


class ManifestRegistry:
    """Maps action names to their :class:`ActionManifest`. Fail-closed lookup."""

    def __init__(self) -> None:
        self._by_action: dict[str, ActionManifest] = {}

    def register(self, manifest: ActionManifest) -> None:
        """Register (or override) the manifest for ``manifest.action``."""
        self._by_action[manifest.action] = manifest

    def classify(self, action: str) -> ReversibilityClass:
        """Return the reversibility of ``action``; unregistered ⇒ IRREVERSIBLE."""
        manifest = self._by_action.get(action)
        if manifest is None:
            _log.warning("unregistered action %r → IRREVERSIBLE (fail-closed)", action)
            return ReversibilityClass.IRREVERSIBLE
        return manifest.reversibility

    def manifest_for(self, action: str) -> ActionManifest | None:
        """Return the full manifest for ``action`` (or ``None`` if unregistered)."""
        return self._by_action.get(action)
