# SPDX-License-Identifier: Apache-2.0
"""Default action → reversibility manifests (EM-09).

Seeds an EM-01 :class:`ManifestRegistry` with the reversibility class of the
known action keys (``effect.action`` for connectors, else ``str(effect.kind)``).
Reads/sandbox writes are REVERSIBLE; connector mutations with an undo are
COMPENSATABLE; external sends are IRREVERSIBLE (→ 2-phase staging). Anything
unregistered is IRREVERSIBLE by EM-01's fail-closed default.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from secugent.core.sec.reversibility import ActionManifest, ManifestRegistry, ReversibilityClass

__all__ = ["default_manifest_registry", "manifest_registry_with", "ManifestSource"]


class ManifestSource(Protocol):
    """Anything that can describe its actions' reversibility (e.g. ``ConnectorRegistry``).

    Declared structurally so this leaf broker module does not import the
    connectors package (which would couple the manifest layer to a specific
    registry implementation).
    """

    def manifest_entries(self) -> list[ActionManifest]: ...


_REVERSIBLE = (
    "file_read",
    "file_write",  # sandbox write — snapshot rollback
    "http_get",
    "net_recv",
    "compute",
    "process_exec",
    "desktop",
)

_COMPENSATABLE: dict[str, str] = {
    "slack.post_message": "slack.delete_message",
    "jira.comment_issue": "jira.delete_comment",
    "notion.create_page": "notion.archive_page",
}

_IRREVERSIBLE = (
    "smtp.send",
    "net_send",
    "connector_action",  # unspecified connector action — conservative
)


def default_manifest_registry() -> ManifestRegistry:
    registry = ManifestRegistry()
    for action in _REVERSIBLE:
        registry.register(ActionManifest(action, ReversibilityClass.REVERSIBLE))
    for action, compensating in _COMPENSATABLE.items():
        registry.register(
            ActionManifest(action, ReversibilityClass.COMPENSATABLE, compensating_action=compensating)
        )
    for action in _IRREVERSIBLE:
        registry.register(ActionManifest(action, ReversibilityClass.IRREVERSIBLE))
    return registry


def manifest_registry_with(*sources: ManifestSource) -> ManifestRegistry:
    """Return :func:`default_manifest_registry` extended with runtime sources.

    Each source contributes its :meth:`manifest_entries` (e.g. every
    ``'<connector>.<action>'`` a :class:`ConnectorRegistry` knows). Later
    entries override earlier ones via :meth:`ManifestRegistry.register`, and the
    static defaults remain (no action silently loses its reversibility class).
    Unregistered actions still classify ``IRREVERSIBLE`` by the registry's
    fail-closed default.
    """
    registry = default_manifest_registry()
    for source in sources:
        _register_all(registry, source.manifest_entries())
    return registry


def _register_all(registry: ManifestRegistry, manifests: Iterable[ActionManifest]) -> None:
    for manifest in manifests:
        registry.register(manifest)
