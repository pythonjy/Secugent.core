# SPDX-License-Identifier: Apache-2.0
"""The :class:`Effect` model — the shared vocabulary of side-effects (EM-01).

An ``Effect`` is the immutable, deterministic description of a single
side-effect an agent wants to produce. Every downstream EM unit (labels, policy,
broker, envelope, staging) consumes ``Effect`` rather than re-deriving its own
representation.

``Effect.target`` must already be a :mod:`canonicalize` output — constructing an
``Effect`` from a raw (non-canonical) path or URL raises :class:`ValueError`.
The structural check here is intentionally local (it does not import
:mod:`canonicalize`, keeping this a leaf module): it rejects the markers that
canonicalization would have removed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - type-only import, not executed at runtime
    # Imported for typing only — a runtime import would create an
    # effects ↔ labels cycle (labels imports SinkClass from here). With
    # ``from __future__ import annotations`` the field annotation stays a string.
    from secugent.core.sec.labels import DataLabel

__all__ = ["EffectKind", "SinkClass", "Effect"]


class EffectKind(StrEnum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NET_SEND = "net_send"
    NET_RECV = "net_recv"
    CONNECTOR_ACTION = "connector_action"
    PROCESS_EXEC = "process_exec"


class SinkClass(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    LOCAL_SANDBOX = "local_sandbox"


_PATH_KINDS = frozenset({EffectKind.FILE_READ, EffectKind.FILE_WRITE})
_NET_KINDS = frozenset({EffectKind.NET_SEND, EffectKind.NET_RECV})

# Local copies (no import of mechanical_oversight / canonicalize — leaf module).
_ENV_VAR_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")
_SHORT_NAME_RE = re.compile(r"~\d")
_NET_PREFIX_RE = re.compile(r"^([a-z][a-z0-9+.\-]*)://([^/]*)")


@dataclass(frozen=True, slots=True)
class Effect:
    """An immutable, canonical description of one side-effect."""

    kind: EffectKind
    target: str
    sink_class: SinkClass
    byte_estimate: int = 0
    action: str | None = None
    meta: tuple[tuple[str, str], ...] = field(default=())
    label: DataLabel | None = None  # EM-02 information-flow label (optional)

    def __post_init__(self) -> None:
        _assert_canonical_target(self.kind, self.target)
        # bool is an int subclass; True/False would serialize as true/false and
        # silently differ from 1/0 in the fingerprint — reject it explicitly.
        if isinstance(self.byte_estimate, bool) or self.byte_estimate < 0:
            raise ValueError("byte_estimate must be a non-negative int (not bool)")
        object.__setattr__(self, "meta", _normalize_meta(self.meta))

    def fingerprint(self) -> str:
        """Stable sha256 over the canonical JSON serialization (audit/cache key).

        Independent of ``meta`` insertion order (meta is sorted on construction).
        """
        payload: dict[str, object] = {
            "kind": str(self.kind),
            "target": self.target,
            "sink_class": str(self.sink_class),
            "byte_estimate": self.byte_estimate,
            "action": self.action,
            "meta": [list(pair) for pair in self.meta],
        }
        # Omit ``label`` when absent so an unlabelled Effect keeps the same
        # fingerprint it had before EM-02 (backward-compatible).
        if self.label is not None:
            payload["label"] = int(self.label)
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_meta(meta: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    for pair in meta:
        if len(pair) != 2 or not isinstance(pair[0], str) or not isinstance(pair[1], str):
            raise ValueError("meta must be (str, str) pairs")
        normalized.append((pair[0], pair[1]))
    return tuple(sorted(normalized))


def _assert_canonical_target(kind: EffectKind, target: str) -> None:
    if not isinstance(target, str) or not target:
        raise ValueError("target must be a non-empty string")
    if target != target.strip():
        raise ValueError("non-canonical target: surrounding whitespace")
    if "\x00" in target:
        raise ValueError("non-canonical target: NUL byte")
    if "\\" in target:
        raise ValueError("non-canonical target: backslash (canonical form uses '/')")

    if kind in _PATH_KINDS:
        if target != target.lower():
            raise ValueError("non-canonical path target: must be lower-case")
        if ".." in target.split("/"):
            raise ValueError("non-canonical path target: unresolved '..' segment")
        if _ENV_VAR_RE.search(target):
            raise ValueError("non-canonical path target: environment-variable expansion")
        if _SHORT_NAME_RE.search(target):
            raise ValueError("non-canonical path target: 8.3 short-name token")
    elif kind in _NET_KINDS:
        match = _NET_PREFIX_RE.match(target)
        if match is None:
            raise ValueError("non-canonical net target: expected 'scheme://host' (lower-case)")
        authority = match.group(2)
        if not authority:
            raise ValueError("non-canonical net target: empty authority")
        if authority != authority.lower():
            raise ValueError("non-canonical net target: host must be lower-case")
        if ".." in target.split("/"):
            raise ValueError("non-canonical net target: unresolved '..' segment")
    # CONNECTOR_ACTION / PROCESS_EXEC: base checks only — no path/URL canonical
    # form exists for these in EM-01 (the EM-05 bridge populates them).
