# SPDX-License-Identifier: Apache-2.0
"""Build a normalized :class:`Effect` from a :class:`Step` (EM-05).

This is the single place that knows both ``core.contracts.Step`` and
``core.sec.Effect`` — it lives in ``io`` (not ``core/sec``) so the deterministic
core stays a leaf. Targets are canonicalized via EM-01; a sandbox file write is
LOCAL_SANDBOX (and classified REVERSIBLE downstream), an http_get is EXTERNAL.
"""

from __future__ import annotations

import unicodedata

from secugent.core.contracts import Step
from secugent.core.sec.canonicalize import (
    AmbiguousEffectError,
    canonicalize_path,
    canonicalize_url,
)
from secugent.core.sec.effects import Effect, EffectKind, SinkClass

__all__ = ["build_effect"]

_KIND_BY_ACTION: dict[str, EffectKind] = {
    "file_read": EffectKind.FILE_READ,
    "file_write": EffectKind.FILE_WRITE,
    "http_get": EffectKind.NET_RECV,
    "compute": EffectKind.PROCESS_EXEC,
    "desktop": EffectKind.PROCESS_EXEC,
    "connector_action": EffectKind.CONNECTOR_ACTION,
}


def _process_target(step: Step) -> str:
    raw = (step.command or step.target or step.id or "compute").strip()
    token = unicodedata.normalize("NFC", raw).replace("\\", "/")
    if not token or "\x00" in token:
        return step.id
    return token


def _connector_params_meta(step: Step) -> tuple[tuple[str, str], ...]:
    """Flatten ``step.context['params']`` into deterministic (str, str) meta pairs.

    The connector layer (``ConnectorAction.params``) is reconstructed from
    ``effect.meta`` by :class:`ConnectorTransport`. Only string→string entries are
    carried (the meta contract is ``(str, str)`` pairs); non-string values are
    NFC-normalized via ``str(...)`` so a Korean channel name round-trips intact.
    A missing/empty/non-dict ``params`` yields no meta (empty params).
    """
    raw = step.context.get("params")
    if not isinstance(raw, dict):
        return ()
    pairs: list[tuple[str, str]] = []
    for key, value in raw.items():
        if not isinstance(key, str):
            raise AmbiguousEffectError("connector_action params keys must be strings")
        normalized = unicodedata.normalize("NFC", value if isinstance(value, str) else str(value))
        pairs.append((unicodedata.normalize("NFC", key), normalized))
    return tuple(pairs)


def _connector_qualified_action(step: Step) -> str:
    """Validate + NFC-normalize the ``'<connector>.<action>'`` target.

    Fail-closed (:class:`AmbiguousEffectError`) on a missing target or one that
    does not split — on the *first* dot — into two non-empty tokens. A residual
    multi-dot action (e.g. ``'a.b'`` from ``'kakaowork.a.b'``) is intentionally
    allowed through here (both tokens are non-empty) and is rejected downstream
    by the ConnectorTransport's malformed-action gate (candidate-1) — this keeps
    the bridge's invariant exactly "first-dot split yields two non-empty tokens".
    """
    if not step.target:
        raise AmbiguousEffectError("connector_action requires a '<connector>.<action>' target")
    token = unicodedata.normalize("NFC", step.target.strip())
    if "\x00" in token or "\\" in token:
        raise AmbiguousEffectError("connector_action target contains a forbidden character")
    # Reject any token that still contains Unicode whitespace or control characters
    # after NFC normalization.  These survive the outer .strip() (which only removes
    # *surrounding* whitespace) when they appear *inside* the token (e.g. U+0085 NEL,
    # U+00A0 NBSP).  If we let such tokens through, Effect.__post_init__ raises a raw
    # ValueError which bypasses EgressBroker's `except AmbiguousEffectError` gate —
    # that would be a fail-closed contract violation (SG-FIX-01).
    if any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in token):
        raise AmbiguousEffectError(
            f"connector_action target contains whitespace/control characters: {step.target!r}"
        )
    connector_name, sep, action_name = token.partition(".")
    if not sep or not connector_name or not action_name:
        raise AmbiguousEffectError(
            f"connector_action target must be '<connector>.<action>' with non-empty "
            f"parts, got {step.target!r}"
        )
    return token


def build_effect(step: Step, *, sandbox_roots: list[str]) -> Effect:
    """Map a Step to a canonical Effect. Raises ``AmbiguousEffectError`` for an
    action that has no effect mapping or a non-canonicalizable target."""
    kind = _KIND_BY_ACTION.get(step.action_type)
    if kind is None:
        raise AmbiguousEffectError(f"no effect mapping for action_type {step.action_type!r}")

    if kind in (EffectKind.FILE_READ, EffectKind.FILE_WRITE):
        if not step.target:
            raise AmbiguousEffectError(f"{step.action_type} requires a target")
        target = canonicalize_path(step.target, sandbox_roots=sandbox_roots)
        return Effect(kind=kind, target=target, sink_class=SinkClass.LOCAL_SANDBOX)

    if kind is EffectKind.NET_RECV:
        if not step.target:
            raise AmbiguousEffectError("http_get requires a target")
        origin, path = canonicalize_url(step.target)
        return Effect(kind=kind, target=origin + path, sink_class=SinkClass.EXTERNAL)

    if kind is EffectKind.CONNECTOR_ACTION:
        # EM-06 connector egress: target is the connector name (the egress key);
        # the qualified '<connector>.<action>' is carried in ``action`` (the key
        # ConnectorTransport / ManifestRegistry use). Connector calls are EXTERNAL.
        qualified = _connector_qualified_action(step)
        connector_name = qualified.partition(".")[0]
        return Effect(
            kind=kind,
            target=connector_name,
            sink_class=SinkClass.EXTERNAL,
            action=qualified,
            meta=_connector_params_meta(step),
        )

    # PROCESS_EXEC (compute / desktop) — runs in the local sandbox.
    return Effect(kind=kind, target=_process_target(step), sink_class=SinkClass.LOCAL_SANDBOX)
