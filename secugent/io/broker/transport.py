# SPDX-License-Identifier: Apache-2.0
"""Transport adapters — the broker's ONLY execution path (EM-05).

The broker decides; the transport performs. ``RouterTransport`` delegates the
four router-backed effect kinds to the existing :class:`ToolRouter`, preserving
its ``sandbox_roots`` / ``allowed_domains`` / ``RealDesktopDisabledError``
enforcement verbatim — the broker only adds gates *in front*. Connector / network
egress (``CONNECTOR_ACTION`` / ``NET_SEND``) has an injection point left empty:
credential delegation is EM-06, so this transport never holds credentials.
"""

from __future__ import annotations

import json
from typing import Any, Protocol

from secugent.core.contracts import ActionType, Step
from secugent.core.sec.effects import EffectKind
from secugent.io.broker.request import EgressRequest
from secugent.tools import builtin
from secugent.tools.router import ToolDispatchError, ToolRouter

__all__ = ["Transport", "RouterTransport"]


class Transport(Protocol):
    """Performs an already-authorized effect. Returns its payload bytes (or None)."""

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None: ...


_ACTION_BY_KIND: dict[EffectKind, ActionType] = {
    EffectKind.FILE_READ: "file_read",
    EffectKind.FILE_WRITE: "file_write",
    EffectKind.NET_RECV: "http_get",
    EffectKind.PROCESS_EXEC: "compute",
}


class RouterTransport:
    """Execute via the existing :class:`ToolRouter` (the only built-in egress)."""

    def __init__(self, router: ToolRouter) -> None:
        self._router = router

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        effect = request.effect
        if effect.kind is EffectKind.CONNECTOR_ACTION:
            # Explicit (not implicit) deny: connector egress is brokered through
            # ConnectorTransport (EM-06), never the router. Naming the kind makes
            # the boundary auditable rather than a generic "no transport" message.
            raise ToolDispatchError(
                "RouterTransport cannot execute CONNECTOR_ACTION; use ConnectorTransport (EM-06)"
            )
        action = _ACTION_BY_KIND.get(effect.kind)
        if action is None:
            # NET_SEND needs the EM-06 connector/network transport.
            raise ToolDispatchError(f"no router transport for effect kind {effect.kind}")
        content = request.content
        step = Step(
            tenant_id=request.principal.tenant_id,
            run_id=request.run_id,
            actor=f"broker:{request.principal.user_id}",
            action_type=action,
            target=effect.target,
        )
        result: builtin.ToolResult = self._router.dispatch(
            step, content=content, http_transport=http_transport
        )
        return json.dumps(result.payload, sort_keys=True, default=str).encode("utf-8")
