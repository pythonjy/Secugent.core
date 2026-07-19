# SPDX-License-Identifier: Apache-2.0
"""``OversightMiddleware`` + ``wrap_tool`` — per-request / per-tool embed surface.

Both apply the **same** core oversight gate
(:class:`~secugent.sdk.gate.OversightGate`) as ``@require_oversight`` — there is
no second control implementation and, critically, **no execution path that
reaches the wrapped app/tool without first passing the gate** (the §4.8 boundary
invariant). A REGULATIONS violation HARD BLOCKs before the downstream callable
runs; a Rule-of-Two 3-axis request forces HITL (fail-closed).

:class:`OversightMiddleware` is intentionally framework-light: it is a plain
callable wrapper (``mw(*args, **kwargs) -> downstream(*args, **kwargs)``) so it
drops in front of any callable request handler — including an ASGI ``app`` —
without binding the Core SDK to a web framework (framework-neutral, §A-2.3).
``target_from`` maps the call arguments to the resource string the REGULATIONS
matchers see; it defaults to a fail-closed extractor that pulls the request path
from an ASGI ``scope`` dict (``app(scope, receive, send)``) — NOT ``str(scope)``,
which would defeat path/domain matching — and otherwise reads the first positional
argument or a conventional resource kwarg. An ASGI scope with no derivable path on
a path/domain ``action_type`` raises :class:`OversightConfigError` (fail-closed):
wire an explicit ``target_from`` for non-standard request shapes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from secugent.core.contracts import ActionType
from secugent.sdk.decorators import resolve_target
from secugent.sdk.gate import OversightGate, build_step

__all__ = ["OversightMiddleware", "wrap_tool"]


class OversightMiddleware:
    """Wrap a request handler / ASGI app so every call passes the oversight gate.

    The wrapper is a callable: invoking the middleware runs the gate for the call,
    then (only if the gate allows) delegates to the wrapped ``app`` with the
    original arguments. Boundary guarantee: the ``app`` is unreachable unless the
    gate allowed the call — there is no bypass branch.
    """

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        action_type: ActionType,
        gate: OversightGate,
        target_from: Callable[..., str | None] | None = None,
        command: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        self._app = app
        self._action_type = action_type
        self._gate = gate
        self._target_from = target_from
        self._command = command
        self._context = context

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        target = resolve_target(
            self._gate,
            self._action_type,
            self._target_from,
            None,
            self._context,
            args,
            kwargs,
        )
        step = build_step(
            action_type=self._action_type,
            tenant_id=self._gate.tenant_id,
            run_id=self._gate.run_id,
            actor=self._gate.actor,
            target=target,
            command=self._command,
            context=self._context,
        )
        # Raises HardBlockException / OversightBlocked on deny (fail-closed) — the
        # wrapped app is never reached on a deny (the boundary invariant).
        self._gate.enforce(step)
        return self._app(*args, **kwargs)


def wrap_tool(
    fn: Callable[..., Any],
    *,
    action_type: ActionType,
    gate: OversightGate,
    target_from: Callable[..., str | None] | None = None,
    command: str | None = None,
    context: dict[str, Any] | None = None,
) -> Callable[..., Any]:
    """Return ``fn`` wrapped so each call first passes the oversight gate.

    The thin function analogue of :class:`OversightMiddleware`: an SI/vendor wraps
    a single existing tool callable so its invocation is gated. Same core path,
    same fail-closed semantics; the wrapped tool never runs on a deny.
    """

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        target = resolve_target(gate, action_type, target_from, None, context, args, kwargs)
        step = build_step(
            action_type=action_type,
            tenant_id=gate.tenant_id,
            run_id=gate.run_id,
            actor=gate.actor,
            target=target,
            command=command,
            context=context,
        )
        gate.enforce(step)
        return fn(*args, **kwargs)

    return wrapped
