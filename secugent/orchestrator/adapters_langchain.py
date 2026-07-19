# SPDX-License-Identifier: Apache-2.0
"""LangChain oversight adapter — gate LangChain tool calls through SecuGent core.

:class:`SecuGentCallbackHandler` is a LangChain
``BaseCallbackHandler`` whose ``on_tool_start`` runs the SecuGent oversight gate
*before* a tool executes: a REGULATIONS violation HARD BLOCKs (raises) and a Rule
of Two 3-axis tool forces HITL — via the SAME :class:`~secugent.sdk.gate.OversightGate`
the decorator/middleware use (no second control implementation, I1).

**Lazy import (I3):** ``langchain`` is an *optional* extra and is imported only
inside :func:`_load_base_callback_handler`, called when the handler class is
actually constructed. So ``import secugent.orchestrator.adapters_langchain`` (and
``import secugent.sdk`` / ``import secugent.core``) succeed with langchain absent;
only *using* the handler without langchain raises a clear ``ImportError`` carrying
the ``pip install secugent[langchain]`` remedy. The handler class is built
dynamically (it must subclass langchain's ``BaseCallbackHandler``, which we cannot
reference at module import time without the extra).

For tests and non-langchain embeddings, :func:`build_handler_for_test` and
:func:`wrap_langchain_tool` expose the same gate enforcement without requiring the
langchain base class.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any

from secugent.core.contracts import ActionType
from secugent.sdk.gate import OversightGate, build_step
from secugent.sdk.middleware import wrap_tool

__all__ = [
    "SecuGentCallbackHandler",
    "build_handler_for_test",
    "wrap_langchain_tool",
]

_INSTALL_HINT = (
    "LangChain is not installed. The SecuGent LangChain adapter is an optional "
    "extra — install it with:\n\n    pip install secugent[langchain]\n"
)


def _load_base_callback_handler() -> type:
    """Import LangChain's ``BaseCallbackHandler`` lazily (I3).

    Tries ``langchain_core`` first (the modern split package), then the legacy
    ``langchain`` location. Uses :func:`importlib.import_module` (not a top-level
    ``import``) so the optional dependency is resolved only on use (I3). Raises a
    clear, actionable :class:`ImportError` with the install remedy when neither is
    available — never a bare ``ModuleNotFoundError``.
    """
    last_exc: Exception | None = None
    for module_name, attr in (
        ("langchain_core.callbacks", "BaseCallbackHandler"),
        ("langchain.callbacks.base", "BaseCallbackHandler"),
    ):
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - try the next known location, else raise below
            last_exc = exc
            continue
        base = getattr(module, attr, None)
        if isinstance(base, type):
            return base
    raise ImportError(_INSTALL_HINT) from last_exc


def _enforce_tool_start(
    gate: OversightGate,
    action_type: ActionType,
    serialized: dict[str, Any],
    input_str: str,
) -> None:
    """Run the oversight gate for a tool-start event (raises on deny, fail-closed).

    ``serialized`` is LangChain's tool descriptor (``{"name": ...}``); ``input_str``
    is the tool input, used as the REGULATIONS target. The tool name is recorded in
    the step context so the audit event is attributable to the specific tool.
    """
    tool_name = str(serialized.get("name", "unknown")) if isinstance(serialized, dict) else "unknown"
    step = build_step(
        action_type=action_type,
        tenant_id=gate.tenant_id,
        run_id=gate.run_id,
        actor=gate.actor,
        target=input_str,
        context={"langchain_tool": tool_name},
    )
    gate.enforce(step)


class _OversightHandlerMixin:
    """Shared ``on_tool_start`` enforcement, independent of the langchain base.

    Both the real (langchain-subclassing) handler and the test handler reuse this
    so the control path is identical (single source). It holds the gate + the
    action type the wrapped tools perform.

    .. warning:: The default ``action_type='connector_action'`` is external
       communication (Rule of Two axis ③) and — mirroring ``SubAgent`` — now
       **always forces HITL** (F4). A gate configured WITHOUT a HITL gateway will
       therefore fail closed (:class:`~secugent.sdk.gate.OversightBlocked`) on a
       connector_action tool start. Pass a gate with a HITL gateway (and, in
       production, an ``ApprovalService``) for connector tools, or set an explicit
       non-connector ``action_type`` for read-only tools.

    .. warning:: **Fail-CLOSED under langchain dispatch (critical).** LangChain's
       ``CallbackManager`` runs every handler inside a ``try/except`` and only
       *re-raises* the handler's exception when ``handler.raise_error`` is truthy;
       ``BaseCallbackHandler.raise_error`` defaults to ``False``. Without an
       explicit opt-in, langchain would **swallow** our HARD BLOCK / forced-HITL
       exception, log 'Error in callback', and run the violating tool anyway — a
       complete bypass of the REGULATIONS HARD BLOCK at the embed boundary (§4.8).
       We therefore set :data:`raise_error` ``= True`` (here and on the
       dynamically-built handler class) so langchain re-raises the gate's verdict
       and the tool never executes. Callers MUST NOT re-wrap the handler with
       ``raise_error=False`` — that re-opens the fail-open hole.
    """

    # F-langchain-fail-open: opt in to langchain re-raising our block (see warning).
    # langchain reads this attribute on the handler instance/class to decide whether
    # to propagate a callback exception; default False ⇒ swallowed ⇒ fail-open.
    raise_error: bool = True

    def __init__(self, *, gate: OversightGate, action_type: ActionType = "connector_action") -> None:
        # Cooperative super().__init__() so, when this mixin is the first base of a
        # dynamically-built ``(mixin, BaseCallbackHandler)`` class, langchain's base
        # initialiser still runs via the MRO. Standalone (test handler) it resolves
        # to ``object.__init__``. No positional args are forwarded — langchain's
        # BaseCallbackHandler.__init__ takes none.
        super().__init__()
        self._gate = gate
        self._action_type = action_type

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        """Enforce the SecuGent gate before a LangChain tool runs (un-passed → raise)."""
        _enforce_tool_start(self._gate, self._action_type, serialized, input_str)


def SecuGentCallbackHandler(*, gate: OversightGate, action_type: ActionType = "connector_action") -> Any:  # noqa: N802 - factory presents as a class to callers
    """Construct a LangChain ``BaseCallbackHandler`` that gates tool calls (lazy).

    Presented as a class-like factory (capitalised) so callers write
    ``SecuGentCallbackHandler(gate=...)`` exactly as the §4.5 contract shows. The
    langchain base class is imported here (I3); absent langchain, this raises a
    clear ``ImportError`` with the ``pip install secugent[langchain]`` hint.

    The concrete handler class is built with :func:`type` because its base class
    (langchain's ``BaseCallbackHandler``) only exists at call time when the
    optional extra is installed — it cannot be referenced as a static base. The
    handler MRO is ``(_OversightHandlerMixin, BaseCallbackHandler)`` so the mixin's
    :meth:`on_tool_start` overrides langchain's no-op default.
    """
    base = _load_base_callback_handler()
    handler_cls = type(
        "_SecuGentCallbackHandler",
        (_OversightHandlerMixin, base),
        {
            "__doc__": "LangChain callback handler enforcing SecuGent oversight on tool start.",
            # Belt-and-braces: set raise_error=True directly on the concrete class
            # too (the mixin already sets it, and is first in the MRO so it wins),
            # so that even if a future langchain base re-declares raise_error the
            # handler still opts in to re-raise — never fail open (§4.8).
            "raise_error": True,
        },
    )
    return handler_cls(gate=gate, action_type=action_type)


def build_handler_for_test(
    *, gate: OversightGate, action_type: ActionType = "connector_action"
) -> _OversightHandlerMixin:
    """Build a langchain-free handler exposing the same ``on_tool_start`` gate.

    Lets tests (and non-langchain embeddings) exercise the exact enforcement path
    without installing the optional extra — it is the same mixin the real handler
    inherits, so there is no divergent control logic.
    """
    return _OversightHandlerMixin(gate=gate, action_type=action_type)


def wrap_langchain_tool(
    fn: Callable[..., Any],
    *,
    action_type: ActionType,
    gate: OversightGate,
    target_from: Callable[..., str | None] | None = None,
) -> Callable[..., Any]:
    """Wrap a LangChain-style tool callable so each call passes the oversight gate.

    A thin alias over :func:`secugent.sdk.middleware.wrap_tool` (the Core wrapper),
    surfaced in the LangChain adapter for discoverability. No langchain import
    required — a LangChain ``Tool``/``StructuredTool``'s ``func``/``coroutine`` is
    a plain callable.
    """
    return wrap_tool(fn, action_type=action_type, gate=gate, target_from=target_from)
