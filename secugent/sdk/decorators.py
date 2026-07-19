# SPDX-License-Identifier: Apache-2.0
"""``@require_oversight`` — wrap any callable so its action passes SecuGent oversight.

Decorating a sync OR async callable makes every invocation,
*before* the wrapped body runs:

1. build the :class:`~secugent.core.contracts.Step` this call represents,
2. run it through the single :class:`~secugent.sdk.gate.OversightGate` (REGULATIONS
   deny-by-default → Rule-of-Two forced HITL → audit emit), and
3. only then call the wrapped function, re-raising its own exceptions unchanged.

A REGULATIONS violation raises :class:`~secugent.core.contracts.HardBlockException`;
a HITL denial raises :class:`~secugent.sdk.gate.OversightBlocked`. Both are
fail-closed — the wrapped body never runs. Neither is swallowed.

**Nested-wrap double-evaluation guard:** when a wrapped callable calls
another wrapped callable on the *same* gate inside the same call stack, only the
outermost wrap evaluates the gate. A :class:`contextvars.ContextVar` sentinel
keyed by ``id(gate)`` marks "this gate is already enforcing on this stack"; the
inner wrap sees the sentinel and skips re-evaluation (no duplicate audit event).
The sentinel is reset in a ``finally`` so it never leaks across calls.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Any, TypeVar, cast

from secugent.core.contracts import ActionType
from secugent.sdk.gate import OversightConfigError, OversightGate, build_step

__all__ = ["require_oversight"]

F = TypeVar("F", bound=Callable[..., Any])

# Set of gate ids currently mid-enforcement on this call stack (per-context). A
# ContextVar (not a thread-local) so the guard is correct under both threads and
# asyncio tasks — each task copies the context, so an inner await cannot leak the
# sentinel to an unrelated task.
_ACTIVE_GATES: ContextVar[frozenset[int]] = ContextVar("_secugent_active_gates", default=frozenset())


# Conventional keyword names a wrapped tool/handler uses for its primary resource
# (the path/host/connector target the REGULATIONS path/domain matchers run against).
# Ordered by preference; the first present, non-None kwarg wins.
_TARGET_KWARG_KEYS: tuple[str, ...] = ("target", "path", "url", "host", "uri", "file", "filepath")

# ASGI scope ``type`` values whose scope dict carries an HTTP-style request ``path``.
_ASGI_SCOPE_TYPES: frozenset[str] = frozenset({"http", "websocket"})

# Action types whose REGULATIONS rules are resource-anchored (path/domain matchers).
# For these, an ASGI scope that yields NO derivable resource must fail closed rather
# than silently skip the rule (deny-by-default).
_RESOURCE_ANCHORED_ACTIONS: frozenset[str] = frozenset({"file_read", "file_write", "desktop", "http_get"})


def _asgi_scope_targets(scope: dict[str, Any]) -> list[str]:
    """Extract REGULATIONS resource candidates from an ASGI ``scope`` dict.

    A real ASGI app is invoked ``app(scope, receive, send)`` where ``scope`` is a
    dict like ``{"type": "http", "path": "/srv/대외비/x", "headers": [...]}``. The
    naive ``str(scope)`` the bare positional default would otherwise produce is a
    dict *repr* that never matches a path glob — so path/domain HARD BLOCK rules
    silently never fire on the real request path (the documented ASGI wiring would
    degrade deny-by-default to allow). We instead pull the request ``path`` and the
    ``Host`` header so the path AND domain matchers see the true request resource.
    """
    targets: list[str] = []
    path = scope.get("path")
    if isinstance(path, str) and path:
        targets.append(path)
    # Host header (bytes tuples per the ASGI spec) → domain candidate.
    headers = scope.get("headers")
    if isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                name, value = item
                name_str = name.decode("latin-1") if isinstance(name, bytes) else str(name)
                if name_str.lower() == "host":
                    host = value.decode("latin-1") if isinstance(value, bytes) else str(value)
                    if host:
                        targets.append(host)
    return targets


def _is_asgi_scope(value: Any) -> bool:
    """True when ``value`` looks like an ASGI ``scope`` dict (http/websocket)."""
    return isinstance(value, dict) and value.get("type") in _ASGI_SCOPE_TYPES


def _default_target_candidates(*args: Any, **kwargs: Any) -> list[str]:
    """All conventional resource candidates for a call, in priority order.

    F5b (security): the resource a banned-path rule must see can be EITHER the
    first positional arg OR a conventional resource kwarg — and BOTH may be present
    at once. LangChain ``StructuredTool`` / class-method / ASGI calls routinely
    carry a non-resource positional (``config`` / ``self`` / ``scope``) plus the
    real resource in a ``path=`` / ``url=`` kwarg. Returning only the positional (as
    the pre-fix single-value extractor did) let a banned kwarg resource fail open.

    We therefore collect *every* candidate the matchers could care about — the
    first positional (when it is a real value, NOT ``None``) followed by each
    present, non-``None`` conventional kwarg (:data:`_TARGET_KWARG_KEYS`) — so the
    gate can evaluate each and fail closed if ANY of them is banned. Order is
    positional-first then kwarg-preference; duplicates are dropped (stable).
    ``None`` positionals are skipped (so ``tool(None, path=...)`` does not extract
    the literal ``"None"`` and mask the banned kwarg).
    """
    candidates: list[str] = []
    if args and args[0] is not None:
        first = args[0]
        if _is_asgi_scope(first):
            # ASGI ``app(scope, receive, send)``: pull scope['path']/Host, never the
            # dict repr (which would defeat path/domain matching — F-asgi).
            candidates.extend(_asgi_scope_targets(first))
        else:
            candidates.append(str(first))
    for key in _TARGET_KWARG_KEYS:
        value = kwargs.get(key)
        if value is not None:
            candidates.append(str(value))
    # Stable de-dup (preserve first-seen order).
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def _default_target_from(*args: Any, **kwargs: Any) -> str | None:
    """Default resource extractor: first positional arg, else a conventional kwarg.

    F2/F5 (security): MANY wrapped tools — especially LangChain ``StructuredTool``
    and ASGI handlers — pass the resource as a **keyword** argument
    (``tool(target="/srv/대외비/x")``, ``app(path=...)``). The old extractor read
    only ``args[0]`` and returned ``None`` for a kwarg resource, so the banned-path
    HARD BLOCK never fired — a deny-by-default control surface silently failing
    open on a common call convention. We now also inspect a small set of
    conventional kwarg keys (:data:`_TARGET_KWARG_KEYS`) so a keyword-passed
    resource is still matched by the path/domain rules.

    This returns the SINGLE *primary* candidate (the first of
    :func:`_default_target_candidates`). The embed surfaces additionally scan ALL
    candidates via the gate so a banned resource in any conventional slot blocks
    (F5b); this single-value form is kept for the public ``target_from`` contract
    and as the fallback target when no candidate is banned.

    When neither a positional arg nor a recognised kwarg is present the target is
    ``None`` (action-type-driven Rule-of-Two axes still apply; a path rule simply
    does not fire). Tools whose resource arg is keyword-only AND non-conventional
    must pass an explicit ``target_from`` / static ``target`` — this is documented
    on ``require_oversight``.
    """
    candidates = _default_target_candidates(*args, **kwargs)
    return candidates[0] if candidates else None


def require_oversight(
    *,
    action_type: ActionType,
    gate: OversightGate,
    target_from: Callable[..., str | None] | None = None,
    target: str | None = None,
    command: str | None = None,
    context: dict[str, Any] | None = None,
) -> Callable[[F], F]:
    """Return a decorator that gates a callable through SecuGent oversight.

    Args:
        action_type: the SecuGent :data:`~secugent.core.contracts.ActionType`
            this call performs (drives Rule-of-Two axis ②/③ classification and the
            REGULATIONS path/command matchers).
        gate: the :class:`~secugent.sdk.gate.OversightGate` that owns the core
            decision path (REGULATIONS + Rule of Two + audit). The SDK never
            re-implements that logic — it only calls this gate (I1).
        target_from: maps the wrapped call's ``(*args, **kwargs)`` to the resource
            string the REGULATIONS matchers see. Defaults to the first positional
            argument, falling back to a conventional keyword
            (``target``/``path``/``url``/``host``/``uri``/``file``/``filepath``) so a
            keyword-passed resource is still policy-matched (F2/F5). A tool whose
            resource arg is keyword-only AND non-conventional MUST supply an
            explicit ``target_from`` (or a static ``target``) — otherwise the
            path/domain rules cannot see its resource. Ignored when a static
            ``target`` is supplied.
        target: a static resource override (path/host/connector). When ``None`` the
            target is derived per-call via ``target_from``.
        command: optional shell command (matched by banned-command rules).
        context: optional :class:`~secugent.core.contracts.Step` context — e.g. a
            declared ``{"rule_of_two": {"untrusted_input": True}}`` or a
            ``provenance`` block that auto-taints axis ①.

    The wrapped function's signature is preserved; its return value and exceptions
    pass through unchanged. The ``cast`` keeps the decorator transparent to static
    callers — the wrapper deliberately has the same call signature as ``func``.
    """

    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                token = _enter(gate)
                entered = token is not None
                try:
                    if entered:
                        # F6: the gate's HITL ``request_decision`` is a BLOCKING,
                        # synchronous human-decision call. Running it inline on the
                        # event loop would freeze every other task/request for the
                        # whole approval TTL — defeating the point of wrapping async
                        # callables. Offload the blocking enforce to a worker thread
                        # via ``asyncio.to_thread`` (which copies the current context,
                        # preserving the ``_ACTIVE_GATES`` nested-wrap sentinel) so the
                        # loop stays responsive while a human decides. The gate is
                        # used one-per-request (its ``_prev_event_id`` is not shared
                        # concurrently), so the off-thread mutation is safe.
                        await asyncio.to_thread(
                            _run_gate,
                            gate,
                            action_type,
                            target_from,
                            target,
                            command,
                            context,
                            args,
                            kwargs,
                        )
                    # The sentinel stays set for the duration of the wrapped body
                    # so a nested call to another callable wrapped on the SAME gate
                    # is deduplicated (single evaluation).
                    # cast: the wrapped coroutine fn returns Awaitable[Any] — mypy
                    # cannot infer that from the bound TypeVar F here.
                    return await cast(Callable[..., Awaitable[Any]], func)(*args, **kwargs)
                finally:
                    if token is not None:
                        _exit(token)

            # cast: functools.wraps preserves func's signature; the wrapper IS an F.
            return cast(F, async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            token = _enter(gate)
            entered = token is not None
            try:
                if entered:
                    _run_gate(gate, action_type, target_from, target, command, context, args, kwargs)
                return func(*args, **kwargs)
            finally:
                if token is not None:
                    _exit(token)

        # cast: same rationale as the async branch — wrapper preserves func's type.
        return cast(F, sync_wrapper)

    return decorator


def resolve_target(
    gate: OversightGate,
    action_type: ActionType,
    target_from: Callable[..., str | None] | None,
    static_target: str | None,
    context: dict[str, Any] | None,
    call_args: tuple[Any, ...],
    call_kwargs: dict[str, Any],
) -> str | None:
    """Derive the REGULATIONS target for one wrapped call (shared by all surfaces).

    Precedence:

    1. a static ``target`` override (decoration-time constant) — used verbatim;
    2. an explicit ``target_from`` — its single returned value is used verbatim
       (the caller owns extraction; we do not second-guess a custom extractor);
    3. the default extractor — we scan ALL conventional candidates (positional +
       conventional kwargs) and let the gate pick the FIRST banned one (F5b
       fail-closed), falling back to the primary candidate when none is banned.

    Returning the banned candidate makes the subsequent single ``gate.enforce``
    deny it — so a benign positional can never mask a banned kwarg resource.
    """
    if static_target is not None:
        return static_target
    if target_from is not None:
        return target_from(*call_args, **call_kwargs)
    candidates = _default_target_candidates(*call_args, **call_kwargs)
    # Fail-closed: an ASGI scope handed to a path/domain action MUST yield a
    # resource. If the scope carried no usable ``path``/host we refuse to proceed
    # (deny-by-default) rather than evaluate a resource-less step that would let the
    # path/domain rule silently not fire — the caller must wire an explicit
    # ``target_from``. This only fires for the resource-anchored action types.
    if (
        not candidates
        and action_type in _RESOURCE_ANCHORED_ACTIONS
        and call_args
        and _is_asgi_scope(call_args[0])
    ):
        raise OversightConfigError(
            "ASGI scope provided for a path/domain action_type "
            f"({action_type!r}) but no request path/host could be derived; "
            "pass an explicit target_from to extract the resource (fail-closed)."
        )
    return gate.select_blocking_target(action_type=action_type, candidates=candidates, context=context)


def _run_gate(
    gate: OversightGate,
    action_type: ActionType,
    target_from: Callable[..., str | None] | None,
    static_target: str | None,
    command: str | None,
    context: dict[str, Any] | None,
    call_args: tuple[Any, ...],
    call_kwargs: dict[str, Any],
) -> None:
    """Build the step for this call and enforce the gate (raises on deny).

    The REGULATIONS target is resolved by :func:`resolve_target` (static override,
    else explicit ``target_from``, else a fail-closed scan of all conventional
    candidates) so the matcher sees the real runtime resource — and a banned
    resource in any conventional slot is never masked by a benign one (F5b).
    """
    target = resolve_target(gate, action_type, target_from, static_target, context, call_args, call_kwargs)
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


def _enter(gate: OversightGate) -> object | None:
    """Mark ``gate`` active on this stack; return a reset token, or ``None`` if it
    is already active (nested wrap → skip re-evaluation)."""
    active = _ACTIVE_GATES.get()
    key = id(gate)
    if key in active:
        return None
    return _ACTIVE_GATES.set(active | {key})


def _exit(token: object) -> None:
    """Reset the sentinel set to its pre-:func:`_enter` value."""
    _ACTIVE_GATES.reset(cast("Any", token))
