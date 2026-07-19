# SPDX-License-Identifier: Apache-2.0
"""COST-01 — run-attribution context for live in-run cost metering.

This module is the PUBLIC, cost-agnostic half of in-run metering. It carries
*who* a live LLM call should be attributed to (``tenant_id`` + ``run_id``)
through a :class:`contextvars.ContextVar`, so a usage observer installed on the
LLM client (the private RECORDER in the ``secugent.cost`` tier) can read the
attribution at the moment :meth:`~secugent.core.llm_client.LLMClient.generate`
fires — without the client, or this module, ever importing ``secugent.cost``.

Why a contextvar (and the threading caveat)
-------------------------------------------
The dispatch path that invokes the LLM is *synchronous* (``HeadAgent.plan`` and
``SubAgent._run_step``; the latter runs inside a ``ThreadPoolExecutor`` worker —
see [[envelope-contextvar-threading-risk]]). ``ContextVar`` is per-thread/per-
task, and ``ThreadPoolExecutor.submit`` does NOT copy the parent context into
the worker. The chosen invariant therefore is: **bind in the same call stack
that calls** ``generate()``. :func:`bind_cost_context` is entered *inside*
``HeadAgent.plan`` / ``SubAgent._run_step`` (already on the worker thread), so
the observer — invoked synchronously from within ``generate()`` on that same
thread — always reads the correct, isolated attribution. No cross-thread
propagation is relied upon, so two concurrent same-tenant runs each see only
their own binding (INV-5 tenant attribution; no mis-attribution).

When no context is bound (boot-time calls, the CLI ``verify`` path, the
deterministic demo, any direct ``generate`` caller), :func:`current_cost_context`
returns ``None`` and the recorder skips — spend is never mis-attributed
(INV-5), and the deterministic fixture path is never touched (INV-6).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass

__all__ = [
    "CostContext",
    "bind_cost_context",
    "current_cost_context",
]


@dataclass(frozen=True)
class CostContext:
    """The run a live LLM call is attributed to.

    Immutable so a bound attribution cannot be mutated mid-call. ``tenant_id``
    and ``run_id`` are kept as plain ``str`` (not :class:`TenantId`) so this
    PUBLIC module stays free of any heavier core/tenancy coupling and the
    recorder re-parses/validates as it needs.
    """

    tenant_id: str
    run_id: str


_CURRENT: ContextVar[CostContext | None] = ContextVar("secugent_cost_context", default=None)


def current_cost_context() -> CostContext | None:
    """Return the attribution bound for the current call stack, or ``None``.

    ``None`` means "no run is currently attributable" — the recorder MUST skip
    rather than guess a tenant (INV-5). Never raises.
    """
    return _CURRENT.get()


@contextmanager
def bind_cost_context(tenant_id: str, run_id: str) -> Iterator[CostContext]:
    """Bind ``(tenant_id, run_id)`` for the duration of the ``with`` block.

    Entered in the *same* synchronous call stack that invokes
    :meth:`~secugent.core.llm_client.LLMClient.generate`, so a usage observer
    reads this exact attribution. The previous binding (possibly ``None``, or a
    nested run) is restored on exit via the :class:`~contextvars.Token`, so
    nesting and concurrent bindings on different threads/tasks stay isolated.

    This is a pure control-plane helper: it never touches the ledger and is safe
    to enter even when no recorder is installed (the observer is simply absent →
    a no-op). It does not swallow exceptions from the wrapped body — the *call*
    is fail-open (the observer can never raise into ``generate``), but binding
    the attribution must not hide a genuine dispatch error.
    """
    token: Token[CostContext | None] = _CURRENT.set(CostContext(tenant_id=tenant_id, run_id=run_id))
    try:
        yield _CURRENT.get()  # type: ignore[misc]  # just-set value is non-None
    finally:
        _CURRENT.reset(token)
