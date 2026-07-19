# SPDX-License-Identifier: Apache-2.0
"""COST-01 — run-attribution contextvar (PUBLIC, cost-agnostic).

Proves:
* default is ``None`` (no run attributable → recorder skips),
* ``bind_cost_context`` sets and restores the binding (nesting safe),
* per-thread isolation (a worker thread does NOT see the parent's binding —
  the [[envelope-contextvar-threading-risk]] guarantee that drives the
  "bind in the same call stack as generate()" design),
* this module never imports the private ``secugent.cost`` tier (closure).
"""

from __future__ import annotations

import ast
import threading
from pathlib import Path

from secugent.core.cost_context import (
    CostContext,
    bind_cost_context,
    current_cost_context,
)


def test_default_is_none() -> None:
    assert current_cost_context() is None


def test_bind_sets_and_restores() -> None:
    assert current_cost_context() is None
    with bind_cost_context("kb-bank", "run-1") as ctx:
        assert ctx == CostContext(tenant_id="kb-bank", run_id="run-1")
        assert current_cost_context() == CostContext(tenant_id="kb-bank", run_id="run-1")
    # Restored to the prior (None) binding on exit.
    assert current_cost_context() is None


def test_nested_bind_restores_outer() -> None:
    with bind_cost_context("kb-bank", "outer"):
        assert current_cost_context() == CostContext(tenant_id="kb-bank", run_id="outer")
        with bind_cost_context("shinhan", "inner"):
            assert current_cost_context() == CostContext(tenant_id="shinhan", run_id="inner")
        # Inner exit restores the outer binding, not None.
        assert current_cost_context() == CostContext(tenant_id="kb-bank", run_id="outer")
    assert current_cost_context() is None


def test_bind_restores_on_exception() -> None:
    class _Boom(RuntimeError):
        pass

    try:
        with bind_cost_context("kb-bank", "run-x"):
            raise _Boom
    except _Boom:
        pass
    # Binding must be restored even when the wrapped body raises.
    assert current_cost_context() is None


def test_thread_isolation() -> None:
    """A worker thread spawned under a binding does NOT inherit it.

    ThreadPoolExecutor.submit does not copy the parent context, which is exactly
    why COST-01 binds INSIDE the worker's call stack (SubAgent._run_step) rather
    than relying on propagation. This test pins that isolation so a future
    refactor cannot silently start leaking attribution across threads.
    """
    seen: list[CostContext | None] = []

    def _worker() -> None:
        seen.append(current_cost_context())

    with bind_cost_context("kb-bank", "parent-run"):
        t = threading.Thread(target=_worker)
        t.start()
        t.join()

    assert seen == [None]


def test_module_does_not_import_secugent_cost() -> None:
    """Closure: the PUBLIC cost_context module must not reach the private tier."""
    src = Path("secugent/core/cost_context.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("secugent.cost"), alias.name
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secugent.cost"), node.module
