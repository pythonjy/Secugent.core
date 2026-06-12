# SPDX-License-Identifier: Apache-2.0
"""Regression test for SG-FIX-02.

Verifies that ``set_current_tenant``'s ``finally`` block does NOT propagate
a ``ValueError`` when ``ContextVar.reset(token)`` is called from a *different*
asyncio Context than the one that called ``set()``.

Root cause: Python's ContextVar.reset() raises
    ValueError("Token was created in a different Context")
when the token is reset outside the Context it was created in.  In production
this is triggered by SSE/StreamingResponse teardown, where the generator's
``close()`` (GeneratorExit) is scheduled in a fresh Context.

The fix must:
  1. Absorb the ``ValueError`` — it must NOT propagate.
  2. Emit one ``logging.WARNING`` message via the module logger (``_logger``).
  3. Leave the normal same-Context reset path untouched (per-task isolation
     preserved).
"""

from __future__ import annotations

import contextvars
import inspect
import logging

import pytest

import secugent.core.tenancy as _tenancy_module
from secugent.core.tenancy import TenantId, current_tenant, set_current_tenant

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_tid(name: str) -> TenantId:
    return TenantId(name)


# ---------------------------------------------------------------------------
# RED / GREEN test: cross-Context reset must not raise ValueError
# ---------------------------------------------------------------------------


def test_cross_context_reset_does_not_raise_and_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Simulate SSE-style teardown: set() happens in one Context, reset()
    happens in a *different* Context (copy_context() produces a sibling).

    Before the fix: ValueError propagates from finally block.
    After the fix: ValueError is absorbed; a WARNING is logged.

    Implementation note: the entire set+cross-exit sequence runs inside a
    ``copy_context().run()`` wrapper so that the main pytest Context is never
    mutated and subsequent tests see a clean ContextVar state.
    """
    tid = _make_tid("acme")

    # Shared mutable container so the inner closure can report back.
    results: dict[str, object] = {}

    def _run_scenario() -> None:
        """Run inside an isolated copy of the current Context.

        1. Enter set_current_tenant (set() records a token in *this* copy).
        2. Trigger __exit__ from a *second* copy (sibling) — simulates SSE
           teardown in a different asyncio Context.
        3. Record whether an exception was raised.
        """
        cm = set_current_tenant(tid)
        cm.__enter__()

        # A copy of the already-copied Context — a sibling, not a child.
        sibling_ctx = contextvars.copy_context()

        def _exit_in_sibling() -> None:
            cm.__exit__(None, None, None)

        try:
            sibling_ctx.run(_exit_in_sibling)
            results["raised"] = None
        except Exception as exc:  # noqa: BLE001 — we're catching to record
            results["raised"] = exc

    outer_copy = contextvars.copy_context()

    with caplog.at_level(logging.WARNING, logger="secugent.core.tenancy"):
        outer_copy.run(_run_scenario)

    # 1. No exception propagated from the fix.
    assert results.get("raised") is None, (
        f"ValueError should have been absorbed, but got: {results['raised']!r}"
    )

    # 2. Exactly one warning logged by the tenancy module logger.
    warning_records = [
        r for r in caplog.records if r.levelno == logging.WARNING and r.name == "secugent.core.tenancy"
    ]
    assert len(warning_records) == 1, (
        f"Expected 1 warning from secugent.core.tenancy, "
        f"got {len(warning_records)}: {[r.message for r in warning_records]}"
    )
    assert (
        "cross-context" in warning_records[0].message.lower()
        or "cross_context" in warning_records[0].message.lower()
        or "different context" in warning_records[0].message.lower()
        or "reset" in warning_records[0].message.lower()
    ), f"Warning message not descriptive enough: {warning_records[0].message!r}"


# ---------------------------------------------------------------------------
# Regression: normal same-Context reset still works (per-task isolation)
# ---------------------------------------------------------------------------


def test_same_context_reset_still_works_after_fix() -> None:
    """Normal set/reset in the same Context must behave exactly as before."""
    tid = _make_tid("contoso")
    with set_current_tenant(tid):
        assert current_tenant() == tid
    # After the context manager exits, the var is unset again.
    with pytest.raises(LookupError):
        current_tenant()


def test_nested_same_context_resets_restore_outer() -> None:
    """Nested bindings in the same Context correctly restore the outer value."""
    outer = _make_tid("alpha")
    inner = _make_tid("bravo")
    with set_current_tenant(outer):
        assert current_tenant() == outer
        with set_current_tenant(inner):
            assert current_tenant() == inner
        assert current_tenant() == outer
    with pytest.raises(LookupError):
        current_tenant()


# ---------------------------------------------------------------------------
# Extra: only ValueError is absorbed — other exceptions in reset propagate
# (This is a design invariant, not directly triggerable via the public API,
#  but we document the intent with a structural assertion on the fix.)
# ---------------------------------------------------------------------------


def test_only_value_error_absorbed_not_arbitrary_exceptions() -> None:
    """The fix must not swallow non-ValueError exceptions from reset.

    We verify this by inspecting the source: only ``except ValueError`` is
    present in the finally block — not a bare ``except`` or ``except Exception``.
    """
    source = inspect.getsource(_tenancy_module.set_current_tenant)
    # Must have a narrowly-typed except for ValueError only.
    assert "except ValueError" in source, "set_current_tenant must catch only ValueError in the finally block"
    # Must NOT have a bare 'except:' or 'except Exception'
    assert "except:" not in source, "Bare 'except:' found — must be ValueError-specific"
    assert "except Exception" not in source, "'except Exception' found — must be narrowed to ValueError"
