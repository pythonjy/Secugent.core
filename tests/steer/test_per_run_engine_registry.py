# SPDX-License-Identifier: Apache-2.0
"""STEER non-regression — patches reach the CORRECT run's engine.

With per-run :class:`OversightEngine` instances (one per dispatch), a STEER
``add_constraint`` directive for run A must patch run A's engine and leave run B's
engine uninfected. When no per-run engine is registered (loader-None / pre-dispatch),
STEER falls back to the handler's default engine and still applies the constraint —
it must NEVER silently no-op (fail-closed, spec invariant 4).

Korean directive fixture (§C-3): 고객정보 폴더 접근 금지.
"""

from __future__ import annotations

from secugent.core.contracts import Step
from secugent.core.event_store import EventStore
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import load_regulations_from_dict
from secugent.core.tenancy import TenantId
from secugent.steer.steer import SteerHandler

_TENANT = TenantId("legacy-default")
_DIRECTIVE = "D:/고객정보 폴더는 절대 건드리지 마"
_PROBE = "D:\\고객정보\\plan.docx"


def _empty_engine() -> OversightEngine:
    return OversightEngine(load_regulations_from_dict({"version": "empty"}))


def _probe(run_id: str) -> Step:
    return Step(
        tenant_id=_TENANT,
        run_id=run_id,
        actor="sub:1",
        action_type="file_read",
        target=_PROBE,
    )


def test_steer_patch_reaches_registered_run_engine_only(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EventStore(tmp_path / "steer.db")
    engine_a = _empty_engine()
    engine_b = _empty_engine()
    fallback = _empty_engine()
    registry: dict[str, OversightEngine] = {"run-a": engine_a, "run-b": engine_b}

    handler = SteerHandler(
        oversight=fallback,
        event_store=store,
        engine_resolver=registry.get,
    )
    # STEER on run-a only.
    handler.apply(run_id="run-a", directive=_DIRECTIVE, actor="role:operator")

    # run-a engine now hard-blocks the 고객정보 path.
    assert engine_a.evaluate(_probe("run-a")).hard_block is True
    # run-b engine is uninfected.
    assert engine_b.evaluate(_probe("run-b")).allowed is True
    # The shared fallback was NOT patched (a registered engine took the patch).
    assert fallback.evaluate(_probe("run-a")).allowed is True


def test_steer_falls_back_to_default_engine_when_unregistered(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = EventStore(tmp_path / "steer2.db")
    fallback = _empty_engine()
    registry: dict[str, OversightEngine] = {}  # run not registered

    handler = SteerHandler(
        oversight=fallback,
        event_store=store,
        engine_resolver=registry.get,
    )
    handler.apply(run_id="run-x", directive=_DIRECTIVE, actor="role:operator")

    # No per-run engine ⇒ the default engine receives the patch (no silent no-op).
    assert fallback.evaluate(_probe("run-x")).hard_block is True


def test_steer_without_resolver_uses_default_engine(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Legacy construction (no resolver) is unchanged — default engine patched."""
    store = EventStore(tmp_path / "steer3.db")
    fallback = _empty_engine()
    handler = SteerHandler(oversight=fallback, event_store=store)
    handler.apply(run_id="run-y", directive=_DIRECTIVE, actor="role:operator")
    assert fallback.evaluate(_probe("run-y")).hard_block is True
