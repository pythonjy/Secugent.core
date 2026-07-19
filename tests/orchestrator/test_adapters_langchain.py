# SPDX-License-Identifier: Apache-2.0
"""Tests for the LangChain oversight adapter (§4.5/§4.6 I3).

Two invariants:

* **I3 (lazy-import isolation):** importing ``secugent.sdk`` and ``secugent.core``
  succeeds with LangChain ABSENT — the core never hard-depends on the optional
  ``langchain`` extra. Constructing the adapter without langchain installed
  raises a clear ``ImportError`` carrying the ``pip install secugent[langchain]``
  install hint (only when the adapter is actually used).
* **on_tool_start enforcement:** a violating tool call routed through the
  callback handler is HARD BLOCKed via the SAME core path (no second control
  implementation). Exercised with a stub ``BaseCallbackHandler`` base so the test
  does not require langchain to be installed.
"""

from __future__ import annotations

import importlib
import sys
import types
from typing import Any

import pytest

from secugent.core.contracts import HardBlockException
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations, load_regulations_from_dict
from secugent.core.tenancy import TenantId

_TENANT = TenantId("lc-tenant")
_RUN = "run_lc_test00"


def _korean_regulations() -> Regulations:
    doc = {
        "version": "lc-1.0.0",
        "banned_paths": [
            {
                "rule_id": "대외비-도구-차단",
                "pattern": "*/대외비/*",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "대외비 경로를 다루는 도구 호출은 차단된다.",
            }
        ],
    }
    return load_regulations_from_dict(doc, source="<lc-test>")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: dict[str, object]) -> None:
        self.events.append(event)


def _langchain_installed() -> bool:
    try:
        importlib.import_module("langchain_core.callbacks")
        return True
    except Exception:
        try:
            importlib.import_module("langchain.callbacks.base")
            return True
        except Exception:
            return False


# --------------------------------------------------------------------------- #
# I3 — lazy-import isolation
# --------------------------------------------------------------------------- #


def test_importing_secugent_sdk_works_without_langchain() -> None:
    """secugent.sdk must import even with langchain absent (no hard dep)."""
    import secugent.sdk as sdk

    assert hasattr(sdk, "require_oversight")
    assert hasattr(sdk, "OversightMiddleware")
    assert hasattr(sdk, "wrap_tool")


def test_importing_secugent_core_works_without_langchain() -> None:
    import secugent.core.mechanical_oversight  # noqa: F401
    import secugent.core.rule_of_two  # noqa: F401

    # If this import line executed, the core never required langchain.
    assert True


def test_importing_adapter_module_does_not_require_langchain() -> None:
    """Importing the adapter module itself must not fail when langchain is absent
    (the import is guarded/deferred); only *constructing* the handler does."""
    mod = importlib.import_module("secugent.orchestrator.adapters_langchain")
    assert hasattr(mod, "SecuGentCallbackHandler")
    assert hasattr(mod, "wrap_langchain_tool")


@pytest.mark.skipif(_langchain_installed(), reason="langchain installed — the missing-dep guard cannot fire")
def test_constructing_handler_without_langchain_raises_install_hint() -> None:
    from secugent.orchestrator.adapters_langchain import SecuGentCallbackHandler
    from secugent.sdk.gate import OversightGate

    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=_RecordingSink(),
    )
    with pytest.raises(ImportError) as excinfo:
        SecuGentCallbackHandler(gate=gate)
    msg = str(excinfo.value)
    assert "secugent[langchain]" in msg


# --------------------------------------------------------------------------- #
# on_tool_start enforcement via a stub base (no langchain required)
# --------------------------------------------------------------------------- #


def test_on_tool_start_blocks_violating_tool_via_core_path() -> None:
    """With a stub BaseCallbackHandler, on_tool_start HARD BLOCKs a violating
    tool call through the same core gate (no second control implementation)."""
    from secugent.orchestrator import adapters_langchain
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )

    handler = adapters_langchain.build_handler_for_test(gate=gate, action_type="file_write")

    serialized = {"name": "file_writer"}
    with pytest.raises(HardBlockException):
        handler.on_tool_start(serialized, "/srv/대외비/leak.txt")
    assert sink.events and sink.events[0]["decision"] == "reject"


def test_on_tool_start_allows_compliant_tool() -> None:
    from secugent.orchestrator import adapters_langchain
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )
    handler = adapters_langchain.build_handler_for_test(gate=gate, action_type="file_read")
    serialized = {"name": "file_reader"}
    # Compliant path: no raise, one approve event.
    handler.on_tool_start(serialized, "/srv/공개/notice.txt")
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


@pytest.fixture
def _fake_langchain(monkeypatch: pytest.MonkeyPatch) -> type:
    """Inject a stub ``langchain_core.callbacks.BaseCallbackHandler`` into sys.modules.

    Exercises the *langchain-present* path of the adapter (dynamic ``type()``
    subclass creation + on_tool_start override) deterministically, without
    installing the real optional extra. The MRO is ``(_OversightHandlerMixin,
    BaseCallbackHandler)`` so the SecuGent enforcement overrides the base no-op.
    """

    class _StubBaseCallbackHandler:
        def __init__(self) -> None:  # langchain's base takes no args
            self.base_inited = True

        def on_tool_start(self, serialized: dict[str, object], input_str: str, **kw: object) -> None:
            # The base's default is a no-op (never enforces) — proving the mixin
            # override is what blocks.
            return None

    pkg = types.ModuleType("langchain_core")
    callbacks_mod = types.ModuleType("langchain_core.callbacks")
    callbacks_mod.BaseCallbackHandler = _StubBaseCallbackHandler  # type: ignore[attr-defined]
    pkg.callbacks = callbacks_mod  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langchain_core", pkg)
    monkeypatch.setitem(sys.modules, "langchain_core.callbacks", callbacks_mod)
    return _StubBaseCallbackHandler


def test_real_callback_handler_subclasses_langchain_base_and_blocks(_fake_langchain: type) -> None:
    """With a (stub) langchain base present, SecuGentCallbackHandler builds a real
    BaseCallbackHandler subclass whose on_tool_start enforces the core gate."""
    from secugent.orchestrator.adapters_langchain import SecuGentCallbackHandler
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )
    handler: Any = SecuGentCallbackHandler(gate=gate, action_type="file_write")
    # It is a genuine subclass of the (stub) langchain base — langchain will treat
    # it as a callback handler — and the base initializer ran via the MRO. The
    # ``isinstance`` check uses a separate ``object``-bound name so it does not
    # narrow ``handler`` (the dynamic ``type()`` subclass is statically ``Any``)
    # away from its callable surface, keeping the ``on_tool_start`` call type-clean.
    handler_obj: object = handler
    assert isinstance(handler_obj, _fake_langchain)
    assert getattr(handler_obj, "base_inited", False) is True

    with pytest.raises(HardBlockException):
        handler.on_tool_start({"name": "file_writer"}, "/srv/대외비/leak.txt")
    assert sink.events[0]["decision"] == "reject"


def test_real_callback_handler_allows_compliant_tool(_fake_langchain: type) -> None:
    from secugent.orchestrator.adapters_langchain import SecuGentCallbackHandler
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )
    handler = SecuGentCallbackHandler(gate=gate, action_type="file_read")
    handler.on_tool_start({"name": "file_reader"}, "/srv/공개/notice.txt")
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


def test_wrap_langchain_tool_blocks_violating_call() -> None:
    from secugent.orchestrator.adapters_langchain import wrap_langchain_tool
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )
    calls: list[str] = []

    def lc_tool(target: str) -> str:
        calls.append(target)
        return "ran"

    wrapped = wrap_langchain_tool(lc_tool, action_type="file_write", gate=gate)
    with pytest.raises(HardBlockException):
        wrapped("/srv/대외비/x.txt")
    assert calls == []


# --------------------------------------------------------------------------- #
# F-langchain-fail-open: the handler MUST NOT fail open under langchain dispatch
# --------------------------------------------------------------------------- #


def _simulate_langchain_handle_event(
    handler: Any,
    method_name: str,
    *args: Any,
    **kwargs: Any,
) -> None:
    """Faithfully mimic ``langchain_core.callbacks.manager.handle_event``.

    LangChain dispatches each callback handler's method inside a ``try/except`` and
    **swallows** the handler's exception UNLESS ``handler.raise_error`` is truthy —
    ``BaseCallbackHandler.raise_error`` defaults to ``False``. So a handler that
    raises to block a tool is, by default, silently ignored and the tool proceeds.
    This helper reproduces that exact gate so the test exercises the real dispatch
    path (langchain is not installed in CI), proving SecuGent's handler sets
    ``raise_error=True`` and therefore does NOT fail open.
    """
    fn = getattr(handler, method_name)
    try:
        fn(*args, **kwargs)
    except Exception:
        # langchain: only re-raise when the handler opted in via raise_error.
        if getattr(handler, "raise_error", False):
            raise
        # Otherwise langchain logs 'Error in callback' and CONTINUES (fail-open).


def test_callback_handler_does_not_fail_open_under_langchain_dispatch(_fake_langchain: type) -> None:
    """REGRESSION (Critical): under langchain's swallow-by-default dispatch, the
    SecuGent handler's HARD BLOCK must still propagate — the violating tool must NOT
    run. Pre-fix the handler did not set ``raise_error=True``, so langchain caught
    the ``HardBlockException`` and executed the tool anyway (a full bypass of the
    REGULATIONS HARD BLOCK at the embed boundary, §4.8)."""
    from secugent.orchestrator.adapters_langchain import SecuGentCallbackHandler
    from secugent.sdk.gate import OversightGate

    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:tool",
        audit=sink,
    )
    handler: Any = SecuGentCallbackHandler(gate=gate, action_type="file_write")

    # The handler must declare raise_error=True so langchain re-raises its block.
    assert getattr(handler, "raise_error", False) is True, (
        "handler must set raise_error=True or langchain swallows the HARD BLOCK (fail-open)"
    )

    tool_ran: list[str] = []

    def violating_tool(target: str) -> str:
        tool_ran.append(target)
        return "wrote"

    # Drive the handler through langchain's dispatch gate, then (only if it did not
    # raise) the tool would run — exactly the production sequence.
    with pytest.raises(HardBlockException):
        _simulate_langchain_handle_event(
            handler, "on_tool_start", {"name": "file_writer"}, "/srv/대외비/payroll.xlsx"
        )
        violating_tool("/srv/대외비/payroll.xlsx")

    assert tool_ran == [], "FAIL-OPEN: the violating tool ran despite the HARD BLOCK"
    assert sink.events[0]["decision"] == "reject"
