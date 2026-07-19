# SPDX-License-Identifier: Apache-2.0
"""Tests for ``OversightMiddleware`` + ``wrap_tool`` (§4.8 §4).

Boundary check (the critical 'no bypass' invariant): EVERY request path through
the middleware passes the same core oversight gate and emits a §C-2 audit event.
There is no execution path that reaches the wrapped app without first running the
gate (I1/I2). A REGULATIONS-violating request HARD BLOCKs before the app runs.
"""

from __future__ import annotations

import pytest

from secugent.core.contracts import HardBlockException
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import Regulations, load_regulations_from_dict
from secugent.core.tenancy import TenantId
from secugent.sdk import OversightMiddleware, wrap_tool
from secugent.sdk.gate import OversightConfigError, OversightGate

_TENANT = TenantId("mw-tenant")
_RUN = "run_mw_test00"


def _korean_regulations() -> Regulations:
    doc = {
        "version": "mw-1.0.0",
        "banned_paths": [
            {
                "rule_id": "기밀-경로-차단",
                "pattern": "*/기밀/*",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "기밀 경로 접근은 차단된다.",
            }
        ],
    }
    return load_regulations_from_dict(doc, source="<mw-test>")


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event: dict[str, object]) -> None:
        self.events.append(event)


def _gate(sink: _RecordingSink) -> OversightGate:
    return OversightGate(
        oversight=OversightEngine(_korean_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="mw:request",
        audit=sink,
    )


# --------------------------------------------------------------------------- #
# wrap_tool
# --------------------------------------------------------------------------- #


def test_wrap_tool_blocks_violating_call() -> None:
    sink = _RecordingSink()
    calls: list[str] = []

    def my_tool(target: str) -> str:
        calls.append(target)
        return "ok"

    wrapped = wrap_tool(my_tool, action_type="file_write", gate=_gate(sink))

    with pytest.raises(HardBlockException):
        wrapped("/data/기밀/secret.txt")
    assert calls == []
    assert sink.events[0]["decision"] == "reject"


def test_wrap_tool_passes_compliant_call_with_one_event() -> None:
    sink = _RecordingSink()

    def my_tool(target: str) -> str:
        return f"ok:{target}"

    wrapped = wrap_tool(my_tool, action_type="file_read", gate=_gate(sink))
    out = wrapped("/data/공개/notice.txt")
    assert out == "ok:/data/공개/notice.txt"
    assert len(sink.events) == 1


# --------------------------------------------------------------------------- #
# OversightMiddleware (callable form) — boundary: no bypass
# --------------------------------------------------------------------------- #


def test_callable_middleware_runs_gate_on_every_request() -> None:
    sink = _RecordingSink()
    served: list[str] = []

    def app(target: str) -> str:
        served.append(target)
        return "served"

    mw = OversightMiddleware(
        app,
        action_type="file_read",
        gate=_gate(sink),
        target_from=lambda target: target,
    )

    # Two compliant requests → two gate events, two served responses.
    assert mw("/data/공개/a.txt") == "served"
    assert mw("/data/공개/b.txt") == "served"
    assert served == ["/data/공개/a.txt", "/data/공개/b.txt"]
    assert len(sink.events) == 2, "boundary: every request must pass the gate exactly once"


def test_callable_middleware_blocks_violating_request_before_app() -> None:
    sink = _RecordingSink()
    served: list[str] = []

    def app(target: str) -> str:
        served.append(target)
        return "served"

    mw = OversightMiddleware(
        app,
        action_type="file_write",
        gate=_gate(sink),
        target_from=lambda target: target,
    )

    with pytest.raises(HardBlockException):
        mw("/data/기밀/x.txt")
    # The downstream app NEVER ran (boundary: no bypass path).
    assert served == []
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "reject"


def test_middleware_target_extractor_default_uses_first_positional() -> None:
    sink = _RecordingSink()

    def app(target: str) -> str:
        return "served"

    # No target_from → default extractor uses the first positional argument.
    mw = OversightMiddleware(app, action_type="file_read", gate=_gate(sink))
    assert mw("/data/공개/ok.txt") == "served"
    assert len(sink.events) == 1


def test_middleware_default_extractor_yields_none_without_positional() -> None:
    """No positional argument → default extractor returns None (a compute action
    has no path target; the action-type Rule-of-Two axes still apply)."""
    sink = _RecordingSink()

    def app() -> str:
        return "served"

    mw = OversightMiddleware(app, action_type="compute", gate=_gate(sink))
    assert mw() == "served"
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


def test_wrap_tool_default_extractor_yields_none_without_positional() -> None:
    sink = _RecordingSink()

    def tool() -> str:
        return "ran"

    wrapped = wrap_tool(tool, action_type="compute", gate=_gate(sink))
    assert wrapped() == "ran"
    assert len(sink.events) == 1


# --------------------------------------------------------------------------- #
# ASGI scope shape: a banned path inside the ASGI ``scope`` dict must HARD BLOCK
# under the DOCUMENTED bare-positional default (no garbage dict-repr matching).
# --------------------------------------------------------------------------- #


def _banned_path_regulations() -> Regulations:
    # An EXACT-path pattern (no leading ``*/``) so a dict-repr like
    # "{'type': 'http', 'path': '/srv/대외비/x', ...}" can NOT accidentally match
    # by substring — only the real ``scope['path']`` does. This faithfully exposes
    # the str(scope) fail-open the finding describes (a ``*/대외비/*`` glob would
    # spuriously match the repr and hide the defect).
    doc = {
        "version": "asgi-1.0.0",
        "banned_paths": [
            {
                "rule_id": "대외비-정확경로",
                "pattern": "/srv/대외비/x",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "대외비 경로 차단",
            }
        ],
    }
    return load_regulations_from_dict(doc, source="<asgi-test>")


def _asgi_gate(sink: _RecordingSink) -> OversightGate:
    return OversightGate(
        oversight=OversightEngine(_banned_path_regulations()),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="mw:request",
        audit=sink,
    )


def test_asgi_scope_banned_path_is_hard_blocked_with_default_extractor() -> None:
    """REGRESSION: wired the documented ASGI way ``app(scope, receive, send)``, the
    default extractor used to do ``str(scope)`` (a dict repr) which never matches a
    ``*/대외비/*`` glob — so path HARD BLOCK silently never fired. The extractor must
    pull ``scope['path']`` so the banned request path blocks before the app runs."""
    sink = _RecordingSink()
    served: list[str] = []

    def asgi_app(scope: dict[str, object], receive: object, send: object) -> str:
        served.append(str(scope.get("path")))
        return "served"

    mw = OversightMiddleware(asgi_app, action_type="file_read", gate=_asgi_gate(sink))
    scope = {"type": "http", "path": "/srv/대외비/x", "headers": []}
    with pytest.raises(HardBlockException):
        mw(scope, object(), object())
    assert served == [], "ASGI app must not run when scope['path'] is banned"
    assert sink.events[-1]["decision"] == "reject"


def test_asgi_scope_benign_path_passes_with_default_extractor() -> None:
    """A benign ASGI request path passes and the extracted target is the real
    ``scope['path']`` (not a dict repr), emitting exactly one approve event."""
    sink = _RecordingSink()
    served: list[str] = []

    def asgi_app(scope: dict[str, object], receive: object, send: object) -> str:
        served.append(str(scope.get("path")))
        return "served"

    mw = OversightMiddleware(asgi_app, action_type="file_read", gate=_asgi_gate(sink))
    scope = {"type": "http", "path": "/srv/공개/notice", "headers": []}
    assert mw(scope, object(), object()) == "served"
    assert served == ["/srv/공개/notice"]
    assert len(sink.events) == 1
    assert sink.events[0]["decision"] == "approve"


def test_asgi_scope_without_path_fails_closed_for_path_action() -> None:
    """Fail-closed: an ASGI scope carrying NO usable path on a path/domain action
    must raise OversightConfigError (never silently skip the resource rule), so the
    downstream app does not run."""
    sink = _RecordingSink()
    served: list[str] = []

    def asgi_app(scope: dict[str, object], receive: object, send: object) -> str:
        served.append("ran")
        return "served"

    mw = OversightMiddleware(asgi_app, action_type="file_read", gate=_asgi_gate(sink))
    scope = {"type": "http", "headers": []}  # no 'path'
    with pytest.raises(OversightConfigError):
        mw(scope, object(), object())
    assert served == []


def test_asgi_scope_host_header_is_a_domain_candidate() -> None:
    """The ASGI Host header is surfaced as a domain candidate so http_get domain
    rules can match the real request host (not a dict repr)."""
    doc = {
        "version": "asgi-domain-1.0.0",
        "domain_policy": {"mode": "deny_list", "domains": ["evil.example"], "hard_block": True},
    }
    regulations = load_regulations_from_dict(doc, source="<asgi-domain-test>")
    sink = _RecordingSink()
    gate = OversightGate(
        oversight=OversightEngine(regulations),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="mw:request",
        audit=sink,
    )
    served: list[str] = []

    def asgi_app(scope: dict[str, object], receive: object, send: object) -> str:
        served.append("ran")
        return "served"

    mw = OversightMiddleware(asgi_app, action_type="http_get", gate=gate)
    scope = {"type": "http", "path": "/api", "headers": [(b"host", b"evil.example")]}
    with pytest.raises(HardBlockException):
        mw(scope, object(), object())
    assert served == []
