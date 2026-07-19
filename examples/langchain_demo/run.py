# SPDX-License-Identifier: Apache-2.0
"""LangChain demo — wrap a LangChain-style tool in SecuGent oversight (embed SDK).

Shows the OEM/embed premise (framework-neutral): an SI/vendor wraps THEIR
existing LangChain tool with the SecuGent embed SDK so a policy-violating tool call
is deterministically HARD BLOCKed before it runs — no API key, no network.

This example is **resilient to langchain being absent** so the smoke test stays
green either way:

* langchain installed  → a real :class:`SecuGentCallbackHandler` (subclass of
  langchain's ``BaseCallbackHandler``) blocks a violating tool via ``on_tool_start``.
* langchain absent     → prints the ``pip install secugent[langchain]`` hint, then
  demonstrates the SAME core block with a langchain-free wrapped tool (the embed
  SDK's :func:`wrap_langchain_tool`). The control verdict is identical — the only
  thing langchain adds is the callback plumbing, not the decision.

Exit code 0 when the forbidden tool call is blocked AND a compliant one passes;
non-0 (fail-closed) if the gate fails to block what it must.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import tempfile  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

from secugent.audit.hash_chain import ChainedEventStore  # noqa: E402
from secugent.core.contracts import HardBlockException  # noqa: E402
from secugent.core.event_store import EventStore  # noqa: E402
from secugent.core.mechanical_oversight import OversightEngine  # noqa: E402
from secugent.core.regulations import load_regulations_from_dict  # noqa: E402
from secugent.core.tenancy import TenantId  # noqa: E402
from secugent.orchestrator.adapters_langchain import (  # noqa: E402
    SecuGentCallbackHandler,
    build_handler_for_test,
    wrap_langchain_tool,
)
from secugent.sdk.gate import (  # noqa: E402
    ChainedEventStoreAuditSink,
    OversightBlocked,
    OversightGate,
)

_TENANT = TenantId("langchain-demo")
_RUN = "run_langchain_demo"


class _ConsoleSink:
    """Prints each decision-gate audit event the gate emits (audit visibility)."""

    def emit(self, event: dict[str, object]) -> None:
        print(f"[langchain_demo] 감사 이벤트: gate={event['gate']} decision={event['decision']}")


def _build_gate() -> OversightGate:
    """A Korean REGULATIONS doc that HARD-BLOCKs 대외비 (confidential) tool inputs."""
    doc = {
        "version": "langchain-demo-1.0.0",
        "banned_paths": [
            {
                "rule_id": "대외비-도구-차단",
                "pattern": "*/대외비/*",
                "actions": ["file_read", "file_write", "desktop"],
                "severity": "critical",
                "hard_block": True,
                "description": "대외비 디렉터리를 다루는 LangChain 툴 호출은 결정적으로 차단된다.",
            }
        ],
    }
    regulations = load_regulations_from_dict(doc, source="<langchain-demo>")
    return OversightGate(
        oversight=OversightEngine(regulations),
        tenant_id=_TENANT,
        run_id=_RUN,
        actor="langchain:file_tool",
        audit=_ConsoleSink(),
    )


def _langchain_available() -> bool:
    try:
        import langchain_core.callbacks  # noqa: F401

        return True
    except Exception:
        try:
            import langchain.callbacks.base  # noqa: F401

            return True
        except Exception:
            return False


def _demo_with_callback_handler(gate: OversightGate) -> bool:
    """Real-langchain path: a callback handler blocks a violating tool start."""
    print("[langchain_demo] LangChain 감지됨 — SecuGentCallbackHandler 로 툴 호출을 게이트합니다.")
    handler = SecuGentCallbackHandler(gate=gate, action_type="file_write")
    serialized = {"name": "file_writer"}
    try:
        handler.on_tool_start(serialized, "/srv/대외비/payroll.xlsx")
    except HardBlockException as exc:
        print(f"[langchain_demo] HARD BLOCK ✓ (위반 툴 호출 차단됨): {exc}")
        return True
    print("[langchain_demo] FAIL: 위반 툴 호출이 차단되지 않았습니다 (fail-closed)")
    return False


def _demo_without_langchain(gate: OversightGate) -> bool:
    """No-langchain path: the SAME core block via a wrapped tool callable."""
    print("[langchain_demo] LangChain 미설치 — 설치하려면: pip install secugent[langchain]")
    print("[langchain_demo] LangChain 없이도 동일한 코어 차단을 시연합니다 (wrap_langchain_tool).")

    def file_writer_tool(target: str) -> str:  # a stand-in LangChain tool .func
        return f"wrote {target}"

    wrapped = wrap_langchain_tool(file_writer_tool, action_type="file_write", gate=gate)
    try:
        wrapped("/srv/대외비/payroll.xlsx")
    except HardBlockException as exc:
        print(f"[langchain_demo] HARD BLOCK ✓ (위반 툴 호출 차단됨): {exc}")
        return True
    print("[langchain_demo] FAIL: 위반 툴 호출이 차단되지 않았습니다 (fail-closed)")
    return False


def _demo_compliant_passes(gate: OversightGate) -> bool:
    """A compliant tool call must pass the gate (uses the langchain-free handler)."""
    handler = build_handler_for_test(gate=gate, action_type="file_read")
    try:
        handler.on_tool_start({"name": "file_reader"}, "/srv/공개/notice.txt")
    except (HardBlockException, OversightBlocked) as exc:
        print(f"[langchain_demo] FAIL: 허용되어야 할 툴 호출이 차단되었습니다: {exc}")
        return False
    print("[langchain_demo] 허용 툴 호출 통과 ✓ (/srv/공개/notice.txt)")
    return True


def _demo_durable_audit_chain() -> bool:
    """Wire the production audit sink: a tamper-evident ChainedEventStore.

    Shows that SDK-emitted decision-gate events land in the durable, append-only
    hash chain (``verify_chain``) — not just a volatile in-memory sink — which is
    what the compliance requirements demand for 6-month, immutable, tamper-evident audit records.
    """
    regulations = load_regulations_from_dict(
        {"version": "langchain-demo-1.0.0", "banned_paths": []},
        source="<langchain-demo-audit>",
    )
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(_Path(tmp) / "events.db")
        chained = ChainedEventStore(store)
        gate = OversightGate(
            oversight=OversightEngine(regulations),
            tenant_id=_TENANT,
            run_id=_RUN,
            actor="langchain:file_tool",
            audit=ChainedEventStoreAuditSink(chained),
        )
        handler = build_handler_for_test(gate=gate, action_type="file_read")
        handler.on_tool_start({"name": "file_reader"}, "/srv/공개/a.txt")
        handler.on_tool_start({"name": "file_reader"}, "/srv/공개/b.txt")
        ok = chained.verify_chain(tenant_id=str(_TENANT))
        n = len(chained.read_chain(tenant_id=str(_TENANT)))
        chained.close()
    print(f"[langchain_demo] 내구성 감사체인 검증 ✓ (verify_chain={ok}, 이벤트 {n}건, 위변조 검출 가능)")
    return bool(ok) and n == 2


def main() -> int:
    gate = _build_gate()

    if _langchain_available():
        blocked = _demo_with_callback_handler(gate)
    else:
        blocked = _demo_without_langchain(gate)

    passed = _demo_compliant_passes(gate)
    durable = _demo_durable_audit_chain()

    if blocked and passed and durable:
        print("[langchain_demo] done — LangChain 툴 oversight 게이트 시연 완료.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
