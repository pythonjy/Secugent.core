# LangChain demo (embed SDK)

Wrap a **LangChain-style tool** in SecuGent oversight so a policy-violating tool
call is deterministically **HARD BLOCKed** before it runs. This is the
framework-neutral embed / OEM premise: an SI/vendor wraps *their* existing
LangChain agent/tool — SecuGent does not own their runtime.

```bash
python examples/langchain_demo/run.py   # exits 0, key-less, no network
```

The example runs **with or without** `langchain` installed:

- **langchain installed** → a real `SecuGentCallbackHandler` (subclass of
  langchain's `BaseCallbackHandler`) blocks a violating tool via `on_tool_start`.
- **langchain absent** → prints the `pip install secugent[langchain]` hint, then
  demonstrates the **same core block** with a langchain-free wrapped tool
  (`wrap_langchain_tool`). The control verdict is identical — langchain only adds
  the callback plumbing, never the decision (a single control source: the SDK never re-implements it).

## What it shows
- [x] A LangChain tool call routed through SecuGent **Mechanical Oversight**
      (REGULATIONS HARD BLOCK) before execution — `*/대외비/*` is denied.
- [x] A compliant tool call (`/srv/공개/notice.txt`) passes the gate.
- [x] Each decision emits a **structured audit event** (printed to the console here;
      production wires a `ChainedEventStore`-backed sink).
- [x] `pip install secugent[langchain]` optional extra (isolated; never a Core dep).

## The embed surface (Core, Apache-2.0)
```python
from secugent.sdk import require_oversight, OversightMiddleware, wrap_tool
from secugent.orchestrator.adapters_langchain import SecuGentCallbackHandler
```
`require_oversight` decorates any sync/async callable; `OversightMiddleware` gates
every request; `wrap_tool` gates a single tool. All call the one
`secugent.sdk.gate.OversightGate` — the SDK never re-implements control logic.
