# Quickstart example

The smallest possible SecuGent run: **no API key, no network** (mock mode,
air-gap first).

```bash
# from the repo root (after `pip install .`)
python examples/quickstart/run.py
# ...or, equivalently, the installed CLI:
secugent demo
```

What it does, in one round:

1. Loads `policy.json` (a real REGULATIONS document) through the production loader.
2. Runs the key-less demo: a forbidden `file_write` is **HARD BLOCKED** by the
   deterministic Mechanical Oversight engine, then a 3-axis (Rule of Two) step is
   gated through a **step-dedicated HITL approval**.
3. Writes every decision to an **append-only, hash-chained audit log** (audit-log
   schema) and prints a summary.

## Files
- `policy.json` — a minimal REGULATIONS document (banned path + egress allow-list).
- `run.py` — the runnable script (exit 0 on success).

## Verify the audit chain
The demo writes to a throw-away temp store. To verify a persistent store you
own, use the read-only proof CLI:

```bash
secugent verify --chain --tenant <tenant> --store <path-to.db>
```
