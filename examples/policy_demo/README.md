# Policy demo (Korean REGULATIONS HARD BLOCK)

Shows the **deterministic** Mechanical Oversight engine HARD-BLOCKing a forbidden
action against a Korean policy — independent of any risk score (§A-2.2
deny-by-default). No API key, no network.

```bash
python examples/policy_demo/run.py
```

What it does:

1. Loads `policy.ko.json` — a Korean REGULATIONS document (대외비/개인정보 banned
   paths + a banned root-delete command).
2. Submits a forbidden `file_write` to `/srv/대외비/...` → **HARD BLOCK** (the
   engine returns `hard_block=True` with the matching `rule_id`).
3. Submits an allowed read to a public path → passes.
4. Exits non-zero (fail-closed) if the engine ever fails to block what it must.

## Files
- `policy.ko.json` — Korean REGULATIONS fixture (§C-3 Korean-enterprise context).
- `run.py` — runnable script (exit 0 on success).

## Why this matters
A clearly-forbidden action can never be "scored down" by a probabilistic stage:
Mechanical Oversight runs first and blocks deterministically. Same input → same
output, every time.
