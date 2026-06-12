# SPDX-License-Identifier: Apache-2.0
"""Quickstart example — a minimal SecuGent agent round, no API key, no network.

Run it directly::

    python examples/quickstart/run.py

It loads the sibling ``policy.json`` (a real REGULATIONS document), then runs the
built-in key-less demo round (REGULATIONS HARD BLOCK -> HITL approval -> audit).
The point is to prove the whole loop works with one command and zero setup; the
deterministic engine, approval service, and append-only hash-chained audit log
are the same ones the product enforces.

Exit code 0 on success (smoke-tested by ``tests/examples/test_examples_smoke.py``).
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# Make `secugent` importable when run from a source checkout (no `pip install`).
# A pip-installed `secugent` is found first; this only adds the repo root as a
# fallback so the example is never a dead example.
_REPO_ROOT = _HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from secugent.cli.demo import run_demo  # noqa: E402  (after sys.path bootstrap)
from secugent.core.regulations import load_regulations  # noqa: E402


def main() -> int:
    # Prove the policy file parses through the real loader (fail-closed on error).
    regulations = load_regulations(_HERE / "policy.json")
    print(f"[quickstart] loaded policy version: {regulations.version}")
    print(f"[quickstart] banned paths: {[bp.rule_id for bp in regulations.banned_paths]}")

    result = run_demo()
    print(f"[quickstart] {result.summary}")
    print("[quickstart] audit events:")
    for evt in result.audit_events:
        print(f"  - [{evt.gate}] {evt.decision} (event_id={evt.event_id}, prev={evt.prev_event_id})")
    print("[quickstart] done. inspect the chain with: secugent verify --chain ...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
