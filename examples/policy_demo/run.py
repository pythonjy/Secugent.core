# SPDX-License-Identifier: Apache-2.0
"""Policy demo — a deterministic REGULATIONS HARD BLOCK with a Korean policy.

Run it directly::

    python examples/policy_demo/run.py

It loads the sibling Korean REGULATIONS document (``policy.ko.json``) and shows
the deterministic Mechanical Oversight engine HARD-BLOCKing a forbidden
``file_write`` to a 대외비 (confidential) directory, independent of any risk
score (§A-2.2 deny-by-default). No API key, no network.

Exit code 0 if the forbidden step is blocked AND an allowed step passes; non-0
(fail-closed) if the engine fails to block what it must.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# Make `secugent` importable when run from a source checkout (no `pip install`).
_REPO_ROOT = _HERE.parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from secugent.core.contracts import ActionType, Step  # noqa: E402  (after sys.path bootstrap)
from secugent.core.mechanical_oversight import OversightEngine  # noqa: E402
from secugent.core.regulations import load_regulations  # noqa: E402
from secugent.core.tenancy import TenantId  # noqa: E402

_TENANT = TenantId("policy-demo")


def _step(action: ActionType, target: str) -> Step:
    return Step(
        tenant_id=_TENANT,
        run_id="run_policy_demo",
        actor="sub:demo",
        action_type=action,
        target=target,
    )


def main() -> int:
    regulations = load_regulations(_HERE / "policy.ko.json")
    engine = OversightEngine(regulations)
    print(f"[policy_demo] 정책 버전: {regulations.version}")

    forbidden = _step("file_write", "/srv/대외비/급여명세서.xlsx")
    blocked = engine.evaluate(forbidden)
    if not (blocked.hard_block and blocked.violation is not None):
        print("[policy_demo] FAIL: 금지된 단계가 차단되지 않았습니다 (fail-closed)")
        return 1
    print(
        f"[policy_demo] HARD BLOCK ✓ rule_id={blocked.violation.rule_id} 메시지={blocked.violation.message}"
    )

    allowed = _step("file_read", "/srv/공개/notice.txt")
    ok = engine.evaluate(allowed)
    if not ok.allowed:
        print("[policy_demo] FAIL: 허용되어야 할 단계가 차단되었습니다")
        return 1
    print("[policy_demo] 허용 단계 통과 ✓ (/srv/공개/notice.txt)")
    print("[policy_demo] done — REGULATIONS HARD BLOCK 결정성 시연 완료.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
