# SPDX-License-Identifier: Apache-2.0
"""``secugent`` CLI entry point — subcommand dispatcher.

Provides the read-only ``verify`` subcommand plus ``demo`` (key-less,
air-gap-first demo) and ``run`` (a minimal real agent round on the mock
client). Dispatch is a thin shim: the first positional token selects the
subcommand and the remaining argv is handed to that subcommand. Unknown or
absent subcommands fail closed with exit code 2.

The HTTP API server is part of the SecuGent Enterprise tier and is not
included in the open-core distribution. Use the Enterprise package for a
production server deployment.
"""

from __future__ import annotations

import sys

from secugent.cli.verify import _emit
from secugent.cli.verify import main as verify_main

__all__ = ["main"]

_USAGE = (
    "usage: secugent <run|demo|verify|evolution|migrate-store|backup|restore|"
    "rotate-secret|sign-policy-bundle> [options]"
)


def _run_demo_cli(rest: list[str]) -> int:
    """``secugent demo`` — run the key-less demo and print a decision-gate audit summary."""
    from secugent.cli.demo import run_demo

    result = run_demo()
    _emit(result.summary)
    for evt in result.audit_events:
        _emit(
            f"  - [{evt.gate}] {evt.decision} by {evt.actor['type']}:{evt.actor['id']} "
            f"(event_id={evt.event_id}, prev={evt.prev_event_id}, axes={evt.rule_of_two_axes})"
        )
    _emit("감사 이벤트는 append-only 해시체인에 기록되었습니다 (secugent verify --chain 으로 재현 가능).")
    return 0


def _run_agent_cli(rest: list[str]) -> int:
    """``secugent run "<goal>"`` — a minimal, key-less agent round (mock client).

    Reuses the demo engine so a first-time user sees the full block→approve→audit
    loop with a single command. The goal is echoed for context; the underlying
    deterministic gates are identical to the demo.
    """
    from secugent.cli.demo import run_demo

    goal = rest[0] if rest else "샘플 목표: 대외비 파일 접근 시도 + 외부 커넥터 호출"
    _emit(f"secugent run — 목표: {goal}")
    result = run_demo()
    _emit(result.summary)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch to a subcommand. Returns the subcommand's exit code.

    0 = success; non-0 = failure (fail-closed). Unknown/absent subcommand ⇒ 2.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        _emit(_USAGE, stderr=True)
        return 2

    command, rest = args[0], args[1:]
    if command == "verify":
        return verify_main(rest)
    if command == "demo":
        return _run_demo_cli(rest)
    if command == "run":
        return _run_agent_cli(rest)
    if command == "evolution":
        from secugent.cli.evolution import main as evolution_main

        return evolution_main(rest)
    if command == "migrate-store":
        from secugent.cli.migrate_store import main as migrate_store_main

        return migrate_store_main(rest)
    if command == "backup":
        from secugent.cli.backup import main as backup_main

        return backup_main(rest)
    if command == "restore":
        from secugent.cli.restore import main as restore_main

        return restore_main(rest)
    if command == "rotate-secret":
        from secugent.cli.rotate_secret import main as rotate_secret_main

        return rotate_secret_main(rest)
    if command == "sign-policy-bundle":
        from secugent.cli.sign_policy_bundle import main as sign_policy_bundle_main

        return sign_policy_bundle_main(rest)

    _emit(f"secugent: unknown subcommand {command!r}\n{_USAGE}", stderr=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
