# SPDX-License-Identifier: Apache-2.0
"""Tests for ``secugent demo`` / ``run_demo``.

Layers (multi-layer test strategy):

* unit — ``run_demo()`` yields >=1 HARD BLOCK + >=1 HITL approval + N audit
  events; every audit event satisfies the C-2 schema (I2); the demo writes a
  verifiable append-only hash chain.
* integration — invoke ``secugent demo`` as a subprocess (no API key / no
  network, I1) and assert exit 0 + an audit summary on stdout.
* determinism — a fixed-seed demo produces byte-identical output across runs.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secugent.cli.demo import (
    C2_REQUIRED_FIELDS,
    DemoAuditEvent,
    DemoResult,
    run_demo,
)

# --------------------------------------------------------------------------- #
# unit
# --------------------------------------------------------------------------- #


def test_run_demo_blocks_and_approves_and_audits() -> None:
    """One round: >=1 HARD BLOCK, >=1 HITL approval, >=1 audit event."""
    result = run_demo()
    assert isinstance(result, DemoResult)
    assert len(result.blocked) >= 1
    assert len(result.approvals) >= 1
    assert len(result.audit_events) >= 1
    assert result.summary  # non-empty stdout summary


def test_audit_events_satisfy_c2_schema() -> None:
    """I2 — every demo audit event carries the full C-2 decision-gate schema."""
    result = run_demo()
    for evt in result.audit_events:
        assert isinstance(evt, DemoAuditEvent)
        as_dict = dataclasses.asdict(evt)
        for field in C2_REQUIRED_FIELDS:
            assert field in as_dict, f"missing C-2 field {field!r}"
        # actor is a {type,id} object (C-2).
        assert set(evt.actor) == {"type", "id"}
        assert evt.actor["type"] in {"human", "head", "sub", "sec", "evo"}
        # gate is one of the C-2 decision gates.
        assert evt.gate in {"plan_review", "hitl", "steer", "evolution_approval"}
        # decision is one of the C-2 decisions.
        assert evt.decision in {"approve", "reject", "partial", "modify"}
        # rule_of_two_axes uses the canonical tokens only.
        for axis in evt.rule_of_two_axes:
            assert axis in {"untrusted_input", "sensitive_access", "external_comm"}
        assert 0 <= evt.risk_score <= 100


def test_audit_events_form_prev_event_hash_chain() -> None:
    """I2 — prev_event_id links each event to its predecessor (genesis prev=None)."""
    result = run_demo()
    assert result.audit_events[0].prev_event_id is None
    for earlier, later in itertools.pairwise(result.audit_events):
        assert later.prev_event_id == earlier.event_id


def test_demo_records_a_hard_block_decision() -> None:
    """A REGULATIONS HARD BLOCK must surface as a reject decision in the audit."""
    result = run_demo()
    rejects = [e for e in result.audit_events if e.decision == "reject"]
    assert rejects, "expected at least one reject (HARD BLOCK) audit event"
    assert any(e.gate == "plan_review" for e in rejects)


def test_emit_audit_false_suppresses_events() -> None:
    result = run_demo(emit_audit=False)
    assert result.audit_events == []
    # The block + approval still happen (the demo still exercises the engine).
    assert result.blocked and result.approvals


def test_demo_writes_a_verifiable_hash_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """I2 — the durable audit log the demo writes is an intact hash chain.

    ``run_demo`` writes to a throw-away temp store it then deletes; we redirect
    that to a stable dir and assert the wrapped ``ChainedEventStore.verify_chain``
    holds for the demo tenant (the same proof ``secugent verify --chain`` runs).
    """
    import secugent.cli.demo as demo_mod
    from secugent.audit.hash_chain import ChainedEventStore
    from secugent.core.event_store import EventStore

    store_dir = tmp_path / "demo-store"
    store_dir.mkdir()
    monkeypatch.setattr(demo_mod.tempfile, "mkdtemp", lambda *a, **k: str(store_dir))
    monkeypatch.setattr(demo_mod.shutil, "rmtree", lambda *a, **k: None)  # keep the store

    result = run_demo()
    assert result.audit_events  # something was written

    inner = EventStore(store_dir / "demo.db")
    chained = ChainedEventStore(inner)
    try:
        assert chained.verify_chain(tenant_id="demo-tenant") is True
    finally:
        chained.close()


# --------------------------------------------------------------------------- #
# determinism (fixed seed → identical output)
# --------------------------------------------------------------------------- #


def _canonical(result: DemoResult) -> str:
    return json.dumps(
        {
            "blocked": result.blocked,
            "approvals": result.approvals,
            "audit_events": [dataclasses.asdict(e) for e in result.audit_events],
            "summary": result.summary,
        },
        sort_keys=True,
        ensure_ascii=False,
    )


def test_run_demo_is_deterministic_across_runs() -> None:
    """Fixed-seed mock demo → byte-identical output (determinism)."""
    first = _canonical(run_demo())
    for _ in range(5):
        assert _canonical(run_demo()) == first


def test_run_demo_korean_rationale_present() -> None:
    """C-3 — at least one audit rationale is Korean (default language KST)."""
    result = run_demo()
    assert any(any("가" <= ch <= "힣" for ch in e.rationale) for e in result.audit_events)


# --------------------------------------------------------------------------- #
# integration — subprocess, no API key / no network (I1)
# --------------------------------------------------------------------------- #


def _demo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)  # I1: prove it works key-less
    env.pop("SECUGENT_ENV", None)
    env["PYTHONUTF8"] = "1"  # avoid cp949 encode crash on Korean output
    return env


def test_demo_subprocess_exit_zero_with_summary() -> None:
    """Integration: `python -m secugent.cli demo` exits 0 and prints a summary."""
    repo_root = Path(__file__).resolve().parents[2]
    proc = subprocess.run(  # noqa: S603  — args are sys.executable + a fixed module token, not untrusted input
        [sys.executable, "-m", "secugent.cli", "demo"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_demo_env(),
        cwd=str(repo_root),
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "HARD BLOCK" in proc.stdout or "차단" in proc.stdout
    assert "HITL" in proc.stdout or "승인" in proc.stdout


def test_unknown_subcommand_fails_closed() -> None:
    from secugent.cli.__main__ import main

    assert main(["frobnicate"]) == 2


def test_no_subcommand_fails_closed() -> None:
    from secugent.cli.__main__ import main

    assert main([]) == 2


def test_run_subcommand_executes_keyless() -> None:
    from secugent.cli.__main__ import main

    assert main(["run", "데모 목표"]) == 0
