# SPDX-License-Identifier: Apache-2.0
"""Deterministic TRIPLE for the read-only ``secugent verify`` CLI (BDP item 2).

Layers (CLAUDE.md §B-4a — this exercises the DETERMINISTIC verification path):

* unit — valid fixture -> ok=True; a single-bit tamper of a chained event -> ok=False
  with ``first_violation`` set (I3); read-only invariant (I1); empty-chain edge.
* property (hypothesis) — for a random valid event sequence, append-then-verify is
  always True (roundtrip), and a single-byte tamper is always detected.
* scenario regression — re-run over a checked-in audit fixture (incl. a Korean-labeled
  one) so a policy/crypto regression trips here.
* determinism 100x — ``verify_determinism(samples=100)`` -> ``distinct_outputs == 1`` (I2).
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.audit.hash_chain import ChainedEventStore
from secugent.cli.verify import (
    ChainReport,
    DeterminismReport,
    VerifyInputError,
    main,
    verify_audit_chain,
    verify_determinism,
)
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

T_A = TenantId("acme")


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def _event(idx: int, tenant: TenantId = T_A) -> Event:
    return Event(
        tenant_id=tenant,
        actor=f"sub:{idx}",
        type="step.completed",
        run_id=f"r{idx}",
        payload={"i": idx, "note": f"이벤트 {idx}"},  # Korean label (C-3)
    )


def _build_store(db: Path, *, n: int, tenant: TenantId = T_A) -> None:
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(n):
            chained.append_event(_event(i, tenant))
    finally:
        chained.close()


def _determinism_fixture(tmp_path: Path) -> Path:
    """A small deterministic-path fixture: regulations + a few steps.

    Includes a Korean-labeled banned path (C-3) and a step exercising each
    Rule-of-Two axis so classify_axes + oversight cover real branches.
    """
    fixture = {
        "regulations": {
            "version": "verify-fixture-1.0.0",
            "banned_paths": [
                {
                    "rule_id": "대외비-차단",  # Korean rule id (C-3)
                    "pattern": "*/대외비/*",
                    "actions": ["file_read", "file_write", "desktop"],
                    "severity": "critical",
                    "hard_block": True,
                    "description": "대외비 디렉터리는 접근 불가.",
                }
            ],
            "domain_policy": {
                "rule_id": "default-domain-policy",
                "mode": "allow_list",
                "domains": ["example.com"],
                "allow_subdomains": True,
                "block_ip_literal": True,
                "block_punycode": True,
                "hard_block": True,
            },
            "banned_commands": [],
            "data_labels": [],
        },
        "steps": [
            {
                "step": {
                    "tenant_id": "acme",
                    "run_id": "r0",
                    "actor": "sub:reader",
                    "action_type": "file_read",
                    "target": "/data/대외비/report.txt",
                    "context": {"sensitive": True},
                }
            },
            {
                "step": {
                    "tenant_id": "acme",
                    "run_id": "r1",
                    "actor": "sub:web",
                    "action_type": "http_get",
                    "target": "https://example.com/ok",
                    "context": {"untrusted_input": True},
                }
            },
            {
                "step": {
                    "tenant_id": "acme",
                    "run_id": "r2",
                    "actor": "sub:writer",
                    "action_type": "file_write",
                    "target": "/data/work/out.txt",
                    "context": {"untrusted_input": True, "sensitive": True},
                }
            },
        ],
    }
    path = tmp_path / "det_fixture.json"
    path.write_text(json.dumps(fixture, ensure_ascii=False), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# (a) unit
# --------------------------------------------------------------------------- #


def test_chain_verify_ok_on_intact(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=4)
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert isinstance(report, ChainReport)
    assert report.ok is True
    assert report.events_checked == 4
    assert report.first_violation is None
    assert report.empty is False


def test_chain_verify_single_bit_tamper_detected(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=5)
    # Tamper one chained event's underlying payload.
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET payload=? WHERE run_id='r2'", (json.dumps({"i": 999}),))
    conn.commit()
    conn.close()

    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None  # I3 — explicit first-violation location


def test_chain_verify_empty_chain_ok_with_flag(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=0)  # creates the schema, no events
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is True
    assert report.empty is True
    assert report.events_checked == 0


def test_chain_verify_missing_store_raises_input_error(tmp_path: Path) -> None:
    with pytest.raises(VerifyInputError):
        verify_audit_chain(tenant_id=str(T_A), store_path=tmp_path / "nope.db")


def test_verify_is_read_only(tmp_path: Path) -> None:
    """I1 — verify must not mutate the store file (byte-identical after)."""
    db = tmp_path / "c.db"
    _build_store(db, n=4)
    before = db.read_bytes()
    verify_audit_chain(tenant_id=str(T_A), store_path=db)
    after = db.read_bytes()
    assert before == after


def test_determinism_ok_on_valid_fixture(tmp_path: Path) -> None:
    fixture = _determinism_fixture(tmp_path)
    report = verify_determinism(samples=8, seed_fixture=fixture)
    assert isinstance(report, DeterminismReport)
    assert report.ok is True
    assert report.distinct_outputs == 1
    assert report.first_divergence is None
    assert report.samples == 8


def test_determinism_corrupt_fixture_raises_input_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(VerifyInputError):
        verify_determinism(samples=4, seed_fixture=bad)


def test_determinism_zero_samples_raises(tmp_path: Path) -> None:
    fixture = _determinism_fixture(tmp_path)
    with pytest.raises(VerifyInputError):
        verify_determinism(samples=0, seed_fixture=fixture)


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ('{"steps": []}', "regulations"),  # missing regulations
        ('{"regulations": {"version": "v"}}', "steps"),  # missing steps
        ('{"regulations": {"version": "v"}, "steps": [{}]}', "step"),  # entry w/o step
        ("[1, 2, 3]", "must be a JSON object"),  # not an object at top level
    ],
)
def test_determinism_malformed_fixture_shapes_raise(tmp_path: Path, payload: str, match: str) -> None:
    bad = tmp_path / "shape.json"
    bad.write_text(payload, encoding="utf-8")
    with pytest.raises(VerifyInputError, match=match):
        verify_determinism(samples=2, seed_fixture=bad)


def test_determinism_invalid_step_raises(tmp_path: Path) -> None:
    bad = tmp_path / "step.json"
    bad.write_text(
        json.dumps(
            {
                "regulations": {"version": "v"},
                "steps": [{"step": {"action_type": "file_read"}}],  # missing required fields
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(VerifyInputError, match="invalid"):
        verify_determinism(samples=2, seed_fixture=bad)


def test_determinism_invalid_regulations_raises(tmp_path: Path) -> None:
    bad = tmp_path / "regs.json"
    bad.write_text(
        json.dumps({"regulations": {"banned_paths": "not-a-list"}, "steps": []}),
        encoding="utf-8",
    )
    with pytest.raises(VerifyInputError):
        verify_determinism(samples=2, seed_fixture=bad)


def test_determinism_unreadable_fixture_raises(tmp_path: Path) -> None:
    with pytest.raises(VerifyInputError, match="cannot read"):
        verify_determinism(samples=2, seed_fixture=tmp_path / "missing.json")


def test_main_chain_success_returns_zero(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    rc = main(["verify", "--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc == 0


def test_main_chain_tamper_returns_nonzero(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET payload=? WHERE run_id='r1'", (json.dumps({"i": -1}),))
    conn.commit()
    conn.close()
    rc = main(["verify", "--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc != 0  # I3 fail-closed


def test_main_determinism_success_returns_zero(tmp_path: Path) -> None:
    fixture = _determinism_fixture(tmp_path)
    rc = main(["verify", "--determinism", "--fixture", str(fixture), "--samples", "10"])
    assert rc == 0


def test_main_missing_inputs_returns_nonzero(tmp_path: Path) -> None:
    # --chain requested but no store path provided -> input error -> non-0.
    rc = main(["verify", "--chain", "--tenant", str(T_A)])
    assert rc != 0


def test_main_multitenant_isolation(tmp_path: Path) -> None:
    """Verifying tenant B does not read tenant A's events (no cross leakage)."""
    db = tmp_path / "c.db"
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(3):
            chained.append_event(_event(i, T_A))
    finally:
        chained.close()
    report = verify_audit_chain(tenant_id="contoso", store_path=db)
    assert report.ok is True
    assert report.events_checked == 0  # tenant B sees none of A's chain


def test_main_both_proofs_default_when_no_flag(tmp_path: Path) -> None:
    """No --determinism/--chain ⇒ run BOTH; success ⇒ exit 0."""
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    fixture = _determinism_fixture(tmp_path)
    rc = main(
        [
            "verify",
            "--tenant",
            str(T_A),
            "--store",
            str(db),
            "--fixture",
            str(fixture),
            "--samples",
            "5",
        ]
    )
    assert rc == 0


def test_main_empty_chain_prints_warning_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=0)
    rc = main(["verify", "--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "EMPTY" in out


def test_main_determinism_corrupt_fixture_returns_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    rc = main(["verify", "--determinism", "--fixture", str(bad)])
    assert rc != 0


def test_main_determinism_without_fixture_returns_nonzero() -> None:
    rc = main(["verify", "--determinism"])
    assert rc != 0


def test_main_no_inputs_fails_closed() -> None:
    # default mode (both) with neither set of inputs ⇒ both report missing inputs
    # ⇒ non-0 (fail-closed; never a silent exit 0).
    rc = main(["verify"])
    assert rc != 0


def test_main_accepts_argv_without_verify_token(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=2)
    rc = main(["--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc == 0


def test_chain_missing_event_chain_table_raises(tmp_path: Path) -> None:
    """A plain SQLite DB with no event_chain table is an operator error."""
    db = tmp_path / "plain.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE foo (x INTEGER)")
    conn.commit()
    conn.close()
    with pytest.raises(VerifyInputError, match="event_chain"):
        verify_audit_chain(tenant_id=str(T_A), store_path=db)


def test_chain_prev_hash_break_detected(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM event_chain WHERE seq=0")
    conn.commit()
    conn.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None
    assert "prev_hash mismatch" in report.first_violation


def test_chain_record_tamper_detected(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    conn = sqlite3.connect(db)
    row = conn.execute("SELECT body_canonical FROM event_chain WHERE seq=1").fetchone()
    body = json.loads(row[0])
    body["payload"] = {"i": 424242}  # valid Event shape, different content
    conn.execute(
        "UPDATE event_chain SET body_canonical=? WHERE seq=1",
        (json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")),),
    )
    conn.commit()
    conn.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None
    assert "chain record tampered" in report.first_violation


def test_chain_event_missing_from_store_detected(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM events WHERE run_id='r1'")
    conn.commit()
    conn.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None
    assert "missing from store" in report.first_violation


def test_chain_corrupt_body_detected(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    _build_store(db, n=3)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE event_chain SET body_canonical='{not json' WHERE seq=1")
    conn.commit()
    conn.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None
    assert "corrupt" in report.first_violation


def test_chain_unparseable_stored_event_raises(tmp_path: Path) -> None:
    """A stored event row whose ts is non-ISO is an operator-grade input error."""
    db = tmp_path / "c.db"
    _build_store(db, n=2)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE events SET ts='not-a-timestamp' WHERE run_id='r0'")
    conn.commit()
    conn.close()
    with pytest.raises(VerifyInputError, match="unparseable"):
        verify_audit_chain(tenant_id=str(T_A), store_path=db)


def test_determinism_divergence_sets_ok_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the path were non-deterministic, ok=False + first_divergence set (I2).

    The engine is genuinely deterministic, so we inject divergence to prove the
    detector (not the engine) behaves correctly.
    """
    import secugent.cli.verify as verify_mod

    fixture = _determinism_fixture(tmp_path)
    seq = iter(["A", "B", "B", "B"])

    def _fake(_: dict[str, object]) -> str:
        return next(seq)

    monkeypatch.setattr(verify_mod, "_canonical_decisions", _fake)
    report = verify_determinism(samples=4, seed_fixture=fixture)
    assert report.ok is False
    assert report.distinct_outputs == 2
    assert report.first_divergence is not None


def test_main_determinism_failure_returns_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import secugent.cli.verify as verify_mod

    fixture = _determinism_fixture(tmp_path)
    seq = iter(["X", "Y", "Y"])
    monkeypatch.setattr(verify_mod, "_canonical_decisions", lambda _: next(seq))
    rc = main(["verify", "--determinism", "--fixture", str(fixture), "--samples", "3"])
    assert rc != 0


def test_main_chain_input_error_returns_nonzero(tmp_path: Path) -> None:
    """CLI surfaces a chain VerifyInputError (no event_chain table) as non-0."""
    db = tmp_path / "plain.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE foo (x INTEGER)")
    conn.commit()
    conn.close()
    rc = main(["verify", "--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc != 0


def test_main_bad_usage_returns_nonzero() -> None:
    """argparse rejects an unknown flag; main preserves fail-closed exit."""
    rc = main(["verify", "--no-such-flag"])
    assert rc != 0


# --------------------------------------------------------------------------- #
# dispatcher (__main__)
# --------------------------------------------------------------------------- #


def test_dispatcher_verify_routes_to_verify(tmp_path: Path) -> None:
    from secugent.cli.__main__ import main as dispatch

    db = tmp_path / "c.db"
    _build_store(db, n=2)
    rc = dispatch(["verify", "--chain", "--tenant", str(T_A), "--store", str(db)])
    assert rc == 0


def test_dispatcher_no_args_returns_two() -> None:
    from secugent.cli.__main__ import main as dispatch

    assert dispatch([]) == 2


def test_dispatcher_run_and_demo_implemented_in_item3() -> None:
    # BDP Phase 1 item 3 implements the previously-reserved run/demo subcommands;
    # both now succeed key-less (mock mode). See tests/cli/test_demo.py for depth.
    from secugent.cli.__main__ import main as dispatch

    assert dispatch(["demo"]) == 0
    assert dispatch(["run", "데모 목표"]) == 0


def test_dispatcher_unknown_subcommand_returns_two() -> None:
    from secugent.cli.__main__ import main as dispatch

    assert dispatch(["bogus"]) == 2


def test_cli_output_survives_non_utf8_console(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: a Korean tenant id printed to a cp949 stdout must NOT crash.

    The deployment target includes Korean Windows hosts whose console codec is
    cp949 and cannot encode every char a tenant id may contain. A bare ``print``
    raised UnicodeEncodeError mid-proof; ``_emit`` must encode safely instead.
    """
    import io

    db = tmp_path / "kr.db"
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(2):
            chained.append_event(
                Event(
                    tenant_id=TenantId("financial-kr"),
                    actor="head:planner",
                    type="approval.granted",
                    run_id=f"배포-{i}",
                    payload={"메모": "한국어"},
                )
            )
    finally:
        chained.close()

    # A stdout whose codec cannot represent the em-dash/escape path.
    cp949_stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp949")
    monkeypatch.setattr(sys, "stdout", cp949_stdout)
    # Must not raise UnicodeEncodeError and must still succeed (exit 0).
    rc = main(["verify", "--chain", "--tenant", "financial-kr", "--store", str(db)])
    assert rc == 0


# --------------------------------------------------------------------------- #
# (b) property (hypothesis)
# --------------------------------------------------------------------------- #


@settings(max_examples=40, deadline=None)
@given(
    payloads=st.lists(
        st.dictionaries(
            keys=st.text(min_size=1, max_size=10),
            values=st.one_of(st.text(max_size=30), st.integers(), st.booleans(), st.none()),
            max_size=4,
        ),
        min_size=1,
        max_size=6,
    ),
)
def test_property_append_then_verify_always_true(
    tmp_path_factory: pytest.TempPathFactory, payloads: list[dict[str, object]]
) -> None:
    db = tmp_path_factory.mktemp("verify") / "c.db"
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i, payload in enumerate(payloads):
            chained.append_event(
                Event(
                    tenant_id=T_A,
                    actor=f"sub:{i}",
                    type="step.completed",
                    run_id=f"r{i}",
                    payload=payload,
                )
            )
    finally:
        chained.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is True
    assert report.events_checked == len(payloads)


@settings(max_examples=30, deadline=None)
@given(n=st.integers(min_value=2, max_value=6), victim=st.integers(min_value=0, max_value=5))
def test_property_single_byte_tamper_always_detected(
    tmp_path_factory: pytest.TempPathFactory, n: int, victim: int
) -> None:
    target = victim % n
    db = tmp_path_factory.mktemp("verify") / "c.db"
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(n):
            chained.append_event(_event(i))
    finally:
        chained.close()
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE events SET payload=? WHERE run_id=?",
        (json.dumps({"i": 10_000 + target}), f"r{target}"),
    )
    conn.commit()
    conn.close()
    report = verify_audit_chain(tenant_id=str(T_A), store_path=db)
    assert report.ok is False
    assert report.first_violation is not None


# --------------------------------------------------------------------------- #
# (c) determinism 100x (I2)
# --------------------------------------------------------------------------- #


def test_determinism_100x(tmp_path: Path) -> None:
    fixture = _determinism_fixture(tmp_path)
    report = verify_determinism(samples=100, seed_fixture=fixture)
    assert report.ok is True
    assert report.samples == 100
    assert report.distinct_outputs == 1
    assert report.first_divergence is None


def test_determinism_report_is_stable_across_calls(tmp_path: Path) -> None:
    """The whole report (incl. output_digest) is identical across two calls —
    this is the property the CI determinism-reproduction job asserts."""
    fixture = _determinism_fixture(tmp_path)
    r1 = verify_determinism(samples=50, seed_fixture=fixture)
    r2 = verify_determinism(samples=50, seed_fixture=fixture)
    assert r1 == r2


# --------------------------------------------------------------------------- #
# (d) scenario regression — Korean-labeled checked-in chain
# --------------------------------------------------------------------------- #


def test_scenario_regression_korean_chain(tmp_path: Path) -> None:
    """A multi-event Korean-payload chain verifies, and verify is deterministic
    100x over it (scenario regression for the audit path)."""
    db = tmp_path / "kr.db"
    inner = EventStore(db)
    chained = ChainedEventStore(inner)
    try:
        for i in range(6):
            chained.append_event(
                Event(
                    tenant_id=TenantId("financial-kr"),
                    actor="head:planner",
                    type="approval.granted",
                    run_id=f"배포-{i}",
                    payload={"메모": f"한국어 감사 이벤트 {i}", "차수": i},
                )
            )
    finally:
        chained.close()
    reports = {verify_audit_chain(tenant_id="financial-kr", store_path=db) for _ in range(100)}
    assert len(reports) == 1  # deterministic
    only = next(iter(reports))
    assert only.ok is True
    assert only.events_checked == 6
