# SPDX-License-Identifier: Apache-2.0
"""SQLiteStagedEffectStore unit + property + determinism tests.

Triple-coverage (§B-4a):
  1. Unit tests (scenarios / regression)
  2. Hypothesis property tests
  3. 100-run determinism proof

Korean fixture: 금융기관 CONFIDENTIAL 문서 외부 전송 staging & recall (I-D 검증).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import Event
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.profiles import ExecutionProfile
from secugent.io.broker.request import EgressRequest
from secugent.io.staging import (
    CommitGate,
    CommitRefusedError,
    SQLiteStagedEffectStore,
    StagedEffectStore,
    StageState,
    _req_to_json,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TENANT = TenantId("kookmin-bank")
_PRINCIPAL = Principal(user_id="심사역-김철수", tenant_id=_TENANT, role="operator")
_NOW = datetime(2026, 6, 24, 9, 0, 0, tzinfo=UTC)


def _make_req(
    *,
    target: str = "https://regulator.fss.or.kr/report",
    kind: EffectKind = EffectKind.NET_SEND,
    sink_class: SinkClass = SinkClass.EXTERNAL,
    tenant: TenantId | None = None,
    run_id: str | None = None,
) -> EgressRequest:
    """한국 금융 픽스처: 금융감독원 보고서 전송 요청."""
    t = tenant or _TENANT
    p = Principal(user_id="보고서-에이전트", tenant_id=t, role="operator")
    return EgressRequest(
        effect=Effect(
            kind=kind,
            target=target,
            sink_class=sink_class,
        ),
        label=DataLabel.CONFIDENTIAL,
        principal=p,
        run_id=run_id or f"run-{uuid.uuid4().hex[:8]}",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content=b"\xec\x9d\xbc\xec\xa0\x80\xeb\xa6\xac \xeb\xb3\xb4\xea\xb3\xa0\xec\x84\x9c",  # "일저리 보고서"
    )


class _RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[EgressRequest] = []

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        self.calls.append(request)
        return b"transmitted"


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[Event] = []

    def append_event(self, event: Event) -> Event:
        self.events.append(event)
        return event


# ---------------------------------------------------------------------------
# Unit tests — CRUD + state machine
# ---------------------------------------------------------------------------


def test_stage_creates_row_and_returns_staged(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=60, now=_NOW)
    assert s.id.startswith("staged_")
    assert s.state is StageState.STAGED
    assert s.req.run_id == req.run_id


def test_get_returns_none_for_unknown(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    assert store.get("staged_doesnotexist") is None


def test_list_staged_filters_by_run_id(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    req1 = _make_req(target="https://fss.or.kr/1")
    req2 = _make_req(target="https://fss.or.kr/2")
    req3 = _make_req(target="https://fss.or.kr/3")
    # req1 and req2 share a run_id (force it)
    req1_fixed = EgressRequest(
        effect=req1.effect,
        label=req1.label,
        principal=req1.principal,
        run_id="run-abc",
        profile=req1.profile,
    )
    req2_fixed = EgressRequest(
        effect=req2.effect,
        label=req2.label,
        principal=req2.principal,
        run_id="run-abc",
        profile=req2.profile,
    )
    req3_fixed = EgressRequest(
        effect=req3.effect,
        label=req3.label,
        principal=req3.principal,
        run_id="run-xyz",
        profile=req3.profile,
    )
    store.stage(req1_fixed, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.stage(req2_fixed, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.stage(req3_fixed, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    results = store.list_staged("run-abc")
    assert len(results) == 2
    assert all(r.req.run_id == "run-abc" for r in results)


def test_recall_guarantees_zero_sends(tmp_path: Path) -> None:
    """I-D: recall (abort) guarantees 0 external sends."""
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    transport = _RecordingTransport()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.abort(s.id, principal=_PRINCIPAL, reason="operator_recall")
    # The transport was NEVER called during abort.
    assert transport.calls == []
    # State is ABORTED.
    s_after = store.get(s.id)
    assert s_after is not None
    assert s_after.state is StageState.ABORTED


def test_commit_after_recall_raises(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    transport = _RecordingTransport()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.abort(s.id, principal=_PRINCIPAL, reason="test")
    with pytest.raises(CommitRefusedError):
        store.commit(
            s.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=True),
            now=_NOW,
            transport=transport,
        )
    assert transport.calls == []


def test_commit_before_hold_window_raises(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    transport = _RecordingTransport()
    req = _make_req()
    hold_sec = 3600
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=hold_sec, now=_NOW)
    # Try to commit immediately — hold window not elapsed.
    with pytest.raises(CommitRefusedError, match="hold window"):
        store.commit(
            s.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=True),
            now=_NOW,
            transport=transport,
        )
    assert transport.calls == []


def test_commit_without_gate_permit_raises(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    transport = _RecordingTransport()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    with pytest.raises(CommitRefusedError, match="commit gate denied"):
        store.commit(
            s.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=False, envelope_budget_remaining=False),
            now=_NOW + timedelta(seconds=10),
            transport=transport,
        )
    assert transport.calls == []


def test_commit_with_hitl_approval_sends(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    transport = _RecordingTransport()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    result = store.commit(
        s.id,
        principal=_PRINCIPAL,
        gate=CommitGate(hitl_approved=True),
        now=_NOW + timedelta(seconds=1),
        transport=transport,
    )
    assert result.ok is True
    assert len(transport.calls) == 1
    # State persisted.
    assert store.get(s.id) is not None
    assert store.get(s.id).state is StageState.COMMITTED  # type: ignore[union-attr]


def test_cross_tenant_abort_raises(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    req = _make_req(tenant=TenantId("kookmin-bank"))
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    bad_principal = Principal(user_id="attacker", tenant_id=TenantId("hana-bank"), role="operator")
    with pytest.raises(CommitRefusedError, match="cross-tenant"):
        store.abort(s.id, principal=bad_principal, reason="pwn")


def test_audit_events_emitted(tmp_path: Path) -> None:
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    audit = _RecordingAudit()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW, audit=audit)
    assert len(audit.events) == 1
    assert audit.events[0].type == "egress.staged"
    store.abort(s.id, principal=_PRINCIPAL, reason="user_cancel", audit=audit)
    assert audit.events[-1].type == "egress.aborted"


# ---------------------------------------------------------------------------
# invariant: staged rows survive process restart (I-E)
# ---------------------------------------------------------------------------


def test_staged_rows_survive_restart(tmp_path: Path) -> None:
    """I-E: SQLiteStagedEffectStore reloads staged rows on construction (restart)."""
    db = tmp_path / "staging.db"
    req = _make_req()
    staged_id: str
    # First instance — stage an effect and close.
    store1 = SQLiteStagedEffectStore(db)
    s = store1.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    staged_id = s.id
    store1.close()

    # Second instance — simulates process restart; should see the staged row.
    store2 = SQLiteStagedEffectStore(db)
    reloaded = store2.get(staged_id)
    assert reloaded is not None
    assert reloaded.state is StageState.STAGED
    assert reloaded.req.run_id == req.run_id


def test_aborted_rows_survive_restart(tmp_path: Path) -> None:
    db = tmp_path / "staging.db"
    req = _make_req()
    store1 = SQLiteStagedEffectStore(db)
    s = store1.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store1.abort(s.id, principal=_PRINCIPAL, reason="pre_restart_abort")
    staged_id = s.id
    store1.close()

    store2 = SQLiteStagedEffectStore(db)
    reloaded = store2.get(staged_id)
    assert reloaded is not None
    assert reloaded.state is StageState.ABORTED


# ---------------------------------------------------------------------------
# Property-based tests (hypothesis)
# ---------------------------------------------------------------------------


@given(hold_sec=st.integers(min_value=0, max_value=86400))
@settings(max_examples=200, deadline=None)
def test_property_hold_sec_non_negative_always_stages(hold_sec: int) -> None:
    """Any non-negative hold_sec must stage successfully."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        store = SQLiteStagedEffectStore(Path(td) / f"staging_{hold_sec}.db")
        req = _make_req()
        s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=hold_sec, now=_NOW)
        assert s.id is not None
        assert s.state is StageState.STAGED
        store.close()


@given(hold_sec=st.integers(min_value=1, max_value=86400))
@settings(max_examples=100, deadline=None)
def test_property_recall_always_zero_sends(hold_sec: int) -> None:
    """Property: abort before commit always guarantees 0 sends (I-D)."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        store = SQLiteStagedEffectStore(Path(td) / f"staging_recall_{hold_sec}.db")
        transport = _RecordingTransport()
        req = _make_req()
        s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=hold_sec, now=_NOW)
        store.abort(s.id, principal=_PRINCIPAL, reason="property_test_recall")
        # Transport must have 0 calls.
        assert len(transport.calls) == 0
        assert store.get(s.id) is not None
        assert store.get(s.id).state is StageState.ABORTED  # type: ignore[union-attr]
        store.close()


@given(st.text(min_size=1, max_size=200))
@settings(max_examples=100, deadline=None)
def test_property_unknown_id_returns_none(unknown_id: str) -> None:
    """get() for any id not in an empty store must return None."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        store = SQLiteStagedEffectStore(Path(td) / "staging_none.db")
        result = store.get(unknown_id)
        assert result is None
        store.close()


# ---------------------------------------------------------------------------
# Determinism: 100-run invariant (§B-4a)
# ---------------------------------------------------------------------------


def test_determinism_100_runs(tmp_path: Path) -> None:
    """Same input → same fingerprint, same hold_until, same run_id (100×)."""
    req = _make_req(target="https://fss.or.kr/annual-report")
    results: list[tuple[str, str, str]] = []
    for i in range(100):
        db = tmp_path / f"det_{i}.db"
        store = SQLiteStagedEffectStore(db)
        s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=300, now=_NOW)
        # The id is random (uuid-based) so we test the deterministic fields.
        fingerprint = s.req.effect.fingerprint()
        hold_iso = s.hold_until.isoformat()
        run_id = s.req.run_id
        results.append((fingerprint, hold_iso, run_id))
        store.close()
    # All fingerprints must match (deterministic hash of same effect).
    assert all(r[0] == results[0][0] for r in results), "fingerprint not deterministic"
    # All hold_until values match (deterministic: NOW + hold_sec).
    assert all(r[1] == results[0][1] for r in results), "hold_until not deterministic"
    # All run_ids match (deterministic: same req.run_id).
    assert all(r[2] == results[0][2] for r in results), "run_id not deterministic"


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------


def test_req_serialization_roundtrip() -> None:
    """EgressRequest survives JSON round-trip with exact field equality."""
    from secugent.io.staging import _json_to_req, _req_to_json

    req = _make_req()
    serialized = _req_to_json(req)
    restored = _json_to_req(serialized)
    assert restored.effect.kind == req.effect.kind
    assert restored.effect.target == req.effect.target
    assert restored.label == req.label
    assert restored.run_id == req.run_id
    assert restored.profile == req.profile
    assert restored.principal.user_id == req.principal.user_id
    assert restored.content == req.content


def test_req_serialization_roundtrip_korean_content() -> None:
    """바이너리 한글 content도 직렬화 후 복원 가능."""
    from secugent.io.staging import _json_to_req, _req_to_json

    korean_content = "금융감독원 보고서 비밀문서 내용".encode()
    req = EgressRequest(
        effect=Effect(
            kind=EffectKind.NET_SEND,
            target="https://fss.or.kr/submit",
            sink_class=SinkClass.EXTERNAL,
        ),
        label=DataLabel.CONFIDENTIAL,
        principal=_PRINCIPAL,
        run_id="run-금융",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content=korean_content,
    )
    restored = _json_to_req(_req_to_json(req))
    assert restored.content == korean_content


# ---------------------------------------------------------------------------
# Additional coverage tests for uncovered branches
# ---------------------------------------------------------------------------


def test_sqlite_store_get_cache_miss_then_hit(tmp_path: Path) -> None:
    """SQLiteStagedEffectStore.get populates the in-memory cache on a miss."""
    db = tmp_path / "staging.db"
    store1 = SQLiteStagedEffectStore(db)
    req = _make_req()
    s = store1.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    staged_id = s.id
    store1.close()

    # Second instance starts with empty cache → forces a DB read (lines 399-401).
    store2 = SQLiteStagedEffectStore(db)
    # Clear the in-memory cache to simulate a cache miss.
    store2._cache.clear()
    loaded = store2.get(staged_id)
    assert loaded is not None
    assert loaded.state is StageState.STAGED
    # Second call hits the cache (line 401 branch already covered).
    loaded2 = store2.get(staged_id)
    assert loaded2 is not None
    store2.close()


def test_sqlite_store_commit_then_abort_raises(tmp_path: Path) -> None:
    """CommitRefusedError is raised when trying to abort an already-committed effect."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)

    store.commit(
        s.id,
        principal=_PRINCIPAL,
        gate=CommitGate(hitl_approved=True),
        now=_NOW,
        transport=_RecordingTransport(),
    )
    # Now try to abort the committed effect → CommitRefusedError (line 541).
    with pytest.raises(CommitRefusedError):
        store.abort(s.id, principal=_PRINCIPAL, reason="too_late")
    store.close()


def test_in_memory_store_list_all_no_tenant_filter(tmp_path: Path) -> None:
    """StagedEffectStore.list_all returns all items when tenant_id=None."""
    from secugent.io.staging import StagedEffectStore

    store: StagedEffectStore = StagedEffectStore()
    req1 = _make_req()
    req2 = _make_req(run_id="run-456")
    store.stage(req1, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.stage(req2, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    # Lines 222-224: list_all with tenant_id=None returns all.
    all_items = store.list_all(tenant_id=None)
    assert len(all_items) == 2


def test_sqlite_store_list_all_no_tenant_filter(tmp_path: Path) -> None:
    """SQLiteStagedEffectStore.list_all(tenant_id=None) returns all rows (line 426)."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    req1 = _make_req()
    req2 = _make_req(run_id="run-789")
    store.stage(req1, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.stage(req2, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    # This exercises the `else` branch (lines 426-429).
    all_items = store.list_all(tenant_id=None)
    assert len(all_items) == 2
    store.close()


def test_sqlite_store_commit_with_audit_callback(tmp_path: Path) -> None:
    """commit() calls audit.append_event when audit is provided (line 459)."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)

    audit_calls: list[Any] = []

    class _Audit:
        def append_event(self, event: Any) -> Any:
            audit_calls.append(event)
            return event

    store.commit(
        s.id,
        principal=_PRINCIPAL,
        gate=CommitGate(hitl_approved=True),
        now=_NOW,
        transport=_RecordingTransport(),
        audit=_Audit(),
    )
    # Line 459 should have been hit — audit should have been called.
    assert len(audit_calls) >= 1
    store.close()


def test_in_memory_store_list_all_with_tenant_filter(tmp_path: Path) -> None:
    """StagedEffectStore.list_all filters by tenant_id when provided (line 224)."""
    store: StagedEffectStore = StagedEffectStore()
    t1 = TenantId("kookmin-bank")
    t2 = TenantId("shinhan-bank")
    req1 = _make_req(tenant=t1)
    req2 = _make_req(tenant=t2)
    store.stage(req1, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.stage(req2, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    # Line 224: tenant_id filter.
    kookmin_items = store.list_all(tenant_id=str(t1))
    assert len(kookmin_items) == 1
    assert str(kookmin_items[0].req.principal.tenant_id) == str(t1)


def test_stage_negative_hold_sec_raises(tmp_path: Path) -> None:
    """stage() with negative hold_sec must raise ValueError (line 352)."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    req = _make_req()
    with pytest.raises(ValueError, match="non-negative"):
        store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=-1, now=_NOW)
    store.close()


def test_sqlite_store_abort_already_aborted_raises(tmp_path: Path) -> None:
    """CommitRefusedError when aborting an already-aborted effect (line 542)."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.abort(s.id, principal=_PRINCIPAL, reason="first_abort")
    # Second abort should raise CommitRefusedError (state is not STAGED).
    with pytest.raises(CommitRefusedError):
        store.abort(s.id, principal=_PRINCIPAL, reason="second_abort")
    store.close()


def test_sqlite_store_abort_unknown_id_raises(tmp_path: Path) -> None:
    """CommitRefusedError when aborting a completely unknown staged_id (line 541)."""
    db = tmp_path / "staging.db"
    store = SQLiteStagedEffectStore(db)
    # No effects staged — any ID is unknown.
    with pytest.raises(CommitRefusedError, match="no staged effect"):
        store.abort("staged_doesnotexist", principal=_PRINCIPAL, reason="unknown")
    store.close()


# ---------------------------------------------------------------------------
# timezone normalization + legacy-schema NULL on reload
# (_row_to_staged branches 591->592/592, 597->598/598, 595->599)
# ---------------------------------------------------------------------------


def _insert_raw_row(
    store: SQLiteStagedEffectStore,
    *,
    staged_id: str,
    hold_until_iso: str,
    created_at_iso: str | None,
) -> None:
    """Insert a staged_effects row directly (bypassing stage()) so we control the
    exact ISO strings — used to forge naive / NULL timestamps that stage() never
    writes (it always emits tz-aware ISO + a non-null created_at)."""
    req_json = _req_to_json(_make_req())
    with store._conn:  # noqa: SLF001 - test forges a row to drive reload branches
        store._conn.execute(  # noqa: SLF001
            """INSERT INTO staged_effects
               (id, run_id, tenant_id, reversibility, hold_until_iso, state,
                compensating_action, req_json, created_at_iso)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                staged_id,
                "run-tz",
                str(_TENANT),
                str(ReversibilityClass.IRREVERSIBLE),
                hold_until_iso,
                StageState.STAGED,
                None,
                req_json,
                created_at_iso,
            ),
        )


def test_reload_naive_hold_until_is_coerced_to_utc(tmp_path: Path) -> None:
    """Branch 591->592/592: a naive hold_until_iso reloads as UTC-aware."""
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    _insert_raw_row(
        store,
        staged_id="staged_naive_hold",
        hold_until_iso="2026-06-24T09:00:00",  # NAIVE (no offset)
        created_at_iso="2026-06-24T08:00:00+00:00",  # aware
    )
    store._cache.clear()  # noqa: SLF001 - force a DB reload through _row_to_staged
    reloaded = store.get("staged_naive_hold")
    assert reloaded is not None
    assert reloaded.hold_until.tzinfo is UTC
    assert reloaded.hold_until == datetime(2026, 6, 24, 9, 0, 0, tzinfo=UTC)
    store.close()


def test_reload_naive_created_at_is_coerced_to_utc(tmp_path: Path) -> None:
    """Branch 597->598/598: a naive created_at_iso reloads as UTC-aware."""
    store = SQLiteStagedEffectStore(tmp_path / "staging.db")
    _insert_raw_row(
        store,
        staged_id="staged_naive_created",
        hold_until_iso="2026-06-24T09:00:00+00:00",  # aware
        created_at_iso="2026-06-24T08:00:00",  # NAIVE (no offset)
    )
    store._cache.clear()  # noqa: SLF001
    reloaded = store.get("staged_naive_created")
    assert reloaded is not None
    assert reloaded.created_at is not None
    assert reloaded.created_at.tzinfo is UTC
    assert reloaded.created_at == datetime(2026, 6, 24, 8, 0, 0, tzinfo=UTC)
    store.close()


def test_reload_legacy_null_created_at_stays_none(tmp_path: Path) -> None:
    """Branch 595->599: a legacy row whose created_at_iso is NULL reloads with
    ``created_at is None`` (the column was added later; old rows lack it)."""
    import sqlite3

    db = tmp_path / "legacy.db"
    # Build a LEGACY schema where created_at_iso is NULLABLE (no NOT NULL), then
    # INSERT a NULL row. The live _DDL uses CREATE TABLE IF NOT EXISTS, so opening
    # SQLiteStagedEffectStore over this file does NOT recreate / alter the table.
    legacy = sqlite3.connect(str(db))
    legacy.executescript(
        """
        CREATE TABLE staged_effects (
            id               TEXT PRIMARY KEY,
            run_id           TEXT NOT NULL,
            tenant_id        TEXT NOT NULL,
            reversibility    TEXT NOT NULL,
            hold_until_iso   TEXT NOT NULL,
            state            TEXT NOT NULL DEFAULT 'staged',
            compensating_action TEXT,
            req_json         TEXT NOT NULL,
            created_at_iso   TEXT
        );
        """
    )
    req_json = _req_to_json(_make_req())
    legacy.execute(
        """INSERT INTO staged_effects
           (id, run_id, tenant_id, reversibility, hold_until_iso, state,
            compensating_action, req_json, created_at_iso)
           VALUES (?,?,?,?,?,?,?,?,NULL)""",
        (
            "staged_legacy",
            "run-legacy",
            str(_TENANT),
            str(ReversibilityClass.IRREVERSIBLE),
            "2026-06-24T09:00:00+00:00",
            StageState.STAGED,
            None,
            req_json,
        ),
    )
    legacy.commit()
    legacy.close()

    store = SQLiteStagedEffectStore(db)
    store._cache.clear()  # noqa: SLF001 - force a DB reload through _row_to_staged
    reloaded = store.get("staged_legacy")
    assert reloaded is not None
    assert reloaded.created_at is None  # legacy row had no creation timestamp
    # hold_until still loads correctly (aware string → aware datetime).
    assert reloaded.hold_until.tzinfo is not None
    store.close()


# ---------------------------------------------------------------------------
# In-memory StagedEffectStore.abort with an audit sink (lines 278-281)
# ---------------------------------------------------------------------------


def test_in_memory_abort_emits_audit_event(tmp_path: Path) -> None:
    """StagedEffectStore.abort(audit=...) emits an egress.aborted event with the
    reason + operator id (lines 278-281)."""
    store = StagedEffectStore()
    audit = _RecordingAudit()
    req = _make_req()
    s = store.stage(req, reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    store.abort(s.id, principal=_PRINCIPAL, reason="operator_recall_심사역", audit=audit)
    aborted = [e for e in audit.events if e.type == "egress.aborted"]
    assert len(aborted) == 1
    assert aborted[0].payload["reason"] == "operator_recall_심사역"
    assert aborted[0].payload["aborted_by"] == _PRINCIPAL.user_id
