# SPDX-License-Identifier: Apache-2.0
"""Two-phase staging commit for irreversible effects (EM-09, invariant I-C).

An irreversible effect cannot be undone, so it is never executed directly. The
broker *stages* it (holding/outbox) and it only reaches the transport on an
explicit commit that requires BOTH (a) envelope irreversible-budget remaining or
a synchronous HITL approval, AND (b) the hold window having elapsed. During the
hold window STEER can recall it (abort) — "catch it before it is sent". Every
state change is recorded on the durable hash chain.

G-M6: adds :class:`SQLiteStagedEffectStore` — a SQLite-backed store that
survives process restart (invariant I-E). ``StagedEffectStore`` (in-memory) is
kept as a test-time or explicit-fallback option; the production boot path uses
the durable store.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from secugent.core.contracts import Event, EventSeverity
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import Decision
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.profiles import ExecutionProfile
from secugent.io.broker.request import EgressRequest, EgressResult
from secugent.io.broker.transport import Transport

__all__ = [
    "StageState",
    "StagedEffect",
    "CommitGate",
    "CommitRefusedError",
    "StagedEffectStore",
    "SQLiteStagedEffectStore",
    "StagingAuditSink",
]

# DDL for the durable staging table (G-M6).
_DDL = """
CREATE TABLE IF NOT EXISTS staged_effects (
    id               TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    reversibility    TEXT NOT NULL,
    hold_until_iso   TEXT NOT NULL,
    state            TEXT NOT NULL DEFAULT 'staged',
    compensating_action TEXT,
    req_json         TEXT NOT NULL,
    created_at_iso   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staged_run ON staged_effects (run_id, state);
CREATE INDEX IF NOT EXISTS idx_staged_tenant ON staged_effects (tenant_id, state);
"""

# Column projection shared by every row-loading query (kept in lock-step with
# ``_row_to_staged``'s tuple unpacking so a schema change touches one place).
_SELECT_COLS = (
    "SELECT id, reversibility, hold_until_iso, state, compensating_action, req_json, created_at_iso "
)


class StageState(StrEnum):
    STAGED = "staged"
    COMMITTING = "committing"  # transient: CAS-claimed by one committer (SG-20260624-02)
    COMMITTED = "committed"
    ABORTED = "aborted"


class StagingAuditSink(Protocol):
    def append_event(self, event: Event) -> Any: ...


class CommitRefusedError(Exception):
    """Raised when a staged effect may not be committed yet (gate or hold window)."""


@dataclass(frozen=True)
class CommitGate:
    """Authority to commit an irreversible effect (besides the hold window)."""

    hitl_approved: bool = False
    envelope_budget_remaining: bool = False

    def permits(self) -> bool:
        return self.hitl_approved or self.envelope_budget_remaining


@dataclass
class StagedEffect:
    id: str
    req: EgressRequest
    reversibility: ReversibilityClass
    hold_until: datetime
    compensating_action: str | None = None
    state: StageState = StageState.STAGED
    # SG-20260624-04: when the effect was staged (UTC). Surfaced by the outbox API
    # as the operator-facing ``created_at`` instead of approximating it from
    # ``hold_until``. None for legacy rows / in-memory stages without a clock.
    created_at: datetime | None = None


# ---------------------------------------------------------------------------
# Serialization helpers (G-M6)
# ---------------------------------------------------------------------------


def _req_to_json(req: EgressRequest) -> str:
    """Serialize an EgressRequest to a JSON string for SQLite storage.

    Only the fields needed to reconstruct a ``EgressRequest`` for later
    transport.execute() are persisted. The transport is NOT stored — on restore
    it must be supplied at commit time (as today). Sensitive ``content`` bytes
    are base64-encoded (binary-safe, but still in the SQLite file, which is
    access-controlled by OS-level permissions — same threat model as the event
    store).
    """
    import base64

    e = req.effect
    meta_list = [[k, v] for k, v in e.meta]
    obj: dict[str, Any] = {
        "effect": {
            "kind": str(e.kind),
            "target": e.target,
            "sink_class": str(e.sink_class),
            "byte_estimate": e.byte_estimate,
            "action": e.action,
            "meta": meta_list,
        },
        "label": int(req.label),
        "principal": {
            "user_id": req.principal.user_id,
            "tenant_id": str(req.principal.tenant_id),
            "role": req.principal.role,
        },
        "run_id": req.run_id,
        "profile": str(req.profile),
        "content_b64": base64.b64encode(req.content).decode() if req.content is not None else None,
    }
    return json.dumps(obj, ensure_ascii=False)


def _json_to_req(raw: str) -> EgressRequest:
    """Reconstruct an :class:`EgressRequest` from JSON (reverse of _req_to_json)."""
    import base64

    obj = json.loads(raw)
    e = obj["effect"]
    meta_tuples: tuple[tuple[str, str], ...] = tuple((k, v) for k, v in e.get("meta", []))
    effect = Effect(
        kind=EffectKind(e["kind"]),
        target=e["target"],
        sink_class=SinkClass(e["sink_class"]),
        byte_estimate=int(e.get("byte_estimate", 0)),
        action=e.get("action"),
        meta=meta_tuples,
    )
    principal = Principal(
        user_id=obj["principal"]["user_id"],
        tenant_id=TenantId(obj["principal"]["tenant_id"]),
        role=obj["principal"]["role"],
    )
    content_b64 = obj.get("content_b64")
    content = base64.b64decode(content_b64) if content_b64 is not None else None
    return EgressRequest(
        effect=effect,
        label=DataLabel(int(obj["label"])),
        principal=principal,
        run_id=obj["run_id"],
        profile=ExecutionProfile(obj["profile"]),
        content=content,
    )


# ---------------------------------------------------------------------------
# In-memory store (kept for test / fallback)
# ---------------------------------------------------------------------------


class StagedEffectStore:
    """Holds staged irreversible effects in memory until committed or aborted.

    For production use, prefer :class:`SQLiteStagedEffectStore` (G-M6 durable).
    This class is retained for tests and as an explicit fallback path where
    durability is not required.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, StagedEffect] = {}

    def stage(
        self,
        req: EgressRequest,
        *,
        reversibility: ReversibilityClass,
        hold_sec: int,
        now: datetime,
        compensating_action: str | None = None,
        audit: StagingAuditSink | None = None,
    ) -> StagedEffect:
        if hold_sec < 0:
            raise ValueError("hold_sec must be non-negative")
        staged = StagedEffect(
            id=f"staged_{uuid.uuid4().hex[:16]}",
            req=req,
            reversibility=reversibility,
            hold_until=now + timedelta(seconds=hold_sec),
            compensating_action=compensating_action,
            created_at=now,
        )
        self._by_id[staged.id] = staged
        if audit is not None:
            audit.append_event(self._event(staged, "egress.staged", "warn"))
        return staged

    def get(self, staged_id: str) -> StagedEffect | None:
        return self._by_id.get(staged_id)

    def list_staged(self, run_id: str) -> list[StagedEffect]:
        return [s for s in self._by_id.values() if s.req.run_id == run_id and s.state is StageState.STAGED]

    def list_all(self, *, tenant_id: str | None = None) -> list[StagedEffect]:
        """Return all effects (any state), optionally filtered by tenant_id."""
        if tenant_id is None:
            return list(self._by_id.values())
        return [s for s in self._by_id.values() if str(s.req.principal.tenant_id) == tenant_id]

    def commit(
        self,
        staged_id: str,
        *,
        principal: Principal,
        gate: CommitGate,
        now: datetime,
        transport: Transport,
        audit: StagingAuditSink | None = None,
    ) -> EgressResult:
        staged = self._require_staged(staged_id)
        self._require_same_tenant(principal, staged)
        if now < staged.hold_until:
            raise CommitRefusedError(f"hold window active until {staged.hold_until.isoformat()}")
        if not gate.permits():
            raise CommitRefusedError("commit gate denied (no envelope budget and no HITL approval)")
        payload = transport.execute(staged.req)
        staged.state = StageState.COMMITTED
        if audit is not None:
            audit.append_event(self._event(staged, "egress.committed", "info"))
        return EgressResult(
            ok=True,
            decision=Decision(outcome="allow", rule_id=None, rationale="staged_commit"),
            payload=payload,
            audit_event_id="",
        )

    def abort(
        self,
        staged_id: str,
        *,
        principal: Principal,
        reason: str,
        audit: StagingAuditSink | None = None,
    ) -> None:
        staged = self._require_staged(staged_id)
        self._require_same_tenant(principal, staged)
        staged.state = StageState.ABORTED
        if audit is not None:
            event = self._event(staged, "egress.aborted", "warn")
            event.payload["reason"] = reason
            event.payload["aborted_by"] = principal.user_id
            audit.append_event(event)

    def _require_staged(self, staged_id: str) -> StagedEffect:
        staged = self._by_id.get(staged_id)
        if staged is None:
            raise CommitRefusedError(f"no staged effect {staged_id!r}")
        if staged.state is not StageState.STAGED:
            raise CommitRefusedError(f"staged effect {staged_id!r} is already {staged.state}")
        return staged

    @staticmethod
    def _require_same_tenant(principal: Principal, staged: StagedEffect) -> None:
        # Fail-closed cross-tenant guard: a principal may only commit/abort a
        # staged effect belonging to its own tenant (confused-deputy defense).
        if principal.tenant_id != staged.req.principal.tenant_id:
            raise CommitRefusedError("cross-tenant staging access denied")

    def _event(self, staged: StagedEffect, event_type: str, severity: EventSeverity) -> Event:
        req = staged.req
        return Event(
            tenant_id=req.principal.tenant_id,
            actor="staging",
            type=event_type,
            run_id=req.run_id,
            payload={
                "staged_id": staged.id,
                "effect_fingerprint": req.effect.fingerprint(),
                "target": req.effect.target,
                "reversibility": str(staged.reversibility),
            },
            severity=severity,
        )


# ---------------------------------------------------------------------------
# G-M6: Durable SQLite-backed store
# ---------------------------------------------------------------------------


class SQLiteStagedEffectStore:
    """SQLite-backed staging store that survives process restart (G-M6, I-E).

    The store keeps a local in-memory cache of rows it has loaded/written so
    hot paths do not require a DB round-trip. The cache is refreshed lazily by
    ``get()`` (DB always authoritative). The DB is the single source of truth;
    in-memory state is never committed ahead of the DB write (fail-closed, I-A).

    Thread safety (SG-20260624-02): the connection runs with
    ``check_same_thread=False`` so it may be shared by the async commit endpoint's
    worker threads. A process-level :class:`threading.RLock` serializes the
    in-process write critical sections, and ``commit`` additionally performs an
    atomic CAS state pre-claim
    (``UPDATE ... SET state='committing' WHERE staged_id=? AND state='staged'``)
    *before* any ``transport.execute`` call: only the thread whose UPDATE affected
    a row (the winning claimer) reaches the transport, so two concurrent commits
    on the same staged_id can send the irreversible effect AT MOST ONCE (I-C/I-D).
    The loser sees ``rowcount == 0`` and raises :class:`CommitRefusedError`.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # WAL mode for concurrent read/write; enforce FK constraints.
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # Create schema; DDL is idempotent.
        self._conn.executescript(_DDL)
        self._conn.commit()
        # Serializes in-process write critical sections (commit/abort/stage) so
        # concurrent threads sharing one store instance cannot interleave a
        # CAS-claim with another transition (SG-20260624-02).
        self._lock = threading.RLock()
        # In-memory cache keyed by staged_id.
        self._cache: dict[str, StagedEffect] = {}
        # Restore staged rows into cache at boot so callers can list without
        # an explicit DB query (I-E invariant: staged rows survive restart).
        self._load_all_into_cache()

    # ------------------------------------------------------------------ #
    # Public API (mirrors StagedEffectStore)
    # ------------------------------------------------------------------ #

    def stage(
        self,
        req: EgressRequest,
        *,
        reversibility: ReversibilityClass,
        hold_sec: int,
        now: datetime,
        compensating_action: str | None = None,
        audit: StagingAuditSink | None = None,
    ) -> StagedEffect:
        if hold_sec < 0:
            raise ValueError("hold_sec must be non-negative")
        staged_id = f"staged_{uuid.uuid4().hex[:16]}"
        hold_until = now + timedelta(seconds=hold_sec)
        req_json = _req_to_json(req)
        created_at = datetime.now(tz=UTC)
        staged = StagedEffect(
            id=staged_id,
            req=req,
            reversibility=reversibility,
            hold_until=hold_until,
            compensating_action=compensating_action,
            created_at=created_at,
        )
        # Durable write BEFORE cache update (I-A: DB before in-memory).
        with self._conn:
            self._conn.execute(
                """INSERT INTO staged_effects
                   (id, run_id, tenant_id, reversibility, hold_until_iso, state,
                    compensating_action, req_json, created_at_iso)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    staged_id,
                    req.run_id,
                    str(req.principal.tenant_id),
                    str(reversibility),
                    hold_until.isoformat(),
                    StageState.STAGED,
                    compensating_action,
                    req_json,
                    created_at.isoformat(),
                ),
            )
        self._cache[staged_id] = staged
        if audit is not None:
            audit.append_event(self._event(staged, "egress.staged", "warn"))
        return staged

    def get(self, staged_id: str) -> StagedEffect | None:
        if staged_id in self._cache:
            return self._cache[staged_id]
        # Fallback: query DB (handles race where another process wrote it).
        row = self._conn.execute(
            _SELECT_COLS + "FROM staged_effects WHERE id=?",
            (staged_id,),
        ).fetchone()
        if row is None:
            return None
        staged = self._row_to_staged(row)
        self._cache[staged_id] = staged
        return staged

    def list_staged(self, run_id: str) -> list[StagedEffect]:
        """Return all STAGED effects for a run (DB authoritative)."""
        rows = self._conn.execute(
            _SELECT_COLS + "FROM staged_effects WHERE run_id=? AND state=?",
            (run_id, StageState.STAGED),
        ).fetchall()
        result: list[StagedEffect] = []
        for row in rows:
            s = self._row_to_staged(row)
            self._cache[s.id] = s
            result.append(s)
        return result

    def list_all(self, *, tenant_id: str | None = None) -> list[StagedEffect]:
        """Return all effects (any state), optionally filtered by tenant_id."""
        if tenant_id is not None:
            rows = self._conn.execute(
                _SELECT_COLS + "FROM staged_effects WHERE tenant_id=?",
                (tenant_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                _SELECT_COLS + "FROM staged_effects",
            ).fetchall()
        result: list[StagedEffect] = []
        for row in rows:
            s = self._row_to_staged(row)
            self._cache[s.id] = s
            result.append(s)
        return result

    def commit(
        self,
        staged_id: str,
        *,
        principal: Principal,
        gate: CommitGate,
        now: datetime,
        transport: Transport,
        audit: StagingAuditSink | None = None,
    ) -> EgressResult:
        # SG-20260624-02: gate checks + an atomic CAS state pre-claim run under the
        # process lock so two concurrent commits on the same staged_id cannot both
        # pass into the transport (double-send of an irreversible effect, I-C/I-D).
        # Only the thread whose UPDATE claimed the 'staged'→'committing' transition
        # (rowcount == 1) calls transport.execute(); the loser raises here.
        with self._lock:
            staged = self._require_staged(staged_id)
            self._require_same_tenant(principal, staged)
            if now < staged.hold_until:
                raise CommitRefusedError(f"hold window active until {staged.hold_until.isoformat()}")
            if not gate.permits():
                raise CommitRefusedError("commit gate denied (no envelope budget and no HITL approval)")
            claimed = self._claim_for_commit(staged_id)
            if not claimed:
                # Another committer already took the staged→committing transition
                # (or the row is no longer STAGED). Refuse: at most one send.
                raise CommitRefusedError(
                    f"staged effect {staged_id!r} is already being committed or committed"
                )
            staged.state = StageState.COMMITTING
        # Transport runs OUTSIDE the lock so a slow/blocking send does not stall
        # commits of other staged_ids. The CAS claim guarantees exclusivity here.
        try:
            payload = transport.execute(staged.req)
        except Exception:
            # Transport failed → roll the claim back to STAGED so a retry is
            # possible (the effect was never sent — fail-closed, no fake success).
            with self._lock:
                self._update_state(staged_id, StageState.STAGED)
                staged.state = StageState.STAGED
            raise
        with self._lock:
            self._update_state(staged_id, StageState.COMMITTED)
            staged.state = StageState.COMMITTED
        if audit is not None:
            audit.append_event(self._event(staged, "egress.committed", "info"))
        return EgressResult(
            ok=True,
            decision=Decision(outcome="allow", rule_id=None, rationale="staged_commit"),
            payload=payload,
            audit_event_id="",
        )

    def _claim_for_commit(self, staged_id: str) -> bool:
        """Atomically claim a STAGED effect for commit (CAS, SG-20260624-02).

        Returns True iff this call transitioned the row staged→committing (i.e.
        ``rowcount == 1``); a concurrent winner or a non-STAGED row yields False.
        """
        with self._conn:
            cur = self._conn.execute(
                "UPDATE staged_effects SET state=? WHERE id=? AND state=?",
                (str(StageState.COMMITTING), staged_id, str(StageState.STAGED)),
            )
        return cur.rowcount == 1

    def abort(
        self,
        staged_id: str,
        *,
        principal: Principal,
        reason: str,
        audit: StagingAuditSink | None = None,
    ) -> None:
        """Recall (abort) a staged effect — guarantees 0 external sends (I-D).

        The state transition is written to the DB BEFORE the audit event so that
        if the audit write fails the effect is still marked as aborted in the
        durable store (the transport is never called in the aborted path).
        """
        # SG-20260624-02: abort shares the commit lock so a recall cannot race a
        # commit's CAS claim (abort only fires from the STAGED state — once a
        # committer has claimed 'committing', _require_staged refuses the abort).
        with self._lock:
            staged = self._require_staged(staged_id)
            self._require_same_tenant(principal, staged)
            # Durable state update first, THEN audit (abort guarantees 0 sends — DB
            # write must be committed before any audit path that might raise).
            self._update_state(staged_id, StageState.ABORTED)
            staged.state = StageState.ABORTED
        if audit is not None:
            event = self._event(staged, "egress.aborted", "warn")
            event.payload["reason"] = reason
            event.payload["aborted_by"] = principal.user_id
            audit.append_event(event)

    def close(self) -> None:
        """Close the underlying SQLite connection (e.g. at application shutdown)."""
        self._conn.close()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _update_state(self, staged_id: str, new_state: StageState) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE staged_effects SET state=? WHERE id=?",
                (str(new_state), staged_id),
            )

    def _load_all_into_cache(self) -> None:
        rows = self._conn.execute(_SELECT_COLS + "FROM staged_effects").fetchall()
        for row in rows:
            staged = self._row_to_staged(row)
            self._cache[staged.id] = staged

    def _row_to_staged(
        self,
        row: tuple[str, str, str, str, str | None, str, str | None],
    ) -> StagedEffect:
        (
            staged_id,
            reversibility_str,
            hold_until_iso,
            state_str,
            comp_action,
            req_json,
            created_at_iso,
        ) = row
        req = _json_to_req(req_json)
        hold_until = datetime.fromisoformat(hold_until_iso)
        # Ensure timezone-aware (SQLite stores ISO8601; fromisoformat gives
        # UTC-aware only if the ISO string included timezone offset).
        if hold_until.tzinfo is None:
            hold_until = hold_until.replace(tzinfo=UTC)
        # SG-20260624-04: load the real creation timestamp (legacy rows may lack it).
        created_at: datetime | None = None
        if created_at_iso is not None:
            created_at = datetime.fromisoformat(created_at_iso)
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
        staged = StagedEffect(
            id=staged_id,
            req=req,
            reversibility=ReversibilityClass(reversibility_str),
            hold_until=hold_until,
            compensating_action=comp_action,
            state=StageState(state_str),
            created_at=created_at,
        )
        return staged

    def _require_staged(self, staged_id: str) -> StagedEffect:
        staged = self.get(staged_id)
        if staged is None:
            raise CommitRefusedError(f"no staged effect {staged_id!r}")
        if staged.state is not StageState.STAGED:
            raise CommitRefusedError(f"staged effect {staged_id!r} is already {staged.state}")
        return staged

    @staticmethod
    def _require_same_tenant(principal: Principal, staged: StagedEffect) -> None:
        if principal.tenant_id != staged.req.principal.tenant_id:
            raise CommitRefusedError("cross-tenant staging access denied")

    def _event(self, staged: StagedEffect, event_type: str, severity: EventSeverity) -> Event:
        req = staged.req
        return Event(
            tenant_id=req.principal.tenant_id,
            actor="staging",
            type=event_type,
            run_id=req.run_id,
            payload={
                "staged_id": staged.id,
                "effect_fingerprint": req.effect.fingerprint(),
                "target": req.effect.target,
                "reversibility": str(staged.reversibility),
            },
            severity=severity,
        )
