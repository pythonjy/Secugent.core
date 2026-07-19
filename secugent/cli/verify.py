# SPDX-License-Identifier: Apache-2.0
"""Read-only public verification API for ``secugent verify`` (BDP Phase 1 item 2).

Two externally-reproducible trust proofs, exposed as a one-line CLI:

* :func:`verify_determinism` — run the deterministic decision path
  (``classify_axes`` + Mechanical Oversight policy evaluation) on a fixed
  fixture ``samples`` times and assert every output is byte-identical. A single
  divergence ⇒ ``ok=False`` (Invariant I2).
* :func:`verify_audit_chain` — externally reproduce the ``prev_event_id`` /
  ``event_hash`` SHA-256 hash chain integrity, re-using the **existing** audit
  crypto (``secugent.audit.hash_chain`` primitives ``canonical`` /
  ``compute_chain_hash`` / ``GENESIS`` and ``stored_view``). It implements **no
  new cryptography** (BDP non-scope; §A-2 "표준 준수"). It mirrors
  :meth:`ChainedEventStore.verify_chain`'s verification semantics exactly:
  prev-hash linkage, event-hash re-derive, underlying-payload cross-check, and
  missing-event detection.

Invariants (see ``docs/specs/2026-06-07-trust-proof-verify.md``):

* **I1** READ-ONLY — the SQLite store is opened with the ``mode=ro`` URI flag, so
  verification never creates tables, runs migrations, or writes a single byte.
  This is *stricter* than going through :class:`EventStore` (whose constructor
  issues ``CREATE TABLE IF NOT EXISTS``). The fixture file is read, never written.
* **I2** determinism ``ok=True`` iff ``distinct_outputs == 1``.
* **I3** chain-verify failure ⇒ non-0 exit + explicit first-violation location
  (no silent pass — §B-8 fail-closed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from secugent.audit.hash_chain import (
    GENESIS,
    canonical,
    compute_chain_hash,
    stored_view,
)
from secugent.core.contracts import Event, Step
from secugent.core.mechanical_oversight import OversightEngine
from secugent.core.regulations import RegulationsLoadError, load_regulations_from_dict
from secugent.core.rule_of_two import (
    RuleOfTwoContext,
    axes_to_audit,
    classify_axes,
    requires_hitl,
)

__all__ = [
    "ChainReport",
    "CheckResult",
    "DeterminismReport",
    "PreflightReport",
    "VerifyInputError",
    "main",
    "verify_audit_chain",
    "verify_deploy_preflight",
    "verify_determinism",
]


class VerifyInputError(ValueError):
    """Fixture/store path is missing, unreadable, or not the expected shape.

    Raised for *operator* errors (bad path, malformed JSON, zero samples) so they
    can be told apart from a genuine integrity failure (which is reported, not
    raised, via the report ``ok=False``).
    """


@dataclass(frozen=True)
class DeterminismReport:
    """Outcome of the same-input → same-output determinism proof."""

    ok: bool
    samples: int
    distinct_outputs: int
    first_divergence: str | None
    output_digest: str


@dataclass(frozen=True)
class ChainReport:
    """Outcome of the audit hash-chain integrity proof."""

    ok: bool
    tenant_id: str
    events_checked: int
    first_violation: str | None
    empty: bool


Severity = Literal["critical", "high", "medium", "info"]


@dataclass(frozen=True)
class CheckResult:
    """One deploy-config preflight finding (B1).

    ``name`` mirrors exactly one documented W6/A1 deploy-shell blocker so an
    operator can trace a finding back to the incident it prevents. ``ok`` is
    ``True`` when the misconfiguration is *absent*; ``message`` states what/why/
    how-to-fix (Korean, KST allowed — the deployment target is Korean enterprise).
    """

    name: str
    severity: Severity
    ok: bool
    message: str


@dataclass(frozen=True)
class PreflightReport:
    """Outcome of the read-only ``verify --deploy`` preflight doctor (B1).

    ``ok`` is ``True`` iff every ``critical`` **and** ``high`` check passed —
    ``info``/``medium`` findings are surfaced but do not fail the report. The
    ``checks`` tuple is in a fixed, stable order so the report is deterministic
    (same env → identical report, needed for the §B-4a 100× determinism proof).
    """

    ok: bool
    checks: tuple[CheckResult, ...]


# --------------------------------------------------------------------------- #
# Determinism proof
# --------------------------------------------------------------------------- #


def _decide(step: Step, engine: OversightEngine) -> dict[str, object]:
    """The deterministic decision for a single step (pure given inputs).

    Combines the two deterministic-core surfaces this proof covers: Rule-of-Two
    axis classification and Mechanical Oversight policy evaluation. The result is
    a plain, JSON-serialisable dict so it can be canonicalised byte-for-byte.
    """
    ctx = RuleOfTwoContext.from_step(step)
    axes = classify_axes(step, ctx)
    result = engine.evaluate(step)
    return {
        "axes": axes_to_audit(axes),
        "requires_hitl": requires_hitl(axes),
        "oversight": {
            "allowed": result.allowed,
            "hard_block": result.hard_block,
            "violation_rule_id": (result.violation.rule_id if result.violation is not None else None),
        },
    }


def _canonical_decisions(fixture: dict[str, object]) -> str:
    """Run the deterministic path once and return its canonical JSON output."""
    raw_regs = fixture.get("regulations")
    if not isinstance(raw_regs, dict):
        raise VerifyInputError("fixture missing a 'regulations' object")
    raw_steps = fixture.get("steps")
    if not isinstance(raw_steps, list):
        raise VerifyInputError("fixture missing a 'steps' list")

    try:
        regulations = load_regulations_from_dict(raw_regs, source="<verify-fixture>")
    except RegulationsLoadError as exc:
        raise VerifyInputError(f"fixture regulations invalid: {exc}") from exc
    engine = OversightEngine(regulations)

    decisions: list[dict[str, object]] = []
    for idx, entry in enumerate(raw_steps):
        if not isinstance(entry, dict) or "step" not in entry:
            raise VerifyInputError(f"steps[{idx}] missing a 'step' object")
        try:
            step = Step.model_validate(entry["step"])
        except ValidationError as exc:
            raise VerifyInputError(f"steps[{idx}].step invalid: {exc}") from exc
        decisions.append(_decide(step, engine))

    return json.dumps(decisions, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _load_fixture(seed_fixture: Path) -> dict[str, object]:
    try:
        text = seed_fixture.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifyInputError(f"cannot read fixture {seed_fixture}: {exc}") from exc
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerifyInputError(f"fixture {seed_fixture} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise VerifyInputError(f"fixture {seed_fixture} must be a JSON object")
    return loaded


def verify_determinism(*, samples: int = 100, seed_fixture: Path) -> DeterminismReport:
    """Run the deterministic decision path ``samples`` times on a fixed fixture.

    Returns a :class:`DeterminismReport`; ``ok`` is True iff every run produced a
    byte-identical canonical output (``distinct_outputs == 1``, Invariant I2).

    Raises :class:`VerifyInputError` for operator errors (missing/corrupt fixture
    or ``samples <= 0`` — you cannot prove determinism over zero runs).
    """
    if samples <= 0:
        raise VerifyInputError("samples must be a positive integer")

    fixture = _load_fixture(seed_fixture)

    seen: dict[str, int] = {}
    first: str | None = None
    first_divergence: str | None = None
    for run_index in range(samples):
        output = _canonical_decisions(fixture)
        if first is None:
            first = output
        elif output != first and first_divergence is None:
            first_divergence = f"run #{run_index} diverged from run #0 (len {len(output)} vs {len(first)})"
        seen[output] = seen.get(output, 0) + 1

    distinct = len(seen)
    # The digest is over the *first* canonical output; when ok it uniquely pins
    # the proof so the CI reproduction job can compare two independent runs.
    digest = hashlib.sha256((first or "").encode("utf-8")).hexdigest()
    return DeterminismReport(
        ok=distinct == 1,
        samples=samples,
        distinct_outputs=distinct,
        first_divergence=first_divergence,
        output_digest=digest,
    )


# --------------------------------------------------------------------------- #
# Audit hash-chain proof (read-only)
# --------------------------------------------------------------------------- #


def _ro_connect(store_path: Path) -> sqlite3.Connection:
    """Open ``store_path`` strictly read-only (Invariant I1).

    Uses the ``mode=ro`` URI flag so SQLite refuses every write — no schema
    creation, no migration, no journal mutation. A missing file fails fast with
    :class:`VerifyInputError` rather than silently creating an empty DB.
    """
    if not store_path.exists():
        raise VerifyInputError(f"store does not exist: {store_path}")
    uri = f"file:{store_path.as_posix()}?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise VerifyInputError(f"cannot open store {store_path}: {exc}") from exc


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def _iter_chain_rows(conn: sqlite3.Connection, *, tenant_id: str) -> Iterator[tuple[int, str, str, str]]:
    """Stream ``(seq, prev_hash, event_hash, body_canonical)`` for one tenant.

    Streaming keeps memory constant for very large chains (spec edge case);
    rows are scoped to ``tenant_id`` so no cross-tenant data is read.
    """
    cur = conn.execute(
        "SELECT seq, prev_hash, event_hash, body_canonical "
        "FROM event_chain WHERE tenant_id=? ORDER BY seq ASC",
        (tenant_id,),
    )
    for seq, prev_hash, event_hash, body_canonical in cur:
        yield int(seq), prev_hash, event_hash, body_canonical


def _stored_event_canonical(conn: sqlite3.Connection, *, event_id: str, tenant_id: str) -> str | None:
    """Return the canonical form of the durably stored event, or ``None``.

    Reads the hot ``events`` table then ``events_archive`` (mirrors
    :meth:`EventStore.get_event`'s live∪archive union) and rebuilds the event,
    then re-applies :func:`stored_view` so the canonical form matches exactly
    what the chain hashed (redacted + UTC-normalised).
    """
    for table in ("events", "events_archive"):
        if not _has_table(conn, table):
            continue
        row = conn.execute(
            f"SELECT id, tenant_id, ts, actor, type, payload, severity, run_id, step_id "  # noqa: S608 — fixed table allow-list, not user input
            f"FROM {table} WHERE id=? AND tenant_id=?",
            (event_id, tenant_id),
        ).fetchone()
        if row is None:
            continue
        try:
            event = Event(
                id=row[0],
                tenant_id=row[1],
                ts=datetime.fromisoformat(row[2]),
                actor=row[3],
                type=row[4],
                payload=json.loads(row[5]),
                severity=row[6],
                run_id=row[7],
                step_id=row[8],
            )
        except (ValidationError, ValueError) as exc:
            raise VerifyInputError(f"stored event {event_id} is unparseable: {exc}") from exc
        return canonical(stored_view(event))
    return None


def verify_audit_chain(*, tenant_id: str, store_path: Path) -> ChainReport:
    """Externally reproduce hash-chain integrity for ``tenant_id`` (read-only).

    Walks the chain front-to-back re-deriving each ``event_hash`` from the stored
    ``body_canonical`` with the existing :func:`compute_chain_hash`, checks the
    ``prev_hash`` linkage, and cross-checks each chained body against the durable
    event row. The *first* inconsistency is reported in
    :attr:`ChainReport.first_violation` and sets ``ok=False`` (Invariant I3) —
    never a silent pass.

    Raises :class:`VerifyInputError` only for operator errors (missing store /
    no chain table / unparseable row). An empty chain (0 events) is a valid,
    intact state: ``ok=True, empty=True`` (spec edge case).
    """
    conn = _ro_connect(store_path)
    try:
        if not _has_table(conn, "event_chain"):
            raise VerifyInputError(f"store {store_path} has no 'event_chain' table (not an audit store?)")

        last_hash = GENESIS
        checked = 0
        first_violation: str | None = None
        for seq, prev_hash, event_hash, body_canonical in _iter_chain_rows(conn, tenant_id=tenant_id):
            checked += 1
            # 1. chain-table integrity (re-derive from the stored body).
            try:
                json.loads(body_canonical)
            except json.JSONDecodeError:
                first_violation = f"chain body corrupt at seq={seq}"
                break
            if prev_hash != last_hash:
                first_violation = f"prev_hash mismatch at seq={seq}"
                break
            if event_hash != compute_chain_hash(last_hash, body_canonical):
                first_violation = f"event_hash mismatch at seq={seq} — chain record tampered"
                break
            # 2. cross-check the underlying durable event (store-table tamper).
            event_id_obj = json.loads(body_canonical).get("id")
            event_id = event_id_obj if isinstance(event_id_obj, str) else ""
            live_canonical = _stored_event_canonical(conn, event_id=event_id, tenant_id=tenant_id)
            if live_canonical is None:
                first_violation = f"event {event_id} present in chain but missing from store (seq={seq})"
                break
            if live_canonical != body_canonical:
                first_violation = f"event_hash mismatch at seq={seq} — underlying payload tampered"
                break
            last_hash = event_hash

        ok = first_violation is None
        # When a break occurs mid-walk, ``checked`` counts up to and including the
        # offending row; report the count of *verified* rows for clarity.
        verified = checked if ok else checked - 1
        return ChainReport(
            ok=ok,
            tenant_id=tenant_id,
            events_checked=verified,
            first_violation=first_violation,
            empty=ok and verified == 0,
        )
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Deploy-config preflight doctor (B1) — read-only, pure (env in → report out)
# --------------------------------------------------------------------------- #
#
# Each ``_check_*`` mirrors ONE documented W6/A1 deploy-shell blocker. They are
# **pure**: they read only the passed env snapshot, perform no I/O, and NEVER
# raise (a check that cannot decide reports a finding). This preserves ``verify``
# Invariant I1 (read-only) and gives a deterministic report (same env → same
# report). The misconfig↔blocker mapping lives in each function's docstring.


def _truthy(value: str | None) -> bool:
    """Interpret an env string as a boolean flag (``1/true/yes/on`` → True)."""
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _present(value: str | None) -> bool:
    """True iff the env value is set and non-blank."""
    return bool((value or "").strip())


def _is_dev(environ: Mapping[str, str]) -> bool:
    """Re-derive the canonical dev predicate against the *passed* snapshot.

    :func:`secugent.core.env.is_dev_env` reads the live ``os.environ`` directly,
    so it cannot be used against a ``--env-file``-overlaid snapshot. This mirrors
    its exact semantics (fail-closed: only an exact, trimmed, case-insensitive
    ``"dev"`` is dev; unset/blank/anything else is production).
    """
    return environ.get("SECUGENT_ENV", "").strip().lower() == "dev"


def _check_kms_signer(environ: Mapping[str, str]) -> CheckResult:
    """A1 — prod boots with the dev HMAC Merkle signer ⇒ boot-crash (critical).

    Mirrors the real B5 guard by reusing the canonical :meth:`KmsSettings.from_env`
    parser (pure — env parsing only, no provider build / no lazy Enterprise
    import). Fires when ``require_external and provider == 'local'``: production
    auto-enforces ``require_external`` (or an operator set it), so ``build_kms_provider``
    would raise ``ValueError`` at boot. We deliberately do NOT call
    ``build_kms_provider`` (it lazy-imports the Enterprise KMS backends).
    """
    name = "kms-signer"
    try:
        from secugent.audit.merkle import KmsSettings

        settings = KmsSettings.from_env(environ)
    except Exception as exc:  # noqa: BLE001 — never raise from a check (P1); degrade to info.
        return CheckResult(
            name=name,
            severity="info",
            ok=True,
            message=(
                f"KMS 설정을 평가할 수 없어 건너뜁니다 (KmsSettings 로드 실패: {exc}). 수동으로 SECUGENT_KMS_* 확인 필요."
            ),
        )
    if settings.require_external and settings.provider == "local":
        return CheckResult(
            name=name,
            severity="critical",
            ok=False,
            message=(
                "프로덕션에서 Merkle 서명자가 dev HMAC(provider=local)로 설정되어 부팅이 즉시 크래시합니다(B5 fail-closed). "
                "실 KMS를 선택하세요: SECUGENT_KMS_PROVIDER=vault_transit|aws_kms|gcp_kms. "
                "비-프로덕션 평가 목적이라면 SECUGENT_KMS_ALLOW_DEV_HMAC=1 로만 dev HMAC을 허용하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="critical",
        ok=True,
        message=f"KMS 서명자 설정 정상 (provider={settings.provider}, require_external={settings.require_external}).",
    )


def _check_audit_persistence(environ: Mapping[str, str]) -> CheckResult:
    """W6-B — single-node install with no durable audit path ⇒ ephemeral chain (high).

    Heuristic (worded as a warning, not certainty): no ``DATABASE_URL`` (single
    node) AND ``SECUGENT_DB_PATH`` unset means the append-only chain lands on the
    ephemeral default (``.secugent/secugent.db``) and is lost on pod restart.
    """
    name = "audit-persistence"
    has_pg = _present(environ.get("DATABASE_URL"))
    has_db_path = _present(environ.get("SECUGENT_DB_PATH"))
    if not has_pg and not has_db_path:
        return CheckResult(
            name=name,
            severity="high",
            ok=False,
            message=(
                "단일노드 설치에서 SECUGENT_DB_PATH가 지정되지 않아 감사 해시체인이 휘발성 기본 경로에 기록될 수 있습니다"
                "(재시작 시 유실 위험). SECUGENT_DB_PATH를 마운트된 볼륨으로 지정하거나 Postgres(DATABASE_URL)를 사용하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="high",
        ok=True,
        message="감사 저장 경로 정상 (DATABASE_URL 또는 SECUGENT_DB_PATH 지정됨).",
    )


def _check_ha_audit_fork(environ: Mapping[str, str]) -> CheckResult:
    """W6-A — HA enabled without a shared Postgres ⇒ forked audit chain (high).

    HA signal = ``SECUGENT_HA_ENABLED`` truthy OR a replica hint
    (``SECUGENT_REPLICA_COUNT`` > 1). Without a shared ``DATABASE_URL`` each
    replica writes its own SQLite chain → the audit chain forks per pod.
    """
    name = "ha-audit-fork"
    replica_raw = environ.get("SECUGENT_REPLICA_COUNT", "").strip()
    try:
        replicas = int(replica_raw)
    except ValueError:
        replicas = 0
    ha_signal = _truthy(environ.get("SECUGENT_HA_ENABLED")) or replicas > 1
    has_pg = _present(environ.get("DATABASE_URL"))
    if ha_signal and not has_pg:
        return CheckResult(
            name=name,
            severity="high",
            ok=False,
            message=(
                "HA(다중 replica)가 켜져 있으나 공유 Postgres(DATABASE_URL)가 없어 replica마다 감사 체인이 분기(fork)됩니다. "
                "DATABASE_URL로 공유 PG를 지정하거나 SECUGENT_HA_ENABLED를 끄고 단일노드로 운영하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="high",
        ok=True,
        message="HA/감사 체인 정합 정상 (단일노드이거나 공유 PG 구성됨).",
    )


def _check_tool_surface(environ: Mapping[str, str]) -> CheckResult:
    """W6-H — no sandbox roots and no allowed domains ⇒ tools disabled (info).

    Both empty means the built-in tool surface is fully closed (the agent does no
    real file/network tool work). Reported as ``info`` because a locked-down
    deny-by-default posture may be intentional.
    """
    name = "tool-surface"
    has_roots = _present(environ.get("SECUGENT_SANDBOX_ROOTS"))
    has_domains = _present(environ.get("SECUGENT_ALLOWED_DOMAINS"))
    if not has_roots and not has_domains:
        return CheckResult(
            name=name,
            severity="info",
            ok=False,
            message=(
                "SECUGENT_SANDBOX_ROOTS와 SECUGENT_ALLOWED_DOMAINS가 모두 비어 있어 내장 도구가 비활성화됩니다"
                "(에이전트가 실제 파일/네트워크 작업을 못 함). 의도적 deny-by-default가 아니라면 허용 경로/도메인을 지정하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="info",
        ok=True,
        message="내장 도구 표면 활성화됨 (sandbox roots 또는 allowed domains 지정됨).",
    )


def _check_domestic_model(environ: Mapping[str, str]) -> CheckResult:
    """W6-LLM — sovereign endpoint set but no model id ⇒ 404s all calls (high).

    Fires when ``ANTHROPIC_API_KEY`` unset AND ``SECUGENT_DOMESTIC_MODEL_ENDPOINT``
    set AND ``SECUGENT_DOMESTIC_MODEL_ID`` unset — the BYO sovereign endpoint has
    no model selected so every inference call 404s.
    """
    name = "domestic-model"
    has_anthropic = _present(environ.get("ANTHROPIC_API_KEY"))
    has_endpoint = _present(environ.get("SECUGENT_DOMESTIC_MODEL_ENDPOINT"))
    has_model_id = _present(environ.get("SECUGENT_DOMESTIC_MODEL_ID"))
    if not has_anthropic and has_endpoint and not has_model_id:
        return CheckResult(
            name=name,
            severity="high",
            ok=False,
            message=(
                "국산/소버린 모델 엔드포인트(SECUGENT_DOMESTIC_MODEL_ENDPOINT)가 설정됐으나 모델 ID가 없어 모든 추론 호출이 404 됩니다. "
                "SECUGENT_DOMESTIC_MODEL_ID를 설정하세요(예: exaone-3.5)."
            ),
        )
    return CheckResult(
        name=name,
        severity="high",
        ok=True,
        message="모델 설정 정상 (ANTHROPIC_API_KEY 또는 국산모델 endpoint+id 구성됨).",
    )


def _check_ldap_tls(environ: Mapping[str, str]) -> CheckResult:
    """W6-F — LDAP over plaintext ldap:// without an explicit opt-in (high).

    Fires when ``SECUGENT_AUTH_MODE=ldap`` AND ``SECUGENT_LDAP_URI`` is plaintext
    ``ldap://`` AND ``SECUGENT_LDAP_ALLOW_INSECURE_TRANSPORT`` is not truthy — the
    app fails closed at boot; warn early with the fix.
    """
    name = "ldap-tls"
    auth_mode = environ.get("SECUGENT_AUTH_MODE", "").strip().lower()
    uri = environ.get("SECUGENT_LDAP_URI", "").strip().lower()
    allow_insecure = _truthy(environ.get("SECUGENT_LDAP_ALLOW_INSECURE_TRANSPORT"))
    if auth_mode == "ldap" and uri.startswith("ldap://") and not allow_insecure:
        return CheckResult(
            name=name,
            severity="high",
            ok=False,
            message=(
                "LDAP 인증(SECUGENT_AUTH_MODE=ldap)이 평문 ldap:// 로 설정돼 앱이 fail-closed로 거부합니다. "
                "ldaps:// (TLS)를 사용하거나, 의도적이라면 SECUGENT_LDAP_ALLOW_INSECURE_TRANSPORT=1을 명시적으로 설정하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="high",
        ok=True,
        message="LDAP 전송 보안 정상 (ldap 미사용이거나 ldaps:// 또는 명시적 insecure opt-in).",
    )


def _check_egress_bundle(environ: Mapping[str, str]) -> CheckResult:
    """B6 — egress broker on in prod without a signed policy bundle ⇒ BootPolicyError (high).

    The egress broker is on by default (``SECUGENT_EGRESS_BROKER != '0'``). In
    production (``SECUGENT_ENV != dev``) it requires a signed policy bundle AND a
    pinned key id, else boot raises ``BootPolicyError``. Fires when the broker is
    on, the env is production, and either the bundle path or the key-id pin is
    missing.
    """
    name = "egress-bundle"
    broker_on = environ.get("SECUGENT_EGRESS_BROKER", "1").strip() != "0"
    has_bundle = _present(environ.get("SECUGENT_POLICY_BUNDLE_PATH"))
    has_key_ids = _present(environ.get("SECUGENT_POLICY_ALLOWED_KEY_IDS"))
    if broker_on and not _is_dev(environ) and not (has_bundle and has_key_ids):
        return CheckResult(
            name=name,
            severity="high",
            ok=False,
            message=(
                "egress 브로커가 켜진 프로덕션인데 서명된 정책 번들 또는 키 ID 핀이 없어 부팅이 BootPolicyError로 거부됩니다. "
                "번들에 서명·마운트하고(SECUGENT_POLICY_BUNDLE_PATH) 서명 키를 핀(SECUGENT_POLICY_ALLOWED_KEY_IDS)하세요."
            ),
        )
    return CheckResult(
        name=name,
        severity="high",
        ok=True,
        message="egress 정책 번들 정상 (브로커 off이거나 dev이거나 서명 번들+키 핀 구성됨).",
    )


def verify_deploy_preflight(environ: Mapping[str, str]) -> PreflightReport:
    """Statically check a resolved runtime env snapshot for W6/A1 misconfigs.

    Pure and read-only: ``environ`` is the only input; no boot, no I/O, no
    exceptions. Each check mirrors one documented deploy-shell blocker. ``ok`` is
    ``True`` iff every ``critical`` and ``high`` check passed. The ``checks`` order
    is fixed so the report is deterministic (same env → identical report).
    """
    checks: tuple[CheckResult, ...] = (
        _check_kms_signer(environ),
        _check_audit_persistence(environ),
        _check_ha_audit_fork(environ),
        _check_tool_surface(environ),
        _check_domestic_model(environ),
        _check_ldap_tls(environ),
        _check_egress_bundle(environ),
    )
    ok = all(c.ok for c in checks if c.severity in ("critical", "high"))
    return PreflightReport(ok=ok, checks=checks)


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a ``KEY=VALUE`` ``.env`` file into a dict (read-only, I1-safe).

    ``#`` comments and blank lines are ignored. A non-blank, non-comment line
    lacking ``=`` (or with an empty key) is an *operator* error →
    :class:`VerifyInputError`, as is an unreadable file — so a broken preflight
    input fails closed with a clear message rather than silently checking nothing.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifyInputError(f"cannot read --env-file {path}: {exc}") from exc
    parsed: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            raise VerifyInputError(f"--env-file {path} line {lineno} is not KEY=VALUE: {raw!r}")
        parsed[key] = value.strip()
    return parsed


def _build_deploy_env(env_file: Path | None) -> dict[str, str]:
    """Resolve the runtime snapshot: ``os.environ`` overlaid with ``--env-file``."""
    snapshot = dict(os.environ)
    if env_file is not None:
        snapshot.update(_parse_env_file(env_file))
    return snapshot


def _emit_preflight(report: PreflightReport) -> None:
    """Print each preflight finding; route failing critical/high to stderr."""
    for check in report.checks:
        status = "OK" if check.ok else "FINDING"
        to_stderr = (not check.ok) and check.severity in ("critical", "high")
        _emit(
            f"verify: deploy [{check.severity}] {check.name}: {status} - {check.message}",
            stderr=to_stderr,
        )
    verdict = "PASS" if report.ok else "FAIL"
    findings = sum(1 for c in report.checks if not c.ok)
    _emit(
        f"verify: deploy preflight {verdict} ({len(report.checks)} checks, {findings} findings)",
        stderr=not report.ok,
    )


# --------------------------------------------------------------------------- #
# CLI dispatcher (the ``verify`` subcommand; item 3 adds run/demo)
# --------------------------------------------------------------------------- #


def _emit(message: str, *, stderr: bool = False) -> None:
    """Write ``message`` + newline robustly, whatever the console encoding is.

    The deployment target includes Korean Windows hosts whose stdout codec is
    often cp949, which cannot encode every character a tenant id / rationale may
    contain. A bare ``print`` would raise ``UnicodeEncodeError`` and crash the CLI
    mid-proof — unacceptable for a trust tool. We therefore encode to the stream's
    own encoding with ``backslashreplace`` so output is always emitted (worst case
    a non-representable char shows as an escape), never fatal.
    """
    stream = sys.stderr if stderr else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    safe = message.encode(encoding, errors="backslashreplace").decode(encoding)
    print(safe, file=stream)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secugent verify",
        description="Read-only trust proofs: determinism + audit-chain integrity.",
    )
    parser.add_argument("--determinism", action="store_true", help="run the determinism proof")
    parser.add_argument("--chain", action="store_true", help="run the audit hash-chain proof")
    parser.add_argument(
        "--deploy",
        action="store_true",
        help="run the read-only deploy-config preflight doctor (W6/A1 misconfigs)",
    )
    parser.add_argument("--tenant", help="tenant id for the chain proof")
    parser.add_argument("--store", type=Path, help="path to the SQLite audit store")
    parser.add_argument("--fixture", type=Path, help="path to the determinism JSON fixture")
    parser.add_argument(
        "--env-file",
        type=Path,
        dest="env_file",
        help="KEY=VALUE .env file overlaid on os.environ for --deploy",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=100,
        help="determinism sample count (default 100)",
    )
    return parser


def _run_verify(args: argparse.Namespace) -> int:
    """Execute the requested proofs. Returns 0 only if all requested proofs pass.

    No flag selected ⇒ run whichever proofs the provided inputs allow (both when
    fully specified). Fail-closed: any failure or input error ⇒ non-0.
    """
    # "no proof selected" defaults to running determinism + chain (byte-unchanged
    # legacy behavior). --deploy is opt-in: it composes with the other flags but,
    # when selected, does NOT trigger the implicit det+chain default.
    any_selected = args.determinism or args.chain or args.deploy
    run_chain = args.chain or not any_selected
    run_det = args.determinism or not any_selected
    run_deploy = args.deploy

    failures = 0
    ran_any = False

    if run_det:
        if args.fixture is None:
            _emit("verify: --determinism requires --fixture <path>", stderr=True)
            failures += 1
        else:
            try:
                report = verify_determinism(samples=args.samples, seed_fixture=args.fixture)
            except VerifyInputError as exc:
                _emit(f"verify: determinism input error: {exc}", stderr=True)
                failures += 1
            else:
                ran_any = True
                if report.ok:
                    _emit(
                        f"verify: determinism OK - {report.samples} runs identical "
                        f"(digest {report.output_digest[:16]})"
                    )
                else:
                    failures += 1
                    _emit(
                        f"verify: determinism FAILED - {report.distinct_outputs} distinct "
                        f"outputs; {report.first_divergence}",
                        stderr=True,
                    )

    if run_chain:
        if args.tenant is None or args.store is None:
            _emit(
                "verify: --chain requires --tenant <id> and --store <path>",
                stderr=True,
            )
            failures += 1
        else:
            try:
                creport = verify_audit_chain(tenant_id=args.tenant, store_path=args.store)
            except VerifyInputError as exc:
                _emit(f"verify: chain input error: {exc}", stderr=True)
                failures += 1
            else:
                ran_any = True
                if creport.ok and creport.empty:
                    _emit(
                        f"verify: chain OK but EMPTY - tenant {creport.tenant_id!r} "
                        "has 0 events (vacuously intact)"
                    )
                elif creport.ok:
                    _emit(
                        f"verify: chain OK - {creport.events_checked} events link cleanly "
                        f"for tenant {creport.tenant_id!r}"
                    )
                else:
                    failures += 1
                    _emit(
                        f"verify: chain FAILED for tenant {creport.tenant_id!r} - {creport.first_violation}",
                        stderr=True,
                    )

    if run_deploy:
        try:
            snapshot = _build_deploy_env(args.env_file)
        except VerifyInputError as exc:
            _emit(f"verify: deploy input error: {exc}", stderr=True)
            failures += 1
        else:
            ran_any = True
            preflight = verify_deploy_preflight(snapshot)
            _emit_preflight(preflight)
            if not preflight.ok:
                failures += 1

    if not ran_any and failures == 0:
        _emit("verify: nothing to do (no valid inputs provided)", stderr=True)
        return 2
    return 0 if failures == 0 else 1


def main(argv: list[str] | None = None) -> int:
    """``secugent verify [--determinism] [--chain] --tenant <id> ...`` → exit code.

    Accepts either a bare argument list (``["--chain", ...]``) or one that leads
    with the ``verify`` subcommand token (``["verify", "--chain", ...]``) so it
    works both as a direct entry point and when dispatched from
    :mod:`secugent.cli.__main__`. 0 = success, non-0 = failure (fail-closed).
    """
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] == "verify":
        args_list = args_list[1:]
    parser = _build_parser()
    try:
        args = parser.parse_args(args_list)
    except SystemExit as exc:
        # argparse exits 2 on bad usage; preserve fail-closed semantics.
        return int(exc.code) if isinstance(exc.code, int) else 2
    return _run_verify(args)


if __name__ == "__main__":  # pragma: no cover - module entry convenience
    raise SystemExit(main())
