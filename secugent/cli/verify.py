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
import sqlite3
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

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
    "DeterminismReport",
    "VerifyInputError",
    "main",
    "verify_audit_chain",
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
    parser.add_argument("--tenant", help="tenant id for the chain proof")
    parser.add_argument("--store", type=Path, help="path to the SQLite audit store")
    parser.add_argument("--fixture", type=Path, help="path to the determinism JSON fixture")
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
    run_chain = args.chain or (not args.determinism and not args.chain)
    run_det = args.determinism or (not args.determinism and not args.chain)

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
