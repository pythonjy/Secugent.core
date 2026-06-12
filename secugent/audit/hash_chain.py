# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — hash-chained event log decorator.

Wraps the PHASE 0 :class:`secugent.core.event_store.EventStore` so every
event written through the chain carries:

* ``prev_hash`` — SHA-256 hex of the previous event's canonical form, or
  the literal string ``"GENESIS"`` for the first event in a tenant chain.
* ``event_hash`` — SHA-256 hex of ``prev_hash || canonical(event_body)``.

A single-byte tamper anywhere in the underlying SQLite events table will
desync ``event_hash`` from the next event's ``prev_hash`` and
:meth:`ChainedEventStore.verify_chain` raises
:class:`AuditChainBrokenError`.

Storage choice: rather than alter every PHASE 0/9/10 caller, we keep
PHASE 0 events untouched and persist the chain in a sibling table
``event_chain`` keyed by event id. Lookups join on event id; tampers in
either table trip the verifier.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, tzinfo

from pydantic import ValidationError

from secugent.core.contracts import Event
from secugent.core.event_store import EventStore, _iso, _parse_dt
from secugent.core.logger import redact

__all__ = [
    "GENESIS",
    "AuditChainBrokenError",
    "ChainedEventRecord",
    "ChainedEventStore",
    "canonical",
    "compute_chain_hash",
    "stored_view",
]


class AuditChainBrokenError(RuntimeError):
    """Raised by the verifier when the hash chain does not link cleanly."""


# Stage 1 (G-M8): ``GENESIS`` plus the three pure functions below are the
# *single source of truth* for hash-chain determinism. They are backend-agnostic
# (no SQLite/PG coupling) so the SQLite :class:`ChainedEventStore` and the PG
# ``PgChainedEventStore`` derive byte-identical ``event_hash`` sequences from the
# same event stream. The ``_``-prefixed aliases below preserve every existing
# import (backward compatibility).
GENESIS = "GENESIS"

_CHAIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_chain (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    body_canonical TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chain_tenant_seq ON event_chain(tenant_id, seq);
"""


@dataclass(frozen=True)
class ChainedEventRecord:
    event: Event
    seq: int
    prev_hash: str
    event_hash: str


def canonical(event: Event) -> str:
    """JSON Canonicalization Scheme-lite — sort keys + ensure_ascii=False."""
    body = event.model_dump(mode="json")
    return json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def stored_view(event: Event) -> Event:
    """Return the event exactly as :class:`EventStore` durably persists it.

    The store redacts the payload (SECURITY_CONTRACT §6) and normalises the
    timestamp to UTC before writing, then reconstructs the event on read. The
    hash chain MUST hash that *redacted, normalised* form — not the raw event —
    so that (a) ``event_hash``/``body_canonical`` never carry plaintext
    PII/secrets (SG-02) and (b) ``verify_chain`` re-deriving from the store
    matches the stored hash instead of false-tripping on redaction (SG-01).

    This mirrors ``EventStore.append_event`` + ``EventStore._row_to_event``;
    a round-trip test keeps the two in lock-step.
    """
    redacted_payload = json.loads(json.dumps(redact(event.payload), ensure_ascii=False))
    return Event(
        id=event.id,
        tenant_id=str(event.tenant_id),
        ts=_parse_dt(_iso(event.ts)),
        actor=event.actor,
        type=event.type,
        payload=redacted_payload,
        severity=event.severity,
        run_id=event.run_id,
        step_id=event.step_id,
    )


def compute_chain_hash(prev_hash: str, canonical_body: str) -> str:
    """``sha256(prev_hash + "\\x00" + canonical_body)`` as hex (chain link hash)."""
    return hashlib.sha256((prev_hash + "\x00" + canonical_body).encode("utf-8")).hexdigest()


# Backward-compatible aliases — existing callers/tests import the ``_`` names.
_GENESIS = GENESIS
_canonical = canonical
_stored_view = stored_view
_hash = compute_chain_hash


class ChainedEventStore:
    """Decorator around :class:`EventStore` that maintains a sha256 chain."""

    def __init__(self, inner: EventStore) -> None:
        self._inner = inner
        self._lock = threading.RLock()
        # Reuse the wrapped store's SQLite connection via its path so we run
        # in the same DB file and benefit from its WAL mode.
        self._conn = sqlite3.connect(
            str(inner.path),
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.executescript(_CHAIN_SCHEMA)

    # ------------------------------------------------------------------ #
    # Pass-through accessors (so callers can use this as drop-in for
    # PHASE 0 EventStore where convenient — keeps PHASE 12 wiring small)
    # ------------------------------------------------------------------ #

    @property
    def inner(self) -> EventStore:
        return self._inner

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:  # pragma: no cover
                pass
        self._inner.close()

    # ------------------------------------------------------------------ #
    # Write path
    # ------------------------------------------------------------------ #

    def append_event(self, event: Event) -> ChainedEventRecord:
        # Hash the redacted/normalised form the store actually persists, so the
        # chain never holds plaintext PII (SG-02) and verify never false-trips
        # on redaction (SG-01).
        stored = _stored_view(event)
        canonical = _canonical(stored)
        with self._lock:
            prev_hash, seq = self._tail(event.tenant_id)
            event_hash = _hash(prev_hash, canonical)

            def _write_chain_row(conn: sqlite3.Connection) -> None:
                conn.execute(
                    "INSERT INTO event_chain(event_id, tenant_id, seq, prev_hash, "
                    "event_hash, body_canonical) VALUES(?,?,?,?,?,?)",
                    (
                        event.id,
                        str(event.tenant_id),
                        seq,
                        prev_hash,
                        event_hash,
                        canonical,
                    ),
                )

            # Atomic write (SG-20260602-02): the event body and its chain row are
            # committed in a single transaction on the store's connection. If
            # either INSERT fails the whole unit rolls back, so a transient store
            # failure can never leave a dangling chain row that would make
            # verify_chain fail permanently. The chain row is written through the
            # inner connection (same DB file) so it shares that transaction.
            self._inner.append_event_atomic(event, within_txn=_write_chain_row)
        return ChainedEventRecord(event=stored, seq=seq, prev_hash=prev_hash, event_hash=event_hash)

    def _tail(self, tenant_id: str) -> tuple[str, int]:
        cur = self._conn.execute(
            "SELECT prev_hash, event_hash, seq FROM event_chain WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
            (tenant_id,),
        )
        row = cur.fetchone()
        if row is None:
            return _GENESIS, 0
        return row[1], int(row[2]) + 1

    # ------------------------------------------------------------------ #
    # Read path + verification
    # ------------------------------------------------------------------ #

    def _iter_chain_rows(self, *, tenant_id: str) -> list[tuple[Event, int, str, str, str]]:
        """Read all chain rows for a tenant as ``(event, seq, prev, hash, body)``.

        ``event`` is reconstructed from the stored (redacted) ``body_canonical``
        so it never exposes plaintext PII.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id, seq, prev_hash, event_hash, body_canonical "
                "FROM event_chain WHERE tenant_id=? ORDER BY seq ASC",
                (tenant_id,),
            )
            rows = cur.fetchall()
        out: list[tuple[Event, int, str, str, str]] = []
        for event_id, seq, prev_hash, event_hash, body_canonical in rows:
            try:
                event = Event.model_validate(json.loads(body_canonical))
            except (json.JSONDecodeError, ValidationError) as exc:
                # A chain row whose body is no longer a valid Event has been
                # corrupted/tampered — fail closed as a chain break rather than
                # leaking a raw parse error.
                raise AuditChainBrokenError(
                    f"event {event_id} chain body is corrupt at seq={seq}: {exc}"
                ) from exc
            out.append((event, int(seq), prev_hash, event_hash, body_canonical))
        return out

    def read_chain(self, *, tenant_id: str) -> list[ChainedEventRecord]:
        return [
            ChainedEventRecord(event=event, seq=seq, prev_hash=prev_hash, event_hash=event_hash)
            for event, seq, prev_hash, event_hash, _body in self._iter_chain_rows(tenant_id=tenant_id)
        ]

    def verify_chain(self, *, tenant_id: str) -> bool:
        """Walk the chain front-to-back and re-derive every event hash.

        Verification is independent of tenant history size (SG-03): each chain
        record is checked against its own stored ``body_canonical`` for chain
        integrity, then matched to the store one event at a time by id. Raises
        :class:`AuditChainBrokenError` on the first inconsistency — a sha256
        mismatch (chain-table tamper), a desync against the underlying
        :class:`EventStore` payload (store-table tamper), or a chained event
        missing from the store (SG-05 partial-write gap).
        """
        last_hash = _GENESIS
        for event, seq, prev_hash, event_hash, body_canonical in self._iter_chain_rows(tenant_id=tenant_id):
            expected_event_hash = _hash(last_hash, body_canonical)
            if prev_hash != last_hash:
                raise AuditChainBrokenError(f"prev_hash mismatch at seq={seq} (event={event.id})")
            if event_hash != expected_event_hash:
                raise AuditChainBrokenError(
                    f"event_hash mismatch at seq={seq} (event={event.id}) — chain record tampered"
                )
            live = self._inner.get_event(event.id, tenant_id=tenant_id)
            if live is None:
                raise AuditChainBrokenError(f"event {event.id} present in chain but missing from store")
            if _canonical(live) != body_canonical:
                raise AuditChainBrokenError(
                    f"event_hash mismatch at seq={seq} (event={event.id}) — underlying payload tampered"
                )
            last_hash = event_hash
        return True

    # ------------------------------------------------------------------ #
    # Helpers for downstream (Merkle batcher)
    # ------------------------------------------------------------------ #

    def iter_hashes(self, *, tenant_id: str) -> Iterable[str]:
        for record in self.read_chain(tenant_id=tenant_id):
            yield record.event_hash

    def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = UTC) -> Iterable[str]:
        """Yield ``event_hash`` only for events whose timestamp falls on ``day``.

        Additive companion to :meth:`iter_hashes` (whole-chain) used by the
        daily Merkle sealer so a "daily" root covers exactly that day's events
        rather than the tenant's full cumulative history. The day boundary is
        evaluated in ``tz`` (default UTC, consistent with the sealer's
        "yesterday UTC" target); ``event.ts`` is timezone-aware so the
        comparison is unambiguous. Chain seq order (``read_chain``) is
        preserved among the matching events, so a fixed day + tenant yields a
        deterministic hash sequence.
        """
        for record in self.read_chain(tenant_id=tenant_id):
            if record.event.ts.astimezone(tz).date() == day:
                yield record.event_hash
