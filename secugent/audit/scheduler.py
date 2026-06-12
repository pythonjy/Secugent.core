# SPDX-License-Identifier: Apache-2.0
"""20260603-02-BE — daily Merkle root sealing scheduler.

EU AI Act Art.26 requires high-risk-AI operators to retain machine-generated
logs for 6+ months. SecuGent's hash chain (:mod:`secugent.audit.hash_chain`)
already links every event tamper-evidently; this scheduler closes the loop by
**sealing** each tenant's daily event hashes into a signed Merkle root
(:class:`secugent.audit.merkle.SignedMerkleRoot`) and persisting an append-only
evidence file plus an ``audit.merkle_sealed`` chain event (§C-2).

Design (see ``docs/specs/2026-06-03-audit-merkle-scheduler.md``):

* stdlib only — :class:`threading.Thread` + :class:`threading.Event` for a
  graceful, leak-free background loop. No APScheduler/croniter (§A-2.6
  air-gapped/on-prem first; daily once is trivial without a 3rd-party
  scheduler).
* Evidence file ``output_dir/YYYY/MM/merkle_YYYYMMDD.json`` is append-only:
  re-sealing the same day raises :class:`FileExistsError` (a re-seal attempt is
  treated as tampering).
* Per-tenant isolation: one failing tenant is logged and skipped, the rest of
  the run continues (availability), while file-level append-only preserves
  fail-closed integrity.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Protocol

from secugent.audit.merkle import MerkleSigner, SignedMerkleRoot
from secugent.core.contracts import Event

__all__ = ["DailyMerkleScheduler", "RetentionHook"]

# A retention pass driven once per seal. Receives the sealed day; runs AFTER the
# seal (file + chain) is durably committed so a retention failure can never roll
# back a seal (G-H2 fail-closed ordering).
RetentionHook = Callable[[date], None]

_LOG = logging.getLogger("secugent.audit.scheduler")

# Fixed +09:00 fallback so the evidence timestamp stays KST (§C-3) even on
# air-gapped hosts that ship without the IANA tzdata database.
_KST = timezone(timedelta(hours=9), "KST")


def _kst_zone() -> timezone:
    """Return the KST tzinfo, preferring IANA ``Asia/Seoul`` when available."""
    try:
        from zoneinfo import ZoneInfo

        # ZoneInfo is a tzinfo; the return annotation stays ``timezone`` for the
        # fixed-offset fallback. Both satisfy the consumer (``.isoformat()``).
        return ZoneInfo("Asia/Seoul")  # type: ignore[return-value]
    except Exception:  # noqa: BLE001 - missing tzdata on air-gapped host
        return _KST


class _ChainStore(Protocol):
    """Structural view of the bits of ``ChainedEventStore`` we depend on."""

    def iter_hashes_for_day(self, *, tenant_id: str, day: date, tz: tzinfo = ...) -> Iterable[str]: ...
    def append_event(self, event: Event) -> object: ...


@dataclass(frozen=True)
class _PendingSealEvent:
    """A seal-event append deferred until the evidence file is durably written.

    Writing the evidence file first then appending the chain event (which only
    back-references the file via ``evidence_rel``) guarantees the chain never
    holds a dangling ``evidence_path`` after a file-write failure
    (SG-20260603-21).
    """

    tenant_id: str
    root: SignedMerkleRoot
    event_count: int
    evidence_rel: str


class DailyMerkleScheduler:
    """Seal each tenant's daily event chain into a signed Merkle root."""

    def __init__(
        self,
        *,
        chain_store: _ChainStore,
        signer: MerkleSigner,
        tenant_ids: list[str],
        output_dir: Path,
        run_hour_utc: int = 15,
        retention_hook: RetentionHook | None = None,
    ) -> None:
        if not 0 <= run_hour_utc <= 23:
            raise ValueError(f"run_hour_utc must be in [0,23], got {run_hour_utc}")
        self._chain_store = chain_store
        self._signer = signer
        self._tenant_ids = list(tenant_ids)
        self._output_dir = Path(output_dir)
        self._run_hour_utc = run_hour_utc
        self._retention_hook = retention_hook
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        """Start the background sealing loop (idempotent while running)."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="merkle-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the loop to stop and join it (no thread leak). Idempotent."""
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join()
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = datetime.now(tz=UTC)
            wait_s = self._seconds_until_next_run(now)
            # Wake early if stop() fires; returns True when stopped.
            if self._stop.wait(timeout=wait_s):
                return
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - keep the unattended loop alive
                _LOG.exception("daily merkle run_once failed; retrying next cycle")

    def _seconds_until_next_run(self, now: datetime) -> float:
        target = now.replace(hour=self._run_hour_utc, minute=0, second=0, microsecond=0)
        if target <= now:
            target = target + timedelta(days=1)
        return (target - now).total_seconds()

    # ------------------------------------------------------------------ #
    # Sealing
    # ------------------------------------------------------------------ #

    def run_once(self, *, day: date | None = None) -> list[SignedMerkleRoot]:
        """Seal ``day`` (default: yesterday UTC) for every configured tenant.

        Only the events whose timestamp falls on ``day`` (UTC boundary) are
        sealed — the evidence file's ``day``/``event_count`` describe exactly
        that day's set, not the tenant's cumulative chain (SG-20260603-20).

        Returns the roots that were successfully sealed. A tenant whose hashes
        cannot be read is logged and skipped; the rest of the run continues.
        The evidence file is written *before* the back-referencing seal events
        are appended (SG-20260603-21), so a file-write failure never leaves a
        dangling ``evidence_path``. Re-sealing a day whose evidence file already
        exists raises :class:`FileExistsError`.
        """
        seal_day = day if day is not None else self._yesterday_utc()
        if not self._tenant_ids:
            return []

        out_path = self._output_path(self._output_dir, seal_day)
        if out_path.exists():
            raise FileExistsError(f"merkle evidence for {seal_day.isoformat()} already exists: {out_path}")

        generated_at = datetime.now(tz=_kst_zone()).isoformat()
        sealed: list[SignedMerkleRoot] = []
        lines: list[str] = []
        # Defer seal-event appends until AFTER the evidence file is durably
        # written (SG-20260603-21). The evidence file is the primary record and
        # the chain event only back-references it via ``evidence_path``; writing
        # the file first means a file-write failure can never leave a dangling
        # seal event pointing at a non-existent evidence file.
        pending_events: list[_PendingSealEvent] = []
        for tenant_id in self._tenant_ids:
            outcome = self._seal_tenant(tenant_id, seal_day, generated_at)
            if outcome is None:
                continue
            root, line, pending = outcome
            sealed.append(root)
            lines.append(line)
            pending_events.append(pending)

        if lines:
            self._write_evidence(out_path, lines)
        # Evidence is now durable on disk → append the redaction-safe seal
        # events that reference it.
        for pending in pending_events:
            self._append_seal_event(
                pending.tenant_id,
                pending.root,
                pending.event_count,
                pending.evidence_rel,
            )
        # Retention runs LAST (G-H2): the seal (file + chain) is the primary
        # compliance artifact and is already committed. A retention failure is
        # best-effort cleanup and must never roll back a seal, so it is logged
        # and swallowed here (fail-closed ordering).
        self._run_retention(seal_day)
        return sealed

    def _run_retention(self, seal_day: date) -> None:
        if self._retention_hook is None:
            return
        try:
            self._retention_hook(seal_day)
        except Exception:  # noqa: BLE001 - retention is best-effort post-seal
            _LOG.error(
                "retention hook failed after sealing %s; seal is unaffected",
                seal_day.isoformat(),
                exc_info=True,
            )

    def _seal_tenant(
        self, tenant_id: str, seal_day: date, generated_at: str
    ) -> tuple[SignedMerkleRoot, str, _PendingSealEvent] | None:
        try:
            # Day-scoped: seal only the events that actually fall on ``seal_day``
            # (UTC boundary, consistent with the "yesterday UTC" target) so the
            # evidence file's day/event_count describe that day's set, not the
            # tenant's full cumulative chain (SG-20260603-20).
            hashes = list(self._chain_store.iter_hashes_for_day(tenant_id=tenant_id, day=seal_day, tz=UTC))
        except Exception:  # noqa: BLE001 - isolate one tenant's failure
            _LOG.error(
                "skipping tenant %r: failed to read event hashes",
                tenant_id,
                exc_info=True,
            )
            return None

        root = self._signer.sign_day(day=seal_day, hashes=hashes)
        line = json.dumps(
            {
                "day": seal_day.isoformat(),
                "tenant_id": tenant_id,
                "root_hex": root.root_hex,
                "signature_hex": root.signature_hex,
                "key_id": root.key_id,
                "algorithm": root.algorithm,
                "generated_at": generated_at,
                "event_count": len(hashes),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        pending = _PendingSealEvent(
            tenant_id=tenant_id,
            root=root,
            event_count=len(hashes),
            evidence_rel=self._evidence_rel_path(seal_day),
        )
        return root, line, pending

    def _append_seal_event(
        self,
        tenant_id: str,
        root: SignedMerkleRoot,
        event_count: int,
        evidence_rel: str,
    ) -> None:
        # NB: ``root_hex`` is deliberately NOT in the chain-event payload. The
        # store's redaction (secugent/core/logger.py) rewrites 64-hex strings to
        # ``[REDACTED:KEY]``, which would desync the canonical body the hash
        # chain signs from the stored body it re-verifies → broken verify_chain.
        # The root lives in the (un-redacted) evidence file; the event carries a
        # redaction-safe ``evidence_path`` back-reference instead.
        try:
            self._chain_store.append_event(
                Event(
                    tenant_id=tenant_id,
                    actor="system",
                    type="audit.merkle_sealed",
                    severity="info",
                    payload={
                        "gate": "audit",
                        "day": root.day.isoformat(),
                        "key_id": root.key_id,
                        "algorithm": root.algorithm,
                        "event_count": event_count,
                        "evidence_path": evidence_rel,
                        "regulations_version": "n/a",
                    },
                )
            )
        except Exception:  # noqa: BLE001 - file is the primary evidence
            _LOG.error(
                "tenant %r sealed but seal-event append failed",
                tenant_id,
                exc_info=True,
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _output_path(output_dir: Path, day: date) -> Path:
        return Path(output_dir) / DailyMerkleScheduler._evidence_rel_path(day)

    @staticmethod
    def _evidence_rel_path(day: date) -> str:
        return f"{day.year:04d}/{day.month:02d}/merkle_{day.strftime('%Y%m%d')}.json"

    @staticmethod
    def _write_evidence(out_path: Path, lines: list[str]) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # ``x`` mode = exclusive create → append-only at the day granularity.
        with out_path.open("x", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    @staticmethod
    def _yesterday_utc() -> date:
        return (datetime.now(tz=UTC) - timedelta(days=1)).date()
