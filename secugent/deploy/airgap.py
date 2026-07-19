# SPDX-License-Identifier: Apache-2.0
"""Air-gap bundle integrity, constraints reproducibility, and HA single-writer.

Three infra-free, deterministic pieces back the deploy artifacts
(``deploy/airgap/bundle.sh``, ``deploy/constraints.txt``, PG HA):

1. **Bundle manifest / checksum** (:func:`build_manifest`, :func:`verify_bundle`)
   — a deterministic sha256 manifest over the bundle's files. ``verify_bundle``
   refuses install on any byte/size/missing/extra drift (invariant **I3**). The
   shell wrapper ``bundle.sh`` materialises the tar; this module owns the *logic*
   so it is unit/property-testable without a tar or a network.
2. **Constraints reproducibility** (:func:`parse_constraints`) — enforces that
   ``constraints.txt`` is **fully exact-pinned** (``name==version``). Any range
   (``>=``/``~=``/``*``), marker, extra, or unpinned line is rejected, because a
   non-pin makes the bundle non-reproducible (invariant **I2**).
3. **HA single writer** (:class:`HaWriterArbiter`) — a thin, in-process gate over
   the existing :class:`secugent.orchestrator.lease.LeaseManager`. Exactly the
   lease *leader* may write; a standby only promotes after the primary releases
   the leader lock, so a *controlled* (step-down/release-driven) failover never
   branches/duplicates writes. This module re-implements **no** lease logic — it
   delegates.

   SCOPE / HONESTY (LOW-12 fix — docstring updated to match actual wiring):
   The single-writer gate IS wired: ``create_app`` calls
   ``event_store_pg.set_writer_guard`` (``main.py`` ~:2529) so the
   ``HaWriterArbiter._assert_writer`` path runs on every PG-backed append.
   However, two genuine residual limits remain:

   (a) The guarantee is **single-process / session-scoped**: the leader lock is
   a ``pg_advisory_lock`` taken on one pooled connection.  It is NOT a durable
   cross-process fence — a second app process on a different host can take its
   own advisory lock on the same PG primary without detecting the first holder.
   (b) **Two independent PG servers** (primary + standby) each have separate
   advisory-lock namespaces, so an app-level lease cannot prevent a PostgreSQL
   split-brain without DB-level fencing (STONITH / sync-replication + connection
   cutover).  The deploy docs therefore describe single-writer serialization
   against ONE PG instance + operator-driven promotion, NOT an automatic
   lease-expiry failover or a multi-process-safe fence.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from secugent.core.event_store_base import LeaderLostError
from secugent.deploy.errors import BundleIntegrityError, ConstraintsError
from secugent.orchestrator.lease import LeaseManager

__all__ = [
    "BundleEntry",
    "BundleIntegrityError",
    "BundleManifest",
    "ConstraintsError",
    "HaWriterArbiter",
    "PinnedRequirement",
    "build_manifest",
    "parse_constraints",
    "verify_bundle",
]


# --------------------------------------------------------------------------- #
# Bundle manifest — deterministic checksum over the bundle's files
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BundleEntry:
    """One file in the air-gap bundle: normalized POSIX path + sha256 + size."""

    path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class BundleManifest:
    """Deterministic record of a bundle's contents.

    ``entries`` are sorted ascending by ``path`` and carry no duplicates, so two
    bundles built from the same files always yield an identical manifest and
    identical :meth:`manifest_sha256` (invariant **I2**).
    """

    version: str
    entries: tuple[BundleEntry, ...]

    def manifest_sha256(self) -> str:
        """A single digest over (version, sorted entries) — the bundle fingerprint.

        Built from a canonical newline-joined ``path\\x00sha256\\x00size`` form so
        it is stable across runs/platforms and independent of dict ordering.
        """
        hasher = hashlib.sha256()
        hasher.update(self.version.encode("utf-8"))
        hasher.update(b"\n")
        for entry in self.entries:
            line = f"{entry.path}\x00{entry.sha256}\x00{entry.size_bytes}\n"
            hasher.update(line.encode("utf-8"))
        return hasher.hexdigest()


def _normalize_path(raw: str) -> str:
    """Normalize a bundle-relative path to a stable POSIX form.

    Strips a leading ``./`` and collapses ``\\`` to ``/`` so ``./a/b`` and
    ``a\\b`` map to the same entry. Rejects absolute paths and ``..`` traversal
    fail-fast — a bundle path must never escape the bundle root (path-injection
    guard, §B-7).
    """
    candidate = raw.replace("\\", "/").strip()
    while candidate.startswith("./"):
        candidate = candidate[2:]
    if not candidate or candidate.startswith("/") or ".." in candidate.split("/"):
        raise BundleIntegrityError(f"invalid bundle path: {raw!r}")
    return candidate


def build_manifest(*, version: str, files: Mapping[str, bytes]) -> BundleManifest:
    """Build a deterministic :class:`BundleManifest` from a path->bytes mapping.

    ``version`` must be non-blank. Paths are normalized; a collision after
    normalization (e.g. ``./a`` and ``a``) is rejected, because it would make the
    manifest ambiguous (which bytes are authoritative?). Pure — no I/O.
    """
    if not version or not version.strip():
        raise BundleIntegrityError("bundle version must be non-blank")

    by_path: dict[str, BundleEntry] = {}
    for raw_path, data in files.items():
        path = _normalize_path(raw_path)
        if path in by_path:
            raise BundleIntegrityError(f"duplicate bundle path after normalization: {path!r}")
        by_path[path] = BundleEntry(
            path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        )
    entries = tuple(by_path[p] for p in sorted(by_path))
    return BundleManifest(version=version, entries=entries)


def verify_bundle(manifest: BundleManifest, files: Mapping[str, bytes]) -> None:
    """Assert ``files`` matches ``manifest`` exactly, else refuse install (I3).

    Deny-by-default: the present set must equal the manifest set (no missing, no
    extra) AND every file's sha256+size must match. The first discrepancy raises
    :class:`BundleIntegrityError`; the caller (install verifier / ``bundle.sh``
    driver) treats that as a hard install refusal.
    """
    present: dict[str, bytes] = {}
    for raw_path, data in files.items():
        path = _normalize_path(raw_path)
        if path in present:
            raise BundleIntegrityError(f"duplicate path in candidate bundle: {path!r}")
        present[path] = data

    expected = {entry.path: entry for entry in manifest.entries}

    missing = sorted(set(expected) - set(present))
    if missing:
        raise BundleIntegrityError(f"bundle missing files: {missing}")
    extra = sorted(set(present) - set(expected))
    if extra:
        raise BundleIntegrityError(f"bundle has unexpected files: {extra}")

    for path, entry in expected.items():
        data = present[path]
        if len(data) != entry.size_bytes:
            raise BundleIntegrityError(
                f"size mismatch for {path!r}: expected {entry.size_bytes}, got {len(data)}"
            )
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry.sha256:
            raise BundleIntegrityError(
                f"checksum mismatch for {path!r}: expected {entry.sha256}, got {digest}"
            )


# --------------------------------------------------------------------------- #
# Constraints — exact-pin reproducibility (I2)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PinnedRequirement:
    """A single exact pin from ``constraints.txt`` — PEP503-normalized name + version."""

    name: str
    version: str


# An exact pin: ``name==version`` with no extras, no markers, no range operators.
# Name per PEP 508 (letters/digits/._-); version is a non-empty token without
# whitespace or wildcards. Anything else is a reproducibility hazard.
_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.\-_+!]*)$")


def _normalize_name(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of ``[-_.]`` -> single ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_constraints(text: str) -> tuple[PinnedRequirement, ...]:
    """Parse ``constraints.txt``, enforcing that every line is an exact pin (I2).

    Blank lines and ``#`` comments are ignored. Every other line must match
    ``name==version`` exactly — a range (``>=``/``~=``/``<``), wildcard (``*``),
    extras (``pkg[all]``), or environment marker (``; python_version<...``) makes
    the bundle non-reproducible and raises :class:`ConstraintsError`. Names are
    PEP503-normalized so duplicates collapse predictably.
    """
    pins: list[PinnedRequirement] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PIN_RE.match(line)
        if match is None:
            raise ConstraintsError(f"constraints line {lineno} is not an exact pin (name==version): {raw!r}")
        pins.append(PinnedRequirement(name=_normalize_name(match.group(1)), version=match.group(2)))
    return tuple(pins)


# --------------------------------------------------------------------------- #
# HA single-writer arbiter — delegates to the existing LeaseManager (I3)
# --------------------------------------------------------------------------- #


# A fixed run-id under which the *writer* (leader) role is leased. The arbiter is
# only a naming/guard shim over the leader lock — it owns no SQL and no lease
# bookkeeping of its own (control decisions have a single source of
# truth; wrappers call core, they never re-decide).
_WRITER_ROLE = "ha-writer"


class HaWriterArbiter:
    """Single-writer gate over a :class:`LeaseManager` for PG HA failover.

    Exactly one worker may hold the writer role at a time. A standby's
    :meth:`try_become_writer` fails while the primary holds the leader lock, and
    only succeeds after the primary :meth:`step_down`\\ s — so a *controlled*
    primary->standby promotion never produces two concurrent writers.

    NOT a runtime I3 guarantee (yet): this arbiter is provisioned but not wired
    into the live append path, and the writer/leader lease has **no TTL/expiry**,
    so a writer that crashes WITHOUT calling :meth:`step_down` holds the role
    until an operator/orchestrator reclaims it — promotion is operator-driven, not
    automatic-on-crash. The leader lease is also not a cross-PG-server fence (see
    the module docstring). Acquisition happens ONLY via :meth:`try_become_writer`;
    :meth:`assert_writer` is a pure read-only check that never acquires.

    All arbitration is delegated to ``lease.try_acquire_leader`` / ``is_leader`` /
    ``release_leader``; this class re-implements none of it.
    """

    def __init__(self, lease: LeaseManager) -> None:
        self._lease = lease

    async def try_become_writer(self, worker_id: str) -> bool:
        """Try to acquire the writer (leader) role. Returns True iff this worker holds it."""
        return await self._lease.try_acquire_leader(worker_id)

    async def assert_writer(self, worker_id: str) -> None:
        """Fail closed if ``worker_id`` is not the current sole writer.

        Pure, NON-mutating ownership check via :meth:`LeaseManager.is_leader` — it
        must never *acquire* leadership as a side effect. (Re-using the acquiring
        :meth:`try_acquire_leader` here was a fail-open defect: when the leader
        slot was free, a non-writer's "assertion" silently promoted it instead of
        raising.) A non-writer raises :class:`LeaderLostError`, blocking the write
        — deny-by-default. Acquisition belongs solely in :meth:`try_become_writer`.
        """
        if not await self._lease.is_leader(worker_id):
            raise LeaderLostError(f"worker {worker_id!r} is not the writer ({_WRITER_ROLE}); write denied")

    async def step_down(self, worker_id: str) -> None:
        """Release the writer role so a standby may promote (controlled failover)."""
        await self._lease.release_leader(worker_id)
