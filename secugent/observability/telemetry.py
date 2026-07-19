# SPDX-License-Identifier: Apache-2.0
"""Opt-in adoption telemetry collector (Core observability).

Why
---
The 6-month "adoption metrics" KPI and OEM pitches need a basis for *what is
actually used*. This collector provides one **without ever shipping PII or
policy content off-box** (§A-2.6 closed-network first; §A privacy).

Design (privacy by construction)
--------------------------------
* **DEFAULT-OFF** — :class:`TelemetryCollector` is a complete no-op until an
  operator opts in (``SECUGENT_TELEMETRY_OPTIN=1`` ⇒
  :class:`~secugent.core.settings.TelemetrySettings`). When off, *nothing* is
  created, buffered, or sent (Invariant I1). No Prometheus collector is
  registered on any global registry, so the metric never appears on ``/metrics``
  even as HELP/TYPE metadata.
* **Counts only, closed name channel** — :meth:`record_feature` increments an
  in-memory counter for a feature *name*. There is no value channel, and the
  name itself is **not** free text: it is validated against a strict
  ``[a-z0-9._]{1,64}`` identifier pattern and rejected otherwise. A caller cannot
  smuggle PII, policy text, a user/tenant id, an email, or an RRN through the
  feature name (Invariant I2, enforced structurally — deny-by-default §A-2.2).
  Distinct names are also **cardinality-bounded**: beyond ``max_features``
  buckets, further new names are coalesced into a single overflow bucket so a
  long-running on-prem process can never grow memory or Prometheus label
  cardinality without bound.
* **Pseudonymous (not anonymous) instance id** — :meth:`instance_hash` is a
  **keyed** HMAC-SHA256 over an opaque install/host value, keyed by a
  *per-install secret* (random by default, never emitted). Same id + same secret
  ⇒ same digest; same id + different secret ⇒ different digest. The raw value is
  never put in the flushed payload. NOTE: this is *pseudonymous*, not provably
  anonymous — the digest is a stable per-install pseudonym, and reversal is hard
  only because the keying secret is secret (a bare SHA-256 of a low-entropy
  hostname under a public constant salt would be trivially preimage-recoverable;
  we do not make that claim). Invariant I3 = "the digest does not reveal the raw
  id to anyone who lacks the per-install secret", NOT "irreversible for all".
* **Local-first sink** — :class:`TelemetrySink` is a minimal structural Protocol
  that flushes the aggregate to a *local* buffer/file. A sink error (disk full)
  is swallowed at the telemetry boundary so the application is **never** affected
  (fail-soft). This is the one place a broad ``except`` is justified.
* **In-memory / sink-only** — telemetry is NOT exported through Prometheus. There
  is no forked Prometheus counter; the in-memory aggregate is the single source
  of truth, flushed only to the optional local sink.
* **Fully separable** — this module imports neither the audit hash-chain nor
  REGULATIONS. Telemetry can be deleted without touching control logic.

Thread-safety
-------------
:meth:`record_feature` and :meth:`snapshot` take a lock so concurrent callers
observe consistent counts.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import threading
from collections import Counter
from typing import Final, Protocol, runtime_checkable

__all__ = [
    "TelemetryCollector",
    "TelemetrySink",
]

_log = logging.getLogger(__name__)

# Domain-separation prefix for the keyed instance digest. Constant (not secret):
# it only namespaces the HMAC message so the digest is a *telemetry* identity
# rather than colliding with an unrelated HMAC elsewhere. Security comes from the
# per-install SECRET key (see ``instance_secret``), not from this prefix.
_INSTANCE_HASH_DOMAIN: Final = b"secugent.telemetry.instance.v2\x00"

# Feature names are a CLOSED identifier channel, not free text. A name must be a
# lowercase ascii identifier so a caller cannot smuggle PII (emails, RRNs, names,
# paths) and so the value can never explode label cardinality (Invariant I2).
_FEATURE_NAME_RE: Final = re.compile(r"[a-z0-9._]{1,64}")

# Default cap on the number of distinct feature buckets kept in memory. Beyond
# this, new names coalesce into the overflow bucket (Invariant: bounded memory /
# bounded cardinality even under semi-dynamic or hostile callers).
_DEFAULT_MAX_FEATURES: Final = 256

# Minimum length (bytes) for an operator-supplied instance keying secret. A
# shorter (or empty) secret cannot provide the keyed-HMAC privacy guarantee
# (Invariant I3): an empty key makes the digest reproducible from public info
# alone (``_INSTANCE_HASH_DOMAIN`` + a low-entropy hostname). 16 bytes = 128
# bits is the floor for a key that is not brute-forceable. The random default
# (``secrets.token_bytes(32)``) comfortably exceeds this.
_MIN_INSTANCE_SECRET_LEN: Final = 16


@runtime_checkable
class TelemetrySink(Protocol):
    """Local-first sink: receives an anonymized aggregate ``{feature: count}``.

    Implementations write to a local buffer/file. They MUST NOT be relied upon
    for delivery — the collector swallows sink errors (fail-soft).
    """

    def flush(self, payload: dict[str, int]) -> None:  # pragma: no cover - protocol
        ...


class TelemetryCollector:
    """Privacy-respecting, default-off, on-prem adoption telemetry collector.

    All public methods are no-ops while ``opt_in`` is ``False``.
    """

    #: Sentinel bucket name into which feature names beyond ``max_features`` are
    #: coalesced. Itself a valid ``[a-z0-9._]{1,64}`` identifier.
    OVERFLOW_FEATURE: Final = "__overflow__"

    def __init__(
        self,
        *,
        opt_in: bool = False,
        sink: TelemetrySink | None = None,
        instance_id: str | None = None,
        instance_secret: bytes | None = None,
        max_features: int = _DEFAULT_MAX_FEATURES,
    ) -> None:
        if max_features < 1:
            raise ValueError("max_features must be >= 1")
        # Validate the security-critical keying secret at the boundary (§B-8).
        # An empty/short operator-supplied secret is `not None`, so the previous
        # code used it verbatim as the HMAC key — making the digest reproducible
        # from PUBLIC info alone (``_INSTANCE_HASH_DOMAIN`` + a low-entropy
        # hostname) and collapsing Invariant I3. A weak key must be rejected as
        # strictly as ``max_features``, never silently accepted.
        if instance_secret is not None:
            if len(instance_secret) < _MIN_INSTANCE_SECRET_LEN:
                raise ValueError(
                    f"instance_secret must be >= {_MIN_INSTANCE_SECRET_LEN} bytes (keyed-HMAC privacy)"
                )
            # HMAC zero-pads the key to the hash block size, so an ALL-ZERO key of
            # any length is indistinguishable from the empty key b"" — it yields
            # the same, publicly-derivable digest. Reject zero-entropy keys so the
            # length check cannot be trivially satisfied by b"\x00" * 16.
            if not any(instance_secret):
                raise ValueError("instance_secret must not be all-zero bytes (zero-entropy key)")
        self._opt_in = opt_in
        self._sink = sink
        self._instance_id = instance_id
        # Per-install keying secret for the instance digest. Random by default so
        # the digest is not reproducible from public info (defeats the
        # unsalted-dictionary attack); an explicit secret lets an operator make
        # the digest stable across restarts by persisting it locally. A supplied
        # secret has already been length-checked above.
        self._instance_secret = instance_secret if instance_secret is not None else secrets.token_bytes(32)
        self._max_features = max_features
        self._counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    # -- configuration -----------------------------------------------------

    def set_opt_in(self, opt_in: bool) -> None:
        """Toggle opt-in at runtime.

        Turning telemetry *off* leaves already-collected in-memory counts intact
        but stops new recording and flushing. Turning it back *on* resumes.
        """
        with self._lock:
            self._opt_in = opt_in

    @property
    def opt_in(self) -> bool:
        return self._opt_in

    # -- recording ---------------------------------------------------------

    def record_feature(self, feature: str) -> None:
        """Increment the count for ``feature``.

        When opted out this returns immediately — **nothing** is created,
        buffered, or sent, and no validation runs (a no-op never raises;
        Invariant I1 takes precedence over validation).

        When opted in, ``feature`` must be a closed-channel identifier matching
        ``[a-z0-9._]{1,64}`` (Invariant I2: structural no-PII / bounded
        cardinality). A name failing this — free text, an email, an RRN, a path,
        uppercase, non-ascii, or over 64 chars — is **rejected** with
        :class:`ValueError` and never counted (deny-by-default). Only the name is
        stored (a count bucket); there is no value channel.

        Distinct names are capped at ``max_features``: once that many buckets
        exist, a new (previously unseen) name is coalesced into
        :data:`OVERFLOW_FEATURE` instead of growing the map without bound.
        """
        # Opt-out short-circuit BEFORE any work (Invariant I1).
        if not self._opt_in:
            return
        self._validate_feature_name(feature)
        with self._lock:
            # Already-known names always increment their own bucket (re-recording
            # never trips the cap). A new name gets its own bucket only while one
            # slot remains reserved for the overflow bucket, so the map never
            # exceeds ``max_features`` distinct keys. When ``max_features == 1``
            # no named bucket fits and every name folds into the single overflow
            # bucket.
            if feature in self._counts or len(self._counts) < self._max_features - 1:
                self._counts[feature] += 1
            else:
                self._counts[self.OVERFLOW_FEATURE] += 1

    @staticmethod
    def _validate_feature_name(feature: str) -> None:
        """Reject any name outside the closed ``[a-z0-9._]{1,64}`` channel.

        Raised on the system boundary (§B-8): a feature name is untrusted caller
        input and must be validated before it becomes a stored key / label.
        """
        if not feature:
            raise ValueError("feature name must be non-empty")
        if _FEATURE_NAME_RE.fullmatch(feature) is None:
            raise ValueError(
                "feature name must match [a-z0-9._]{1,64} "
                "(no PII / free text / uppercase / non-ascii); "
                f"rejected name of length {len(feature)}"
            )

    # -- aggregation -------------------------------------------------------

    def snapshot(self) -> dict[str, int]:
        """Return the anonymized aggregate ``{feature: count}``.

        Empty while opted out. Contains only feature names and their occurrence
        counts — never values, PII, or identifiers (Invariant I2).
        """
        if not self._opt_in:
            return {}
        with self._lock:
            return dict(self._counts)

    def instance_hash(self) -> str:
        """Return the keyed (HMAC-SHA256) pseudonymous digest of the instance id.

        Keyed by this install's secret (random unless one was supplied), so the
        digest is a *stable per-install pseudonym* of the opaque install/host
        value (Invariant I3): same id + same secret ⇒ same digest; same id +
        different secret ⇒ different digest. Returns the digest of the empty
        string when no instance id is configured.

        This is **pseudonymous, not provably anonymous**: an adversary who does
        NOT hold the per-install secret cannot recover the raw id (even for a
        low-entropy hostname) because the HMAC key is secret. We deliberately do
        not claim a bare-SHA256-of-hostname guarantee, which would be
        dictionary-recoverable under a public salt.
        """
        raw = (self._instance_id or "").encode("utf-8")
        return hmac.new(self._instance_secret, _INSTANCE_HASH_DOMAIN + raw, hashlib.sha256).hexdigest()

    # -- sink --------------------------------------------------------------

    def flush(self) -> None:
        """Flush the current aggregate to the local sink (fail-soft).

        No-op when opted out or when no sink is configured. Any sink error
        (disk full, IO error) is swallowed and logged at debug so the
        application is never affected by telemetry.
        """
        if not self._opt_in or self._sink is None:
            return
        payload = self.snapshot()
        try:
            self._sink.flush(payload)
        except Exception:  # noqa: BLE001 - telemetry boundary: never affect app
            # Justified broad catch: a telemetry sink failure (e.g. disk full)
            # must not propagate into the application. Log at debug only.
            _log.debug("telemetry sink flush failed; dropping payload", exc_info=True)
