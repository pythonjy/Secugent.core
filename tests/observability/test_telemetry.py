# SPDX-License-Identifier: Apache-2.0
"""BDP_02 항목 7 — opt-in adoption telemetry collector tests.

The collector is privacy-respecting, DEFAULT-OFF, and on-prem local. These
tests pin the spec's invariants:

* **I1 (default off)**: ``opt_in=False`` ⇒ complete no-op (snapshot empty,
  sink never touched).
* **I2 (no PII)**: payloads carry ONLY ``{feature: count}`` — no policy text,
  user/tenant id, or audit body.
* **I3 (irreversible id)**: any instance identifier is a one-way hash; the raw
  host/install value is not recoverable from it.
* edge: runtime toggle, no sink, sink raises (disk-full) ⇒ fail-soft, and
  concurrent ``record_feature`` keeps counts consistent.
"""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

import pytest
from hypothesis import given
from hypothesis import strategies as st

from secugent.core.settings import TelemetrySettings
from secugent.observability.telemetry import (
    TelemetryCollector,
    TelemetrySink,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class RecordingSink:
    """Local sink that records every flush payload (no I/O)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, int]] = []

    def flush(self, payload: dict[str, int]) -> None:
        # Defensive copy so later mutation of the collector buffer cannot
        # retroactively change what we asserted was flushed.
        self.calls.append(dict(payload))


class ExplodingSink:
    """Sink whose flush always fails (simulates disk-full / IO error)."""

    def __init__(self) -> None:
        self.attempts = 0

    def flush(self, payload: dict[str, int]) -> None:
        self.attempts += 1
        raise OSError("No space left on device")


def test_recording_sink_is_a_telemetry_sink() -> None:
    # Structural Protocol conformance — no inheritance required.
    assert isinstance(RecordingSink(), TelemetrySink)
    assert isinstance(ExplodingSink(), TelemetrySink)


# ---------------------------------------------------------------------------
# I1 — default off / opt-out is a complete no-op
# ---------------------------------------------------------------------------


def test_default_is_opt_out() -> None:
    collector = TelemetryCollector()
    assert collector.snapshot() == {}


def test_opt_out_record_then_snapshot_is_empty() -> None:
    sink = RecordingSink()
    collector = TelemetryCollector(opt_in=False, sink=sink)

    collector.record_feature("steer.pause")
    collector.record_feature("steer.pause")
    collector.flush()

    # Nothing buffered ...
    assert collector.snapshot() == {}
    # ... and the sink was NEVER touched.
    assert sink.calls == []


def test_opt_out_flush_does_not_touch_sink() -> None:
    sink = RecordingSink()
    collector = TelemetryCollector(opt_in=False, sink=sink)
    collector.flush()
    assert sink.calls == []


# ---------------------------------------------------------------------------
# I2 — opt-in records counts ONLY, no PII / policy / audit body
# ---------------------------------------------------------------------------


def test_opt_in_counts_only() -> None:
    collector = TelemetryCollector(opt_in=True)
    collector.record_feature("hitl.approve")
    collector.record_feature("hitl.approve")
    collector.record_feature("policy.block")

    assert collector.snapshot() == {"hitl.approve": 2, "policy.block": 1}


def test_opt_in_snapshot_has_only_int_counts() -> None:
    collector = TelemetryCollector(opt_in=True)
    collector.record_feature("audit.export")
    snap = collector.snapshot()
    assert all(isinstance(v, int) for v in snap.values())
    assert list(snap.keys()) == ["audit.export"]


def test_no_pii_in_serialized_payload() -> None:
    """A would-be PII / policy / audit value passed as the *feature name* is
    still only ever a key (a count bucket) — but we additionally assert that no
    secret VALUE ever appears: snapshot exposes counts, never the raw strings a
    caller might smuggle as data."""
    sink = RecordingSink()
    collector = TelemetryCollector(opt_in=True, sink=sink, instance_id="host-secret-01")

    # The caller can only pass a feature *name*; there is no value channel.
    collector.record_feature("connector.salesforce")
    collector.flush()

    serialized = json.dumps({"snapshot": collector.snapshot(), "sink_calls": sink.calls})
    # Raw instance id must never appear (only its one-way hash may, see I3).
    assert "host-secret-01" not in serialized
    # No audit/tenant/user identifiers leak.
    for forbidden in ("tenant", "user_id", "rationale", "prev_event_id", "regulations_version"):
        assert forbidden not in serialized


def test_snapshot_keys_are_subset_of_recorded_features() -> None:
    collector = TelemetryCollector(opt_in=True)
    recorded = ["a", "b", "a", "c"]
    for f in recorded:
        collector.record_feature(f)
    assert set(collector.snapshot()) <= set(recorded)


# ---------------------------------------------------------------------------
# I3 — instance id is a one-way hash (stable, not back-traceable)
# ---------------------------------------------------------------------------


def test_instance_hash_is_stable_for_same_input_and_secret() -> None:
    # "Stable for same input" now means same id AND same per-install secret
    # (the digest is keyed; see findings #1/#3). A persisted operator secret
    # makes the pseudonym stable across restarts.
    secret = b"persisted-install-secret-0123456789"
    a = TelemetryCollector(opt_in=True, instance_id="install-A", instance_secret=secret)
    b = TelemetryCollector(opt_in=True, instance_id="install-A", instance_secret=secret)
    assert a.instance_hash() == b.instance_hash()
    # Same collector is always stable across repeated calls (random-secret case).
    c = TelemetryCollector(opt_in=True, instance_id="install-A")
    assert c.instance_hash() == c.instance_hash()


def test_instance_hash_differs_for_different_input() -> None:
    secret = b"shared-secret-so-only-the-id-varies"
    a = TelemetryCollector(opt_in=True, instance_id="install-A", instance_secret=secret)
    b = TelemetryCollector(opt_in=True, instance_id="install-B", instance_secret=secret)
    assert a.instance_hash() != b.instance_hash()


def test_instance_hash_does_not_reveal_raw_value() -> None:
    raw = "very-secret-hostname.internal"
    collector = TelemetryCollector(opt_in=True, instance_id=raw)
    digest = collector.instance_hash()
    assert raw not in digest
    # sha256 hex is 64 chars; a one-way hash is fixed-length regardless of input.
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_flushed_payload_is_exactly_snapshot_no_instance_id() -> None:
    """The flushed payload is exactly ``{feature: count}`` — it carries NEITHER
    the raw instance id NOR its digest.

    Finding #8: the previous test was named ``..._present_in_flushed_payload...``
    yet only asserted raw-absence, which is vacuously true because the id is
    never emitted at all. This pins the real contract: the id (raw *and* hashed)
    is intentionally kept out of the wire payload, so the payload is exactly the
    snapshot.
    """
    sink = RecordingSink()
    raw = "kr-bank-prod-node-7"
    collector = TelemetryCollector(opt_in=True, sink=sink, instance_id=raw)
    collector.record_feature("steer.resume")
    collector.flush()

    assert sink.calls, "opt-in flush should reach the sink"
    # The payload equals the anonymized aggregate — nothing more.
    assert sink.calls == [{"steer.resume": 1}]
    serialized = json.dumps(sink.calls)
    # Neither the raw value nor its one-way digest leaks into the payload.
    assert raw not in serialized
    assert collector.instance_hash() not in serialized


# ---------------------------------------------------------------------------
# I3 (hardened) — digest is KEYED by a per-install SECRET salt, not a global
# public constant. Two installs with the SAME hostname but different secret
# salts must produce DIFFERENT digests (findings #1/#3).
# ---------------------------------------------------------------------------


def test_instance_hash_is_keyed_by_per_install_secret() -> None:
    raw = "kr-bank-prod-node-7"  # same low-entropy hostname for both installs
    a = TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=b"install-A-secret-0123456789abcdef")
    b = TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=b"install-B-secret-fedcba9876543210")
    # Same hostname, different per-install secret ⇒ different digest. This is
    # what defeats the unsalted-dictionary attack the old constant salt allowed.
    assert a.instance_hash() != b.instance_hash()
    # Each is still stable for its own (id, secret) pair.
    assert (
        a.instance_hash()
        == TelemetryCollector(
            opt_in=True, instance_id=raw, instance_secret=b"install-A-secret-0123456789abcdef"
        ).instance_hash()
    )


def test_instance_hash_is_not_plain_sha256_of_public_salt() -> None:
    """The digest must NOT be reproducible from public information alone (the
    module constant + the raw id). A keyed HMAC with a secret the adversary does
    not hold is required (findings #1/#3)."""
    import hashlib

    raw = "host-secret-01"
    collector = TelemetryCollector(
        opt_in=True, instance_id=raw, instance_secret=b"a-high-entropy-secret-key-32bytes!"
    )
    # The naive, attackable construction an adversary would precompute.
    public_only = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert collector.instance_hash() != public_only


def test_instance_hash_default_secret_is_per_install_random() -> None:
    """When no explicit secret is supplied, each collector mints its own random
    secret, so even two collectors with the same id differ by default."""
    raw = "same-hostname.internal"
    a = TelemetryCollector(opt_in=True, instance_id=raw)
    b = TelemetryCollector(opt_in=True, instance_id=raw)
    assert a.instance_hash() != b.instance_hash()


# ---------------------------------------------------------------------------
# I3 (boundary) — a weak operator-supplied secret must be REJECTED at __init__,
# never silently used as the HMAC key (finding #1). An empty / short secret
# would make the keyed digest reproducible from PUBLIC info alone (the module
# constant + a low-entropy hostname) — exactly the dictionary/preimage attack
# the keyed-HMAC design claims to defeat. The constructor validates the
# security-critical key just as strictly as it validates ``max_features``.
# ---------------------------------------------------------------------------


# 16 bytes is the documented minimum keying-secret length (matches the
# ValueError message in the constructor); kept in one place so the test and the
# implementation agree on the boundary.
_MIN_INSTANCE_SECRET_LEN = 16


def test_empty_instance_secret_is_rejected() -> None:
    # b"" is `not None`, so the OLD code used it verbatim as the HMAC key,
    # collapsing Invariant I3 (the digest became reproducible from public info).
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=b"")


@pytest.mark.parametrize("length", list(range(0, _MIN_INSTANCE_SECRET_LEN)))
def test_short_instance_secret_is_rejected(length: int) -> None:
    # Any secret below the minimum length is rejected at the boundary — it is
    # too low-entropy to provide the keyed-HMAC privacy guarantee.
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=b"\x00" * length)


@pytest.mark.parametrize("length", [_MIN_INSTANCE_SECRET_LEN, _MIN_INSTANCE_SECRET_LEN + 1, 32, 64])
def test_secret_at_or_above_minimum_length_is_accepted(length: int) -> None:
    # A secret of exactly the minimum length (or longer) is accepted and keys
    # the digest as documented.
    secret = b"k" * length
    a = TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=secret)
    b = TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=secret)
    assert a.instance_hash() == b.instance_hash()
    assert len(a.instance_hash()) == 64


def test_no_caller_reachable_path_yields_public_derivable_digest() -> None:
    """Whatever secret a caller supplies (if accepted), the resulting digest is
    NEVER reproducible from public information alone — the module constant
    ``_INSTANCE_HASH_DOMAIN`` plus the (possibly low-entropy) raw id. This is the
    direct, security-relevant assertion behind finding #1.
    """
    import hashlib
    import hmac

    from secugent.observability.telemetry import _INSTANCE_HASH_DOMAIN

    raw = "host-01"  # low-entropy hostname an adversary can guess
    # The empty-key construction the OLD code allowed (and which the public
    # adversary can fully precompute).
    public_derivable = hmac.new(b"", _INSTANCE_HASH_DOMAIN + raw.encode("utf-8"), hashlib.sha256).hexdigest()

    # An empty secret is now rejected outright — it can never reach instance_hash.
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=b"")

    # And a *valid* secret never reproduces that public-derivable digest.
    valid = TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=b"x" * 32)
    assert valid.instance_hash() != public_derivable
    # The random default is likewise never public-derivable.
    default = TelemetryCollector(opt_in=True, instance_id=raw)
    assert default.instance_hash() != public_derivable


@given(st.binary(min_size=0, max_size=_MIN_INSTANCE_SECRET_LEN - 1))
def test_property_any_short_secret_is_rejected(secret: bytes) -> None:
    # Property: NO secret shorter than the minimum is ever accepted, regardless
    # of byte content (high-byte values do not buy back the missing length).
    assert len(secret) < _MIN_INSTANCE_SECRET_LEN
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=secret)


# Up to the SHA-256 HMAC block size (64 bytes) an all-zero key zero-pads to the
# same block as the empty key, so it produces the IDENTICAL public-derivable
# digest. (Above the block size HMAC hashes the key first, breaking the exact
# collision — but a zero-entropy key is still rejected on principle.)
_SHA256_BLOCK_SIZE = 64


@pytest.mark.parametrize(
    "length", [_MIN_INSTANCE_SECRET_LEN, _MIN_INSTANCE_SECRET_LEN + 1, 32, _SHA256_BLOCK_SIZE]
)
def test_all_zero_secret_within_block_size_collides_with_empty_and_is_rejected(length: int) -> None:
    """HMAC zero-pads the key to the hash block size, so an ALL-ZERO key up to
    64 bytes yields the SAME digest as the empty key b"" — i.e. it is just as
    public-derivable. A length-only check would be bypassable with
    ``b"\\x00" * 16``; the constructor must reject zero-entropy keys too."""
    import hashlib
    import hmac

    from secugent.observability.telemetry import _INSTANCE_HASH_DOMAIN

    # Sanity: confirm the all-zero key really collides with the empty key here.
    raw = "host-01"
    msg = _INSTANCE_HASH_DOMAIN + raw.encode("utf-8")
    assert (
        hmac.new(b"\x00" * length, msg, hashlib.sha256).hexdigest()
        == hmac.new(b"", msg, hashlib.sha256).hexdigest()
    )
    # ... therefore it must be rejected at the boundary.
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=b"\x00" * length)


@pytest.mark.parametrize("length", [_MIN_INSTANCE_SECRET_LEN, 32, _SHA256_BLOCK_SIZE, 100, 200])
def test_all_zero_secret_is_rejected_at_any_length(length: int) -> None:
    # Regardless of collision behaviour, a zero-entropy key provides no privacy
    # guarantee and is rejected for every length >= the minimum.
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, instance_id="host-01", instance_secret=b"\x00" * length)


@given(
    st.binary(min_size=_MIN_INSTANCE_SECRET_LEN, max_size=128).filter(lambda b: any(b)),
)
def test_property_long_enough_nonzero_secret_is_accepted_and_not_public_derivable(secret: bytes) -> None:
    import hashlib
    import hmac

    from secugent.observability.telemetry import _INSTANCE_HASH_DOMAIN

    raw = "host-01"
    collector = TelemetryCollector(opt_in=True, instance_id=raw, instance_secret=secret)
    digest = collector.instance_hash()
    assert len(digest) == 64
    public_derivable = hmac.new(b"", _INSTANCE_HASH_DOMAIN + raw.encode("utf-8"), hashlib.sha256).hexdigest()
    assert digest != public_derivable


# ---------------------------------------------------------------------------
# I2 (hardened) — feature NAME is a closed structural channel, not free text.
# A non-allowlisted / PII-shaped name is REJECTED (findings #2/#6).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "login:alice@example.com",  # email PII smuggled as a name
        "user 901010-1234567",  # RRN-shaped + space
        "/var/data/tenant/acme/file.csv",  # path
        "Feature.With.Capitals",  # uppercase (not in [a-z0-9._])
        "한글기능",  # non-ascii
        "x" * 65,  # too long (>64)
        "has space",
        "semi;colon",
        "comma,sep",
    ],
)
def test_record_feature_rejects_non_allowlisted_name(bad: str) -> None:
    collector = TelemetryCollector(opt_in=True)
    with pytest.raises(ValueError):
        collector.record_feature(bad)
    # A rejected name must never have been counted.
    assert collector.snapshot() == {}


@pytest.mark.parametrize(
    "good",
    ["steer.pause", "hitl.approve", "policy.block", "audit.export", "a", "x" * 64, "a_b.c0"],
)
def test_record_feature_accepts_structural_names(good: str) -> None:
    collector = TelemetryCollector(opt_in=True)
    collector.record_feature(good)
    assert collector.snapshot() == {good: 1}


def test_record_feature_validation_is_opt_out_safe() -> None:
    # Opt-out short-circuits BEFORE validation: a no-op never raises even for a
    # would-be-invalid name (I1 takes precedence).
    collector = TelemetryCollector(opt_in=False)
    collector.record_feature("login:alice@example.com")  # no raise — pure no-op
    assert collector.snapshot() == {}


@given(
    st.text(min_size=1, max_size=80).filter(
        lambda s: __import__("re").fullmatch(r"[a-z0-9._]{1,64}", s) is None
    )
)
def test_record_feature_rejects_any_non_matching_name(name: str) -> None:
    collector = TelemetryCollector(opt_in=True)
    with pytest.raises(ValueError):
        collector.record_feature(name)


# ---------------------------------------------------------------------------
# edge — cardinality cap: distinct feature buckets are BOUNDED (finding #4).
# ---------------------------------------------------------------------------


def test_feature_cardinality_is_bounded_with_overflow_bucket() -> None:
    cap = 8
    collector = TelemetryCollector(opt_in=True, max_features=cap)
    # Record far more distinct names than the cap allows.
    for i in range(cap * 10):
        collector.record_feature(f"feat.{i}")

    snap = collector.snapshot()
    # The map never exceeds cap distinct buckets (the cap counts the overflow
    # bucket as one of its slots).
    assert len(snap) <= cap
    # Overflow names are coalesced, not dropped — total observations preserved.
    assert sum(snap.values()) == cap * 10
    assert TelemetryCollector.OVERFLOW_FEATURE in snap


def test_feature_cardinality_known_names_keep_own_buckets() -> None:
    collector = TelemetryCollector(opt_in=True, max_features=4)
    for _ in range(3):
        collector.record_feature("steer.pause")
    # Re-recording an already-known name never trips the cap.
    for _ in range(100):
        collector.record_feature("steer.pause")
    assert collector.snapshot() == {"steer.pause": 103}


def test_max_features_one_folds_everything_into_overflow() -> None:
    collector = TelemetryCollector(opt_in=True, max_features=1)
    collector.record_feature("steer.pause")
    collector.record_feature("hitl.approve")
    snap = collector.snapshot()
    assert len(snap) == 1
    assert snap == {TelemetryCollector.OVERFLOW_FEATURE: 2}


@pytest.mark.parametrize("bad_cap", [0, -1, -100])
def test_max_features_below_one_is_rejected(bad_cap: int) -> None:
    with pytest.raises(ValueError):
        TelemetryCollector(opt_in=True, max_features=bad_cap)


def test_overflow_bucket_name_is_itself_a_valid_feature_name() -> None:
    # The overflow sentinel must satisfy the same structural rule so it cannot
    # be mistaken for smuggled data.
    import re

    assert re.fullmatch(r"[a-z0-9._]{1,64}", TelemetryCollector.OVERFLOW_FEATURE)


# ---------------------------------------------------------------------------
# edge — runtime toggle, no sink, sink raises (fail-soft), concurrency
# ---------------------------------------------------------------------------


def test_runtime_toggle_opt_in() -> None:
    collector = TelemetryCollector(opt_in=False)
    collector.record_feature("ignored.while.off")
    assert collector.snapshot() == {}

    collector.set_opt_in(True)
    collector.record_feature("counted.now")
    collector.record_feature("counted.now")
    assert collector.snapshot() == {"counted.now": 2}

    # Toggling OFF stops new recording AND hides the aggregate (privacy: an
    # opted-out collector exposes nothing).
    collector.set_opt_in(False)
    collector.record_feature("ignored.again")
    assert collector.snapshot() == {}

    # Toggling back ON resumes — already-collected counts are retained, the
    # while-off feature was never recorded.
    collector.set_opt_in(True)
    assert collector.snapshot() == {"counted.now": 2}


def test_opt_in_property_reflects_state() -> None:
    collector = TelemetryCollector(opt_in=False)
    assert collector.opt_in is False
    collector.set_opt_in(True)
    assert collector.opt_in is True


def test_no_sink_is_local_only() -> None:
    collector = TelemetryCollector(opt_in=True, sink=None)
    collector.record_feature("local.only")
    # flush with no sink must not raise.
    collector.flush()
    assert collector.snapshot() == {"local.only": 1}


def test_sink_disk_full_is_fail_soft() -> None:
    sink = ExplodingSink()
    collector = TelemetryCollector(opt_in=True, sink=sink)
    collector.record_feature("survives.disk.full")

    # flush must NOT propagate the OSError — the app is never affected.
    collector.flush()

    assert sink.attempts == 1
    # In-memory counts are unaffected by the sink failure.
    assert collector.snapshot() == {"survives.disk.full": 1}


def test_concurrent_record_feature_is_consistent() -> None:
    collector = TelemetryCollector(opt_in=True)
    threads_count = 8
    per_thread = 1000

    def worker() -> None:
        for _ in range(per_thread):
            collector.record_feature("concurrent")

    threads = [threading.Thread(target=worker) for _ in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert collector.snapshot() == {"concurrent": threads_count * per_thread}


# ---------------------------------------------------------------------------
# Korean fixture (§C-3) — feature NAMES are a closed ascii identifier channel;
# Korean free text (a display label / potential PII carrier) is REJECTED so the
# no-PII invariant is structural, not aspirational.
# ---------------------------------------------------------------------------


def test_korean_free_text_feature_name_rejected() -> None:
    collector = TelemetryCollector(opt_in=True)
    # A Korean label belongs in the display layer, never as a telemetry key.
    # Rejecting it structurally prevents smuggling e.g. "고객_홍길동" (a name) or
    # "주민901010" (an RRN fragment) through the feature channel.
    with pytest.raises(ValueError):
        collector.record_feature("승인_대기열_조회")
    with pytest.raises(ValueError):
        collector.record_feature("고객_홍길동")  # Korean personal name shape
    assert collector.snapshot() == {}


def test_korean_feature_uses_ascii_identifier() -> None:
    # The Korean "승인 대기열 조회" feature is recorded under its ascii identifier.
    collector = TelemetryCollector(opt_in=True)
    collector.record_feature("hitl.approval_queue.view")
    collector.record_feature("hitl.approval_queue.view")
    collector.record_feature("policy.block")
    snap = collector.snapshot()
    assert snap == {"hitl.approval_queue.view": 2, "policy.block": 1}
    serialized = json.dumps(snap, ensure_ascii=False)
    assert "주민" not in serialized  # RRN marker
    assert "@" not in serialized  # email marker


# ---------------------------------------------------------------------------
# property (hypothesis) — snapshot is exactly an occurrence-count dict
# ---------------------------------------------------------------------------


# Valid feature names live in the closed [a-z0-9._]{1,64} channel. Draw from a
# small fixed alphabet of short names so the number of DISTINCT names stays well
# under the cardinality cap — this exercises the exact-count contract for the
# unsaturated case (saturation is covered by the cardinality-cap tests above).
_VALID_FEATURE_NAMES = st.sampled_from(
    [f"feat.{c}" for c in "abcdefghij"]  # 10 distinct names, far under the cap
)


@given(st.lists(_VALID_FEATURE_NAMES, max_size=200))
def test_snapshot_is_exact_count_dict(features: list[str]) -> None:
    collector = TelemetryCollector(opt_in=True)
    for f in features:
        collector.record_feature(f)

    snap = collector.snapshot()

    expected: dict[str, int] = {}
    for f in features:
        expected[f] = expected.get(f, 0) + 1

    # keys ⊆ recorded names, values = occurrence counts, nothing else.
    assert snap == expected
    assert set(snap) <= set(features)
    assert all(isinstance(v, int) and v > 0 for v in snap.values())


@given(st.lists(st.text(min_size=1, max_size=10), max_size=100))
def test_opt_out_property_always_empty(features: list[str]) -> None:
    collector = TelemetryCollector(opt_in=False)
    for f in features:
        collector.record_feature(f)
    assert collector.snapshot() == {}


# ---------------------------------------------------------------------------
# Empty feature name is rejected (no empty buckets)
# ---------------------------------------------------------------------------


def test_empty_feature_name_rejected() -> None:
    collector = TelemetryCollector(opt_in=True)
    with pytest.raises(ValueError):
        collector.record_feature("")


def test_empty_feature_name_rejected_even_when_opt_out() -> None:
    # Opt-out short-circuits BEFORE validation: a no-op must never raise.
    collector = TelemetryCollector(opt_in=False)
    collector.record_feature("")  # no raise — pure no-op
    assert collector.snapshot() == {}


# ---------------------------------------------------------------------------
# settings — SECUGENT_TELEMETRY_OPTIN feeds opt_in (default off)
# ---------------------------------------------------------------------------


def test_settings_default_is_off() -> None:
    assert TelemetrySettings().opt_in is False


def test_settings_from_env_unset_is_off() -> None:
    assert TelemetrySettings.from_env({}).opt_in is False


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "Yes", "on", " on "])
def test_settings_from_env_truthy(raw: str) -> None:
    settings = TelemetrySettings.from_env({"SECUGENT_TELEMETRY_OPTIN": raw})
    assert settings.opt_in is True


@pytest.mark.parametrize("raw", ["0", "false", "no", "off", "", "garbage"])
def test_settings_from_env_falsey(raw: str) -> None:
    settings = TelemetrySettings.from_env({"SECUGENT_TELEMETRY_OPTIN": raw})
    assert settings.opt_in is False


def test_settings_feeds_collector_opt_in() -> None:
    settings = TelemetrySettings.from_env({"SECUGENT_TELEMETRY_OPTIN": "1"})
    collector = TelemetryCollector(opt_in=settings.opt_in)
    collector.record_feature("wired")
    assert collector.snapshot() == {"wired": 1}


# ---------------------------------------------------------------------------
# metrics — telemetry is in-memory/sink-only; NOTHING leaks onto /metrics (I1)
# ---------------------------------------------------------------------------


def test_telemetry_absent_from_global_prometheus_exposition() -> None:
    """Finding #5/#7: no telemetry collector is registered on the global default
    Prometheus registry, so it never appears in the /metrics exposition — even
    as HELP/TYPE metadata — regardless of opt-in. Telemetry is in-memory /
    sink-only (the dead, leaking ``TELEMETRY_FEATURE`` counter was removed).
    """
    from prometheus_client import generate_latest

    # The /metrics endpoint scrapes the global default registry.
    body = generate_latest().decode("utf-8")
    assert "secugent_telemetry_feature" not in body
    assert "secugent_telemetry" not in body


def test_telemetry_feature_counter_is_not_exported() -> None:
    """The forked, never-incremented Prometheus counter was deleted (finding
    #7). The metrics module must not export it."""
    import secugent.observability.metrics as metrics_mod

    assert not hasattr(metrics_mod, "TELEMETRY_FEATURE")
    assert "TELEMETRY_FEATURE" not in metrics_mod.__all__


def test_telemetry_metric_not_in_dashboard_snapshot() -> None:
    from secugent.observability.metrics import metrics_snapshot

    names = {m["name"] for m in metrics_snapshot()}
    assert "secugent_telemetry_feature" not in names
    exposed = {m["exposed_name"] for m in metrics_snapshot()}
    assert "secugent_telemetry_feature_total" not in exposed
