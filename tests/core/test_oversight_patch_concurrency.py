# SPDX-License-Identifier: Apache-2.0
"""Concurrency regression — STEER ``add_session_patch`` ↔ SUB-worker ``evaluate``.

Regression for a live-constraint concurrency race found in review.

The live-constraint path routes a STEER ``add_constraint`` to the **live per-run** ``OversightEngine``
that this run's SUB workers are concurrently reading. STEER writes from one thread
(``POST /steer`` → ``asyncio.to_thread`` → ``add_session_patch``) while the SUB
workers iterate the same ``OversightEngine._patches`` list inside the matchers
(``Dispatcher`` ``ThreadPoolExecutor`` → ``evaluate`` → ``_match_banned_path`` /
``_match_banned_command``). When ``_patches`` was a plain ``list`` mutated in place
with no lock, this was a data race: CPython will not raise, but enforcement was
timing-dependent and an in-flight step could miss a just-added STEER constraint,
weakening the P0 real-time-stop guarantee (spec invariant 2 "per-run engine
read-only shared → race-free" was false on the STEER path).

These tests pin the two properties the fix (lock + copy-on-write swap, snapshot
read) must guarantee:

1. **No torn read** — concurrent ``add_session_patch`` while N workers iterate the
   matchers never raises (no "list changed size during iteration" / partial view).
2. **Happens-before (no lost STEER constraint)** — once a strengthening patch has
   been added, *every* ``evaluate`` that STARTS afterwards deterministically
   ``hard_block``s the now-forbidden step. No evaluation begun after the swap may
   still see the pre-patch snapshot.

Both loops use deterministic iteration counts (never randomised) so the race is
exercised reproducibly.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from secugent.core.contracts import SessionRegulationPatch, Step
from secugent.core.mechanical_oversight import OversightEngine, OversightResult
from secugent.core.regulations import Regulations
from secugent.core.tenancy import TenantId

_TENANT = TenantId("legacy-default")
# Path the BASE policy allows and the STEER patch forbids (강화 only).
_PROBE_PATH = "D:/sandbox/고객정보/balance.txt"
_PROBE_CMD = "mail boss@example.com < report.csv"


def _empty_engine() -> OversightEngine:
    """Engine whose base policy ALLOWS both probe targets (so only the patch blocks)."""
    return OversightEngine(
        Regulations(
            version="conc-1",
            banned_paths=[],
            banned_commands=[],
            data_labels=[],
            domain_policy=None,
        )
    )


def _path_step() -> Step:
    return Step(
        tenant_id=_TENANT,
        run_id="run-conc",
        actor="sub:worker",
        action_type="file_read",
        target=_PROBE_PATH,
    )


def _command_step() -> Step:
    return Step(
        tenant_id=_TENANT,
        run_id="run-conc",
        actor="sub:worker",
        action_type="compute",
        command=_PROBE_CMD,
    )


def _banned_path_patch() -> SessionRegulationPatch:
    return SessionRegulationPatch(
        tenant_id=_TENANT,
        run_id="run-conc",
        rules=[
            {
                "category": "banned_path",
                "rule_id": "session-고객정보",
                "pattern": "*/고객정보/*",
                "actions": ["file_read", "file_write", "desktop"],
                "hard_block": True,
            }
        ],
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        reason="STEER: 고객정보 경로 차단",
    )


def _banned_command_patch() -> SessionRegulationPatch:
    return SessionRegulationPatch(
        tenant_id=_TENANT,
        run_id="run-conc",
        rules=[
            {
                "category": "banned_command",
                "rule_id": "session-mail",
                "pattern": r"\bmail\b",
                "hard_block": True,
            }
        ],
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        reason="STEER: 외부 메일 차단",
    )


# --------------------------------------------------------------------------- #
# 1. No torn read — concurrent write + N reader workers, no exception
# --------------------------------------------------------------------------- #


def test_concurrent_add_patch_and_evaluate_never_raises() -> None:
    """A writer thread floods ``add_session_patch`` while N workers iterate the
    path AND command matchers. With a plain in-place list this is the window for
    a torn/partial read; the fix must make every iteration complete cleanly."""
    engine = _empty_engine()
    writes = 400
    reads_per_worker = 400
    worker_count = 8

    errors: list[BaseException] = []
    start = threading.Barrier(worker_count + 1)
    stop = threading.Event()

    def writer() -> None:
        start.wait()
        try:
            for i in range(writes):
                # Alternate path/command patches so BOTH matcher loops iterate a
                # list that is simultaneously being swapped underneath them.
                engine.add_session_patch(_banned_path_patch() if i % 2 == 0 else _banned_command_patch())
        except BaseException as exc:  # noqa: BLE001 - surfaced to the assertion
            errors.append(exc)
        finally:
            stop.set()

    def reader() -> None:
        start.wait()
        try:
            for _ in range(reads_per_worker):
                # Both matcher paths read self._patches mid-flight.
                engine.evaluate(_path_step())
                engine.evaluate(_command_step())
                if stop.is_set():
                    # Keep going a little past the writer so reads straddle the
                    # final swaps, but bound the loop deterministically.
                    pass
        except BaseException as exc:  # noqa: BLE001 - surfaced to the assertion
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=worker_count + 1) as pool:
        futures = [pool.submit(reader) for _ in range(worker_count)]
        futures.append(pool.submit(writer))
        for future in futures:
            future.result()

    assert errors == [], f"concurrent add/evaluate raised: {errors!r}"


# --------------------------------------------------------------------------- #
# 2. Happens-before — every evaluate STARTED after a patch sees it (no lost write)
# --------------------------------------------------------------------------- #


def test_evaluate_started_after_patch_always_sees_it() -> None:
    """Once a strengthening patch is installed, every subsequent evaluation that
    BEGINS after the swap must deterministically hard-block — no in-flight worker
    may observe the pre-patch snapshot for a fresh call. This is the real-time
    STEER guarantee: a lost STEER constraint would let a forbidden step slip."""
    engine = _empty_engine()
    rounds = 200
    worker_count = 6

    # Baseline: before any patch, the probe path is allowed.
    assert engine.evaluate(_path_step()).allowed is True

    patched = threading.Event()
    missed: list[OversightResult] = []
    errors: list[BaseException] = []
    start = threading.Barrier(worker_count + 1)

    def writer() -> None:
        start.wait()
        engine.add_session_patch(_banned_path_patch())
        patched.set()

    def reader() -> None:
        start.wait()
        try:
            for _ in range(rounds):
                if patched.is_set():
                    # The swap is already published. Any evaluate beginning now
                    # MUST see the patch (atomic rebind + snapshot read).
                    res = engine.evaluate(_path_step())
                    if not res.hard_block:
                        missed.append(res)
        except BaseException as exc:  # noqa: BLE001 - surfaced to the assertion
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=worker_count + 1) as pool:
        futures = [pool.submit(reader) for _ in range(worker_count)]
        futures.append(pool.submit(writer))
        for future in futures:
            future.result()

    assert errors == [], f"reader raised: {errors!r}"
    assert missed == [], (
        "lost STEER constraint: an evaluate started after the patch was published "
        f"did not hard-block ({len(missed)} occurrence(s))"
    )

    # And after the dust settles the patch is permanently in effect.
    final = engine.evaluate(_path_step())
    assert final.hard_block is True
    assert final.violation is not None
    assert final.violation.rule_id == "session-고객정보"


# --------------------------------------------------------------------------- #
# 3. Determinism preserved — copy-on-write swap does not change pure outputs
# --------------------------------------------------------------------------- #


def test_evaluate_remains_deterministic_after_patch() -> None:
    """The lock only orders concurrent writes; single-threaded behaviour (same
    input → same output) is unchanged. Guards the B-4a 100×-determinism contract."""
    engine = _empty_engine()
    engine.add_session_patch(_banned_path_patch())
    engine.add_session_patch(_banned_command_patch())

    path_results = {
        (
            r.allowed,
            r.hard_block,
            r.violation.rule_id if r.violation else None,
        )
        for r in (engine.evaluate(_path_step()) for _ in range(100))
    }
    cmd_results = {
        (
            r.allowed,
            r.hard_block,
            r.violation.rule_id if r.violation else None,
        )
        for r in (engine.evaluate(_command_step()) for _ in range(100))
    }
    assert path_results == {(False, True, "session-고객정보")}
    assert cmd_results == {(False, True, "session-mail")}


# --------------------------------------------------------------------------- #
# 4. Deterministic torn read — mutate _patches DURING a matcher iteration
# --------------------------------------------------------------------------- #


class _IterMutatingList(list[SessionRegulationPatch]):
    """A patch list that performs an in-place mutation the instant a matcher
    starts iterating it. This deterministically reproduces the *exact* unsafe
    interleaving the STEER↔worker race produces — without relying on thread
    scheduling luck.

    With the old code (``_match_*`` iterating ``self._patches`` directly while
    ``add_session_patch`` does ``self._patches.append`` in place), a write that
    lands during the matcher loop grows the very list being iterated. CPython
    then visits the just-appended element too, so the matcher observes a view
    whose length changed underneath it (``len`` before != elements iterated) —
    a torn read.

    With the fix (matcher takes ``patches = self._patches`` snapshot, writer
    rebinds ``self._patches = self._patches + [patch]`` under a lock), the
    iterated object is frozen for the call: the concurrent append creates a NEW
    list and the in-flight iterator's length is stable. We assert exactly that
    length-stability invariant — it holds only after the fix.
    """

    def __init__(self, engine: OversightEngine, extra: SessionRegulationPatch) -> None:
        super().__init__()
        self._engine = engine
        self._extra = extra
        self._fired = False
        self.iterated_len: int | None = None

    def __iter__(self):  # type: ignore[no-untyped-def]
        length_at_start = len(self)
        if not self._fired:
            self._fired = True
            # Mutate mid-flight, exactly as a concurrent STEER write would.
            self._engine.add_session_patch(self._extra)
        # Record how many elements an iteration over THIS object now walks. If the
        # engine mutated us in place, this snapshot's length changed; if it
        # copy-on-write swapped to a new list, we stay frozen.
        snapshot = list(super().__iter__())
        self.iterated_len = len(snapshot)
        assert self.iterated_len == length_at_start, (
            "torn read: patch list length changed during matcher iteration "
            f"({length_at_start} -> {self.iterated_len}); add_session_patch "
            "mutated the in-flight list instead of copy-on-write swapping"
        )
        return iter(snapshot)


def test_matcher_iteration_is_length_stable_under_mid_iteration_write() -> None:
    """Force an ``add_session_patch`` to land in the middle of a matcher's
    iteration and assert the iterated view stays length-stable. Fails on the
    in-place implementation (the list grows mid-iteration); passes after the
    copy-on-write + snapshot-read fix."""
    engine = _empty_engine()
    seed = _banned_path_patch()  # base content; pattern will not match the probe
    probe = _IterMutatingList(engine, _banned_command_patch())
    probe.append(seed)
    # Inject our instrumented list as the engine's patch store.
    engine._patches = probe  # noqa: SLF001 - white-box regression on the race surface

    # Evaluating iterates the patches; the instrumented __iter__ mutates mid-flight.
    result = engine.evaluate(_path_step())
    assert isinstance(result, OversightResult)
    # The matcher walked a length-stable snapshot (assertion inside __iter__).
    assert probe.iterated_len == 1
    # After the call the concurrently-added command patch is fully in effect.
    after = engine.evaluate(_command_step())
    assert after.hard_block is True
    assert after.violation is not None
    assert after.violation.rule_id == "session-mail"
