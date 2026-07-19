# SPDX-License-Identifier: Apache-2.0
"""Concurrent-commit regression — a commit must not double-send (I-C/I-D).

Two threads commit the SAME staged_id simultaneously. With ``check_same_thread=
False`` the SQLite store is shared across both. The fix requires a CAS state
pre-claim (``UPDATE ... SET state='committing' WHERE state='staged'``) plus a
process-level lock so EXACTLY ONE thread calls ``transport.execute`` and the
loser raises :class:`CommitRefusedError`. Without the fix both threads pass
``_require_staged`` and both call ``transport.execute`` → double external send of
an irreversible effect.

Korean fixture: 금융감독원 비밀 보고서 외부 전송 (한 번만 발송되어야 함).
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.reversibility import ReversibilityClass
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker import EgressRequest, ExecutionProfile
from secugent.io.staging import (
    CommitGate,
    CommitRefusedError,
    SQLiteStagedEffectStore,
    StageState,
)

_TENANT = TenantId("kookmin-bank")
_PRINCIPAL = Principal(user_id="심사역", tenant_id=_TENANT, role="operator")
_NOW = datetime(2026, 6, 24, 9, 0, 0, tzinfo=UTC)


class _CountingTransport:
    """Counts execute() calls; a small sleep widens the concurrency window."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()
        self._barrier = threading.Barrier(1)

    def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
        with self._lock:
            self.calls += 1
        # Hold the transport briefly so a second un-guarded commit would overlap.
        import time

        time.sleep(0.05)
        return b"sent"


def _req() -> EgressRequest:
    return EgressRequest(
        effect=Effect(
            kind=EffectKind.NET_SEND,
            target="https://fss.or.kr/secret-report",
            sink_class=SinkClass.EXTERNAL,
        ),
        label=DataLabel.CONFIDENTIAL,
        principal=_PRINCIPAL,
        run_id="run-kookmin",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content="금융감독원 비밀보고서".encode(),
    )


def test_concurrent_commit_sends_at_most_once(tmp_path: Path) -> None:
    """Two concurrent commit() on the same staged_id → exactly ONE execute()."""
    store = SQLiteStagedEffectStore(tmp_path / "staged.db")
    staged = store.stage(_req(), reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    transport = _CountingTransport()

    results: list[str] = []
    errors: list[Exception] = []
    start = threading.Barrier(2)

    def _commit() -> None:
        start.wait()
        try:
            store.commit(
                staged.id,
                principal=_PRINCIPAL,
                gate=CommitGate(hitl_approved=True),
                now=_NOW,
                transport=transport,
            )
            results.append("committed")
        except CommitRefusedError as exc:  # loser of the CAS race
            errors.append(exc)

    t1 = threading.Thread(target=_commit)
    t2 = threading.Thread(target=_commit)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one thread reaches the transport — irreversible effect sent once.
    assert transport.calls == 1, f"double-send: transport called {transport.calls} times"
    assert results == ["committed"]
    assert len(errors) == 1
    assert isinstance(errors[0], CommitRefusedError)

    reloaded = store.get(staged.id)
    assert reloaded is not None
    assert reloaded.state is StageState.COMMITTED
    store.close()


def test_commit_after_committed_raises(tmp_path: Path) -> None:
    """A second sequential commit on a committed effect is refused (idempotency)."""
    store = SQLiteStagedEffectStore(tmp_path / "staged.db")
    staged = store.stage(_req(), reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    transport = _CountingTransport()
    store.commit(
        staged.id,
        principal=_PRINCIPAL,
        gate=CommitGate(hitl_approved=True),
        now=_NOW,
        transport=transport,
    )
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=True),
            now=_NOW,
            transport=transport,
        )
    assert transport.calls == 1
    store.close()


def test_commit_refused_when_already_claimed(tmp_path: Path) -> None:
    """Deterministic CAS-loser branch: a row already in 'committing' is refused.

    Simulates the race-loser path (the winner has claimed staged→committing but
    not yet finished) without thread timing, so the refusal branch is covered
    deterministically (§B-4a)."""
    store = SQLiteStagedEffectStore(tmp_path / "staged.db")
    staged = store.stage(_req(), reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)
    # The winning committer claims the row first.
    assert store._claim_for_commit(staged.id) is True
    # A second claim attempt fails (row no longer 'staged').
    assert store._claim_for_commit(staged.id) is False
    transport = _CountingTransport()
    # commit() now sees a non-'staged' row → refused, transport untouched.
    with pytest.raises(CommitRefusedError):
        store.commit(
            staged.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=True),
            now=_NOW,
            transport=transport,
        )
    assert transport.calls == 0
    store.close()


def test_failed_transport_leaves_staged_for_retry(tmp_path: Path) -> None:
    """If transport.execute() raises, the CAS claim is rolled back to STAGED so a
    retry is possible (the effect was never sent)."""
    store = SQLiteStagedEffectStore(tmp_path / "staged.db")
    staged = store.stage(_req(), reversibility=ReversibilityClass.IRREVERSIBLE, hold_sec=0, now=_NOW)

    class _FailingTransport:
        def execute(self, request: EgressRequest, *, http_transport: Any | None = None) -> bytes | None:
            raise RuntimeError("transport down")

    with pytest.raises(RuntimeError):
        store.commit(
            staged.id,
            principal=_PRINCIPAL,
            gate=CommitGate(hitl_approved=True),
            now=_NOW,
            transport=_FailingTransport(),
        )
    reloaded = store.get(staged.id)
    assert reloaded is not None
    assert reloaded.state is StageState.STAGED, "failed commit must remain retryable"
    store.close()
