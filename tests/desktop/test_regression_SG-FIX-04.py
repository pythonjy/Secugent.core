# SPDX-License-Identifier: Apache-2.0
"""Regression tests for SG-FIX-04.

WindowsSandboxBackend.stop() must log a warning when _proc.terminate() raises,
instead of silently swallowing the exception. _proc must still be set to None
after the call (cleanup invariant).

No real Windows Sandbox binary is needed — is_windows_sandbox_available() is
patched to return True and Popen is patched so no child process is spawned.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helper: build a backend with a fake _proc
# ---------------------------------------------------------------------------


def _make_backend(
    *,
    terminate_raises: BaseException | None = None,
) -> Any:
    """Return a WindowsSandboxBackend wired to a fake process."""
    from secugent.desktop.windows_sandbox_backend import WindowsSandboxBackend

    fake_proc: MagicMock = MagicMock(spec=subprocess.Popen)
    if terminate_raises is not None:
        fake_proc.terminate.side_effect = terminate_raises
    else:
        fake_proc.terminate.return_value = None
    fake_proc.poll.return_value = None  # looks alive

    with (
        patch(
            "secugent.desktop.windows_sandbox_backend.is_windows_sandbox_available",
            return_value=True,
        ),
        patch("secugent.desktop.windows_sandbox_backend.subprocess.Popen", return_value=fake_proc),
        patch.object(Path, "write_text"),
    ):
        backend = WindowsSandboxBackend()
        backend._proc = fake_proc
        backend._session = "sess-wsb"

    return backend, fake_proc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_terminate_raises_no_propagation() -> None:
    """stop() must not propagate when _proc.terminate() raises."""
    backend, _ = _make_backend(terminate_raises=PermissionError("access denied"))

    # Must not raise
    await backend.stop("sess-wsb")


@pytest.mark.asyncio
async def test_stop_terminate_raises_warning_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """stop() must log a warning when _proc.terminate() raises."""
    backend, _ = _make_backend(terminate_raises=OSError("os error"))

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.windows_sandbox"):
        await backend.stop("sess-wsb")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_msgs, f"Expected a terminate-failure warning, got: {warning_msgs}"
    assert any("terminate" in m.lower() for m in warning_msgs), (
        f"Warning should mention 'terminate', got: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_stop_terminate_raises_proc_cleared() -> None:
    """_proc must be set to None even when terminate() raises."""
    backend, _ = _make_backend(terminate_raises=RuntimeError("boom"))

    await backend.stop("sess-wsb")

    assert backend._proc is None, "_proc must be None after stop(), even on terminate failure"
    assert backend._session is None, "_session must be None after stop()"


@pytest.mark.asyncio
async def test_stop_happy_path_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When terminate() succeeds, no warning should be emitted."""
    backend, _ = _make_backend()

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.windows_sandbox"):
        await backend.stop("sess-wsb")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert not warning_msgs, f"Unexpected warnings on happy path: {warning_msgs}"


@pytest.mark.asyncio
async def test_stop_happy_path_proc_cleared() -> None:
    """After a successful stop(), _proc must be None."""
    backend, _ = _make_backend()

    await backend.stop("sess-wsb")

    assert backend._proc is None
    assert backend._session is None
