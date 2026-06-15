# SPDX-License-Identifier: Apache-2.0
"""Regression tests for SG-FIX-03.

DockerBackend.stop() must log a warning when container.kill() or
container.remove() raises an exception, instead of silently swallowing it.

The test uses a fake container/client so no Docker daemon is needed.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal fakes so we can construct DockerBackend without a real daemon
# ---------------------------------------------------------------------------


class _FakeContainer:
    """Fake Docker container object with controllable kill/remove."""

    def __init__(
        self,
        *,
        kill_raises: BaseException | None = None,
        remove_raises: BaseException | None = None,
    ) -> None:
        self._kill_raises = kill_raises
        self._remove_raises = remove_raises
        self.id = "deadbeef12345678"
        self.status = "running"

    def kill(self) -> None:
        if self._kill_raises is not None:
            raise self._kill_raises

    def remove(self, *, force: bool = False) -> None:
        if self._remove_raises is not None:
            raise self._remove_raises

    def reload(self) -> None:
        pass


def _make_backend(container: _FakeContainer) -> Any:
    """Return a DockerBackend with its internals pre-wired to *container*."""
    from secugent.desktop.docker_backend import DockerBackend

    from secugent.config import DockerBackendConfig

    cfg = DockerBackendConfig(image="secugent-test:latest")

    # Patch validate_security and docker.from_env so no daemon is needed.
    fake_client = MagicMock()
    with (
        patch("secugent.desktop.docker_backend.validate_security"),
        patch("secugent.desktop.docker_backend._import_docker_sdk") as sdk_mock,
    ):
        sdk_inst = MagicMock()
        sdk_inst.from_env.return_value = fake_client
        sdk_mock.return_value = sdk_inst
        backend = DockerBackend(cfg)

    backend._containers["sess-kill"] = container
    return backend


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_kill_raises_no_propagation_and_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """stop() must NOT propagate when kill() raises; a warning must be logged."""
    exc = RuntimeError("kill failed")
    container = _FakeContainer(kill_raises=exc)
    backend = _make_backend(container)

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.docker"):
        # Must not raise
        await backend.stop("sess-kill")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("kill" in m.lower() for m in warning_msgs), (
        f"Expected a kill-failure warning in caplog, got: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_stop_remove_raises_no_propagation_and_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """stop() must NOT propagate when remove() raises; a warning must be logged."""
    exc = OSError("remove failed")
    container = _FakeContainer(remove_raises=exc)
    backend = _make_backend(container)

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.docker"):
        await backend.stop("sess-kill")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("remove" in m.lower() for m in warning_msgs), (
        f"Expected a remove-failure warning in caplog, got: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_stop_both_raise_both_warnings_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When both kill() and remove() raise, both warnings must appear."""
    container = _FakeContainer(
        kill_raises=RuntimeError("kill gone"),
        remove_raises=ValueError("remove gone"),
    )
    backend = _make_backend(container)

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.docker"):
        await backend.stop("sess-kill")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("kill" in m.lower() for m in warning_msgs), f"Expected kill warning, got: {warning_msgs}"
    assert any("remove" in m.lower() for m in warning_msgs), f"Expected remove warning, got: {warning_msgs}"


@pytest.mark.asyncio
async def test_stop_happy_path_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When kill/remove succeed, no warning should be emitted."""
    container = _FakeContainer()
    backend = _make_backend(container)

    with caplog.at_level(logging.WARNING, logger="secugent.desktop.docker"):
        await backend.stop("sess-kill")

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert not warning_msgs, f"Unexpected warnings on happy path: {warning_msgs}"
