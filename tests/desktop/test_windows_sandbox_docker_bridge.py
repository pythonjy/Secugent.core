# SPDX-License-Identifier: Apache-2.0
"""Docker integration test for the S8b exec bridge (G-M9).

These tests exercise the *real* exec/copy round-trip through a Docker container
acting as the WindowsSandboxBackend exec bridge. They are gated behind the
``docker`` marker and SKIP gracefully when no Docker daemon is reachable, so
CI / airgapped dev boxes without Docker stay green.

Isolation assertion (INV-1): the bridge runs ``network=none`` and a file is
only visible inside the container after an explicit ``copy_in`` — the sandbox
cannot reach host files it was not told to copy.

We drive the *bridge* (DockerBackend) directly rather than constructing a real
WindowsSandboxBackend, because the latter requires the WindowsSandbox.exe host
binary which is never present in CI. The WindowsSandboxBackend → bridge
delegation itself is covered by the unit suite with a fake bridge.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

# secugent.desktop.* is a D1-deferred private tier excluded from the public OSS
# release; keep its imports type-only (TYPE_CHECKING, runtime-erased) or lazy so
# this test stays import-closed for scripts/check_public_release.py.
if TYPE_CHECKING:
    from secugent.desktop.base import VirtualDesktopBackend

pytestmark = pytest.mark.docker


def _docker_or_skip() -> None:
    try:
        from secugent.desktop.docker_backend import is_docker_available
    except ImportError:
        pytest.skip("docker SDK not installed")
    if not is_docker_available():
        pytest.skip("no reachable Docker daemon")


def _make_bridge() -> VirtualDesktopBackend:
    from secugent.config import DockerBackendConfig
    from secugent.desktop.docker_backend import DockerBackend

    # A tiny, ubiquitous image keeps the test self-contained.
    return DockerBackend(DockerBackendConfig(image="busybox:latest", network_mode="none"))


@pytest.mark.asyncio
async def test_exec_round_trip() -> None:
    _docker_or_skip()
    bridge = _make_bridge()
    sid = "s8b-exec"
    try:
        await bridge.start(sid)
        result = await bridge.exec(sid, ["echo", "secugent"])
        assert result.exit_code == 0
        assert b"secugent" in result.stdout
    finally:
        await bridge.stop(sid)


@pytest.mark.asyncio
async def test_copy_in_then_exec_sees_file(tmp_path: Path) -> None:
    """copy_in makes a host file visible inside the sandbox; not before."""
    _docker_or_skip()
    bridge = _make_bridge()
    sid = "s8b-copy"
    src = tmp_path / "매출보고서.txt"  # Korean fixture (C-3)
    src.write_text("금융 데이터", encoding="utf-8")
    guest = "/tmp/매출보고서.txt"  # noqa: S108 — container-internal guest path, not host temp
    try:
        await bridge.start(sid)

        # INV-1 isolation: before copy_in the file does NOT exist in the sandbox.
        before = await bridge.exec(sid, ["cat", guest])
        assert before.exit_code != 0, "host file must not be visible before copy_in"

        await bridge.copy_in(sid, str(src), guest)
        after = await bridge.exec(sid, ["cat", guest])
        assert after.exit_code == 0
        assert "금융".encode() in after.stdout
    finally:
        await bridge.stop(sid)


@pytest.mark.asyncio
async def test_copy_out_round_trip(tmp_path: Path) -> None:
    _docker_or_skip()
    bridge = _make_bridge()
    sid = "s8b-copyout"
    dst = tmp_path / "out.txt"
    try:
        await bridge.start(sid)
        # Create a file inside the sandbox, then copy it out.
        await bridge.exec(sid, ["sh", "-c", "echo isolated > /tmp/out.txt"])  # noqa: S108 — container-internal guest path
        await bridge.copy_out(sid, "/tmp/out.txt", str(dst))  # noqa: S108 — container-internal guest path
        assert dst.exists()
        assert "isolated" in dst.read_text(encoding="utf-8")
    finally:
        await bridge.stop(sid)


@pytest.mark.asyncio
async def test_isolation_no_host_path_leak(tmp_path: Path) -> None:
    """The sandbox cannot read a host file outside any declared copy path.

    A secret file is written on the host but never copy_in'd; the sandbox must
    not be able to cat the host path (it does not share the host filesystem).
    """
    _docker_or_skip()
    bridge = _make_bridge()
    sid = "s8b-iso"
    secret = tmp_path / "host_secret.txt"
    secret.write_text("DO_NOT_LEAK", encoding="utf-8")
    try:
        await bridge.start(sid)
        # Use the host absolute path inside the sandbox — must NOT resolve.
        host_path = str(secret)
        if sys.platform == "win32":
            # POSIX container cannot interpret a Windows path; cat will fail.
            host_path = host_path.replace("\\", "/")
        probe = await bridge.exec(sid, ["cat", host_path])
        assert probe.exit_code != 0, "host secret must be unreachable from sandbox"
        assert b"DO_NOT_LEAK" not in probe.stdout
    finally:
        await bridge.stop(sid)
