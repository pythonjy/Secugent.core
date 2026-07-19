# SPDX-License-Identifier: Apache-2.0
"""Unit + property tests for S8b (G-M9): WindowsSandboxBackend exec/copy.

The backend has no guest-side helper, so exec/copy_in/copy_out delegate to an
injected Docker *exec bridge* (a VirtualDesktopBackend). These tests use a fake
bridge so no Docker daemon is required; the Docker integration is exercised
separately behind the ``docker`` marker in
``test_windows_sandbox_docker_bridge.py``.

Security invariants under test:

* INV-1 — exec/copy MUST route through the bridge (sandbox), never the host.
* INV-2 — no bridge available ⇒ fail-closed (BackendNotAvailableError).
* INV-3 — guest/host paths with ``..`` / NUL / empty ⇒ rejected.
* INV-4 — windows_sandbox is NOT the default execution path (factory default).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

# NOTE: ``secugent.desktop.*`` is a D1-deferred private tier excluded from the
# public OSS release. All runtime imports of it are kept *inside functions*
# (lazy) so this test stays import-closed for the public-release gate
# (scripts/check_public_release.py — function bodies are not load-time imports).
# Type-only references go under TYPE_CHECKING, which is runtime-erased.
if TYPE_CHECKING:
    from secugent.desktop.base import ExecResult, VirtualDesktopBackend

    # At type-check time _FakeBridge IS-A VirtualDesktopBackend (so it satisfies
    # the ``exec_bridge`` parameter type); at runtime its base is plain ``object``
    # — no load-time import of the private desktop tier.
    _BridgeBase = VirtualDesktopBackend
else:
    _BridgeBase = object

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeBridge(_BridgeBase):
    """Records delegated calls; returns canned results. No real sandbox.

    Subclasses ``VirtualDesktopBackend`` only under TYPE_CHECKING (runtime base
    is ``object``) so this module needs no load-time import of the private
    desktop tier. Mirrors the lazy-import discipline of the existing
    ``test_regression_SG-FIX-0{3,4}.py``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.started: list[str] = []

    async def start(self, session_id: str) -> None:
        self.started.append(session_id)
        self.calls.append(("start", (session_id,)))

    async def stop(self, session_id: str) -> None:
        self.calls.append(("stop", (session_id,)))

    async def exec(
        self,
        session_id: str,
        command: list[str],
        timeout_sec: float = 30.0,
    ) -> ExecResult:
        from secugent.desktop.base import ExecResult

        self.calls.append(("exec", (session_id, tuple(command), timeout_sec)))
        return ExecResult(stdout=b"ok", stderr=b"", exit_code=0, duration_sec=0.01)

    async def copy_in(self, session_id: str, src_host: str, dst_guest: str) -> None:
        self.calls.append(("copy_in", (session_id, src_host, dst_guest)))

    async def copy_out(self, session_id: str, src_guest: str, dst_host: str) -> None:
        self.calls.append(("copy_out", (session_id, src_guest, dst_host)))

    async def screenshot(self, session_id: str) -> bytes | None:
        return None

    async def is_alive(self, session_id: str) -> bool:
        return True


def _make_backend(bridge: VirtualDesktopBackend | None) -> Any:
    """Construct a WindowsSandboxBackend with availability patched True."""
    from secugent.desktop.windows_sandbox_backend import WindowsSandboxBackend

    with patch(
        "secugent.desktop.windows_sandbox_backend.is_windows_sandbox_available",
        return_value=True,
    ):
        return WindowsSandboxBackend(exec_bridge=bridge)


# --------------------------------------------------------------------------- #
# exec — delegation + validation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_exec_delegates_to_bridge() -> None:
    from secugent.desktop.base import ExecResult

    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    result = await backend.exec("sess-1", ["echo", "hi"], timeout_sec=5.0)

    assert isinstance(result, ExecResult)
    assert result.exit_code == 0
    # INV-1: must have started the bridge session and delegated exec.
    assert ("start", ("sess-1",)) in bridge.calls
    exec_calls = [c for c in bridge.calls if c[0] == "exec"]
    assert exec_calls, "exec must delegate to the bridge"
    assert exec_calls[0][1][0] == "sess-1"
    assert exec_calls[0][1][1] == ("echo", "hi")


@pytest.mark.asyncio
async def test_exec_empty_command_rejected() -> None:
    from secugent.desktop.base import BackendConfigurationError

    backend = _make_backend(_FakeBridge())
    with pytest.raises(BackendConfigurationError):
        await backend.exec("sess-1", [], timeout_sec=5.0)


@pytest.mark.asyncio
async def test_exec_no_bridge_fail_closed() -> None:
    """INV-2: no bridge + Docker unavailable ⇒ BackendNotAvailableError."""
    from secugent.desktop.base import BackendNotAvailableError

    backend = _make_backend(None)
    with patch(
        "secugent.desktop.windows_sandbox_backend.is_docker_available",
        return_value=False,
    ):
        with pytest.raises(BackendNotAvailableError):
            await backend.exec("sess-1", ["echo", "hi"])


# --------------------------------------------------------------------------- #
# copy_in / copy_out — delegation + path validation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_copy_in_delegates(tmp_path: Path) -> None:
    src = tmp_path / "report.txt"
    src.write_text("data", encoding="utf-8")
    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    await backend.copy_in("sess-1", str(src), "/sandbox/report.txt")

    copy_calls = [c for c in bridge.calls if c[0] == "copy_in"]
    assert copy_calls
    assert copy_calls[0][1] == ("sess-1", str(src), "/sandbox/report.txt")


@pytest.mark.asyncio
async def test_copy_in_missing_src_raises(tmp_path: Path) -> None:
    backend = _make_backend(_FakeBridge())
    missing = tmp_path / "nope.txt"
    with pytest.raises(FileNotFoundError):
        await backend.copy_in("sess-1", str(missing), "/sandbox/nope.txt")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "/sandbox/../escape", "/sandbox/a\x00b", "../../etc/passwd"])
async def test_copy_in_unsafe_guest_rejected(tmp_path: Path, bad: str) -> None:
    from secugent.desktop.base import BackendConfigurationError

    src = tmp_path / "ok.txt"
    src.write_text("x", encoding="utf-8")
    backend = _make_backend(_FakeBridge())
    with pytest.raises(BackendConfigurationError):
        await backend.copy_in("sess-1", str(src), bad)


@pytest.mark.asyncio
async def test_copy_out_delegates(tmp_path: Path) -> None:
    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    await backend.copy_out("sess-1", "/sandbox/out.txt", str(tmp_path / "out.txt"))

    copy_calls = [c for c in bridge.calls if c[0] == "copy_out"]
    assert copy_calls
    assert copy_calls[0][1][0] == "sess-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "/sandbox/../escape", "a\x00b", "../secret"])
async def test_copy_out_unsafe_guest_rejected(tmp_path: Path, bad: str) -> None:
    from secugent.desktop.base import BackendConfigurationError

    backend = _make_backend(_FakeBridge())
    with pytest.raises(BackendConfigurationError):
        await backend.copy_out("sess-1", bad, str(tmp_path / "dst.txt"))


@pytest.mark.asyncio
async def test_copy_out_unsafe_host_rejected() -> None:
    from secugent.desktop.base import BackendConfigurationError

    backend = _make_backend(_FakeBridge())
    with pytest.raises(BackendConfigurationError):
        await backend.copy_out("sess-1", "/sandbox/ok.txt", "../../escape.txt")


# --------------------------------------------------------------------------- #
# Korean fixture (C-3)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_korean_filename_and_command(tmp_path: Path) -> None:
    """한국어 파일명/명령 경로가 정상 위임된다."""
    src = tmp_path / "매출보고서.txt"
    src.write_text("금융 데이터", encoding="utf-8")
    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    await backend.copy_in("sess-kr", str(src), "/sandbox/매출보고서.txt")
    result = await backend.exec("sess-kr", ["cat", "/sandbox/매출보고서.txt"])

    assert result.exit_code == 0
    copy_calls = [c for c in bridge.calls if c[0] == "copy_in"]
    assert copy_calls[0][1][2] == "/sandbox/매출보고서.txt"
    exec_calls = [c for c in bridge.calls if c[0] == "exec"]
    assert exec_calls[0][1][1] == ("cat", "/sandbox/매출보고서.txt")


# --------------------------------------------------------------------------- #
# INV-4 — windows_sandbox is NOT the default execution path
# --------------------------------------------------------------------------- #


def test_factory_default_is_not_windows_sandbox() -> None:
    """A feature flag boundary: default backend stays 'stub', not the sandbox."""
    from secugent.config import VirtualDesktopConfig
    from secugent.desktop.factory import get_backend

    cfg = VirtualDesktopConfig()
    assert cfg.backend == "stub"
    backend = get_backend(cfg)
    assert type(backend).__name__ == "StubBackend"


# --------------------------------------------------------------------------- #
# Property: path-safety classifier is total + delegation round-trips
# --------------------------------------------------------------------------- #

_UNSAFE = st.one_of(
    st.just(""),
    st.text(min_size=1).map(lambda s: s + "\x00"),
    st.text().map(lambda s: "/sandbox/../" + s),
    st.text().map(lambda s: "../" + s),
)

# Safe guest paths: absolute-looking, no traversal, no NUL, non-empty.
_SAFE_SEG = st.text(
    alphabet=st.characters(blacklist_characters="\x00/\\", blacklist_categories=["Cs"]),
    min_size=1,
    max_size=12,
).filter(lambda s: s not in {".", ".."})
_SAFE = st.lists(_SAFE_SEG, min_size=1, max_size=4).map(lambda parts: "/sandbox/" + "/".join(parts))


@settings(max_examples=200)
@given(bad=_UNSAFE)
def test_property_unsafe_guest_always_rejected(bad: str) -> None:
    import asyncio

    from secugent.desktop.base import BackendConfigurationError

    backend = _make_backend(_FakeBridge())

    async def _run() -> None:
        # use a real temp file so the failure is the path check, not missing src
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("x")
            src = fh.name
        try:
            with pytest.raises(BackendConfigurationError):
                await backend.copy_in("s", src, bad)
        finally:
            import os

            os.unlink(src)

    asyncio.run(_run())


@settings(max_examples=200)
@given(safe=_SAFE)
def test_property_safe_guest_round_trips(safe: str) -> None:
    import asyncio

    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    async def _run() -> None:
        import os
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("x")
            src = fh.name
        try:
            await backend.copy_in("s", src, safe)
        finally:
            os.unlink(src)

    asyncio.run(_run())
    copy_calls = [c for c in bridge.calls if c[0] == "copy_in"]
    assert copy_calls, "safe guest path must be delegated, not rejected"
    assert copy_calls[-1][1][2] == safe


# --------------------------------------------------------------------------- #
# start/stop regression guard (INV-5) — exec_bridge must not break lifecycle
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_start_stop_lifecycle_unchanged() -> None:
    from secugent.desktop.windows_sandbox_backend import WindowsSandboxBackend

    fake_proc: MagicMock = MagicMock(spec=subprocess.Popen)
    fake_proc.poll.return_value = None
    with (
        patch(
            "secugent.desktop.windows_sandbox_backend.is_windows_sandbox_available",
            return_value=True,
        ),
        patch(
            "secugent.desktop.windows_sandbox_backend.subprocess.Popen",
            return_value=fake_proc,
        ),
        patch.object(Path, "write_text"),
    ):
        backend = WindowsSandboxBackend(exec_bridge=_FakeBridge())
        await backend.start("sess-life")
        assert await backend.is_alive("sess-life") is True
        await backend.stop("sess-life")
        assert backend._proc is None


# --------------------------------------------------------------------------- #
# Bridge session lifecycle: idempotent start, teardown on stop()
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_bridge_session_started_once() -> None:
    """A bridge session is started lazily once and reused (idempotent)."""
    bridge = _FakeBridge()
    backend = _make_backend(bridge)

    await backend.exec("sess-x", ["echo", "1"])
    await backend.exec("sess-x", ["echo", "2"])
    await backend.copy_out("sess-x", "/sandbox/a", "/host/a")

    start_calls = [c for c in bridge.calls if c[0] == "start"]
    assert len(start_calls) == 1, "bridge session must be started exactly once"


@pytest.mark.asyncio
async def test_stop_tears_down_bridge_session() -> None:
    """stop() stops the bridge session that exec() lazily started."""
    bridge = _FakeBridge()
    backend = _make_backend(bridge)
    await backend.exec("sess-td", ["echo", "1"])

    await backend.stop("sess-td")

    stop_calls = [c for c in bridge.calls if c[0] == "stop"]
    assert ("stop", ("sess-td",)) in stop_calls
    assert "sess-td" not in backend._bridge_sessions


@pytest.mark.asyncio
async def test_stop_swallows_bridge_stop_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A bridge-stop failure is logged, not propagated, and session is cleared."""

    class _BoomBridge(_FakeBridge):
        async def stop(self, session_id: str) -> None:
            raise RuntimeError("bridge down")

    bridge = _BoomBridge()
    backend = _make_backend(bridge)
    await backend.exec("sess-boom", ["echo", "1"])

    with caplog.at_level("WARNING", logger="secugent.desktop.windows_sandbox"):
        await backend.stop("sess-boom")  # must not raise

    assert "sess-boom" not in backend._bridge_sessions


# --------------------------------------------------------------------------- #
# _DockerExecBridge passthrough + lazy Docker build (INV-1/INV-2)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_docker_exec_bridge_passthrough() -> None:
    """_DockerExecBridge forwards every call to its inner backend verbatim."""
    from secugent.desktop.windows_sandbox_backend import _DockerExecBridge

    inner = _FakeBridge()
    wrapped = _DockerExecBridge(inner)

    await wrapped.start("s")
    await wrapped.exec("s", ["echo"], 1.0)
    await wrapped.copy_in("s", "/h", "/g")
    await wrapped.copy_out("s", "/g", "/h")
    assert await wrapped.screenshot("s") is None
    assert await wrapped.is_alive("s") is True
    await wrapped.stop("s")

    kinds = [c[0] for c in inner.calls]
    assert kinds == ["start", "exec", "copy_in", "copy_out", "stop"]


@pytest.mark.asyncio
async def test_lazy_docker_bridge_built_when_available() -> None:
    """INV-1: with no injected bridge but Docker available, a DockerBackend
    bridge is constructed (network=none) and used."""
    backend = _make_backend(None)

    fake_inner = _FakeBridge()

    class _FakeDockerBackend:
        def __init__(self, cfg: Any) -> None:
            # Assert the isolation default is preserved.
            assert cfg.network_mode == "none"
            self._inner = fake_inner

        async def start(self, session_id: str) -> None:
            await fake_inner.start(session_id)

        async def exec(self, session_id: str, command: list[str], timeout_sec: float = 30.0) -> ExecResult:
            return await fake_inner.exec(session_id, command, timeout_sec)

    with (
        patch(
            "secugent.desktop.windows_sandbox_backend.is_docker_available",
            return_value=True,
        ),
        patch("secugent.desktop.docker_backend.DockerBackend", _FakeDockerBackend),
    ):
        result = await backend.exec("sess-lazy", ["echo", "hi"])

    assert result.exit_code == 0
    assert ("start", ("sess-lazy",)) in fake_inner.calls


# --------------------------------------------------------------------------- #
# Availability + lifecycle guards
# --------------------------------------------------------------------------- #


def test_constructor_fails_closed_when_unavailable() -> None:
    """INV-2/§A-1: unavailable host ⇒ BackendNotAvailableError (no silent host)."""
    from secugent.desktop.base import BackendNotAvailableError
    from secugent.desktop.windows_sandbox_backend import WindowsSandboxBackend

    with patch(
        "secugent.desktop.windows_sandbox_backend.is_windows_sandbox_available",
        return_value=False,
    ):
        with pytest.raises(BackendNotAvailableError):
            WindowsSandboxBackend()


@pytest.mark.asyncio
async def test_start_rejects_second_concurrent_instance() -> None:
    from secugent.desktop.base import BackendNotAvailableError
    from secugent.desktop.windows_sandbox_backend import WindowsSandboxBackend

    fake_proc: MagicMock = MagicMock(spec=subprocess.Popen)
    fake_proc.poll.return_value = None
    with (
        patch(
            "secugent.desktop.windows_sandbox_backend.is_windows_sandbox_available",
            return_value=True,
        ),
        patch(
            "secugent.desktop.windows_sandbox_backend.subprocess.Popen",
            return_value=fake_proc,
        ),
        patch.object(Path, "write_text"),
    ):
        backend = WindowsSandboxBackend(exec_bridge=_FakeBridge())
        await backend.start("a")
        with pytest.raises(BackendNotAvailableError):
            await backend.start("b")


@pytest.mark.asyncio
async def test_screenshot_is_none_and_is_alive_false_for_unknown_session() -> None:
    backend = _make_backend(_FakeBridge())
    assert await backend.screenshot("any") is None
    # No GUI process started ⇒ is_alive must be False.
    assert await backend.is_alive("never-started") is False


# --------------------------------------------------------------------------- #
# Module-level availability helpers
# --------------------------------------------------------------------------- #


def test_is_windows_sandbox_available_false_off_windows() -> None:
    from secugent.desktop import windows_sandbox_backend as mod

    with patch("secugent.desktop.windows_sandbox_backend.platform.system", return_value="Linux"):
        assert mod.is_windows_sandbox_available() is False


def test_is_docker_available_delegates_to_docker_backend() -> None:
    from secugent.desktop import windows_sandbox_backend as mod

    with patch(
        "secugent.desktop.docker_backend.is_docker_available",
        return_value=True,
    ):
        assert mod.is_docker_available() is True
