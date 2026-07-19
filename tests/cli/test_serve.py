# SPDX-License-Identifier: Apache-2.0
"""Tests for the Phase 1 Tauri sidecar ``serve`` entrypoint.

Security properties verified (§A-2.1, §A-2.2, §B-4, §C-1):

1. ``apply_serve_defaults`` sets REGULATIONS_PATH to the real deny-by-default
   policy, SECUGENT_DB_PATH to the per-user writable dir, SECUGENT_ENV=dev,
   and SECUGENT_HITL_REQUIRE_APPROVAL=1 — without clobbering values already
   set by the user.

2. ``create_app`` with SECUGENT_HITL_REQUIRE_APPROVAL=1 uses the real
   PendingApprovalGateway (NOT AutoApproveHitlGateway), even in dev env.
   Without the flag, dev keeps AutoApproveHitlGateway (unchanged behavior).

3. Single-user boot with SECUGENT_REGULATIONS_PATH pointing at the bundled
   default.json produces a NON-empty OversightEngine that BLOCKS a known
   policy-violating action (not allow-all).

Korean fixture: 한국 금융 도메인 경로로 Rule-of-Two 위반 차단 검증 (§C-3).
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_REGS = _REPO_ROOT / "regulations_examples" / "default.json"


# ---------------------------------------------------------------------------
# Fixtures: isolate every test from ambient env
# ---------------------------------------------------------------------------


_SERVE_ENV_VARS = (
    "SECUGENT_REGULATIONS_PATH",
    "SECUGENT_DB_PATH",
    "SECUGENT_ENV",
    "SECUGENT_HITL_REQUIRE_APPROVAL",
    "SECUGENT_HOST",
    "SECUGENT_PORT",
    "SECUGENT_AUTH_MODE",
    "SECUGENT_LOCAL_AUTH_PATH",
    "SECUGENT_SESSION_SECRET",
)


@pytest.fixture(autouse=True)
def _isolate_env() -> Iterator[None]:
    """Snapshot serve-relevant env vars, clear them, and FULLY restore after.

    ``apply_serve_defaults`` mutates ``os.environ`` directly (not via monkeypatch),
    so any var it *creates* during a test would otherwise leak into later tests in
    the same process — e.g. ``SECUGENT_AUTH_MODE=local`` flipping the auth mode for
    an unrelated console test. We snapshot the originals and restore them verbatim
    on teardown so this module's mutations never escape.
    """
    saved = {var: os.environ.get(var) for var in _SERVE_ENV_VARS}
    for var in _SERVE_ENV_VARS:
        os.environ.pop(var, None)
    try:
        yield
    finally:
        for var, value in saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value


# ---------------------------------------------------------------------------
# 1. apply_serve_defaults — sets correct defaults, does NOT clobber user values
# ---------------------------------------------------------------------------


def test_apply_defaults_sets_regulations_path() -> None:
    """Regulations path is set to the real bundled policy when unset."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    path = os.environ.get("SECUGENT_REGULATIONS_PATH", "")
    assert path, "SECUGENT_REGULATIONS_PATH must be set"
    assert Path(path).exists(), f"Policy file must exist: {path}"
    assert Path(path).name == "default.json"


def test_apply_defaults_does_not_clobber_existing_regulations_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """User-provided SECUGENT_REGULATIONS_PATH is preserved."""
    custom = tmp_path / "custom.json"
    custom.write_text('{"version":"custom-test","banned_paths":[],"domain_policy":null}', encoding="utf-8")
    monkeypatch.setenv("SECUGENT_REGULATIONS_PATH", str(custom))

    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_REGULATIONS_PATH"] == str(custom)


def test_apply_defaults_sets_db_path_to_per_user_dir() -> None:
    """DB path is set to a per-user writable location (not the install dir)."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    db = os.environ.get("SECUGENT_DB_PATH", "")
    assert db, "SECUGENT_DB_PATH must be set"
    db_path = Path(db)
    # Parent must exist (apply_serve_defaults creates it)
    assert db_path.parent.exists(), f"DB parent dir must exist: {db_path.parent}"
    # Must be inside a per-user dir, not the repo root
    assert "secugent" in db_path.parent.name.lower() or "secugent" in str(db_path).lower()


def test_apply_defaults_does_not_clobber_existing_db_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """User-provided SECUGENT_DB_PATH is preserved."""
    custom_db = str(tmp_path / "my.db")
    monkeypatch.setenv("SECUGENT_DB_PATH", custom_db)

    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_DB_PATH"] == custom_db


def test_apply_defaults_sets_dev_env() -> None:
    """SECUGENT_ENV is set to 'dev' when unset."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ.get("SECUGENT_ENV") == "dev"


def test_apply_defaults_does_not_clobber_existing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """User-provided SECUGENT_ENV is preserved."""
    monkeypatch.setenv("SECUGENT_ENV", "production")

    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_ENV"] == "production"


def test_apply_defaults_sets_hitl_require_approval() -> None:
    """SECUGENT_HITL_REQUIRE_APPROVAL is set to '1' when unset."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ.get("SECUGENT_HITL_REQUIRE_APPROVAL") == "1"


def test_apply_defaults_does_not_clobber_existing_hitl_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-provided SECUGENT_HITL_REQUIRE_APPROVAL is preserved."""
    monkeypatch.setenv("SECUGENT_HITL_REQUIRE_APPROVAL", "0")

    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_HITL_REQUIRE_APPROVAL"] == "0"


def test_apply_defaults_flag_override_parameters(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Caller-provided kwargs take precedence over both env and defaults."""
    custom_db = str(tmp_path / "override.db")
    custom_regs = str(_DEFAULT_REGS)

    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults(
        regulations_path=custom_regs,
        db_path=custom_db,
        host="0.0.0.0",  # noqa: S104 — test-only, not production
        port=9999,
    )
    assert os.environ["SECUGENT_REGULATIONS_PATH"] == custom_regs
    assert os.environ["SECUGENT_DB_PATH"] == custom_db


# ---------------------------------------------------------------------------
# 1b. Option D — local auth mode, credential path, persistent session secret
# ---------------------------------------------------------------------------


@pytest.fixture
def _userdata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect LOCALAPPDATA / Path.home() to a temp dir so defaults write there."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    return tmp_path


def test_apply_defaults_sets_local_auth_mode(_userdata: Path) -> None:
    """SECUGENT_AUTH_MODE=local is set when unset (desktop single-user login)."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ.get("SECUGENT_AUTH_MODE") == "local"


def test_apply_defaults_does_not_clobber_auth_mode(_userdata: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A user-provided SECUGENT_AUTH_MODE is preserved."""
    monkeypatch.setenv("SECUGENT_AUTH_MODE", "header")
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_AUTH_MODE"] == "header"


def test_apply_defaults_sets_local_auth_path(_userdata: Path) -> None:
    """SECUGENT_LOCAL_AUTH_PATH is set to a per-user dir (not the install dir)."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    path = os.environ.get("SECUGENT_LOCAL_AUTH_PATH", "")
    assert path, "SECUGENT_LOCAL_AUTH_PATH must be set"
    assert Path(path).name == "local_auth.json"
    assert "secugent" in str(path).lower()


def test_apply_defaults_does_not_clobber_local_auth_path(
    _userdata: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A user-provided SECUGENT_LOCAL_AUTH_PATH is preserved."""
    custom = str(tmp_path / "custom_auth.json")
    monkeypatch.setenv("SECUGENT_LOCAL_AUTH_PATH", custom)
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_LOCAL_AUTH_PATH"] == custom


def test_apply_defaults_generates_and_persists_session_secret(_userdata: Path) -> None:
    """A per-install session secret is generated, persisted, and exported."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    secret = os.environ.get("SECUGENT_SESSION_SECRET", "")
    # >= 32 bytes (resolve_session_secret minimum). hex of 32 bytes = 64 chars.
    assert len(secret) >= 64
    # The secret was persisted to a user-data file.
    secret_file = _userdata / "SecuGent" / "session_secret"
    if not secret_file.exists():  # non-Windows path
        secret_file = _userdata / ".secugent" / "session_secret"
    assert secret_file.exists(), "session secret must be persisted to user-data"
    assert secret_file.read_text(encoding="utf-8").strip() == secret


def test_apply_defaults_reuses_persisted_session_secret(_userdata: Path) -> None:
    """A second boot reuses the SAME persisted secret (sessions survive restart)."""
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    first = os.environ["SECUGENT_SESSION_SECRET"]
    # Simulate a restart: clear the env var, boot again — same secret loads.
    del os.environ["SECUGENT_SESSION_SECRET"]
    apply_serve_defaults()
    assert os.environ["SECUGENT_SESSION_SECRET"] == first


def test_apply_defaults_does_not_clobber_session_secret(
    _userdata: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user-provided SECUGENT_SESSION_SECRET is preserved (not overwritten)."""
    provided = "u" * 48
    monkeypatch.setenv("SECUGENT_SESSION_SECRET", provided)
    from secugent.server_main import apply_serve_defaults

    apply_serve_defaults()
    assert os.environ["SECUGENT_SESSION_SECRET"] == provided


def test_resolve_default_regulations_path_finds_source_tree() -> None:
    """Source-tree resolution finds the bundled default.json."""
    from secugent.server_main import _resolve_default_regulations_path

    path = _resolve_default_regulations_path()
    assert Path(path).exists()
    assert Path(path).name == "default.json"


def test_resolve_default_db_path_is_writable_per_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-user DB path is resolved and the parent dir is created."""
    # Redirect LOCALAPPDATA so the test does not write to the real user profile
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    # Temporarily patch Path.home() for non-Windows to avoid home-dir writes
    import secugent.server_main as srv_mod

    original_home = Path.home
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    try:
        db_path = srv_mod._resolve_default_db_path()
    finally:
        monkeypatch.setattr(Path, "home", staticmethod(original_home))

    assert Path(db_path).name == "secugent.db"
    assert Path(db_path).parent.exists()


# ---------------------------------------------------------------------------
# 2. HITL flag — create_app selects the correct gateway type
# ---------------------------------------------------------------------------


def test_create_app_with_hitl_flag_uses_pending_approval_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SECUGENT_HITL_REQUIRE_APPROVAL=1 + dev env → PendingApprovalGateway."""
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.setenv("SECUGENT_HITL_REQUIRE_APPROVAL", "1")
    monkeypatch.setenv("SECUGENT_REGULATIONS_PATH", str(_DEFAULT_REGS))
    monkeypatch.setenv("SECUGENT_DB_PATH", str(tmp_path / "hitl_flag.db"))

    from secugent.api.hitl_gateway import PendingApprovalGateway
    from secugent.api.main import AppState

    state = AppState(db_path=tmp_path / "hitl_flag.db", auto_build_pipeline=True)
    try:
        # Access the pipeline's HITL gateway via the internal attribute
        # (_hitl_gateway is set in _build_real_pipeline)
        gw = state._hitl_gateway
        assert isinstance(gw, PendingApprovalGateway), (
            f"Expected PendingApprovalGateway with SECUGENT_HITL_REQUIRE_APPROVAL=1, got {type(gw).__name__}"
        )
    finally:
        state.store.close()


def test_create_app_without_hitl_flag_uses_auto_approve_in_dev(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without the flag in dev env → AutoApproveHitlGateway (unchanged behaviour)."""
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.delenv("SECUGENT_HITL_REQUIRE_APPROVAL", raising=False)
    # No SECUGENT_REGULATIONS_PATH → dev empty engine

    from secugent.api.main import AppState

    state = AppState(db_path=tmp_path / "auto.db", auto_build_pipeline=True)
    try:
        gw = state._hitl_gateway
        # _hitl_gateway is None when AutoApprove is chosen (chosen inside _build_real_pipeline
        # and assigned to hitl_gw local var, not back to self._hitl_gateway). We verify
        # indirectly: the gateway stored on SubAgent after pipeline build.
        # The simplest observable: state._hitl_gateway is None (AutoApprove path) OR
        # if it is set, it must NOT be PendingApprovalGateway.
        from secugent.api.hitl_gateway import PendingApprovalGateway

        if gw is not None:
            assert not isinstance(gw, PendingApprovalGateway), (
                "Without SECUGENT_HITL_REQUIRE_APPROVAL=1 in dev, PendingApprovalGateway must NOT be used"
            )
    finally:
        state.store.close()


# ---------------------------------------------------------------------------
# 2b. FLAKE-1 regression — a torn-down dev-HITL AppState must not poison a
#     later real_adapters boot in the SAME process (no leaked loop / no
#     closed-store closure surfacing as EventStoreError).
# ---------------------------------------------------------------------------


def test_dev_hitl_appstate_close_releases_loop_and_fails_soft(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Tearing down a dev-HITL AppState must:

    1. close the event loop it OWNS (the dev gateway fabricates one when no loop
       is running at build time) — otherwise it leaks into a later boot. This is
       the LOAD-BEARING flake fix (a leaked open loop poisoned the next boot).
    2. leave a stale audit-write closure FAIL-SOFT: invoking it after the store
       is closed must not re-raise. A pre-existing broad ``except`` already kept
       it from propagating, so the EventStoreError branch's real, testable
       contract is the LOG LEVEL — a torn-down store is an EXPECTED condition and
       must be a WARNING ("skipped"), not an error traceback.
    """
    from secugent.core.contracts import Event
    from secugent.core.tenancy import TenantId

    _tenant = TenantId("legacy-default")

    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.setenv("SECUGENT_HITL_REQUIRE_APPROVAL", "1")
    monkeypatch.setenv("SECUGENT_REGULATIONS_PATH", str(_DEFAULT_REGS))

    from secugent.api.hitl_gateway import PendingApprovalGateway
    from secugent.api.main import AppState

    state = AppState(db_path=tmp_path / "dev_hitl.db", auto_build_pipeline=True)
    gw = state._hitl_gateway
    assert isinstance(gw, PendingApprovalGateway)

    # No loop is running in this sync test → the dev gateway fabricated one that
    # this AppState now OWNS (must be closed on teardown).
    owned = state._owned_event_loop
    assert owned is not None, "dev HITL gateway must own the loop it fabricated"
    assert not owned.is_closed()

    # Reach the gateway's internal dev audit-write closure (audit_write kwarg).
    audit_write = gw._audit_write
    assert audit_write is not None

    # Tear down. close() must close BOTH the store and the owned loop.
    state.close()
    assert owned.is_closed(), "AppState.close() must close the loop it owns"
    assert state._owned_event_loop is None

    # The stale closure now points at a CLOSED store. Firing it must fail SOFT.
    # NOTE: a pre-existing broad ``except Exception`` already prevented this from
    # propagating, so non-raising alone does NOT prove the EventStoreError branch
    # is doing anything. The branch's observable contract is the LOG LEVEL: assert
    # it WARNs (expected, "skipped") and does NOT log an error traceback. Remove
    # the EventStoreError branch and the catch-all logs via ``_log.exception``
    # (ERROR + traceback), failing the assertions below — so they are load-bearing.
    stale_event = Event(
        tenant_id=_tenant,
        actor="gateway:hitl",
        type="hitl.decided",
        severity="info",
        payload={"gate": "hitl", "decision": "reject"},
    )
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        audit_write(stale_event)  # fail-soft no-op (must not raise)
    closed_warnings = [
        r for r in caplog.records if r.levelno == logging.WARNING and "already closed" in r.getMessage()
    ]
    assert closed_warnings, (
        "stale dev-HITL audit closure must WARN-and-skip on a closed store; "
        f"records={[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR], (
        "a torn-down store is EXPECTED — the fail-soft branch must not log an error/traceback"
    )

    # And a *fresh* real_adapters-style boot in the SAME process must succeed
    # with NO EventStoreError and be able to append an event.
    from secugent.config import SecuGentConfig

    monkeypatch.delenv("SECUGENT_HITL_REQUIRE_APPROVAL", raising=False)
    fresh = AppState(
        db_path=tmp_path / "fresh.db",
        config=SecuGentConfig(),
        auto_build_pipeline=True,
    )
    try:
        ev = Event(
            tenant_id=_tenant,
            actor="api",
            type="probe.ok",
            severity="info",
            payload={"probe": True},
        )
        fresh.store.append_event(ev)  # must not raise
        assert any(e.id == ev.id for e in fresh.store.list_events())
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# 3. Single-user boot enforces Rule-of-Two — NOT allow-all
# ---------------------------------------------------------------------------


def test_single_user_boot_blocks_policy_violating_action(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Boot with the bundled default.json → OversightEngine HARD BLOCKs a
    confidential-path file_read (§C-1 deny-by-default, not allow-all).

    Korean fixture: 한국 금융기관 대외비 경로 접근 시도가 차단되어야 한다.
    """
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.setenv("SECUGENT_REGULATIONS_PATH", str(_DEFAULT_REGS))
    monkeypatch.setenv("SECUGENT_HITL_REQUIRE_APPROVAL", "1")

    from secugent.api.main import AppState
    from secugent.core.contracts import Step
    from secugent.core.mechanical_oversight import OversightEngine
    from secugent.core.tenancy import TenantId

    state = AppState(db_path=tmp_path / "rule2.db", auto_build_pipeline=True)
    try:
        engine = state.oversight_engine
        assert isinstance(engine, OversightEngine)

        # The engine must have real rules (not an empty allow-all engine).
        regs = engine.regulations
        assert regs.version == "default-1.0.0", (
            f"Expected real policy 'default-1.0.0', got '{regs.version}' — "
            "single-user boot must load the real deny-by-default policy."
        )
        assert len(regs.banned_paths) > 0, "Real policy must have banned_paths rules"

        # Korean fixture: 한국 금융기관 대외비 경로 접근 차단
        risky_step = Step(
            tenant_id=TenantId("legacy-default"),
            run_id="r-한국금융-001",
            actor="sub:researcher",
            action_type="file_read",
            target="/data/한국은행/confidential/board_minutes.pdf",
        )
        result = engine.evaluate(risky_step)
        assert result.allowed is False, (
            "대외비(confidential) 경로 접근이 차단되어야 합니다 — "
            "Rule-of-Two 위반: OversightEngine이 HARD BLOCK을 반환해야 합니다."
        )
        assert result.hard_block is True, (
            "confidential 경로 접근은 HARD BLOCK이어야 합니다 (§A-2.2 Deny-by-default)."
        )
    finally:
        state.store.close()


def test_single_user_boot_real_policy_has_multiple_block_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The bundled real policy has multiple hard-block rules (not allow-all).

    Verifies that secrets/ paths and destructive commands are also blocked.
    """
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.setenv("SECUGENT_REGULATIONS_PATH", str(_DEFAULT_REGS))

    from secugent.api.main import AppState
    from secugent.core.contracts import Step
    from secugent.core.tenancy import TenantId

    state = AppState(db_path=tmp_path / "policy_rules.db", auto_build_pipeline=True)
    try:
        engine = state.oversight_engine
        assert engine is not None

        # Test secrets/ directory block
        secrets_step = Step(
            tenant_id=TenantId("legacy-default"),
            run_id="r-secrets-001",
            actor="sub:agent",
            action_type="file_read",
            target="/app/secrets/api_keys.json",
        )
        result = engine.evaluate(secrets_step)
        assert result.allowed is False, "secrets/ path must be blocked by real policy"

        # Test allowed path is NOT blocked (engine is not deny-all)
        allowed_step = Step(
            tenant_id=TenantId("legacy-default"),
            run_id="r-allowed-001",
            actor="sub:agent",
            action_type="file_read",
            target="/app/public/readme.txt",
        )
        allowed_result = engine.evaluate(allowed_step)
        assert allowed_result.allowed is True, (
            "Non-violating path must be allowed — engine must not be deny-ALL, "
            "only deny-by-specific-rule (deny-by-default for the defined rules)."
        )
    finally:
        state.store.close()


# ---------------------------------------------------------------------------
# 3b. W5-d review — the server MUST run with proxy headers DISABLED so
#     request.client is always the true TCP peer. uvicorn's ProxyHeadersMiddleware
#     (default proxy_headers=True, forwarded_allow_ips=127.0.0.1) would otherwise
#     let a caller rewrite scope['client'] via X-Forwarded-For, bypassing the
#     /metrics loopback/CIDR gate (cross-tenant leak).
# ---------------------------------------------------------------------------


def test_main_starts_uvicorn_with_proxy_headers_disabled(
    _userdata: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uvicorn

    captured: dict[str, object] = {}

    def _fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", _fake_run)

    from secugent.server_main import main

    main(host="127.0.0.1", port=8123)
    assert captured["proxy_headers"] is False, (
        "the deployed server must disable uvicorn proxy headers so X-Forwarded-For "
        "cannot rewrite request.client (the /metrics gate trusts the real TCP peer)"
    )


# ---------------------------------------------------------------------------
# 4. CLI integration — serve subcommand routing
# ---------------------------------------------------------------------------


def test_serve_subcommand_is_dispatched() -> None:
    """``secugent serve --help`` is recognized without error (routing works)."""
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-m", "secugent.cli", "serve", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    # argparse --help exits 0 and prints usage
    assert proc.returncode == 0, proc.stderr
    assert "serve" in proc.stdout or "127.0.0.1" in proc.stdout


def test_unknown_subcommand_still_fails_closed() -> None:
    """Existing fail-closed behavior unchanged after adding serve."""
    from secugent.cli.__main__ import main

    assert main(["no-such-command"]) == 2
