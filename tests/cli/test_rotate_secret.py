# SPDX-License-Identifier: Apache-2.0
"""Unit suite for ``secugent rotate-secret`` (DA-H6) — honest rotation wrapper.

INV-ROTATE-1: the wrapper never fakes success. Env is an explicit no-op (exit 0,
"nothing changed in-process"); Vault/AWS surface their out-of-band message and
fail closed (exit 1); a missing secret or misconfig fails closed; the secret
value is never emitted.
"""

from __future__ import annotations

import pytest

import secugent.cli.rotate_secret as rs
from secugent.core.secrets import (
    EnvSecretsBackend,
    SecretNotFoundError,
    SecretsBackend,
    SecretStr,
)


class _OutOfBandBackend(SecretsBackend):
    """Mimics Vault/AWS: rotation is out-of-band → NotImplementedError."""

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        return SecretStr("super-secret-value-do-not-print")

    async def rotate(self, name: str) -> None:
        raise NotImplementedError(
            "AwsSecretsManagerBackend does not drive rotation; AWS Secrets Manager "
            "rotation is configured out-of-band (rotation Lambda / schedule)"
        )


class _MissingBackend(SecretsBackend):
    async def get(self, name: str, version: str | None = None) -> SecretStr:
        raise SecretNotFoundError(name)

    async def rotate(self, name: str) -> None:
        raise SecretNotFoundError(name)


def test_env_backend_reports_noop_exit_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rs, "build_secrets_backend", lambda settings: EnvSecretsBackend())
    assert rs.run_rotate_secret(name="DB_PASSWORD") == 0
    out = capsys.readouterr().out
    assert "no-op" in out
    assert "restart the process" in out


def test_out_of_band_backend_surfaced_honestly_exit_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rs, "build_secrets_backend", lambda settings: _OutOfBandBackend())
    assert rs.run_rotate_secret(name="api/token") == 1
    err = capsys.readouterr().err
    assert "out-of-band" in err
    # No fabricated success language.
    assert "rotated;" not in err
    # The secret value must never leak.
    assert "super-secret-value-do-not-print" not in err


def test_missing_secret_fails_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(rs, "build_secrets_backend", lambda settings: _MissingBackend())
    assert rs.run_rotate_secret(name="nope") == 1
    assert "not found" in capsys.readouterr().err


def test_misconfigured_backend_fails_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def _boom(settings: object) -> SecretsBackend:
        raise ValueError("VAULT_ADDR is set but no Vault auth was provided")

    monkeypatch.setattr(rs, "build_secrets_backend", _boom)
    assert rs.run_rotate_secret(name="x") == 1
    assert "misconfigured" in capsys.readouterr().err


def test_real_env_backend_via_from_env_is_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # No VAULT_* / AWS_SECRETS_* env → build_secrets_backend returns EnvSecretsBackend.
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "AWS_SECRETS_REGION"):
        monkeypatch.delenv(var, raising=False)
    assert rs.run_rotate_secret(name="ANY") == 0
    assert "no-op" in capsys.readouterr().out
