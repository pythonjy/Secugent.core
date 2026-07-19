# SPDX-License-Identifier: Apache-2.0
"""``build_secrets_backend`` boot factory.

Selects a fail-closed Vault backend when Vault is configured (token OR AppRole),
else the plaintext ``EnvSecretsBackend``. When Vault IS configured but the
transport/auth fails, it raises ``VaultBackendError`` — it must NEVER silently
fall back to plaintext env (fail-closed: a configured secret backend must never
silently degrade to plaintext).

``hvac`` is not installed in CI, so the AppRole-login path injects a fake hvac
module via ``sys.modules`` (mirroring tests/unit/test_vault_secrets_backend.py).
A Korean finance fixture (금융감독원 / KB국민은행) exercises the config path (§C-3).
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from secugent.core.secrets import (
    AwsSecretsManagerBackend,
    EnvSecretsBackend,
    SecretsSettings,
    VaultBackendError,
    VaultSecretsBackend,
    build_secrets_backend,
)

# Korean finance fixture (§C-3): 금융감독원 폐쇄망 Vault KV 마운트.
_FSS_ADDR = "https://vault.fss.go.kr:8200"
_FSS_TOKEN = "s.fss-kv-token-2026"  # noqa: S105 - test fixture, not a real secret
_KB_ROLE_ID = "kb-bank-approle-role-id"
_KB_SECRET_ID = "kb-bank-approle-secret-id"  # noqa: S105 - test fixture
# S8a — AWS Secrets Manager fixture (KB국민은행 서울 리전 폐쇄망 배포).
_KB_AWS_REGION = "ap-northeast-2"


# --------------------------------------------------------------------------- #
# SecretsSettings — config detection
# --------------------------------------------------------------------------- #


def test_settings_default_is_not_vault_configured() -> None:
    assert SecretsSettings().vault_configured is False


def test_settings_token_mode_is_configured() -> None:
    s = SecretsSettings(vault_addr=_FSS_ADDR, vault_token=SecretStr(_FSS_TOKEN))
    assert s.vault_configured is True


def test_settings_approle_mode_is_configured() -> None:
    s = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    assert s.vault_configured is True


def test_settings_addr_only_is_not_configured() -> None:
    # addr without any auth material is NOT "configured" — it is a misconfig that
    # build_secrets_backend must reject (never fall back to plaintext).
    assert SecretsSettings(vault_addr=_FSS_ADDR).vault_configured is False


def test_settings_from_env_token_mode() -> None:
    env = {"VAULT_ADDR": _FSS_ADDR, "VAULT_TOKEN": _FSS_TOKEN}
    s = SecretsSettings.from_env(env)
    assert s.vault_addr == _FSS_ADDR
    assert s.vault_token is not None
    assert s.vault_token.get_secret_value() == _FSS_TOKEN
    assert s.vault_configured is True


def test_settings_from_env_approle_mode() -> None:
    env = {
        "VAULT_ADDR": _FSS_ADDR,
        "VAULT_ROLE_ID": _KB_ROLE_ID,
        "VAULT_SECRET_ID": _KB_SECRET_ID,
        "VAULT_NAMESPACE": "kb-bank",
        "VAULT_MOUNT_POINT": "kv-fin",
    }
    s = SecretsSettings.from_env(env)
    assert s.vault_role_id == _KB_ROLE_ID
    assert s.vault_secret_id is not None
    assert s.vault_secret_id.get_secret_value() == _KB_SECRET_ID
    assert s.vault_namespace == "kb-bank"
    assert s.vault_mount_point == "kv-fin"
    assert s.vault_configured is True


def test_settings_from_empty_env_is_not_configured() -> None:
    assert SecretsSettings.from_env({}).vault_configured is False


def test_settings_token_redacts_on_repr() -> None:
    s = SecretsSettings(vault_addr=_FSS_ADDR, vault_token=SecretStr(_FSS_TOKEN))
    assert _FSS_TOKEN not in repr(s)


# --------------------------------------------------------------------------- #
# build_secrets_backend — selection
# --------------------------------------------------------------------------- #


def test_build_returns_env_backend_when_unconfigured() -> None:
    backend = build_secrets_backend(SecretsSettings())
    assert isinstance(backend, EnvSecretsBackend)


def test_build_returns_vault_backend_for_token_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    # Token mode constructs a real (non-DI) VaultSecretsBackend, which imports
    # hvac. hvac is absent in CI, so install the fake module.
    _install_fake_hvac(monkeypatch, login_return={"auth": {"client_token": "x"}})
    backend = build_secrets_backend(SecretsSettings(vault_addr=_FSS_ADDR, vault_token=SecretStr(_FSS_TOKEN)))
    assert isinstance(backend, VaultSecretsBackend)


def test_build_addr_without_auth_raises_value_error() -> None:
    # fail-closed: addr present but NO auth material is a misconfig. Must NOT
    # silently downgrade to EnvSecretsBackend (plaintext).
    with pytest.raises(ValueError, match="auth"):
        build_secrets_backend(SecretsSettings(vault_addr=_FSS_ADDR))


# --------------------------------------------------------------------------- #
# AppRole login — uses a fake hvac module (hvac absent in CI)
# --------------------------------------------------------------------------- #


def _install_fake_hvac(
    monkeypatch: pytest.MonkeyPatch,
    *,
    login_return: dict[str, Any] | None = None,
    login_side_effect: BaseException | None = None,
) -> dict[str, Any]:
    """Inject a minimal fake ``hvac`` whose AppRole login is observable."""
    exceptions = types.ModuleType("hvac.exceptions")

    class InvalidPath(Exception):  # noqa: N801 - mirror hvac's class name
        pass

    class Forbidden(Exception):  # noqa: N801 - mirror hvac's class name
        pass

    exceptions.InvalidPath = InvalidPath  # type: ignore[attr-defined]
    exceptions.Forbidden = Forbidden  # type: ignore[attr-defined]

    captured: dict[str, Any] = {}

    class _AppRole:
        def login(self, *, role_id: str, secret_id: str) -> dict[str, Any]:
            captured["role_id"] = role_id
            captured["secret_id"] = secret_id
            if login_side_effect is not None:
                raise login_side_effect
            return login_return if login_return is not None else {}

    class _Auth:
        def __init__(self) -> None:
            self.approle = _AppRole()

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs
            self.auth = _Auth()
            self.secrets = MagicMock()
            self.token: str | None = kwargs.get("token")
            self.is_authenticated = MagicMock(return_value=True)

    hvac = types.ModuleType("hvac")
    hvac.Client = _Client  # type: ignore[attr-defined]
    hvac.exceptions = exceptions  # type: ignore[attr-defined]
    hvac._captured = captured  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "hvac", hvac)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", exceptions)
    return captured


def test_build_approle_logs_in_and_returns_vault_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_hvac(
        monkeypatch,
        login_return={"auth": {"client_token": "s.derived-approle-token"}},
    )
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    backend = build_secrets_backend(settings)
    assert isinstance(backend, VaultSecretsBackend)
    # The AppRole login was actually performed with the configured credentials.
    assert captured["role_id"] == _KB_ROLE_ID
    assert captured["secret_id"] == _KB_SECRET_ID


def test_build_approle_login_403_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # AppRole login is rejected (bad secret_id / 403). This must fail CLOSED with
    # VaultBackendError, NEVER fall back to EnvSecretsBackend (plaintext env).
    fake_exc = RuntimeError("permission denied")
    _install_fake_hvac(monkeypatch, login_side_effect=fake_exc)
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    with pytest.raises(VaultBackendError):
        build_secrets_backend(settings)


def test_build_approle_login_missing_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # A login response with no client_token cannot authenticate — fail CLOSED.
    _install_fake_hvac(monkeypatch, login_return={"auth": {}})
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    with pytest.raises(VaultBackendError):
        build_secrets_backend(settings)


def test_build_approle_error_does_not_leak_secret_id(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_hvac(
        monkeypatch,
        login_side_effect=RuntimeError(f"secret_id={_KB_SECRET_ID} rejected"),
    )
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    with pytest.raises(VaultBackendError) as exc_info:
        build_secrets_backend(settings)
    assert _KB_SECRET_ID not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_build_token_mode_takes_precedence_over_approle(monkeypatch: pytest.MonkeyPatch) -> None:
    # When BOTH a token and AppRole creds are present, the explicit token wins and
    # no AppRole login is attempted (the more direct credential).
    captured = _install_fake_hvac(monkeypatch, login_return={"auth": {"client_token": "x"}})
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_token=SecretStr(_FSS_TOKEN),
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    backend = build_secrets_backend(settings)
    assert isinstance(backend, VaultSecretsBackend)
    assert "role_id" not in captured  # AppRole login was NOT attempted


def test_build_never_returns_env_backend_when_vault_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    # The fail-closed invariant, stated directly: a configured-Vault path can only
    # yield a VaultSecretsBackend or raise — never an EnvSecretsBackend.
    _install_fake_hvac(monkeypatch, login_return={"auth": {"client_token": "s.tok"}})
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_role_id=_KB_ROLE_ID,
        vault_secret_id=SecretStr(_KB_SECRET_ID),
    )
    backend = build_secrets_backend(settings)
    assert not isinstance(backend, EnvSecretsBackend)


# --------------------------------------------------------------------------- #
# AWS Secrets Manager selection branch
# --------------------------------------------------------------------------- #


def test_settings_aws_region_is_aws_configured() -> None:
    assert SecretsSettings(aws_secrets_region=_KB_AWS_REGION).aws_configured is True


def test_settings_default_is_not_aws_configured() -> None:
    assert SecretsSettings().aws_configured is False


def test_settings_from_env_aws_mode() -> None:
    env = {
        "AWS_SECRETS_REGION": _KB_AWS_REGION,
        "AWS_SECRETS_ENDPOINT_URL": "https://vpce-1234.secretsmanager.ap-northeast-2.vpce.amazonaws.com",
    }
    s = SecretsSettings.from_env(env)
    assert s.aws_secrets_region == _KB_AWS_REGION
    assert s.aws_secrets_endpoint_url is not None
    assert s.aws_configured is True


def test_build_returns_aws_backend_when_aws_configured() -> None:
    # AWS construction is DI-free here (no boto3 import until get()), so this
    # selects the AWS backend without needing a fake boto3 module.
    backend = build_secrets_backend(SecretsSettings(aws_secrets_region=_KB_AWS_REGION))
    assert isinstance(backend, AwsSecretsManagerBackend)


def test_build_aws_passes_region_and_endpoint() -> None:
    endpoint = "https://vpce-1234.secretsmanager.ap-northeast-2.vpce.amazonaws.com"
    backend = build_secrets_backend(
        SecretsSettings(aws_secrets_region=_KB_AWS_REGION, aws_secrets_endpoint_url=endpoint)
    )
    assert isinstance(backend, AwsSecretsManagerBackend)
    assert backend._region_name == _KB_AWS_REGION
    assert backend._endpoint_url == endpoint


def test_build_vault_and_aws_both_configured_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # An ambiguous config (BOTH Vault and AWS) must fail CLOSED: a human must say
    # which secret plane is authoritative. Never silently pick one.
    # (The 3-way extension in B7 changed the error message from "Both ... and ..."
    # to "Multiple secret planes configured simultaneously: ...".)
    settings = SecretsSettings(
        vault_addr=_FSS_ADDR,
        vault_token=SecretStr(_FSS_TOKEN),
        aws_secrets_region=_KB_AWS_REGION,
    )
    with pytest.raises(ValueError, match="(?i)Multiple secret planes"):
        build_secrets_backend(settings)


def test_build_never_returns_env_backend_when_aws_configured() -> None:
    # Fail-closed invariant: a configured-AWS path yields an AWS backend, never
    # the plaintext EnvSecretsBackend.
    backend = build_secrets_backend(SecretsSettings(aws_secrets_region=_KB_AWS_REGION))
    assert not isinstance(backend, EnvSecretsBackend)
