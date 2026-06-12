# SPDX-License-Identifier: Apache-2.0
"""Unit tests — VaultSecretsBackend (C-3).

``hvac`` is not installed in CI, so we never ``patch("hvac.Client")``; instead
we inject a ``MagicMock`` client via the ``client=`` DI slot for most tests. The
tests that exercise the *real* (non-DI) ``import hvac`` constructor branch stub a
minimal fake ``hvac`` module through ``sys.modules`` (see ``_install_fake_hvac``)
so they pass whether or not the library is present, while the ImportError test
forces ``hvac`` absent the same way.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from secugent.core.secrets import (
    SecretNotFoundError,
    SecretRevokedError,
    VaultBackendError,
    VaultSecretsBackend,
)


# hvac raises ``hvac.exceptions.InvalidPath`` when a KV path is absent. On the
# DI/test path (hvac absent) the backend falls back to matching the exception
# *class name*, so a local class named ``InvalidPath`` faithfully simulates it
# without importing hvac.
class InvalidPath(Exception):
    """Stand-in for ``hvac.exceptions.InvalidPath`` (DI/test path)."""


def _client(
    *,
    read_return: dict[str, Any] | None = None,
    read_side_effect: BaseException | None = None,
    authenticated: bool = True,
) -> MagicMock:
    client = MagicMock()
    rsv = client.secrets.kv.v2.read_secret_version
    if read_side_effect is not None:
        rsv.side_effect = read_side_effect
    else:
        rsv.return_value = read_return
    client.is_authenticated.return_value = authenticated
    return client


def _backend(client: MagicMock, **kw: Any) -> VaultSecretsBackend:
    return VaultSecretsBackend("http://localhost:8200", "test-token", client=client, **kw)


# ---------------------------------------------------------------------------
# get() — happy paths
# ---------------------------------------------------------------------------


async def test_get_returns_secret_value() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"value": "my-secret-value"}}}))
    result = await backend.get("my/path")
    assert isinstance(result, SecretStr)
    assert result.get_secret_value() == "my-secret-value"


async def test_get_with_custom_field() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"api_key": "key-123"}}}))
    result = await backend.get("my/path#api_key")
    assert result.get_secret_value() == "key-123"


async def test_get_uses_default_mount_point_and_field() -> None:
    client = _client(read_return={"data": {"data": {"value": "v"}}})
    backend = _backend(client)
    await backend.get("my/path")
    _, kwargs = client.secrets.kv.v2.read_secret_version.call_args
    assert kwargs["path"] == "my/path"
    assert kwargs["mount_point"] == "secret"
    assert kwargs["version"] is None


async def test_get_custom_mount_point() -> None:
    client = _client(read_return={"data": {"data": {"value": "v"}}})
    backend = _backend(client, mount_point="kv-enterprise")
    await backend.get("my/path")
    _, kwargs = client.secrets.kv.v2.read_secret_version.call_args
    assert kwargs["mount_point"] == "kv-enterprise"


async def test_get_passes_numeric_version() -> None:
    client = _client(read_return={"data": {"data": {"value": "v"}}})
    backend = _backend(client)
    await backend.get("my/path", version="7")
    _, kwargs = client.secrets.kv.v2.read_secret_version.call_args
    assert kwargs["version"] == 7


async def test_get_non_numeric_version_raises_not_found() -> None:
    # A non-numeric version pin (e.g. "latest") must stay inside the documented
    # 3-way failure model — never escape as a bare ValueError. The backend
    # rejects the call before touching hvac.
    backend = _backend(_client(read_return={"data": {"data": {"value": "v"}}}))
    with pytest.raises(SecretNotFoundError):
        await backend.get("my/path", version="latest")


async def test_get_non_numeric_version_is_not_value_error() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"value": "v"}}}))
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get("my/path", version="v2")
    # ValueError IS a base of nothing here, but assert the typed contract holds:
    # the raised error is the documented type, and the bad version is echoed.
    assert "v2" in str(exc_info.value)


# ---------------------------------------------------------------------------
# get() — fail-as-missing (SecretNotFoundError / KeyError)
# ---------------------------------------------------------------------------


async def test_get_missing_path_raises_not_found() -> None:
    backend = _backend(_client(read_side_effect=InvalidPath("404")))
    with pytest.raises(SecretNotFoundError):
        await backend.get("nonexistent/path")


async def test_get_missing_field_raises_not_found() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"value": "x"}}}))
    with pytest.raises(SecretNotFoundError):
        await backend.get("my/path#absent_field")


async def test_get_empty_name_raises_not_found() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"value": "x"}}}))
    with pytest.raises(SecretNotFoundError):
        await backend.get("")


# ---------------------------------------------------------------------------
# get() — fail-CLOSED (VaultBackendError, NOT SecretNotFoundError)
# ---------------------------------------------------------------------------


async def test_get_connection_error_fails_closed() -> None:
    # A transport/permission failure must NOT read as "secret missing" (which
    # would let a caller fall back to a permissive default — fail-open).
    backend = _backend(_client(read_side_effect=RuntimeError("connection refused")))
    with pytest.raises(VaultBackendError):
        await backend.get("some/path")


async def test_get_connection_error_is_not_secret_not_found() -> None:
    backend = _backend(_client(read_side_effect=RuntimeError("vault sealed")))
    with pytest.raises(VaultBackendError) as exc_info:
        await backend.get("some/path")
    assert not isinstance(exc_info.value, SecretNotFoundError)
    assert not isinstance(exc_info.value, KeyError)


def test_vault_backend_error_type_separation() -> None:
    # Static guarantee of the fail-closed invariant: backend errors are never
    # KeyError/SecretNotFoundError, so ``except SecretNotFoundError`` cannot
    # swallow a Vault outage.
    assert not issubclass(VaultBackendError, KeyError)
    assert not issubclass(VaultBackendError, SecretNotFoundError)


async def test_get_does_not_leak_secret_value_in_error() -> None:
    backend = _backend(_client(read_side_effect=RuntimeError("token=s.SECRETVALUE leaked")))
    with pytest.raises(VaultBackendError) as exc_info:
        await backend.get("db/password")
    # Only the path + exception *type* surface — never the upstream message body.
    assert "SECRETVALUE" not in str(exc_info.value)


async def test_get_drops_cause_so_traceback_does_not_leak_secret() -> None:
    # ``from None`` is used so the upstream exception (whose message can echo a
    # token) is NOT attached as __cause__. Otherwise a default traceback render
    # (logging.exception / Sentry / uncaught propagation) would leak the token
    # even though the direct message is clean (SECURITY_CONTRACT §6).
    backend = _backend(_client(read_side_effect=RuntimeError("token=s.SECRETVALUE leaked")))
    with pytest.raises(VaultBackendError) as exc_info:
        await backend.get("db/password")
    assert exc_info.value.__cause__ is None
    # Defensive: even rendering the whole chain must not surface the secret.
    assert "SECRETVALUE" not in repr(exc_info.value)
    assert "SECRETVALUE" not in str(exc_info.value.__cause__)


# ---------------------------------------------------------------------------
# get() — deleted/destroyed version is REVOKED (fail-closed), not "missing"
# ---------------------------------------------------------------------------


async def test_get_soft_deleted_version_classified_as_revoked() -> None:
    # hvac re-raises InvalidPath for a deleted version — the SAME type as a
    # truly absent path — so revocation CANNOT be read from the exception. With
    # raise_on_deleted_version=False the envelope carries the signal in
    # data.metadata.deletion_time. A soft-deleted version must fail CLOSED as a
    # distinct SecretRevokedError, never be mistaken for an absent secret.
    backend = _backend(
        _client(
            read_return={
                "data": {
                    "data": None,
                    "metadata": {"deletion_time": "2026-06-05T00:00:00Z", "destroyed": False},
                }
            }
        )
    )
    with pytest.raises(SecretRevokedError) as exc_info:
        await backend.get("revoked/secret")
    # Revoked is a VaultBackendError (fail-closed), NOT a SecretNotFoundError.
    assert isinstance(exc_info.value, VaultBackendError)
    assert not isinstance(exc_info.value, SecretNotFoundError)


async def test_get_destroyed_version_classified_as_revoked() -> None:
    # A destroyed (purged) version: metadata.destroyed is True. Same fail-closed
    # classification as a soft-deleted version.
    backend = _backend(
        _client(
            read_return={
                "data": {
                    "data": None,
                    "metadata": {"deletion_time": "", "destroyed": True},
                }
            }
        )
    )
    with pytest.raises(SecretRevokedError):
        await backend.get("destroyed/secret")


async def test_get_revoked_takes_precedence_over_missing_field() -> None:
    # Revocation is checked BEFORE field extraction, so a deleted version is
    # never downgraded to a "no such field" SecretNotFoundError.
    backend = _backend(
        _client(
            read_return={
                "data": {
                    "data": {"value": "stale"},
                    "metadata": {"deletion_time": "2026-06-05T00:00:00Z", "destroyed": False},
                }
            }
        )
    )
    with pytest.raises(SecretRevokedError):
        await backend.get("revoked/secret#value")


async def test_get_live_version_not_classified_as_revoked() -> None:
    # A live version has empty deletion_time and destroyed=False -> returns the
    # secret normally, no SecretRevokedError.
    backend = _backend(
        _client(
            read_return={
                "data": {
                    "data": {"value": "live"},
                    "metadata": {"deletion_time": "", "destroyed": False},
                }
            }
        )
    )
    result = await backend.get("live/secret")
    assert result.get_secret_value() == "live"


def test_secret_revoked_error_is_not_secret_not_found() -> None:
    # Static guarantee: a revoked credential can never be swallowed by an
    # ``except SecretNotFoundError`` fallback-to-default path.
    assert issubclass(SecretRevokedError, VaultBackendError)
    assert not issubclass(SecretRevokedError, SecretNotFoundError)
    assert not issubclass(SecretRevokedError, KeyError)


async def test_get_missing_path_also_drops_cause() -> None:
    # The fail-as-missing path must likewise drop the cause; an absent-path
    # error should never carry an upstream traceback that might echo material.
    backend = _backend(_client(read_side_effect=InvalidPath("404")))
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get("nonexistent/path")
    assert exc_info.value.__cause__ is None


async def test_returned_secret_redacts_on_repr() -> None:
    backend = _backend(_client(read_return={"data": {"data": {"value": "topsecret"}}}))
    result = await backend.get("my/path")
    assert "topsecret" not in repr(result)
    assert "topsecret" not in str(result)


# ---------------------------------------------------------------------------
# rotate() / is_authenticated()
# ---------------------------------------------------------------------------


async def test_rotate_raises_not_implemented() -> None:
    backend = _backend(_client())
    with pytest.raises(NotImplementedError):
        await backend.rotate("anything")


def test_is_authenticated_true() -> None:
    assert _backend(_client(authenticated=True)).is_authenticated() is True


def test_is_authenticated_false() -> None:
    assert _backend(_client(authenticated=False)).is_authenticated() is False


def test_is_authenticated_swallows_backend_error() -> None:
    client = _client()
    client.is_authenticated.side_effect = RuntimeError("vault down")
    # Health probe must never raise — it fails closed to False.
    assert _backend(client).is_authenticated() is False


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_empty_addr_raises_value_error() -> None:
    with pytest.raises(ValueError):
        VaultSecretsBackend("", "test-token", client=_client())


def test_empty_token_raises_value_error() -> None:
    with pytest.raises(ValueError):
        VaultSecretsBackend("http://localhost:8200", "", client=_client())


def test_import_error_without_hvac(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force ``import hvac`` to fail regardless of whether hvac is installed.
    monkeypatch.setitem(sys.modules, "hvac", None)
    with pytest.raises(ImportError, match="hvac"):
        VaultSecretsBackend("http://localhost:8200", "test-token")


# ---------------------------------------------------------------------------
# Real (non-DI) constructor path — the ``else:`` branch that imports hvac and
# captures the REAL exception types. Every other test injects a MagicMock via
# ``client=`` and so never exercises this branch. We stub a fake ``hvac`` module
# through ``sys.modules`` so the test passes whether or not hvac is installed.
# ---------------------------------------------------------------------------


def _install_fake_hvac(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Inject a minimal fake ``hvac`` + ``hvac.exceptions`` into sys.modules."""
    import types

    exceptions = types.ModuleType("hvac.exceptions")

    class InvalidPath(Exception):  # noqa: N801 - mirror hvac's class name
        pass

    exceptions.InvalidPath = InvalidPath  # type: ignore[attr-defined]

    hvac = types.ModuleType("hvac")
    hvac.exceptions = exceptions  # type: ignore[attr-defined]

    constructed: dict[str, Any] = {}

    class _Client:
        def __init__(self, **kwargs: Any) -> None:
            constructed["kwargs"] = kwargs
            self.secrets = MagicMock()
            self.is_authenticated = MagicMock(return_value=True)

    hvac.Client = _Client  # type: ignore[attr-defined]
    hvac._constructed = constructed  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "hvac", hvac)
    monkeypatch.setitem(sys.modules, "hvac.exceptions", exceptions)
    return hvac


def test_real_constructor_captures_invalid_path_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Non-DI path: the constructor imports hvac, builds a real client, and
    # captures the REAL InvalidPath type for spoof-proof isinstance matching.
    fake = _install_fake_hvac(monkeypatch)
    backend = VaultSecretsBackend("http://localhost:8200", "test-token")
    assert backend._invalid_path_type is fake.exceptions.InvalidPath
    assert fake._constructed["kwargs"]["url"] == "http://localhost:8200"
    assert fake._constructed["kwargs"]["token"] == "test-token"


async def test_real_path_invalid_path_classified_via_isinstance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Drive get() whose read raises a REAL InvalidPath instance and prove the
    # isinstance path (not the class-name string fallback) classifies it as
    # SecretNotFoundError. The fallback can't fire because _invalid_path_type is
    # the captured real type, so this exercises the spoof-proof branch.
    fake = _install_fake_hvac(monkeypatch)
    backend = VaultSecretsBackend("http://localhost:8200", "test-token")
    backend._client.secrets.kv.v2.read_secret_version.side_effect = fake.exceptions.InvalidPath("404")
    assert backend._invalid_path_type is not None
    with pytest.raises(SecretNotFoundError):
        await backend.get("nonexistent/path")
