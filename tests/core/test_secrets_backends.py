# SPDX-License-Identifier: Apache-2.0
"""PHASE 9 — secrets backends unit tests (RED first)."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import SecretStr

from secugent.core.secrets import (
    AwsSecretsManagerBackend,
    EnvSecretsBackend,
    SecretNotFoundError,
    SecretsBackend,
    SecretsManager,
)

# ---------------------------------------------------------------------------
# EnvSecretsBackend (the only fully-implemented backend in PHASE 9)
# ---------------------------------------------------------------------------


async def test_env_backend_get_existing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_TEST_SECRET", "shh")
    backend = EnvSecretsBackend()
    value = await backend.get("SECUGENT_TEST_SECRET")
    assert isinstance(value, SecretStr)
    assert value.get_secret_value() == "shh"


async def test_env_backend_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECUGENT_DOES_NOT_EXIST", raising=False)
    backend = EnvSecretsBackend()
    with pytest.raises(SecretNotFoundError):
        await backend.get("SECUGENT_DOES_NOT_EXIST")


async def test_env_backend_rotate_not_supported() -> None:
    # Env-based secrets are externally rotated; rotate() is a no-op or
    # documented refusal. Either is acceptable; we assert "no exception".
    backend = EnvSecretsBackend()
    await backend.rotate("SECUGENT_ANYTHING")


# ---------------------------------------------------------------------------
# Skeleton backends — contract test (NotImplementedError is acceptable)
#
# VaultSecretsBackend is no longer a skeleton (C-3): it is implemented and
# covered by tests/unit/test_vault_secrets_backend.py. Only AWS Secrets Manager
# remains a fail-closed skeleton here.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "factory",
    [AwsSecretsManagerBackend],
    ids=["aws_sm"],
)
async def test_skeleton_backend_get_raises_not_implemented(
    factory: type[SecretsBackend],
) -> None:
    backend = factory()
    with pytest.raises(NotImplementedError):
        await backend.get("anything")


@pytest.mark.parametrize(
    "factory",
    [AwsSecretsManagerBackend],
    ids=["aws_sm"],
)
async def test_skeleton_backend_rotate_raises_not_implemented(
    factory: type[SecretsBackend],
) -> None:
    backend = factory()
    with pytest.raises(NotImplementedError):
        await backend.rotate("anything")


# ---------------------------------------------------------------------------
# SecretsManager — TTL cache, hot-swap invalidation
# ---------------------------------------------------------------------------


class _RecordingBackend(SecretsBackend):
    """In-memory backend that records every get/rotate call."""

    def __init__(self, store: dict[str, str] | None = None) -> None:
        self.store: dict[str, str] = dict(store or {})
        self.get_calls: list[str] = []
        self.rotate_calls: list[str] = []

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        self.get_calls.append(name)
        if name not in self.store:
            raise SecretNotFoundError(name)
        return SecretStr(self.store[name])

    async def rotate(self, name: str) -> None:
        self.rotate_calls.append(name)
        self.store[name] = self.store.get(name, "") + "-rotated"


async def test_manager_caches_within_ttl() -> None:
    backend = _RecordingBackend({"k": "v"})
    mgr = SecretsManager(backend, ttl_seconds=60)
    v1 = await mgr.get("k")
    v2 = await mgr.get("k")
    assert v1.get_secret_value() == "v" == v2.get_secret_value()
    # Backend only consulted once
    assert backend.get_calls == ["k"]


async def test_manager_ttl_expiry_refetches() -> None:
    backend = _RecordingBackend({"k": "v"})
    mgr = SecretsManager(backend, ttl_seconds=0)  # immediate expiry
    await mgr.get("k")
    await asyncio.sleep(0.01)
    await mgr.get("k")
    assert backend.get_calls == ["k", "k"]


async def test_manager_swap_backend_invalidates_cache() -> None:
    old = _RecordingBackend({"k": "old"})
    new = _RecordingBackend({"k": "new"})
    mgr = SecretsManager(old, ttl_seconds=60)
    v1 = await mgr.get("k")
    assert v1.get_secret_value() == "old"
    assert old.get_calls == ["k"]
    mgr.swap_backend(new)
    v2 = await mgr.get("k")
    assert v2.get_secret_value() == "new"
    assert new.get_calls == ["k"]
