# SPDX-License-Identifier: Apache-2.0
"""Secrets management (PHASE 9).

Three backends + one facade:

* :class:`EnvSecretsBackend` — fully implemented. Reads from ``os.environ``.
* :class:`VaultSecretsBackend` — skeleton (PHASE 9 §10.3, Env-only本구현).
  Contract is fixed; PHASE 10/11 can drop in HashiCorp Vault HTTP calls.
* :class:`AwsSecretsManagerBackend` — same: skeleton, raises
  :class:`NotImplementedError`.

:class:`SecretsManager` is a thin facade with a TTL cache + hot-swap. When
operators rotate credentials, calling :meth:`SecretsManager.swap_backend`
empties the cache immediately so the very next ``get`` consults the new
backend (no stale lookups).

Per the secrets-disclosure controls in ``docs/security/threat_model.md`` the
secrets are wrapped in :class:`pydantic.SecretStr` so they redact on
``repr()``/``str()`` and stay out of structured logs (see ``logger.redact``).
"""

from __future__ import annotations

import asyncio
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import SecretStr

__all__ = [
    "AwsSecretsManagerBackend",
    "EnvSecretsBackend",
    "SecretNotFoundError",
    "SecretRevokedError",
    "SecretsBackend",
    "SecretsManager",
    "VaultBackendError",
    "VaultSecretsBackend",
]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SecretNotFoundError(KeyError):
    """Raised when a backend cannot resolve a secret name."""


class VaultBackendError(RuntimeError):
    """Raised when the Vault backend itself fails (unreachable, 403, sealed…).

    Deliberately **not** a :class:`SecretNotFoundError`/``KeyError`` subclass: a
    transport/permission failure must fail *closed*. If it were collapsed into
    "secret not found", a caller's ``except SecretNotFoundError`` could fall back
    to a permissive default while Vault is merely unreachable — a fail-*open*
    hole (see the disclosure controls in ``docs/security/threat_model.md``). The
    type split keeps the two cases distinct.
    """


class SecretRevokedError(VaultBackendError):
    """Raised when a secret version was explicitly deleted/destroyed in Vault.

    A *revoked* credential must never be mistaken for one that *never existed*:
    "absent" can legitimately fall back to a default, whereas "revoked" is an
    active security signal that must fail *closed*. By subclassing
    :class:`VaultBackendError` (not :class:`SecretNotFoundError`) a caller's
    ``except SecretNotFoundError`` cannot downgrade a revoked secret to a
    permissive default — the unreachable-vs-absent ambiguity collapses to the
    safe side.
    """


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class SecretsBackend(ABC):
    """Common contract every secret store must satisfy."""

    @abstractmethod
    async def get(self, name: str, version: str | None = None) -> SecretStr:
        """Return the secret value. Raises :class:`SecretNotFoundError`."""

    @abstractmethod
    async def rotate(self, name: str) -> None:
        """Trigger backend-side rotation (no-op for env-style stores)."""


# ---------------------------------------------------------------------------
# EnvSecretsBackend
# ---------------------------------------------------------------------------


class EnvSecretsBackend(SecretsBackend):
    """Reads from ``os.environ``.

    Suitable for dev / single-tenant deployments. Rotation is externally
    managed (operator restarts process with new env), so :meth:`rotate` is
    a deliberate no-op rather than raising.
    """

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        if version is not None:
            # Env vars have no version concept. Refusing strict version pins
            # is a contract decision: callers that pass version=X for an env
            # backend almost certainly have a bug.
            raise NotImplementedError("EnvSecretsBackend does not support versioned reads")
        if name not in os.environ:
            raise SecretNotFoundError(name)
        return SecretStr(os.environ[name])

    async def rotate(self, name: str) -> None:
        return None  # externally rotated; no-op


# ---------------------------------------------------------------------------
# Skeleton backends (PHASE 10+ work)
# ---------------------------------------------------------------------------


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault KV v2 backend (PHASE 10 — C-3).

    Install with ``pip install 'secugent[vault]'``. Construction holds an
    authenticated ``hvac.Client``; secrets are addressed as
    ``"path/to/secret#field"`` where the optional ``#field`` selects one key
    inside the KV v2 secret (default field name ``"value"``).

    Failure model (fail-closed):

    * KV path absent (hvac ``InvalidPath``)        → :class:`SecretNotFoundError`
    * field absent in an existing secret           → :class:`SecretNotFoundError`
    * version deleted/destroyed (revoked)          → :class:`SecretRevokedError`
    * anything else (unreachable, 403, sealed, …)  → :class:`VaultBackendError`

    Revoked-vs-absent discrimination is driven by the Vault *payload*, not by an
    exception type. hvac's ``read_secret_version(raise_on_deleted_version=True)``
    re-raises the *same* ``InvalidPath`` for a deleted/destroyed version as for a
    genuinely absent path, so an exception-type test cannot tell them apart (and
    no ``VaultDeletedVersion``/``VaultDestroyedVersion`` exception type exists in
    any hvac release). Instead :meth:`get` reads with
    ``raise_on_deleted_version=False`` and inspects ``data.metadata``: a non-empty
    ``deletion_time`` (soft-deleted) or ``destroyed == true`` is classified as
    :class:`SecretRevokedError` *before* the field is extracted. A true
    ``InvalidPath`` (no such path at all) maps to :class:`SecretNotFoundError`.

    The "missing path" exception itself is still matched against the *real*
    ``hvac.exceptions.InvalidPath`` type (captured at construction on the non-DI
    path), never by a bare class-name string — a string match would let any
    in-process component named ``InvalidPath`` downgrade a hard
    ``VaultBackendError`` into a soft ``SecretNotFoundError`` (fail-open). On the
    DI/test path (where ``hvac`` may be absent) the string fallback is the only
    option and is used solely there.

    ``hvac`` ships no type stubs, so the client is typed :data:`Any` (see the
    justification at the import site). Every value handed back is re-wrapped in
    :class:`pydantic.SecretStr` so it redacts on ``repr()``/log.
    """

    _DEFAULT_FIELD: Final[str] = "value"

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        *,
        namespace: str | None = None,
        mount_point: str = "secret",
        timeout: int = 5,
        client: Any | None = None,
    ) -> None:
        if not vault_addr:
            raise ValueError("vault_addr must be a non-empty Vault URL")
        if not vault_token:
            raise ValueError("vault_token must be a non-empty Vault token")
        # Real hvac InvalidPath type, captured once at construction on the
        # non-DI path so get() can match the ACTUAL class via isinstance
        # (spoof-proof) instead of a class-name string. None on the DI/test
        # path, where hvac may be absent and the string fallback is used.
        # Revoked-vs-absent is NOT discriminated by an exception type (no such
        # hvac type exists); see get() — it is read off the payload metadata.
        self._invalid_path_type: type[BaseException] | None = None
        if client is not None:
            # Dependency-injected client (tests / custom auth flows): the caller
            # owns auth, so we skip the hvac import + construction entirely.
            self._client: Any = client
        else:
            try:
                import hvac
                import hvac.exceptions as hvac_exc
            except ImportError as exc:
                raise ImportError(
                    "hvac is required for VaultSecretsBackend — install it with: "
                    "pip install 'secugent[vault]'"
                ) from exc
            # hvac has no type stubs; the client is intentionally Any (§B-3 waiver).
            self._client = hvac.Client(
                url=vault_addr,
                token=vault_token,
                namespace=namespace,
                timeout=timeout,
            )
            self._invalid_path_type = hvac_exc.InvalidPath
        self._mount_point = mount_point

    @staticmethod
    def _revocation_reason(response: dict[str, Any]) -> str | None:
        """Return a revoked-version reason from the KV v2 envelope, else None.

        hvac re-raises ``InvalidPath`` for a deleted/destroyed version — the
        same type as a genuinely absent path — so revocation cannot be detected
        from the exception. With ``raise_on_deleted_version=False`` the deleted
        version still returns an envelope whose ``data.metadata`` carries the
        signal: a non-empty ``deletion_time`` (soft-deleted) or ``destroyed ==
        true`` (purged). Either is a *revoked* credential that must fail CLOSED,
        never collapse into "absent".
        """
        meta = response.get("data", {})
        meta = meta.get("metadata", {}) if isinstance(meta, dict) else {}
        if not isinstance(meta, dict):
            return None
        if meta.get("destroyed") is True:
            return "destroyed"
        deletion_time = meta.get("deletion_time")
        if isinstance(deletion_time, str) and deletion_time != "":
            return "deleted"
        return None

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        path, sep, field_name = name.partition("#")
        field_name = field_name if sep else self._DEFAULT_FIELD
        if not path:
            raise SecretNotFoundError(name)
        try:
            version_int = int(version) if version else None
        except ValueError as exc:
            # A non-numeric version pin (e.g. "latest", "v2") is a caller bug, but
            # it must NOT escape as a bare ValueError outside the documented
            # 3-way failure model. Classify it as "not found" (fail-as-missing):
            # the requested version cannot be resolved.
            raise SecretNotFoundError(f"Vault: version must be an integer, got {version!r}") from exc

        def _read() -> dict[str, Any]:
            # raise_on_deleted_version=False: a deleted/destroyed version returns
            # an envelope whose data.metadata flags the revocation. With True,
            # hvac raises InvalidPath — indistinguishable from a truly absent
            # path — which would downgrade a *revoked* credential to "missing"
            # (fail-open). See _revocation_reason / the failure-model docstring.
            result = self._client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self._mount_point,
                version=version_int,
                raise_on_deleted_version=False,
            )
            # hvac returns Any; normalise to a plain dict for downstream typing.
            return dict(result)

        try:
            # Block the synchronous hvac/requests call off the event loop.
            response = await asyncio.to_thread(_read)
        except Exception as exc:
            # Classify "no such secret" (fail-as-missing) vs revoked
            # (fail-CLOSED) vs ANY other backend/transport/authorization
            # failure (fail-CLOSED via a non-KeyError). Capture only the
            # exception *type name* up front; it never echoes secret material,
            # unlike the message body.
            exc_type_name = type(exc).__name__
            # "Missing path" — match the REAL hvac.exceptions.InvalidPath type on
            # the non-DI path (spoof-proof). Fall back to the class-name string
            # ONLY when no real type was captured (DI/test path, hvac absent).
            is_invalid_path = (
                isinstance(exc, self._invalid_path_type)
                if self._invalid_path_type is not None
                else exc_type_name == "InvalidPath"
            )
            if is_invalid_path:
                raise SecretNotFoundError(f"Vault: no secret at '{path}'") from None
            # Surface only the path + exception *type* — never the upstream
            # message body, which could echo token/secret material. ``from None``
            # drops the cause so chained-traceback rendering (logging.exception,
            # uncaught propagation, Sentry) cannot leak the token carried in the
            # upstream exception's message.
            raise VaultBackendError(f"Vault read failed for '{path}': {exc_type_name}") from None

        # A deleted/destroyed version is a *revoked* credential, NOT an absent
        # one. Detect it from the payload metadata (hvac cannot signal it via an
        # exception type) and fail CLOSED before extracting any field, so a
        # caller's ``except SecretNotFoundError`` can never downgrade a revoked
        # secret to a permissive default.
        revocation = self._revocation_reason(response)
        if revocation is not None:
            raise SecretRevokedError(f"Vault: secret '{path}' version is {revocation} (revoked)")

        data = response.get("data", {}).get("data", {})
        if not isinstance(data, dict) or field_name not in data:
            raise SecretNotFoundError(f"Vault secret '{path}' has no field '{field_name}'")
        return SecretStr(str(data[field_name]))

    async def rotate(self, name: str) -> None:
        # KV v2 holds *static* secrets; SecuGent does not drive their rotation
        # (that is a dynamic-secrets-engine / external concern). Fail loud rather
        # than silently no-op so an operator never believes a static Vault secret
        # was rotated when it was not. Use ``SecretsManager.invalidate(name)`` to
        # evict a cached value.
        raise NotImplementedError(
            "VaultSecretsBackend manages static KV v2 secrets; rotation is "
            "performed out-of-band (dynamic secrets engine / external rotation)"
        )

    def is_authenticated(self) -> bool:
        # Readiness/health probe. Any failure (unreachable, bad token, sealed)
        # reads as "not authenticated" — a fail-closed boolean that never raises
        # and crashes a deployment probe.
        try:
            return bool(self._client.is_authenticated())
        except Exception:
            return False


class AwsSecretsManagerBackend(SecretsBackend):
    """Skeleton for AWS Secrets Manager. Same fail-closed treatment as Vault."""

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        raise NotImplementedError("AwsSecretsManagerBackend is a PHASE 9 skeleton")

    async def rotate(self, name: str) -> None:
        raise NotImplementedError("AwsSecretsManagerBackend.rotate is not implemented yet")


# ---------------------------------------------------------------------------
# SecretsManager facade with TTL cache + hot-swap
# ---------------------------------------------------------------------------


_DEFAULT_TTL_SECONDS: Final[int] = 300


@dataclass
class _CacheEntry:
    value: SecretStr
    expires_at: float = field(default=0.0)


class SecretsManager:
    """Cache-and-fan-out wrapper around a :class:`SecretsBackend`.

    * In-memory dict cache keyed by secret name.
    * Per-entry expiry timestamp computed from ``ttl_seconds``.
    * :meth:`swap_backend` invalidates the cache atomically so the next
      lookup consults the fresh backend — used during operator-driven
      rotations.
    """

    def __init__(self, backend: SecretsBackend, *, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        if ttl_seconds < 0:
            raise ValueError("ttl_seconds must be >= 0")
        self._backend = backend
        self._ttl = ttl_seconds
        self._cache: dict[str, _CacheEntry] = {}

    @property
    def backend(self) -> SecretsBackend:
        return self._backend

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        now = time.monotonic()
        # Version is part of the cache identity: a versioned read pins a specific
        # value, so caching by name alone would serve a stale version after a
        # rotation/version bump (fail-stale). NUL separates the two halves so no
        # name/version pair can collide with another.
        cache_key = f"{name}\x00{version}"
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at > now:
            return cached.value
        value = await self._backend.get(name, version=version)
        self._cache[cache_key] = _CacheEntry(
            value=value, expires_at=now + self._ttl if self._ttl > 0 else 0.0
        )
        return value

    async def rotate(self, name: str) -> None:
        await self._backend.rotate(name)
        self._evict_all_versions(name)

    def invalidate(self, name: str) -> None:
        """Drop one cached secret so the next ``get`` re-consults the backend.

        Unlike :meth:`rotate`, this does NOT trigger backend-side rotation — it
        is the revoke/refresh hook (EM-06): when a credential is suspected
        compromised, evict it immediately without waiting for TTL. Unknown names
        are a no-op.
        """
        self._evict_all_versions(name)

    def _evict_all_versions(self, name: str) -> None:
        """Drop every cached version of ``name``.

        The cache key is ``f"{name}\\x00{version}"`` (see :meth:`get`), so a
        rotation/revoke for a name must evict all of its version-pinned entries,
        not just one — otherwise a stale pinned value could survive.
        """
        prefix = f"{name}\x00"
        for key in [k for k in self._cache if k.startswith(prefix)]:
            self._cache.pop(key, None)

    def swap_backend(self, new_backend: SecretsBackend) -> None:
        """Replace the underlying backend; invalidate the entire cache."""
        self._backend = new_backend
        self._cache.clear()
