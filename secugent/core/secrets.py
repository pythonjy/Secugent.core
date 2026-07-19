# SPDX-License-Identifier: Apache-2.0
"""Secrets management (PHASE 9; G-H13 boot factory).

Four backends + one facade + one boot factory:

* :class:`EnvSecretsBackend` — fully implemented. Reads from ``os.environ``.
* :class:`VaultSecretsBackend` — **fully implemented** HashiCorp Vault KV v2
  backend (fail-closed; see the class docstring for the failure model). Requires
  the ``vault`` extra (``pip install 'secugent[vault]'``).
* :class:`AwsSecretsManagerBackend` — **fully implemented** AWS Secrets Manager
  backend (S8a / G-M7; fail-closed, same model as Vault — see the class
  docstring). Requires the ``aws`` extra (``pip install 'secugent[aws]'``).
* :class:`GcpSecretManagerBackend` — **fully implemented** GCP Secret Manager
  backend (B7; fail-closed, same model as AWS — see the class docstring). Auth
  via Application Default Credentials / Workload Identity; static key files are
  never accepted. Requires the ``gcp`` extra
  (``pip install 'secugent[gcp]'``).

:class:`SecretsManager` is a thin facade with a TTL cache + hot-swap. When
operators rotate credentials, calling :meth:`SecretsManager.swap_backend`
empties the cache immediately so the very next ``get`` consults the new
backend (no stale lookups).

:func:`build_secrets_backend` is the boot factory the ``create_app`` integration
step calls: it selects :class:`VaultSecretsBackend` when Vault is configured
(``VAULT_ADDR`` + a token OR an AppRole role-id/secret-id), else
:class:`GcpSecretManagerBackend` when ``GCP_SECRETS_PROJECT`` is set, else
:class:`AwsSecretsManagerBackend` when ``AWS_SECRETS_REGION`` is set, else
:class:`EnvSecretsBackend`. When Vault IS configured but unreachable / the auth
is rejected it raises :class:`VaultBackendError` — it NEVER silently falls back
to plaintext env (fail-closed, SECURITY_CONTRACT §6). ANY TWO of {Vault, AWS,
GCP} configured simultaneously raises ``ValueError`` (ambiguous secret plane,
fail-closed).

Per :data:`SECURITY_CONTRACT.md` §6 the secrets are wrapped in
:class:`pydantic.SecretStr` so they redact on ``repr()``/``str()`` and stay
out of structured logs (see ``logger.redact``).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from pydantic import BaseModel, ConfigDict, SecretStr

__all__ = [
    "AwsSecretsBackendError",
    "AwsSecretsManagerBackend",
    "EnvSecretsBackend",
    "GcpSecretsBackendError",
    "GcpSecretManagerBackend",
    "SecretNotFoundError",
    "SecretRevokedError",
    "SecretsBackend",
    "SecretsManager",
    "SecretsSettings",
    "VaultBackendError",
    "VaultSecretsBackend",
    "build_secrets_backend",
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
    hole (SECURITY_CONTRACT §6). The type split keeps the two cases distinct.
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


class AwsSecretsBackendError(RuntimeError):
    """Raised when the AWS Secrets Manager backend itself fails (S8a / G-M7).

    Covers AccessDenied, decryption failure, throttling, and any transport /
    availability error. Deliberately **not** a
    :class:`SecretNotFoundError`/``KeyError`` subclass — exactly like
    :class:`VaultBackendError`: a permission/transport failure must fail *closed*.
    If it collapsed into "secret not found", a caller's
    ``except SecretNotFoundError`` could fall back to a permissive default while
    AWS is merely throttling or denying access — a fail-*open* hole
    (SECURITY_CONTRACT §6). Only AWS ``ResourceNotFoundException`` (the secret /
    version genuinely does not exist) maps to :class:`SecretNotFoundError`.
    """


class GcpSecretsBackendError(RuntimeError):
    """Raised when the GCP Secret Manager backend itself fails (B7).

    Covers PermissionDenied, transport failure, throttling, missing credentials,
    and decryption errors. Deliberately **not** a
    :class:`SecretNotFoundError`/``KeyError`` subclass — exactly like
    :class:`AwsSecretsBackendError`: a permission/transport failure must fail
    *closed*. If it collapsed into "secret not found", a caller's
    ``except SecretNotFoundError`` could fall back to a permissive default while
    GCP is merely throttling or denying access — a fail-*open* hole
    (SECURITY_CONTRACT §6). Only ``google.api_core.exceptions.NotFound`` (the
    secret / version genuinely does not exist) maps to
    :class:`SecretNotFoundError`.
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
# Vault + AWS Secrets Manager backends (both fully implemented, fail-closed)
# ---------------------------------------------------------------------------


class VaultSecretsBackend(SecretsBackend):
    """HashiCorp Vault KV v2 backend (C-3) — fully implemented, fail-closed.

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


# ---------------------------------------------------------------------------
# Shared helpers — JSON field extraction + GCP error classification
# ---------------------------------------------------------------------------


def _select_secret_field(
    secret_string: str,
    field_name: str | None,
    secret_id: str,
    *,
    backend_name: str,
) -> str:
    """Return the raw secret, or one JSON field when ``field_name`` is set.

    Without a field the raw string is returned verbatim. With a field, the
    secret MUST parse as a JSON object containing that key, else it is a
    fail-as-missing :class:`SecretNotFoundError` (a ``#field`` on a
    non-JSON / fieldless secret cannot resolve).

    ``from None`` on :class:`json.JSONDecodeError`: a JSONDecodeError message
    echoes a snippet of the offending input — i.e. the SECRET material — so it
    must never be chained as ``__cause__`` (SECURITY_CONTRACT §6). Only the
    backend name, SecretId, and caller-supplied field name (not secret material)
    are surfaced.
    """
    if field_name is None:
        return secret_string
    try:
        parsed = json.loads(secret_string)
    except (json.JSONDecodeError, ValueError):
        raise SecretNotFoundError(
            f"{backend_name} secret '{secret_id}' is not a JSON object; cannot select field '{field_name}'"
        ) from None
    if not isinstance(parsed, dict) or field_name not in parsed:
        raise SecretNotFoundError(f"{backend_name} secret '{secret_id}' has no field '{field_name}'")
    return str(parsed[field_name])


def _gcp_is_not_found(exc: BaseException) -> bool:
    """Best-effort: detect ``google.api_core.exceptions.NotFound`` without importing it.

    Works WITHOUT importing ``google.api_core`` (the extra may be absent on a
    slim install). Detection strategy:

    1. If an int status code is present, trust it exclusively: 404 ⇒ NotFound,
       anything else ⇒ NOT NotFound. ``google-api-core``'s ``GoogleAPICallError``
       subclasses set ``.code`` (the int HTTP status, e.g. 404 for ``NotFound``);
       some transports also set ``.http_status_code``. We read ``.code`` first,
       then ``.http_status_code``, and trust the value only when it is a plain
       ``int`` — a gRPC ``StatusCode`` enum or a callable ``.code`` is ignored.
       This prevents a class coincidentally named "NotFound" from being
       misclassified when the status signals a different error (e.g. 500).
    2. If no int status code is present (bare gRPC transport), fall back to the
       type-name ``"NotFound"`` — the canonical, stable class name across all
       google-api-core releases for gRPC STATUS_NOT_FOUND.

    A bare transport error (``ConnectionError``, ``ReadTimeoutError``) has no int
    status code and a different class name ⇒ returns ``False`` ⇒ treated as an
    availability failure (fail-CLOSED). Mirrors :func:`_aws_error_code`'s
    best-effort, import-free classification pattern.
    """
    # google-api-core's ``GoogleAPICallError`` subclasses (NotFound,
    # PermissionDenied, …) expose the HTTP status as an int ``.code`` (e.g. 404);
    # some transports also set ``.http_status_code``. Read ``.code`` first (the
    # attribute the real library sets), then fall back to ``.http_status_code``,
    # and trust the value only when it is a plain ``int`` — a gRPC ``StatusCode``
    # enum or a callable ``.code`` is NOT an int and is ignored.
    http_code = getattr(exc, "code", None)
    if not isinstance(http_code, int):
        http_code = getattr(exc, "http_status_code", None)
    if isinstance(http_code, int):
        # Structured code present: trust it exclusively, don't fall through to
        # the type-name branch even if the class happens to be named "NotFound".
        # A non-404 code with a "NotFound" class name is a collision, not a real
        # NotFound — failing closed (returning False) is the safe choice.
        return http_code == 404
    # No structured int code (bare gRPC transport): type name is the canonical signal.
    return type(exc).__name__ == "NotFound"


# ---------------------------------------------------------------------------
# GCP Secret Manager backend (B7 / Workload Identity — fully implemented, fail-closed)
# ---------------------------------------------------------------------------

_GCP_DEFAULT_VERSION: Final[str] = "latest"


class _GcpSecretManagerClient(Protocol):
    """The GCP Secret Manager subset this backend uses.

    Typing ``_client`` as this Protocol (not :data:`Any`) makes mypy --strict
    check the call signature of the external call statically, while still
    admitting injected test fakes and the lazily-built
    ``SecretManagerServiceClient`` (mirrors :class:`_AwsSecretsClient`).
    """

    def access_secret_version(self, *, name: str) -> Any: ...


class GcpSecretManagerBackend(SecretsBackend):
    """GCP Secret Manager backend (B7) — fully implemented, fail-closed.

    Install with ``pip install 'secugent[gcp]'``. Auth via Application Default
    Credentials (ADC); on GKE this resolves to Workload Identity automatically.
    A static key file / service-account JSON is **never** accepted — operators
    must provision ADC (Workload Identity or ``gcloud auth application-default
    login`` for local dev) so credentials rotate without a redeploy
    (SECURITY_CONTRACT §6).

    Secrets are addressed by their short secret_id (NOT the full resource path);
    an optional ``"#field"`` selects one key inside a JSON payload (e.g.
    ``"prod-db-creds#password"``). Without ``#field`` the raw UTF-8 payload is
    returned verbatim. GCP secret ids must match ``[a-zA-Z0-9_-]+`` (no slashes
    or other special characters), so the ``#`` is the only reserved separator.

    Resource path built internally:
    ``projects/<project>/secrets/<id>/versions/<version-or-latest>``

    A ``client`` may be injected (tests / custom auth flows); otherwise a
    ``SecretManagerServiceClient`` is built **lazily** the first time a secret
    is needed (google-cloud-secret-manager absent ⇒ an actionable
    :class:`ImportError`, never a bare ``ModuleNotFoundError``).

    Failure model (fail-closed, identical in spirit to
    :class:`AwsSecretsManagerBackend`):

    * secret / version absent (``google.api_core.exceptions.NotFound``)  →
      :class:`SecretNotFoundError`
    * ``#field`` absent / payload not a JSON object                       →
      :class:`SecretNotFoundError`
    * binary payload that is not valid UTF-8                              →
      :class:`SecretNotFoundError`
    * PermissionDenied / transport / throttle / missing-creds / decrypt   →
      :class:`GcpSecretsBackendError`

    The NotFound verdict is extracted from the exception's int status code
    (``.code``, falling back to ``http_status_code``) WITHOUT importing
    ``google.api_core`` (the extra may be absent on a slim install), so a bare
    transport error with no structured code fails CLOSED. Only the secret_id + exception *type name* are surfaced in errors —
    never the upstream message body (which can echo IAM tokens or secret
    material) — and ``from None`` drops the cause so chained-traceback rendering
    (logging.exception / Sentry / uncaught propagation) cannot leak it
    (SECURITY_CONTRACT §6). Every value handed back is wrapped in
    :class:`pydantic.SecretStr` so it redacts on ``repr()``/log.
    """

    def __init__(
        self,
        *,
        project: str,
        client: _GcpSecretManagerClient | None = None,
    ) -> None:
        if not project:
            raise ValueError(
                "project must be a non-empty GCP project id (e.g. 'my-project' or 'projects/my-project')"
            )
        self._project = project
        # DI/test path: caller owns the client, so the google import is skipped
        # entirely. Otherwise the client is built lazily on first get().
        self._client: _GcpSecretManagerClient | None = client

    def _secret_manager(self) -> _GcpSecretManagerClient:
        if self._client is not None:
            return self._client
        try:
            # google.cloud.secretmanager has no bundled type stubs; absent stubs
            # are already covered by `ignore_missing_imports = true` in
            # pyproject.toml [tool.mypy] (§B-3 waiver; mirrors the boto3 pattern
            # in AwsSecretsManagerBackend._secretsmanager).
            from google.cloud import secretmanager
        except ImportError as exc:
            raise ImportError(
                "google-cloud-secret-manager is required for GcpSecretManagerBackend "
                "— install it with: pip install 'secugent[gcp]'"
            ) from exc
        # The assignment to the Protocol boundary is the one Any-crossing;
        # mypy still checks the call sites against _GcpSecretManagerClient.
        sm_client: _GcpSecretManagerClient = secretmanager.SecretManagerServiceClient()
        self._client = sm_client
        return sm_client

    def _resource_name(self, secret_id: str, version: str | None) -> str:
        # Treat both ``None`` and ``""`` as "use the default version" (mirrors the
        # Vault backend's ``if version else`` idiom). An empty string would
        # otherwise build ``.../versions/`` (trailing slash → INVALID_ARGUMENT,
        # which fail-closes as a non-NotFound backend error rather than 'latest').
        v = version if version else _GCP_DEFAULT_VERSION
        return f"projects/{self._project}/secrets/{secret_id}/versions/{v}"

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        secret_id, sep, field_name = name.partition("#")
        selected_field: str | None = field_name if sep else None
        if not secret_id:
            raise SecretNotFoundError(name)

        # Resolve the client; may import google-cloud-secret-manager (lazy).
        # Do NOT swallow ImportError as a backend error — a missing extra is a
        # config error, not a GCP outage.
        client = self._secret_manager()
        resource_name = self._resource_name(secret_id, version)

        def _read() -> Any:
            # google-cloud-secretmanager is synchronous over gRPC/REST; block
            # it off the event loop so we don't stall the async server.
            return client.access_secret_version(name=resource_name)

        try:
            # Block the synchronous GCP client call off the event loop.
            response = await asyncio.to_thread(_read)
        except Exception as exc:
            # Classify "no such secret/version" (fail-as-missing) vs ANY other
            # backend/transport/permission failure (fail-CLOSED via a non-KeyError).
            # Capture only the exception *type name* up front; it never echoes
            # secret material, unlike the message body.
            exc_type_name = type(exc).__name__
            if _gcp_is_not_found(exc):
                raise SecretNotFoundError(f"GCP Secret Manager: no secret '{secret_id}'") from None
            # PermissionDenied / transport / throttle / missing-creds / decrypt:
            # fail CLOSED. Surface only the secret_id + exception *type* (never
            # the upstream message body, which can echo IAM tokens or secret
            # material). ``from None`` drops the cause so chained-traceback
            # rendering (logging.exception / Sentry / uncaught propagation)
            # cannot leak it (SECURITY_CONTRACT §6).
            raise GcpSecretsBackendError(
                f"GCP Secret Manager read failed for '{secret_id}': {exc_type_name}"
            ) from None

        # Extract the bytes payload. An absent/None payload is classified as
        # fail-as-missing (not a transport error — the API call succeeded).
        payload = getattr(response, "payload", None)
        raw: object = getattr(payload, "data", None) if payload is not None else None
        if not isinstance(raw, bytes):
            raise SecretNotFoundError(f"GCP secret '{secret_id}' has no byte payload")

        # Decode UTF-8; a binary-only secret is not returnable as text.
        try:
            secret_string = raw.decode("utf-8")
        except UnicodeDecodeError:
            # ``from None``: UnicodeDecodeError.reason echoes the offending
            # byte sequence and position — not secret material per se, but
            # erring on the side of §6 minimal disclosure.
            raise SecretNotFoundError(
                f"GCP secret '{secret_id}' payload is not valid UTF-8 text "
                "(binary-only secrets are unsupported)"
            ) from None

        value = _select_secret_field(secret_string, selected_field, secret_id, backend_name="GCP")
        return SecretStr(value)

    async def rotate(self, name: str) -> None:
        # GCP Secret Manager drives rotation externally (Cloud Scheduler /
        # rotation functions). SecuGent does not trigger it. Fail loud rather
        # than silently no-op so an operator never believes a secret was rotated
        # when it was not (mirrors AwsSecretsManagerBackend). Use
        # ``SecretsManager.invalidate(name)`` to evict a cached value.
        raise NotImplementedError(
            "GcpSecretManagerBackend does not drive rotation; GCP Secret Manager "
            "rotation is configured out-of-band (Cloud Scheduler / rotation function)"
        )


# ---------------------------------------------------------------------------
# AWS Secrets Manager helpers
# ---------------------------------------------------------------------------

# AWS error codes that are a DEFINITE "the secret/version does not exist" verdict
# (fail-as-missing), NOT a transport/permission failure. Everything else —
# AccessDenied, DecryptionFailure, throttling, network, missing credentials —
# fails CLOSED as an AwsSecretsBackendError.
_AWS_NOT_FOUND_CODE: Final[str] = "ResourceNotFoundException"


class _AwsSecretsClient(Protocol):
    """The exact boto3 Secrets Manager subset this backend uses.

    Typing ``_client`` as this Protocol (not :data:`Any`) makes mypy --strict
    check the kwarg names and return shape of the external call statically, while
    still admitting the injected test fakes and the lazily-built boto3 client
    (mirrors :class:`secugent.enterprise.kms._AwsKmsClient`).
    """

    def get_secret_value(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _aws_error_code(exc: BaseException) -> str | None:
    """Best-effort extract of a botocore ``ClientError`` ``Error.Code`` (or None).

    Works WITHOUT importing botocore (the extra may be absent on a slim install).
    A bare transport error (e.g. ``ConnectionError``, ``ReadTimeoutError``) has no
    such structured code and yields ``None`` ⇒ treated as an availability failure
    (fail-CLOSED), not a "not found" verdict. Mirrors
    :func:`secugent.enterprise.kms._aws_error_code`.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            code = error.get("Code")
            if isinstance(code, str):
                return code
    return None


class AwsSecretsManagerBackend(SecretsBackend):
    """AWS Secrets Manager backend (S8a / G-M7) — fully implemented, fail-closed.

    Install with ``pip install 'secugent[aws]'``. Secrets are addressed by their
    AWS ``SecretId`` (name or ARN); an optional ``"#field"`` selects one key
    inside a JSON ``SecretString`` (e.g. ``"prod/db#password"``). Without
    ``#field`` the raw ``SecretString`` is returned verbatim (it may itself be
    JSON — the caller asked for the whole secret).

    A ``client`` may be injected (tests / custom auth flows); otherwise a boto3
    ``secretsmanager`` client is built **lazily** the first time a secret is
    needed (boto3 absent ⇒ an actionable :class:`ImportError`, never a bare
    ``ModuleNotFoundError``).

    Failure model (fail-closed, identical in spirit to
    :class:`VaultSecretsBackend`):

    * secret / version absent (``ResourceNotFoundException``)  → :class:`SecretNotFoundError`
    * ``#field`` absent / SecretString not JSON                → :class:`SecretNotFoundError`
    * binary-only secret (no ``SecretString``)                 → :class:`SecretNotFoundError`
    * AccessDenied / decryption / throttle / network / no-creds → :class:`AwsSecretsBackendError`

    The AWS error code is read off ``exc.response["Error"]["Code"]`` WITHOUT
    importing botocore (the extra may be absent), so a transport error with no
    structured code falls CLOSED. Only the ``SecretId`` + exception *type name*
    are surfaced in errors — never the upstream message body (which can echo
    token/ciphertext material) — and ``from None`` drops the cause so chained
    traceback rendering cannot leak it (SECURITY_CONTRACT §6). Every value handed
    back is wrapped in :class:`pydantic.SecretStr` so it redacts on ``repr()``/log.
    """

    _DEFAULT_FIELD_SENTINEL: Final[None] = None

    def __init__(
        self,
        *,
        region_name: str,
        endpoint_url: str | None = None,
        client: _AwsSecretsClient | None = None,
    ) -> None:
        if not region_name:
            raise ValueError("region_name must be a non-empty AWS region (e.g. 'ap-northeast-2')")
        self._region_name = region_name
        self._endpoint_url = endpoint_url
        # DI/test path: caller owns the client, so the boto3 import is skipped
        # entirely. Otherwise the client is built lazily on first get().
        self._client: _AwsSecretsClient | None = client

    def _secretsmanager(self) -> _AwsSecretsClient:
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError as exc:
            raise ImportError(
                "boto3 is required for AwsSecretsManagerBackend — install it with: "
                "pip install 'secugent[aws]'"
            ) from exc
        # boto3 is untyped here (optional extra); the assignment to the Protocol
        # is the one Any-boundary, and mypy still checks the call against
        # _AwsSecretsClient (mirrors enterprise/kms.py AwsKmsProvider._kms).
        client: _AwsSecretsClient = boto3.client(
            "secretsmanager",
            region_name=self._region_name,
            endpoint_url=self._endpoint_url,
        )
        self._client = client
        return client

    @staticmethod
    def _select_field(secret_string: str, field_name: str | None, secret_id: str) -> str:
        """Return the raw secret, or one JSON field when ``field_name`` is set.

        Delegates to the module-level :func:`_select_secret_field` with
        ``backend_name="AWS"`` so both AWS and GCP share the same
        JSON-field-selection contract (SECURITY_CONTRACT §6: ``from None`` on
        decode, never echo secret material in the error).
        """
        return _select_secret_field(secret_string, field_name, secret_id, backend_name="AWS")

    async def get(self, name: str, version: str | None = None) -> SecretStr:
        secret_id, sep, field_name = name.partition("#")
        selected_field = field_name if sep else self._DEFAULT_FIELD_SENTINEL
        if not secret_id:
            raise SecretNotFoundError(name)

        # boto3 is synchronous; resolving the client may import boto3 (lazy). Do
        # NOT swallow that ImportError as a backend error — a missing extra is a
        # config error, not an AWS outage.
        client = self._secretsmanager()

        kwargs: dict[str, Any] = {"SecretId": secret_id}
        if version is not None:
            # AWS pins a specific version by VersionId. An unknown id surfaces as
            # ResourceNotFoundException -> SecretNotFoundError (fail-as-missing).
            kwargs["VersionId"] = version

        def _read() -> Mapping[str, Any]:
            # boto3 returns a plain dict; the Protocol return type is Mapping.
            return client.get_secret_value(**kwargs)

        try:
            # Block the synchronous boto3/botocore call off the event loop.
            response = await asyncio.to_thread(_read)
        except Exception as exc:
            # Classify "no such secret/version" (fail-as-missing) vs ANY other
            # backend/transport/permission failure (fail-CLOSED via a non-KeyError).
            # Capture only the exception *type name* + the AWS error code up front;
            # neither echoes secret material, unlike the message body.
            exc_type_name = type(exc).__name__
            code = _aws_error_code(exc)
            if code == _AWS_NOT_FOUND_CODE:
                raise SecretNotFoundError(f"AWS Secrets Manager: no secret '{secret_id}'") from None
            # AccessDenied / decryption / throttle / network / missing creds: fail
            # CLOSED. Surface only the SecretId + exception *type* (and the AWS
            # code when present) — never the upstream message body, which could
            # echo token/ciphertext material. ``from None`` drops the cause so a
            # chained-traceback render (logging.exception / Sentry / uncaught
            # propagation) cannot leak it (SECURITY_CONTRACT §6).
            detail = code or exc_type_name
            raise AwsSecretsBackendError(
                f"AWS Secrets Manager read failed for '{secret_id}': {detail}"
            ) from None

        secret_string = response.get("SecretString")
        if not isinstance(secret_string, str):
            # Binary-only secret (SecretBinary, no SecretString) cannot be
            # returned as text — this backend's contract is text secrets.
            raise SecretNotFoundError(
                f"AWS secret '{secret_id}' has no text SecretString (binary-only secrets are unsupported)"
            )
        value = self._select_field(secret_string, selected_field, secret_id)
        return SecretStr(value)

    async def rotate(self, name: str) -> None:
        # AWS Secrets Manager drives rotation via its own Lambda/schedule; SecuGent
        # does not trigger it. Fail loud rather than silently no-op so an operator
        # never believes a secret was rotated when it was not (mirrors
        # VaultSecretsBackend). Use ``SecretsManager.invalidate(name)`` to evict a
        # cached value.
        raise NotImplementedError(
            "AwsSecretsManagerBackend does not drive rotation; AWS Secrets Manager "
            "rotation is configured out-of-band (rotation Lambda / schedule)"
        )


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


# ---------------------------------------------------------------------------
# G-H13 + S8a — boot settings + factory (selects Vault / AWS / Env, fail-closed)
# ---------------------------------------------------------------------------


class SecretsSettings(BaseModel):
    """Operator-facing secrets configuration (G-H13; S8a AWS branch).

    Read from the environment by :meth:`from_env`. ``vault_addr`` plus EITHER a
    token (``VAULT_TOKEN``) OR an AppRole pair (``VAULT_ROLE_ID`` +
    ``VAULT_SECRET_ID``) means "use Vault". An addr with NO auth material is a
    misconfiguration that :func:`build_secrets_backend` rejects — it must never
    be silently downgraded to the plaintext :class:`EnvSecretsBackend`.

    ``aws_secrets_region`` (``AWS_SECRETS_REGION``) means "use AWS Secrets
    Manager" (S8a / G-M7). Vault and AWS configured *simultaneously* is an
    ambiguous config the factory rejects (fail-closed) — a human must say which
    secret plane is authoritative.
    """

    model_config = ConfigDict(extra="forbid")

    vault_addr: str | None = None
    # Both auth secrets are SecretStr so they redact on repr()/log.
    vault_token: SecretStr | None = None
    vault_role_id: str | None = None
    vault_secret_id: SecretStr | None = None
    vault_namespace: str | None = None
    vault_mount_point: str = "secret"
    vault_timeout_seconds: int = 5
    # S8a (G-M7) — AWS Secrets Manager. A region is the explicit opt-in (no
    # implicit AWS_REGION fallback): operators must name the secret plane.
    aws_secrets_region: str | None = None
    aws_secrets_endpoint_url: str | None = None
    # B7 — GCP Secret Manager. A project id is the explicit opt-in (no implicit
    # GOOGLE_CLOUD_PROJECT fallback): operators must name the secret plane. Auth
    # via Application Default Credentials (never a static key file).
    gcp_secrets_project: str | None = None

    @property
    def vault_configured(self) -> bool:
        """True iff an addr AND some auth material (token or AppRole pair) exist.

        An addr alone is deliberately NOT "configured": that is a misconfig the
        factory must reject, not a reason to fall back to plaintext env.
        """
        if not self.vault_addr:
            return False
        if self.vault_token is not None:
            return True
        return self.vault_role_id is not None and self.vault_secret_id is not None

    @property
    def aws_configured(self) -> bool:
        """True iff an AWS Secrets Manager region is set (the explicit opt-in)."""
        return bool(self.aws_secrets_region)

    @property
    def gcp_configured(self) -> bool:
        """True iff a GCP Secret Manager project id is set (the explicit opt-in).

        No implicit ``GOOGLE_CLOUD_PROJECT`` fallback: an operator must
        explicitly set ``GCP_SECRETS_PROJECT`` to opt-in. This prevents a
        misconfigured environment silently routing secrets to GCP when the
        intent was plaintext env.
        """
        return bool(self.gcp_secrets_project)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> SecretsSettings:
        """Build from the ``VAULT_*`` / ``AWS_SECRETS_*`` / ``GCP_SECRETS_*`` env contract.

        See ``deploy/.env.example`` for the Vault contract; the AWS branch reads
        ``AWS_SECRETS_REGION`` (the opt-in) and the optional
        ``AWS_SECRETS_ENDPOINT_URL`` (VPC endpoint / localstack). The GCP
        branch reads ``GCP_SECRETS_PROJECT`` (the explicit opt-in; no implicit
        ``GOOGLE_CLOUD_PROJECT`` fallback).
        """
        env = os.environ if environ is None else environ
        token = env.get("VAULT_TOKEN")
        secret_id = env.get("VAULT_SECRET_ID")
        mount = env.get("VAULT_MOUNT_POINT")
        return cls(
            vault_addr=env.get("VAULT_ADDR") or None,
            vault_token=SecretStr(token) if token else None,
            vault_role_id=env.get("VAULT_ROLE_ID") or None,
            vault_secret_id=SecretStr(secret_id) if secret_id else None,
            vault_namespace=env.get("VAULT_NAMESPACE") or None,
            vault_mount_point=mount if mount else "secret",
            aws_secrets_region=env.get("AWS_SECRETS_REGION") or None,
            aws_secrets_endpoint_url=env.get("AWS_SECRETS_ENDPOINT_URL") or None,
            gcp_secrets_project=env.get("GCP_SECRETS_PROJECT") or None,
        )


# A non-empty placeholder token used only to satisfy VaultSecretsBackend's
# non-empty-token construction guard on the AppRole path, where the REAL bearer
# token lives on the injected, already-authenticated hvac client (the backend
# reads via the client, not this string). It is never sent anywhere.
_APPROLE_CLIENT_TOKEN_SENTINEL: Final[str] = "<approle-authenticated-client>"  # noqa: S105 - placeholder, not a secret (real token is on the injected client)


def _build_approle_client(settings: SecretsSettings) -> Any:
    """Authenticate an hvac client via AppRole and return it (fail-closed).

    A login that is unreachable / rejected (403, bad secret-id, sealed) raises
    :class:`VaultBackendError` — never a fall-through to plaintext env. Only the
    exception *type name* is surfaced; the upstream message (which can echo the
    secret-id) is dropped with ``from None`` (SECURITY_CONTRACT §6).
    """
    try:
        import hvac
    except ImportError as exc:
        raise ImportError(
            "hvac is required for Vault AppRole auth — install it with: pip install 'secugent[vault]'"
        ) from exc

    assert settings.vault_addr is not None  # guarded by vault_configured
    assert settings.vault_role_id is not None  # guarded by caller
    assert settings.vault_secret_id is not None  # guarded by caller
    # hvac has no type stubs; the client is intentionally Any (§B-3 waiver).
    client: Any = hvac.Client(
        url=settings.vault_addr,
        namespace=settings.vault_namespace,
        timeout=settings.vault_timeout_seconds,
    )
    try:
        response = client.auth.approle.login(
            role_id=settings.vault_role_id,
            secret_id=settings.vault_secret_id.get_secret_value(),
        )
    except Exception as exc:
        # Transport / permission failure: fail CLOSED. Surface only the exception
        # type — never the body, which may echo the secret-id.
        raise VaultBackendError(f"Vault AppRole login failed: {type(exc).__name__}") from None
    auth = response.get("auth") if isinstance(response, Mapping) else None
    client_token = auth.get("client_token") if isinstance(auth, Mapping) else None
    if not client_token:
        # A login that returns no usable client_token cannot authenticate — a
        # missing token must fail the seal, not produce a half-authed client.
        raise VaultBackendError("Vault AppRole login returned no client_token")
    return client


def build_secrets_backend(settings: SecretsSettings) -> SecretsBackend:
    """Select the secrets backend for the running app (G-H13 + S8a + B7, fail-closed).

    * ANY TWO of {Vault, AWS, GCP} configured simultaneously → ``ValueError``
      (ambiguous secret plane — fail-closed, a human must choose exactly one).
    * Vault configured (token or AppRole) → :class:`VaultSecretsBackend`
      (token mode takes precedence over AppRole when both are set).
    * VAULT_ADDR set but no auth → ``ValueError`` (misconfig, never plaintext).
    * GCP configured (``GCP_SECRETS_PROJECT``) → :class:`GcpSecretManagerBackend`
      (B7; auth via ADC / Workload Identity).
    * AWS configured (``AWS_SECRETS_REGION``) → :class:`AwsSecretsManagerBackend`
      (S8a / G-M7).
    * Otherwise → the plaintext :class:`EnvSecretsBackend`.

    A configured Vault that is unreachable / rejected raises
    :class:`VaultBackendError`; a configured GCP backend raises
    :class:`GcpSecretsBackendError` at read time; a configured AWS backend
    raises :class:`AwsSecretsBackendError` at read time. This function NEVER
    silently downgrades a requested Vault/GCP/AWS backend to the plaintext
    :class:`EnvSecretsBackend`.
    """
    # 3-way ambiguity: ANY two of {Vault, AWS, GCP} configured simultaneously
    # fails CLOSED — silently picking one could route secrets to the wrong (or
    # weaker) plane. A human must name exactly one secret plane.
    _configured_planes = {
        "Vault (VAULT_*)": settings.vault_configured,
        "AWS Secrets Manager (AWS_SECRETS_REGION)": settings.aws_configured,
        "GCP Secret Manager (GCP_SECRETS_PROJECT)": settings.gcp_configured,
    }
    _active = [name for name, ok in _configured_planes.items() if ok]
    if len(_active) > 1:
        raise ValueError(
            f"Multiple secret planes configured simultaneously: "
            f"{' and '.join(_active)}. "
            "Refusing to guess which is authoritative — configure exactly one "
            "(fail-closed)."
        )

    if not settings.vault_configured:
        if settings.vault_addr:
            raise ValueError(
                "VAULT_ADDR is set but no Vault auth (VAULT_TOKEN or "
                "VAULT_ROLE_ID + VAULT_SECRET_ID) was provided. Refusing to fall "
                "back to plaintext env secrets (fail-closed)."
            )
        if settings.gcp_configured:
            assert settings.gcp_secrets_project is not None  # guaranteed by gcp_configured
            return GcpSecretManagerBackend(project=settings.gcp_secrets_project)
        if settings.aws_configured:
            assert settings.aws_secrets_region is not None  # guaranteed by aws_configured
            return AwsSecretsManagerBackend(
                region_name=settings.aws_secrets_region,
                endpoint_url=settings.aws_secrets_endpoint_url,
            )
        return EnvSecretsBackend()

    assert settings.vault_addr is not None  # guaranteed by vault_configured

    if settings.vault_token is not None:
        return VaultSecretsBackend(
            settings.vault_addr,
            settings.vault_token.get_secret_value(),
            namespace=settings.vault_namespace,
            mount_point=settings.vault_mount_point,
            timeout=settings.vault_timeout_seconds,
        )

    # AppRole mode: the bearer token is derived by the login and lives on the
    # injected client; the sentinel only satisfies the non-empty-token guard.
    client = _build_approle_client(settings)
    return VaultSecretsBackend(
        settings.vault_addr,
        _APPROLE_CLIENT_TOKEN_SENTINEL,
        namespace=settings.vault_namespace,
        mount_point=settings.vault_mount_point,
        timeout=settings.vault_timeout_seconds,
        client=client,
    )
