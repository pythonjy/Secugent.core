# SPDX-License-Identifier: Apache-2.0
"""B7 — GcpSecretManagerBackend unit + property + scenario tests (§B-4a 3중).

``google-cloud-secret-manager`` is NOT installed in CI, so we never make a live
GCP call. Instead we inject a fake client via the ``client=`` DI slot for most
tests, and the test that exercises the *real* (non-DI) import path stubs a
minimal fake ``google.cloud.secretmanager`` module through ``sys.modules``
(see ``_install_fake_secretmanager``) so it passes whether or not the library is
present. The ImportError test forces the GCP extra absent the same way.

Real google-api-core errors expose an int ``.code`` (404 for NotFound) and a
stable type name (``http_status_code`` is only a secondary fallback); the
backend reads them WITHOUT importing google.api_core, so we simulate them with
small ``_FakeNotFound`` / ``_FakePermissionDenied`` stubs that mirror that shape —
exactly how production google-api-core exceptions surface.

Korean finance fixture (§C-3): 하나은행 GCP PoC 시크릿 이름.
"""

from __future__ import annotations

import json as _json
import sys
import types
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr

from secugent.core.secrets import (
    GcpSecretManagerBackend,
    GcpSecretsBackendError,
    SecretNotFoundError,
    SecretsSettings,
    _gcp_is_not_found,
    build_secrets_backend,
)

# ---------------------------------------------------------------------------
# Korean finance fixture (§C-3): 하나은행 GCP PoC
# ---------------------------------------------------------------------------

_HANA_PROJECT = "hana-bank-gcp-poc-kr"
_HANA_SECRET_ID = "하나은행/금융결제원-api-키"  # non-ASCII secret id (Korean)
_HANA_SECRET_ID_SIMPLE = "hana-bank-api-key"  # ASCII (used when GCP requires it)


# ---------------------------------------------------------------------------
# Fake GCP exception stubs (mirror google.api_core.exceptions shape)
# ---------------------------------------------------------------------------


class _FakeNotFound(Exception):
    """Stand-in for google.api_core.exceptions.NotFound.

    Production GCP exceptions expose ``http_status_code = 404``; the backend
    reads exactly that attribute (without importing google.api_core), so this
    faithfully simulates the REST-transport shape.
    """

    http_status_code: int = 404


class _FakePermissionDenied(Exception):
    """Stand-in for google.api_core.exceptions.PermissionDenied (403)."""

    http_status_code: int = 403


class _FakeServiceUnavailable(Exception):
    """Stand-in for google.api_core.exceptions.ServiceUnavailable (503)."""

    http_status_code: int = 503


# ---------------------------------------------------------------------------
# Fake GCP response and client builder
# ---------------------------------------------------------------------------


class _FakePayload:
    def __init__(self, data: bytes) -> None:
        self.data = data


class _FakeResponse:
    def __init__(self, data: bytes) -> None:
        self.payload = _FakePayload(data)


class _FakeGcpClient:
    """Minimal GCP SecretManagerServiceClient fake for tests."""

    def __init__(
        self,
        *,
        return_data: bytes | None = None,
        side_effect: Exception | None = None,
    ) -> None:
        self._return_data = return_data
        self._side_effect = side_effect
        self.calls: list[str] = []

    def access_secret_version(self, *, name: str) -> _FakeResponse:
        self.calls.append(name)
        if self._side_effect is not None:
            raise self._side_effect
        assert self._return_data is not None, "return_data not configured"
        return _FakeResponse(self._return_data)


def _backend(
    *,
    return_data: bytes | None = None,
    side_effect: Exception | None = None,
    project: str = _HANA_PROJECT,
) -> GcpSecretManagerBackend:
    return GcpSecretManagerBackend(
        project=project,
        client=_FakeGcpClient(return_data=return_data, side_effect=side_effect),
    )


# ---------------------------------------------------------------------------
# get() — happy paths
# ---------------------------------------------------------------------------


async def test_get_returns_plain_secret_string() -> None:
    backend = _backend(return_data=b"my-secret-value")
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert isinstance(result, SecretStr)
    assert result.get_secret_value() == "my-secret-value"


async def test_get_passes_correct_resource_name() -> None:
    fake_client = _FakeGcpClient(return_data=b"v")
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=fake_client)
    await backend.get("my-secret")
    assert len(fake_client.calls) == 1
    assert fake_client.calls[0] == f"projects/{_HANA_PROJECT}/secrets/my-secret/versions/latest"


async def test_get_passes_version_in_resource_name() -> None:
    fake_client = _FakeGcpClient(return_data=b"v")
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=fake_client)
    await backend.get("my-secret", version="3")
    assert fake_client.calls[0] == f"projects/{_HANA_PROJECT}/secrets/my-secret/versions/3"


async def test_get_empty_version_uses_latest_not_malformed_path() -> None:
    """version='' is treated like None → 'latest', never a trailing-slash path.

    An empty string would otherwise build ``.../versions/`` (INVALID_ARGUMENT),
    which fail-closes as a backend error rather than reading 'latest' (B7 Low #3).
    """
    fake_client = _FakeGcpClient(return_data=b"v")
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=fake_client)
    await backend.get("my-secret", version="")
    assert fake_client.calls[0] == f"projects/{_HANA_PROJECT}/secrets/my-secret/versions/latest"


async def test_get_trailing_hash_empty_field_raises_not_found() -> None:
    """name='secret#' (trailing '#', empty field) resolves the '' key → not found.

    Consistent with the AWS backend's empty-field semantics (B7 Low #4).
    """
    payload = b'{"api_key": "key-abc-123"}'  # no empty-string key
    backend = _backend(return_data=payload)
    with pytest.raises(SecretNotFoundError):
        await backend.get(f"{_HANA_SECRET_ID_SIMPLE}#")


async def test_get_json_field_selection() -> None:
    payload = b'{"api_key": "key-abc-123", "other": "x"}'
    backend = _backend(return_data=payload)
    result = await backend.get(f"{_HANA_SECRET_ID_SIMPLE}#api_key")
    assert result.get_secret_value() == "key-abc-123"


async def test_get_without_field_returns_raw_even_if_json() -> None:
    raw = b'{"api_key": "key-abc-123"}'
    backend = _backend(return_data=raw)
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert result.get_secret_value() == raw.decode()


async def test_get_korean_secret_id_in_resource_name() -> None:
    """§C-3: 한국어 시크릿 이름이 리소스 경로에 올바르게 포함된다."""
    fake_client = _FakeGcpClient(return_data="한국금융결제원-api-키-값".encode())
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=fake_client)
    await backend.get(_HANA_SECRET_ID)
    # The Korean secret id must appear verbatim in the resource path
    assert _HANA_SECRET_ID in fake_client.calls[0]


async def test_get_result_wraps_in_secret_str() -> None:
    backend = _backend(return_data=b"topsecret")
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert isinstance(result, SecretStr)


# ---------------------------------------------------------------------------
# get() — fail-as-missing (SecretNotFoundError / KeyError subclass)
# ---------------------------------------------------------------------------


async def test_get_not_found_raises_secret_not_found_error() -> None:
    backend = _backend(side_effect=_FakeNotFound("secret not found"))
    with pytest.raises(SecretNotFoundError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


async def test_get_not_found_by_type_name_only() -> None:
    """gRPC-transport path: http_status_code absent, type name 'NotFound' matches.

    When the GCP gRPC transport is used (no REST http_status_code attribute),
    _gcp_is_not_found falls back to the class name "NotFound" as the canonical
    signal for gRPC STATUS_NOT_FOUND.
    """

    class NotFound(Exception):
        """Simulates a gRPC-only NotFound with no http_status_code attribute."""

    backend = _backend(side_effect=NotFound("not found"))
    # Type name "NotFound" alone must classify as SecretNotFoundError
    with pytest.raises(SecretNotFoundError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


async def test_get_missing_json_field_raises_not_found() -> None:
    backend = _backend(return_data=b'{"present": "x"}')
    with pytest.raises(SecretNotFoundError):
        await backend.get(f"{_HANA_SECRET_ID_SIMPLE}#absent_field")


async def test_get_field_on_non_json_secret_raises_not_found() -> None:
    backend = _backend(return_data=b"not-json-plaintext")
    with pytest.raises(SecretNotFoundError):
        await backend.get(f"{_HANA_SECRET_ID_SIMPLE}#api_key")


async def test_get_field_on_non_json_secret_does_not_leak_secret() -> None:
    """SECURITY_CONTRACT §6: the secret payload must NOT appear in the error."""
    backend = _backend(return_data=b"SECRET_PLAINTEXT_MATERIAL not json")
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get(f"{_HANA_SECRET_ID_SIMPLE}#api_key")
    assert exc_info.value.__cause__ is None
    assert "SECRET_PLAINTEXT_MATERIAL" not in str(exc_info.value)
    assert "SECRET_PLAINTEXT_MATERIAL" not in repr(exc_info.value)


async def test_get_binary_only_non_utf8_raises_not_found() -> None:
    # Bytes that are not valid UTF-8 cannot be returned as text.
    backend = _backend(return_data=b"\xff\xfe\x00\x01")
    with pytest.raises(SecretNotFoundError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


async def test_get_empty_name_raises_not_found() -> None:
    backend = _backend(return_data=b"x")
    with pytest.raises(SecretNotFoundError):
        await backend.get("")


async def test_get_no_byte_payload_raises_not_found() -> None:
    """A response with a None/missing payload.data raises SecretNotFoundError."""

    class _EmptyPayload:
        data: None = None  # no bytes

    class _EmptyResponse:
        payload = _EmptyPayload()

    class _EmptyClient:
        def access_secret_version(self, *, name: str) -> _EmptyResponse:
            return _EmptyResponse()

    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=_EmptyClient())  # type: ignore[arg-type]
    with pytest.raises(SecretNotFoundError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


# ---------------------------------------------------------------------------
# get() — fail-CLOSED (GcpSecretsBackendError, NOT SecretNotFoundError)
# ---------------------------------------------------------------------------


async def test_get_permission_denied_fails_closed() -> None:
    # PermissionDenied must NOT read as "secret missing" — fail-open hole.
    backend = _backend(side_effect=_FakePermissionDenied("permission denied"))
    with pytest.raises(GcpSecretsBackendError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


async def test_get_permission_denied_is_not_secret_not_found() -> None:
    backend = _backend(side_effect=_FakePermissionDenied("denied"))
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert not isinstance(exc_info.value, SecretNotFoundError)
    assert not isinstance(exc_info.value, KeyError)


async def test_get_transport_error_fails_closed() -> None:
    # A bare transport error has no http_status_code -> fail CLOSED.
    backend = _backend(side_effect=RuntimeError("connection reset by peer"))
    with pytest.raises(GcpSecretsBackendError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


async def test_get_service_unavailable_fails_closed() -> None:
    backend = _backend(side_effect=_FakeServiceUnavailable("service unavailable"))
    with pytest.raises(GcpSecretsBackendError):
        await backend.get(_HANA_SECRET_ID_SIMPLE)


def test_gcp_backend_error_type_separation() -> None:
    # Static guarantee: GcpSecretsBackendError is never a KeyError/SecretNotFoundError,
    # so ``except SecretNotFoundError`` cannot swallow a GCP outage / PermissionDenied.
    assert not issubclass(GcpSecretsBackendError, KeyError)
    assert not issubclass(GcpSecretsBackendError, SecretNotFoundError)


# ---------------------------------------------------------------------------
# get() — no credential/secret leak in error or __cause__ (SECURITY_CONTRACT §6)
# ---------------------------------------------------------------------------


async def test_get_does_not_leak_secret_id_message_body() -> None:
    backend = _backend(
        side_effect=_FakePermissionDenied(
            "HANA_API_TOKEN=ghp_secret123 denied for projects/.../secrets/hana-bank-api-key"
        )
    )
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    # Only the secret_id + exception *type* surface — never the upstream body
    assert "ghp_secret123" not in str(exc_info.value)
    assert "ghp_secret123" not in repr(exc_info.value)


async def test_get_drops_cause_so_traceback_does_not_leak() -> None:
    """`from None` so the upstream exception (whose body can echo token material)
    is NOT attached as __cause__; otherwise a default traceback render leaks it.
    """
    backend = _backend(side_effect=_FakePermissionDenied("AKIASECRETVALUE leaked in message"))
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert exc_info.value.__cause__ is None
    assert "AKIASECRETVALUE" not in repr(exc_info.value)


async def test_get_not_found_also_drops_cause() -> None:
    backend = _backend(side_effect=_FakeNotFound("not found with embedded token"))
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert exc_info.value.__cause__ is None


async def test_returned_secret_redacts_on_repr() -> None:
    backend = _backend(return_data=b"topsecret")
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert "topsecret" not in repr(result)
    assert "topsecret" not in str(result)


# ---------------------------------------------------------------------------
# get() — error message surfaces secret_id + exception type, NOT message body
# ---------------------------------------------------------------------------


async def test_error_message_contains_secret_id() -> None:
    backend = _backend(side_effect=_FakePermissionDenied("permission denied"))
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert _HANA_SECRET_ID_SIMPLE in str(exc_info.value)


async def test_error_message_contains_exception_type_name() -> None:
    backend = _backend(side_effect=_FakePermissionDenied("permission denied"))
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert "_FakePermissionDenied" in str(exc_info.value)


# ---------------------------------------------------------------------------
# rotate()
# ---------------------------------------------------------------------------


async def test_rotate_raises_not_implemented() -> None:
    backend = _backend(return_data=b"x")
    with pytest.raises(NotImplementedError):
        await backend.rotate(_HANA_SECRET_ID_SIMPLE)


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_empty_project_raises_value_error() -> None:
    with pytest.raises(ValueError, match="project"):
        GcpSecretManagerBackend(project="")


# ---------------------------------------------------------------------------
# ImportError — google-cloud-secret-manager absent (lazy import path)
# ---------------------------------------------------------------------------


def test_import_error_without_gcp_library(monkeypatch: pytest.MonkeyPatch) -> None:
    """No DI client + library absent: lazy get() must raise an actionable ImportError."""
    # Stub google.cloud as absent
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", None)
    monkeypatch.setitem(sys.modules, "google.cloud", None)
    monkeypatch.setitem(sys.modules, "google", None)
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT)
    with pytest.raises(ImportError, match="google-cloud-secret-manager"):
        import asyncio

        asyncio.run(backend.get(_HANA_SECRET_ID_SIMPLE))


# ---------------------------------------------------------------------------
# Real (non-DI) constructor path — the lazy import branch
# ---------------------------------------------------------------------------


def _install_fake_secretmanager(monkeypatch: pytest.MonkeyPatch, *, return_data: bytes) -> dict[str, Any]:
    """Inject a minimal fake google.cloud.secretmanager module."""
    captured: dict[str, Any] = {}

    class _FakeServiceClient:
        def __init__(self) -> None:
            captured["client_created"] = True

        def access_secret_version(self, *, name: str) -> _FakeResponse:
            captured["name"] = name
            return _FakeResponse(return_data)

    class _FakeSecretManagerModule:
        SecretManagerServiceClient = _FakeServiceClient

    fake_google_cloud_sm = _FakeSecretManagerModule()

    # Build a minimal module hierarchy
    google_mod = types.ModuleType("google")
    google_cloud_mod = types.ModuleType("google.cloud")
    google_cloud_sm_mod = types.ModuleType("google.cloud.secretmanager")
    google_cloud_sm_mod.SecretManagerServiceClient = _FakeServiceClient  # type: ignore[attr-defined]
    google_mod.cloud = google_cloud_mod  # type: ignore[attr-defined]
    google_cloud_mod.secretmanager = fake_google_cloud_sm  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.cloud", google_cloud_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", google_cloud_sm_mod)
    return captured


async def test_real_constructor_builds_secretmanager_client(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_secretmanager(monkeypatch, return_data=b"live-value")
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT)
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert result.get_secret_value() == "live-value"
    assert captured["client_created"] is True
    assert f"projects/{_HANA_PROJECT}/secrets/{_HANA_SECRET_ID_SIMPLE}/versions/latest" == captured["name"]


async def test_real_client_is_built_once_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_secretmanager(monkeypatch, return_data=b"x")
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT)
    await backend.get(_HANA_SECRET_ID_SIMPLE)
    first = backend._client
    await backend.get(_HANA_SECRET_ID_SIMPLE)
    assert backend._client is first  # built once, reused on subsequent calls


# ---------------------------------------------------------------------------
# _gcp_is_not_found — best-effort, google.api_core-free classification
# ---------------------------------------------------------------------------


def test_gcp_is_not_found_reads_real_code_attribute() -> None:
    """The REAL google-api-core NotFound exposes an int ``.code`` (404), not
    ``http_status_code``. The classifier must read ``.code`` first (B7 Low #1)."""

    class _RealApiNotFound(Exception):
        code: int = 404  # google.api_core.exceptions.NotFound.code

    assert _gcp_is_not_found(_RealApiNotFound("not found")) is True


def test_gcp_is_not_found_false_for_real_code_403() -> None:
    """A non-404 int ``.code`` is a definite NON-NotFound verdict (fail-closed)."""

    class _RealApiDenied(Exception):
        code: int = 403

    assert _gcp_is_not_found(_RealApiDenied("denied")) is False


def test_gcp_is_not_found_ignores_non_int_code_falls_back() -> None:
    """A callable/enum ``.code`` (gRPC) is ignored; classification falls back to
    ``http_status_code`` then the type name."""

    class _GrpcLikeNotFound(Exception):
        http_status_code: int = 404

        def code(self) -> str:  # gRPC-style callable, not an int
            return "NOT_FOUND"

    assert _gcp_is_not_found(_GrpcLikeNotFound("not found")) is True


def test_gcp_is_not_found_with_http_404() -> None:
    assert _gcp_is_not_found(_FakeNotFound("not found")) is True


def test_gcp_is_not_found_false_for_403() -> None:
    assert _gcp_is_not_found(_FakePermissionDenied("denied")) is False


def test_gcp_is_not_found_false_for_503() -> None:
    assert _gcp_is_not_found(_FakeServiceUnavailable("unavailable")) is False


def test_gcp_is_not_found_false_for_bare_transport_error() -> None:
    # No structured http_status_code -> False -> treated as availability failure (closed)
    assert _gcp_is_not_found(RuntimeError("socket timeout")) is False


def test_gcp_is_not_found_by_type_name_fallback() -> None:
    """gRPC-only transports expose the type name 'NotFound' without http_status_code."""

    class NotFound(Exception):
        pass  # no http_status_code attribute

    assert _gcp_is_not_found(NotFound("not found")) is True


def test_gcp_is_not_found_false_for_class_named_not_found_with_wrong_code() -> None:
    """A class named 'NotFound' with an http_status_code that is NOT 404 returns
    False — the structured HTTP code wins over the type name.

    This prevents a collision with an in-process class also named 'NotFound' from
    a different library from being misclassified as a GCP NotFound when its HTTP
    code signals a different error (e.g. 500 Internal Server Error).
    """

    class NotFound(Exception):
        http_status_code = 500  # WRONG code — not a real GCP NotFound

    # http_status_code is 500 → structured code wins → returns False
    # (the type-name branch is NOT reached when http_status_code is present)
    assert _gcp_is_not_found(NotFound("internal")) is False


# ---------------------------------------------------------------------------
# Property-based tests (§B-4a: hypothesis)
# ---------------------------------------------------------------------------


@given(value=st.text(min_size=1, max_size=200))
@settings(max_examples=200, deadline=None)
async def test_property_any_secret_redacts_but_round_trips(value: str) -> None:
    """Any secret value redacts on repr/str but round-trips through get_secret_value."""
    backend = GcpSecretManagerBackend(
        project=_HANA_PROJECT,
        client=_FakeGcpClient(return_data=value.encode("utf-8")),
    )
    result = await backend.get(_HANA_SECRET_ID_SIMPLE)
    # The value round-trips...
    assert result.get_secret_value() == value
    # ...but the repr is the FIXED mask token, never the plaintext.
    assert repr(result) == "SecretStr('**********')"
    assert str(result) == "**********"


@given(
    secret_id=st.text(
        alphabet=st.characters(blacklist_characters="#", blacklist_categories=("Cs",)),
        min_size=1,
        max_size=100,
    ),
    field=st.one_of(
        st.none(),
        # Restrict to printable Unicode (no control chars, no surrogates) so the
        # generated JSON payload is always parseable by json.loads — raw embedding
        # of control chars (e.g. \x1f) yields invalid JSON (RFC 8259 §7).
        st.text(
            alphabet=st.characters(
                blacklist_categories=("Cs", "Cc"),  # no surrogates, no control chars
            ),
            min_size=1,
            max_size=50,
        ),
    ),
)
@settings(max_examples=100, deadline=None)
async def test_property_name_parsing_round_trip(secret_id: str, field: str | None) -> None:
    """The '#field' partition in get() correctly separates secret_id from field_name."""
    if field is None:
        full_name = secret_id
    else:
        full_name = f"{secret_id}#{field}"

    # Build a JSON-safe payload using json.dumps so all chars are properly escaped;
    # raw f-string embedding would produce invalid JSON for control characters.
    if field is not None:
        payload = _json.dumps({field: "test-value"}).encode()
    else:
        payload = b"test-value"

    fake_client = _FakeGcpClient(return_data=payload)
    backend = GcpSecretManagerBackend(project=_HANA_PROJECT, client=fake_client)

    result = await backend.get(full_name)
    assert result.get_secret_value() == "test-value"
    # The resource name in the client call must use only the secret_id portion
    if len(fake_client.calls) > 0:
        assert f"/secrets/{secret_id}/versions/" in fake_client.calls[0]


# ---------------------------------------------------------------------------
# Secret-leak regression: upstream exception message NEVER in raised error
# ---------------------------------------------------------------------------


_FIXED_ERROR_TEMPLATE = (
    f"GCP Secret Manager read failed for '{_HANA_SECRET_ID_SIMPLE}': _FakePermissionDenied"
)


@given(
    msg=st.text(
        alphabet=st.characters(blacklist_categories=("Cs",)),
        # min_size=30: a 30+ char random string is statistically impossible to
        # be a coincidental substring of the 80-char fixed error template.
        # Single or very-short messages (e.g. 'C', 'G') would be trivially found
        # in "GCP" — which is not a leak of the upstream message, just a coincidence.
        min_size=30,
        max_size=300,
    ).filter(
        # Belt-and-suspenders: explicitly skip any message that is a substring of
        # the fixed error template string (would be a false positive regardless
        # of length, not a security leak).
        lambda m: m not in _FIXED_ERROR_TEMPLATE
    )
)
@settings(max_examples=100, deadline=None)
async def test_property_upstream_message_never_leaks_in_error(msg: str) -> None:
    """The upstream exception message body must NEVER appear in the raised error.

    Only the secret_id + exception type name may surface (SECURITY_CONTRACT §6).
    The ``from None`` discipline means the cause is also not attached.
    """
    backend = GcpSecretManagerBackend(
        project=_HANA_PROJECT,
        client=_FakeGcpClient(side_effect=_FakePermissionDenied(msg)),
    )
    with pytest.raises(GcpSecretsBackendError) as exc_info:
        await backend.get(_HANA_SECRET_ID_SIMPLE)
    err_str = str(exc_info.value)
    err_repr = repr(exc_info.value)
    # The upstream message body (which may contain token/secret material) must
    # NOT appear in either string representation of the raised error.
    assert msg not in err_str, f"Upstream message leaked in str(): {err_str!r}"
    assert msg not in err_repr, f"Upstream message leaked in repr(): {err_repr!r}"
    # __cause__ must be None (from None discipline)
    assert exc_info.value.__cause__ is None


# ---------------------------------------------------------------------------
# Boot-selection tests: build_secrets_backend factory (§B-4a)
# ---------------------------------------------------------------------------


def test_build_secrets_backend_returns_gcp_when_only_gcp_configured() -> None:
    settings_obj = SecretsSettings(gcp_secrets_project=_HANA_PROJECT)
    backend = build_secrets_backend(settings_obj)
    assert isinstance(backend, GcpSecretManagerBackend)


def test_build_secrets_backend_gcp_plus_aws_raises_value_error() -> None:
    """3-way ambiguity: GCP + AWS simultaneously configured fails CLOSED."""
    settings_obj = SecretsSettings(
        gcp_secrets_project=_HANA_PROJECT,
        aws_secrets_region="ap-northeast-2",
    )
    with pytest.raises(ValueError, match="Multiple secret planes"):
        build_secrets_backend(settings_obj)


def test_build_secrets_backend_gcp_plus_vault_raises_value_error() -> None:
    """3-way ambiguity: GCP + Vault simultaneously configured fails CLOSED."""
    settings_obj = SecretsSettings(
        gcp_secrets_project=_HANA_PROJECT,
        vault_addr="https://vault.example.com",
        vault_token=SecretStr("token-abc"),
    )
    with pytest.raises(ValueError, match="Multiple secret planes"):
        build_secrets_backend(settings_obj)


def test_build_secrets_backend_aws_plus_vault_still_raises_value_error() -> None:
    """Existing 2-way ambiguity still raises (not broken by 3-way extension)."""
    settings_obj = SecretsSettings(
        aws_secrets_region="ap-northeast-2",
        vault_addr="https://vault.example.com",
        vault_token=SecretStr("token-abc"),
    )
    with pytest.raises(ValueError, match="Multiple secret planes"):
        build_secrets_backend(settings_obj)


def test_build_secrets_backend_from_env_gcp_project(monkeypatch: pytest.MonkeyPatch) -> None:
    """GCP_SECRETS_PROJECT env var activates the GCP branch via from_env."""
    monkeypatch.setenv("GCP_SECRETS_PROJECT", _HANA_PROJECT)
    s = SecretsSettings.from_env()
    assert s.gcp_configured
    assert s.gcp_secrets_project == _HANA_PROJECT


def test_build_secrets_backend_google_cloud_project_not_implicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GOOGLE_CLOUD_PROJECT must NOT activate GCP; only GCP_SECRETS_PROJECT does."""
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "some-project")
    monkeypatch.delenv("GCP_SECRETS_PROJECT", raising=False)
    s = SecretsSettings.from_env()
    assert not s.gcp_configured


def test_gcp_configured_false_when_not_set() -> None:
    s = SecretsSettings()
    assert not s.gcp_configured


def test_gcp_configured_true_when_project_set() -> None:
    s = SecretsSettings(gcp_secrets_project=_HANA_PROJECT)
    assert s.gcp_configured
