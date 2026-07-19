# SPDX-License-Identifier: Apache-2.0
"""AwsSecretsManagerBackend unit + property + scenario tests.

``boto3`` is not installed in CI, so we never make a live AWS call; instead we
inject a ``MagicMock`` client via the ``client=`` DI slot for most tests, and the
test that exercises the *real* (non-DI) ``import boto3`` constructor branch stubs
a minimal fake ``boto3`` module through ``sys.modules`` (see ``_install_fake_boto3``)
so it passes whether or not the library is present. The ImportError test forces
``boto3`` absent the same way.

A botocore ``ClientError`` carries the AWS error code at
``exc.response["Error"]["Code"]``; the backend reads it without importing
botocore, so we simulate one with a tiny ``_FakeClientError`` that mirrors that
shape — exactly how production botocore exceptions surface.

Korean finance fixture (§C-3): a KB국민은행(KB Bank) closed-network secret ARN.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr

from secugent.core.secrets import (
    AwsSecretsBackendError,
    AwsSecretsManagerBackend,
    SecretNotFoundError,
    _aws_error_code,
)

# Korean finance fixture (§C-3): KB국민은행 폐쇄망 Secrets Manager 시크릿.
_KB_REGION = "ap-northeast-2"  # 서울 리전
_KB_SECRET_ARN = "arn:aws:secretsmanager:ap-northeast-2:111122223333:secret:kb-bank/금융결제원-api-키-AbCdEf"


class _FakeClientError(Exception):
    """Stand-in for ``botocore.exceptions.ClientError``.

    Production botocore exceptions expose the AWS error code at
    ``exc.response["Error"]["Code"]``; the backend reads exactly that path
    (without importing botocore), so this faithfully simulates it.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.response = {"Error": {"Code": code, "Message": message or code}}


def _client(
    *,
    get_return: dict[str, Any] | None = None,
    get_side_effect: BaseException | None = None,
) -> MagicMock:
    client = MagicMock()
    gsv = client.get_secret_value
    if get_side_effect is not None:
        gsv.side_effect = get_side_effect
    else:
        gsv.return_value = get_return
    return client


def _backend(client: MagicMock, **kw: Any) -> AwsSecretsManagerBackend:
    return AwsSecretsManagerBackend(region_name=_KB_REGION, client=client, **kw)


# ---------------------------------------------------------------------------
# get() — happy paths
# ---------------------------------------------------------------------------


async def test_get_returns_plain_secret_string() -> None:
    backend = _backend(_client(get_return={"SecretString": "my-secret-value"}))
    result = await backend.get(_KB_SECRET_ARN)
    assert isinstance(result, SecretStr)
    assert result.get_secret_value() == "my-secret-value"


async def test_get_passes_secret_id_and_current_stage() -> None:
    client = _client(get_return={"SecretString": "v"})
    backend = _backend(client)
    await backend.get(_KB_SECRET_ARN)
    _, kwargs = client.get_secret_value.call_args
    assert kwargs["SecretId"] == _KB_SECRET_ARN
    # No explicit version -> AWSCURRENT stage, never a VersionId.
    assert "VersionId" not in kwargs


async def test_get_passes_version_id() -> None:
    client = _client(get_return={"SecretString": "v"})
    backend = _backend(client)
    await backend.get(_KB_SECRET_ARN, version="v-7")
    _, kwargs = client.get_secret_value.call_args
    assert kwargs["VersionId"] == "v-7"


async def test_get_json_field_selection() -> None:
    backend = _backend(_client(get_return={"SecretString": '{"api_key": "key-123", "other": "x"}'}))
    result = await backend.get(f"{_KB_SECRET_ARN}#api_key")
    assert result.get_secret_value() == "key-123"


async def test_get_without_field_returns_raw_even_if_json() -> None:
    # No #field -> the raw SecretString (which may itself be JSON) is returned
    # verbatim. The caller asked for the whole secret, not a field.
    raw = '{"api_key": "key-123"}'
    backend = _backend(_client(get_return={"SecretString": raw}))
    result = await backend.get(_KB_SECRET_ARN)
    assert result.get_secret_value() == raw


# ---------------------------------------------------------------------------
# get() — fail-as-missing (SecretNotFoundError / KeyError subclass)
# ---------------------------------------------------------------------------


async def test_get_resource_not_found_raises_not_found() -> None:
    backend = _backend(_client(get_side_effect=_FakeClientError("ResourceNotFoundException")))
    with pytest.raises(SecretNotFoundError):
        await backend.get("absent/secret")


async def test_get_missing_json_field_raises_not_found() -> None:
    backend = _backend(_client(get_return={"SecretString": '{"present": "x"}'}))
    with pytest.raises(SecretNotFoundError):
        await backend.get(f"{_KB_SECRET_ARN}#absent_field")


async def test_get_field_on_non_json_secret_raises_not_found() -> None:
    # A #field on a non-JSON SecretString cannot resolve a field -> missing.
    backend = _backend(_client(get_return={"SecretString": "not-json-plaintext"}))
    with pytest.raises(SecretNotFoundError):
        await backend.get(f"{_KB_SECRET_ARN}#api_key")


async def test_get_field_on_non_json_secret_does_not_leak_secret() -> None:
    # A JSONDecodeError message echoes a snippet of the offending input — i.e. the
    # SECRET — so the not-found error must NOT chain it as __cause__ and must not
    # echo the secret in its own message (secrets must never surface in errors).
    backend = _backend(_client(get_return={"SecretString": "AKIASECRETPLAINTEXT not json"}))
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get(f"{_KB_SECRET_ARN}#api_key")
    assert exc_info.value.__cause__ is None
    assert "AKIASECRETPLAINTEXT" not in str(exc_info.value)
    assert "AKIASECRETPLAINTEXT" not in repr(exc_info.value)


async def test_get_binary_only_secret_raises_not_found() -> None:
    # A binary-only secret (no SecretString) cannot be returned as text.
    backend = _backend(_client(get_return={"SecretBinary": b"\x00\x01\x02"}))
    with pytest.raises(SecretNotFoundError):
        await backend.get(_KB_SECRET_ARN)


async def test_get_empty_name_raises_not_found() -> None:
    backend = _backend(_client(get_return={"SecretString": "x"}))
    with pytest.raises(SecretNotFoundError):
        await backend.get("")


# ---------------------------------------------------------------------------
# get() — fail-CLOSED (AwsSecretsBackendError, NOT SecretNotFoundError)
# ---------------------------------------------------------------------------


async def test_get_access_denied_fails_closed() -> None:
    # AccessDenied must NOT read as "secret missing" (which would let a caller
    # fall back to a permissive default — fail-open).
    backend = _backend(_client(get_side_effect=_FakeClientError("AccessDeniedException")))
    with pytest.raises(AwsSecretsBackendError):
        await backend.get(_KB_SECRET_ARN)


async def test_get_access_denied_is_not_secret_not_found() -> None:
    backend = _backend(_client(get_side_effect=_FakeClientError("AccessDeniedException")))
    with pytest.raises(AwsSecretsBackendError) as exc_info:
        await backend.get(_KB_SECRET_ARN)
    assert not isinstance(exc_info.value, SecretNotFoundError)
    assert not isinstance(exc_info.value, KeyError)


async def test_get_network_error_fails_closed() -> None:
    # A bare transport error has no structured AWS error code -> fail CLOSED.
    backend = _backend(_client(get_side_effect=RuntimeError("connection reset by peer")))
    with pytest.raises(AwsSecretsBackendError):
        await backend.get(_KB_SECRET_ARN)


async def test_get_decryption_failure_fails_closed() -> None:
    backend = _backend(_client(get_side_effect=_FakeClientError("DecryptionFailure")))
    with pytest.raises(AwsSecretsBackendError):
        await backend.get(_KB_SECRET_ARN)


async def test_get_throttling_fails_closed() -> None:
    backend = _backend(_client(get_side_effect=_FakeClientError("ThrottlingException")))
    with pytest.raises(AwsSecretsBackendError):
        await backend.get(_KB_SECRET_ARN)


def test_aws_backend_error_type_separation() -> None:
    # Static guarantee of the fail-closed invariant: backend errors are never
    # KeyError/SecretNotFoundError, so ``except SecretNotFoundError`` cannot
    # swallow an AWS outage / AccessDenied.
    assert not issubclass(AwsSecretsBackendError, KeyError)
    assert not issubclass(AwsSecretsBackendError, SecretNotFoundError)


# ---------------------------------------------------------------------------
# get() — no credential leak in error / __cause__
# ---------------------------------------------------------------------------


async def test_get_does_not_leak_secret_in_error() -> None:
    backend = _backend(
        _client(get_side_effect=_FakeClientError("AccessDeniedException", "token=AKIASECRETVALUE denied"))
    )
    with pytest.raises(AwsSecretsBackendError) as exc_info:
        await backend.get(_KB_SECRET_ARN)
    # Only the SecretId + exception *type* surface — never the upstream body.
    assert "AKIASECRETVALUE" not in str(exc_info.value)


async def test_get_drops_cause_so_traceback_does_not_leak() -> None:
    # ``from None`` so the upstream exception (whose message can echo a token) is
    # NOT attached as __cause__; otherwise a default traceback render leaks it.
    backend = _backend(
        _client(get_side_effect=_FakeClientError("AccessDeniedException", "AKIASECRETVALUE leaked"))
    )
    with pytest.raises(AwsSecretsBackendError) as exc_info:
        await backend.get(_KB_SECRET_ARN)
    assert exc_info.value.__cause__ is None
    assert "AKIASECRETVALUE" not in repr(exc_info.value)


async def test_get_not_found_also_drops_cause() -> None:
    backend = _backend(_client(get_side_effect=_FakeClientError("ResourceNotFoundException")))
    with pytest.raises(SecretNotFoundError) as exc_info:
        await backend.get("absent/secret")
    assert exc_info.value.__cause__ is None


async def test_returned_secret_redacts_on_repr() -> None:
    backend = _backend(_client(get_return={"SecretString": "topsecret"}))
    result = await backend.get(_KB_SECRET_ARN)
    assert "topsecret" not in repr(result)
    assert "topsecret" not in str(result)


# ---------------------------------------------------------------------------
# Property-based — any secret value redacts and round-trips (no leak in repr)
# ---------------------------------------------------------------------------


# deadline=None: each example offloads the read via ``asyncio.to_thread``, whose
# latency depends on the shared thread-pool scheduler — under a saturated full
# suite a per-example deadline can trip on timing alone (not a logic failure).
# This property asserts *redaction correctness*, not latency, so the deadline is
# disabled to keep it deterministic regardless of host load.
@given(value=st.text(min_size=1, max_size=200))
@settings(max_examples=200, deadline=None)
async def test_property_any_secret_redacts_but_round_trips(value: str) -> None:
    backend = AwsSecretsManagerBackend(
        region_name=_KB_REGION,
        client=_client(get_return={"SecretString": value}),
    )
    result = await backend.get(_KB_SECRET_ARN)
    # Round-trips exactly through get_secret_value...
    assert result.get_secret_value() == value
    # ...but the repr is the FIXED mask token, never the plaintext. A naive
    # ``value not in repr`` check is wrong: a value that is itself a substring of
    # the mask (e.g. "*") would false-positive even though redaction is correct.
    # The real invariant is that repr equals the constant mask — i.e. it does not
    # vary with, and so cannot reveal, the secret. (hypothesis found value="*".)
    assert repr(result) == "SecretStr('**********')"
    assert str(result) == "**********"


# ---------------------------------------------------------------------------
# rotate()
# ---------------------------------------------------------------------------


async def test_rotate_raises_not_implemented() -> None:
    backend = _backend(_client())
    with pytest.raises(NotImplementedError):
        await backend.rotate("anything")


# ---------------------------------------------------------------------------
# _aws_error_code — best-effort, botocore-free code extraction
# ---------------------------------------------------------------------------


def test_aws_error_code_extracts_from_clienterror_shape() -> None:
    assert _aws_error_code(_FakeClientError("AccessDeniedException")) == "AccessDeniedException"


def test_aws_error_code_none_for_bare_transport_error() -> None:
    # No structured ``response`` -> None -> treated as availability failure (closed).
    assert _aws_error_code(RuntimeError("socket timeout")) is None


def test_aws_error_code_none_when_error_field_malformed() -> None:
    # ``response`` is a Mapping but ``Error`` is absent / not a Mapping / Code not a
    # str: every branch yields None, so the read falls CLOSED (never "not found").
    exc_no_error: Exception = Exception()
    exc_no_error.response = {"ResponseMetadata": {}}  # type: ignore[attr-defined]
    assert _aws_error_code(exc_no_error) is None

    exc_error_not_mapping: Exception = Exception()
    exc_error_not_mapping.response = {"Error": "oops"}  # type: ignore[attr-defined]
    assert _aws_error_code(exc_error_not_mapping) is None

    exc_code_not_str: Exception = Exception()
    exc_code_not_str.response = {"Error": {"Code": 500}}  # type: ignore[attr-defined]
    assert _aws_error_code(exc_code_not_str) is None


async def test_get_malformed_error_response_fails_closed() -> None:
    # An exception with a ``response`` whose code is unreadable must NOT be
    # mistaken for ResourceNotFound — it fails CLOSED (AwsSecretsBackendError).
    exc: Exception = Exception("opaque")
    exc.response = {"Error": {"Code": 500}}  # type: ignore[attr-defined]
    backend = _backend(_client(get_side_effect=exc))
    with pytest.raises(AwsSecretsBackendError):
        await backend.get(_KB_SECRET_ARN)


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


def test_empty_region_raises_value_error() -> None:
    with pytest.raises(ValueError, match="region"):
        AwsSecretsManagerBackend(region_name="", client=_client())


def test_import_error_without_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    # No DI client + boto3 absent: the lazy client build at get() time must fail
    # with an actionable ImportError, never a bare ModuleNotFoundError.
    monkeypatch.setitem(sys.modules, "boto3", None)
    backend = AwsSecretsManagerBackend(region_name=_KB_REGION)
    with pytest.raises(ImportError, match="boto3"):
        # ImportError surfaces when the client is first needed.
        import asyncio

        asyncio.run(backend.get(_KB_SECRET_ARN))


# ---------------------------------------------------------------------------
# Real (non-DI) constructor path — the lazy ``import boto3`` branch. Every other
# test injects a MagicMock via ``client=`` and so never exercises this branch.
# We stub a fake ``boto3`` through ``sys.modules`` so the test passes whether or
# not boto3 is installed.
# ---------------------------------------------------------------------------


def _install_fake_boto3(monkeypatch: pytest.MonkeyPatch, *, get_return: dict[str, Any]) -> dict[str, Any]:
    """Inject a minimal fake ``boto3`` whose ``client(...)`` is observable."""
    captured: dict[str, Any] = {}

    class _SecretsClient:
        def get_secret_value(self, **kwargs: Any) -> dict[str, Any]:
            captured["get_kwargs"] = kwargs
            return get_return

    def _client_factory(service: str, **kwargs: Any) -> _SecretsClient:
        captured["service"] = service
        captured["client_kwargs"] = kwargs
        return _SecretsClient()

    boto3 = types.ModuleType("boto3")
    boto3.client = _client_factory  # type: ignore[attr-defined]
    boto3._captured = captured  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "boto3", boto3)
    return captured


async def test_real_constructor_builds_boto3_client(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _install_fake_boto3(monkeypatch, get_return={"SecretString": "live-value"})
    backend = AwsSecretsManagerBackend(region_name=_KB_REGION, endpoint_url="https://vpce.example")
    result = await backend.get(_KB_SECRET_ARN)
    assert result.get_secret_value() == "live-value"
    assert captured["service"] == "secretsmanager"
    assert captured["client_kwargs"]["region_name"] == _KB_REGION
    assert captured["client_kwargs"]["endpoint_url"] == "https://vpce.example"
    assert captured["get_kwargs"]["SecretId"] == _KB_SECRET_ARN


async def test_real_client_is_built_once_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    # The lazily-built client is reused across calls (built once).
    _install_fake_boto3(monkeypatch, get_return={"SecretString": "x"})
    backend = AwsSecretsManagerBackend(region_name=_KB_REGION)
    await backend.get(_KB_SECRET_ARN)
    first = backend._client
    await backend.get(_KB_SECRET_ARN)
    assert backend._client is first
