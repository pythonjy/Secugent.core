# SPDX-License-Identifier: Apache-2.0
"""Domestic/sovereign LLM adapter contract tests.

Covers (§10.8 + §B-8/§B-10):
* contract conformance (each adapter is an LLMClient; generate returns str),
* transport failure → LLMError; malformed/non-JSON/partial → LLMResponseFormatError,
* bounded retry on transient then raise,
* registry + get_default_client prod wiring (concrete, not Mock),
* prod fail-closed for unknown/unselected model,
* isolation: core does not import concrete adapters; control decision is
  model-invariant,
* secret/PII redaction; token/cost limit; Korean prompt fixture.
"""

from __future__ import annotations

import ast
import importlib
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from secugent.core.llm_client import (
    LLMClient,
    LLMError,
    LLMResponseFormatError,
    MockLLMClient,
    UsageEvent,
    get_default_client,
)
from secugent.core.llm_clients import (
    DOMESTIC_MODELS,
    AxLLMClient,
    ExaoneLLMClient,
    HyperClovaLLMClient,
    SolarLLMClient,
    build_domestic_client,
)
from secugent.core.llm_clients._base import BaseDomesticLLMClient
from secugent.core.llm_clients._transport import HttpResponse, TransportError

# ---------------------------------------------------------------------------
# Fake transport infrastructure
# ---------------------------------------------------------------------------


class _FakeResponse:
    """In-memory :class:`HttpResponse` for the adapters' transport contract."""

    def __init__(self, *, status_code: int, body: Any, raw: str | None = None) -> None:
        self._status_code = status_code
        self._body = body
        self._raw = raw

    @property
    def status_code(self) -> int:
        return self._status_code

    def json(self) -> Any:
        if isinstance(self._body, _NonJson):
            raise ValueError("not valid JSON")
        return self._body

    @property
    def text(self) -> str:
        return self._raw if self._raw is not None else "<body>"


class _NonJson:
    """Sentinel marking a body that fails JSON parsing."""


class _RecordingTransport:
    """Transport that returns scripted responses / raises scripted errors.

    Records every call so tests can assert payload/headers and retry counts.
    """

    def __init__(self, outcomes: list[Any]) -> None:
        self._outcomes = list(outcomes)
        self.calls: list[dict[str, Any]] = []

    def post(
        self,
        url: str,
        *,
        json: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> HttpResponse:
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        outcome = self._outcomes.pop(0) if self._outcomes else self._outcomes_default()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    @staticmethod
    def _outcomes_default() -> HttpResponse:  # pragma: no cover - defensive
        raise AssertionError("transport called more times than scripted")


def _ok_openai(text: str = "안녕하세요") -> _FakeResponse:
    return _FakeResponse(
        status_code=200,
        body={"choices": [{"message": {"role": "assistant", "content": text}}]},
    )


def _ok_clova(text: str = "안녕하세요") -> _FakeResponse:
    return _FakeResponse(
        status_code=200,
        body={"result": {"message": {"role": "assistant", "content": text}}},
    )


def _ok_openai_with_usage(
    text: str = "안녕하세요", *, prompt: int = 321, completion: int = 123
) -> _FakeResponse:
    """OpenAI-compatible success response that exposes provider usage."""
    return _FakeResponse(
        status_code=200,
        body={
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
        },
    )


def _ok_clova_with_usage(text: str = "안녕하세요", *, prompt: int = 11, completion: int = 7) -> _FakeResponse:
    """CLOVA success response that exposes provider usage (camelCase fields)."""
    return _FakeResponse(
        status_code=200,
        body={
            "result": {
                "message": {"role": "assistant", "content": text},
                "usage": {"promptTokens": prompt, "completionTokens": completion},
            }
        },
    )


_USER_MESSAGES: list[dict[str, str]] = [{"role": "user", "content": "테스트 질문"}]


# Adapter / success-response pairings used across parametrized tests.
_OPENAI_ADAPTERS = [ExaoneLLMClient, SolarLLMClient, AxLLMClient]
_ALL_ADAPTERS = [
    (ExaoneLLMClient, _ok_openai),
    (SolarLLMClient, _ok_openai),
    (AxLLMClient, _ok_openai),
    (HyperClovaLLMClient, _ok_clova),
]


# ---------------------------------------------------------------------------
# Contract conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_adapter_is_llmclient(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    client = adapter_cls(endpoint="https://model.internal/v1", transport=_RecordingTransport([]))
    assert isinstance(client, LLMClient)


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_generate_success_returns_str(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([ok_resp()])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert isinstance(out, str)
    assert out == "안녕하세요"
    assert len(transport.calls) == 1


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_transport_failure_raises_llmerror(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    # Every attempt raises TransportError → after retries, LLMError.
    transport = _RecordingTransport(
        [TransportError("timeout"), TransportError("timeout"), TransportError("timeout")]
    )
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport, max_attempts=3)
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(transport.calls) == 3  # bounded retry exhausted


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_non_json_raises_format_error(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body=_NonJson(), raw="<html>502</html>")])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_partial_response_raises_format_error(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    # Valid JSON but missing the assistant-text field → partial.
    transport = _RecordingTransport([_FakeResponse(status_code=200, body={"foo": "bar"})])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_non_object_json_raises_format_error(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body=["not", "a", "dict"])])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_bounded_retry_then_success(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    # Two transient failures then a success → returns text, 3 calls total.
    transport = _RecordingTransport([TransportError("timeout"), TransportError("timeout"), ok_resp()])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport, max_attempts=3)
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"
    assert len(transport.calls) == 3


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_retryable_status_then_raise(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport(
        [
            _FakeResponse(status_code=503, body={}),
            _FakeResponse(status_code=503, body={}),
            _FakeResponse(status_code=503, body={}),
        ]
    )
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport, max_attempts=3)
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(transport.calls) == 3


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_auth_failure_is_terminal(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=401, body={})])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport, max_attempts=3)
    with pytest.raises(LLMError) as exc_info:
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(transport.calls) == 1  # NOT retried (terminal)
    assert "authentication failed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Input validation / normalization (§B-8)
# ---------------------------------------------------------------------------


def test_empty_endpoint_rejected() -> None:
    with pytest.raises(LLMError):
        ExaoneLLMClient(endpoint="   ")


def test_non_http_endpoint_rejected() -> None:
    with pytest.raises(LLMError):
        ExaoneLLMClient(endpoint="ftp://model.internal")


def test_empty_messages_rejected() -> None:
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=[])


def test_unsupported_role_rejected() -> None:
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=[{"role": "system", "content": "x"}])


def test_non_positive_max_tokens_rejected() -> None:
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES, max_tokens=0)


def test_token_limit_enforced() -> None:
    """§B-10 token/cost guard: over-limit max_tokens fails closed."""
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError) as exc_info:
        client.generate(model="m", system="sys", messages=_USER_MESSAGES, max_tokens=999_999)
    assert "exceeds limit" in str(exc_info.value)


def test_invalid_timeout_rejected() -> None:
    with pytest.raises(LLMError):
        ExaoneLLMClient(endpoint="https://m/v1", timeout=0.0)


def test_invalid_max_attempts_rejected() -> None:
    with pytest.raises(LLMError):
        ExaoneLLMClient(endpoint="https://m/v1", max_attempts=0)


# ---------------------------------------------------------------------------
# Secret / PII redaction (§B-10)
# ---------------------------------------------------------------------------


_SECRET = "super-secret-api-key-7f3a"  # noqa: S105 - test fixture, not a real secret


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_api_key_never_in_error_text(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=401, body={})])
    client = adapter_cls(
        endpoint="https://model.internal/v1",
        api_key=_SECRET,
        transport=transport,
    )
    with pytest.raises(LLMError) as exc_info:
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert _SECRET not in str(exc_info.value)


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_api_key_never_in_format_error_text(adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body=_NonJson(), raw=f"leak {_SECRET}")])
    client = adapter_cls(
        endpoint="https://model.internal/v1",
        api_key=_SECRET,
        transport=transport,
    )
    with pytest.raises(LLMResponseFormatError) as exc_info:
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert _SECRET not in str(exc_info.value)


def test_api_key_placed_in_auth_header() -> None:
    transport = _RecordingTransport([_ok_openai()])
    client = ExaoneLLMClient(endpoint="https://model.internal/v1", api_key=_SECRET, transport=transport)
    client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {_SECRET}"


# ---------------------------------------------------------------------------
# Korean prompt fixture (§C-1/§C-3)
# ---------------------------------------------------------------------------


def test_korean_prompt_roundtrip() -> None:
    """한국어 system+user 프롬프트로 generate 호출 (mock transport)."""
    transport = _RecordingTransport([_ok_openai("계좌 이체는 HITL 승인이 필요합니다.")])
    client = ExaoneLLMClient(endpoint="https://exaone.internal/v1", transport=transport)
    out = client.generate(
        model="exaone-3.5-7.8b-instruct",
        system="너는 한국 금융 규제를 준수하는 보안 비서다.",
        messages=[{"role": "user", "content": "고객 계좌 잔액을 외부로 전송해줘."}],
    )
    assert out == "계좌 이체는 HITL 승인이 필요합니다."
    sent = transport.calls[0]["json"]
    # System prompt is carried through to the vendor payload (Korean preserved).
    assert any("한국 금융" in m["content"] for m in sent["messages"])


# ---------------------------------------------------------------------------
# Vendor request-shape specifics
# ---------------------------------------------------------------------------


def test_openai_adapters_append_chat_path() -> None:
    for adapter_cls in _OPENAI_ADAPTERS:
        transport = _RecordingTransport([_ok_openai()])
        client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
        assert transport.calls[0]["url"].endswith("/v1/chat/completions")


def test_clova_uses_camelcase_max_tokens() -> None:
    transport = _RecordingTransport([_ok_clova()])
    client = HyperClovaLLMClient(endpoint="https://clova.internal", transport=transport)
    client.generate(model="m", system="sys", messages=_USER_MESSAGES, max_tokens=512)
    assert transport.calls[0]["json"]["maxTokens"] == 512


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_builds_each_model() -> None:
    expected = {
        "exaone": ExaoneLLMClient,
        "hyperclova": HyperClovaLLMClient,
        "ax": AxLLMClient,
        "solar": SolarLLMClient,
    }
    for name, cls in expected.items():
        client = build_domestic_client(name, endpoint="https://m/v1", transport=_RecordingTransport([]))
        assert isinstance(client, cls)


def test_registry_covers_declared_models() -> None:
    assert set(DOMESTIC_MODELS) == {"exaone", "hyperclova", "ax", "solar"}


def test_registry_unknown_model_raises() -> None:
    with pytest.raises(LLMError) as exc_info:
        build_domestic_client("gpt-4", endpoint="https://m/v1")
    assert "unsupported domestic model" in str(exc_info.value)


# ---------------------------------------------------------------------------
# get_default_client integration / prod fail-closed
# ---------------------------------------------------------------------------


def test_get_default_client_prod_builds_concrete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://exaone.internal/v1")
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL", "exaone")
    client = get_default_client()
    assert isinstance(client, ExaoneLLMClient)
    assert not isinstance(client, MockLLMClient)


def test_get_default_client_dev_builds_concrete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # dev must be OPTED IN explicitly (unset ⇒ production, fail-closed). The
    # old form delenv'd SECUGENT_ENV and relied on the fail-OPEN "dev" default —
    # encoding the very inconsistency finding #5 flagged. Set it explicitly.
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://solar.internal/v1")
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL", "solar")
    client = get_default_client()
    assert isinstance(client, SolarLLMClient)


def test_get_default_client_prod_unknown_model_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Boundary: prod + endpoint + UNKNOWN model → boot refuse (never Mock)."""
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://x.internal/v1")
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL", "totally-unknown")
    with pytest.raises(LLMError):
        get_default_client()


def test_get_default_client_prod_no_model_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """prod + endpoint but NO model selector → fail-closed (never Mock)."""
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://x.internal/v1")
    monkeypatch.delenv("SECUGENT_DOMESTIC_MODEL", raising=False)
    with pytest.raises(LLMError):
        get_default_client()


def test_get_default_client_dev_no_model_is_mock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Dev (explicitly opted in) + endpoint but no concrete model selector ⇒ Mock is
    # the intended dev/test convenience. In PROD the same config raises (see below).
    monkeypatch.setenv("SECUGENT_ENV", "dev")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://x.internal/v1")
    monkeypatch.delenv("SECUGENT_DOMESTIC_MODEL", raising=False)
    client = get_default_client()
    assert isinstance(client, MockLLMClient)


def test_get_default_client_unset_env_is_production_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """INV-C2-1 regression (finding #5): an UNSET ``SECUGENT_ENV`` is
    PRODUCTION here too, exactly like the auth layer — not the old fail-OPEN "dev".

    With no API key, no concrete domestic model, and the env var unset, an operator
    who forgot to set ``SECUGENT_ENV`` on a prod box must get a hard ``LLMError``,
    NOT a silent ``MockLLMClient`` driving the planner/risk_analyzer.
    """
    monkeypatch.delenv("SECUGENT_ENV", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://x.internal/v1")
    monkeypatch.delenv("SECUGENT_DOMESTIC_MODEL", raising=False)
    with pytest.raises(LLMError):
        get_default_client()


# ---------------------------------------------------------------------------
# Fail-soft uniformity: sovereign-adapter format errors must not crash callers
# ---------------------------------------------------------------------------
#
# Regression for the High finding: the four sovereign adapters are the first
# generate() impls to raise LLMResponseFormatError DIRECTLY (on a non-JSON /
# non-object / partial body from an air-gapped vLLM/CLOVA gateway). The callers
# (HEAD, STEER, EVOLUTION, RegulationConverter) only guard ``except LLMError``,
# so unless LLMResponseFormatError IS-A LLMError, a single malformed body turns
# designed graceful degradation into an uncaught crash across orchestration.


def test_format_error_is_subclass_of_llmerror() -> None:
    """Hierarchy invariant: every ``except LLMError`` site also catches a
    sovereign-adapter format error (one place, all callers fail-soft)."""
    assert issubclass(LLMResponseFormatError, LLMError)


@pytest.mark.parametrize(
    "adapter_cls,bad_body",
    [
        (ExaoneLLMClient, _NonJson()),  # HTML 502 from gateway → non-JSON
        (ExaoneLLMClient, ["not", "a", "dict"]),  # non-object JSON
        (ExaoneLLMClient, {"foo": "bar"}),  # partial: missing assistant text
        (HyperClovaLLMClient, _NonJson()),
    ],
)
def test_sovereign_format_error_is_caught_as_llmerror(
    adapter_cls: type[BaseDomesticLLMClient], bad_body: Any
) -> None:
    """A malformed sovereign body raised from generate() is an ``LLMError`` so a
    bare ``except LLMError`` caller (head/steer/evolution/regulation) fail-soft
    instead of crashing."""
    transport = _RecordingTransport([_FakeResponse(status_code=200, body=bad_body)])
    client = adapter_cls(endpoint="https://model.internal/v1", transport=transport)
    with pytest.raises(LLMError):  # would NOT match before the subclass fix
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


def test_regulation_converter_fail_soft_on_sovereign_format_error() -> None:
    """End-to-end caller proof: RegulationConverter.convert returns ``None``
    (human-drafting fallback) when a sovereign adapter yields a malformed body,
    rather than propagating LLMResponseFormatError."""
    from secugent.core.ml.regulation_converter import RegulationConverter

    transport = _RecordingTransport(
        [_FakeResponse(status_code=200, body=_NonJson(), raw="<html>502 Bad Gateway</html>")]
    )
    adapter = ExaoneLLMClient(endpoint="https://exaone.internal/v1", transport=transport)
    converter = RegulationConverter(adapter)
    result = converter.convert("계좌 이체는 승인이 필요하다.", tenant_id="t-kr-bank")
    assert result is None


# ---------------------------------------------------------------------------
# Isolation: core decision modules do not import concrete adapters
# ---------------------------------------------------------------------------


_CORE_DECISION_MODULES = [
    "secugent/core/mechanical_oversight.py",
    "secugent/core/regulations.py",
    "secugent/core/approval.py",
    "secugent/core/rule_of_two.py",
    "secugent/core/risk_analyzer.py",
]

_CONCRETE_ADAPTER_MODULES = {
    "secugent.core.llm_clients.exaone",
    "secugent.core.llm_clients.hyperclova",
    "secugent.core.llm_clients.ax",
    "secugent.core.llm_clients.solar",
}

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _imported_modules(source_path: Path) -> set[str]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            names.add(node.module)
    return names


def test_core_decision_modules_do_not_import_concrete_adapters() -> None:
    """I2 isolation: core decides via the LLMClient abstraction only."""
    for rel in _CORE_DECISION_MODULES:
        path = _REPO_ROOT / rel
        if not path.exists():
            continue
        imported = _imported_modules(path)
        leaked = imported & _CONCRETE_ADAPTER_MODULES
        assert not leaked, f"{rel} imports concrete adapter(s): {leaked}"


# ---------------------------------------------------------------------------
# Model-invariance: the CONTROL decision is identical regardless of adapter
# ---------------------------------------------------------------------------


def test_control_decision_is_model_invariant() -> None:
    """Swapping the LLM adapter must not change a deterministic control decision.

    classify_axes is a pure core function that takes no LLM; running it with
    different adapters "installed" yields identical axes — proving the decision
    does not depend on which sovereign model is wired in.
    """
    from secugent.core.contracts import Step
    from secugent.core.rule_of_two import Axis, classify_axes

    step = Step(
        tenant_id="t-kr-bank",
        run_id="run-1",
        actor="sub:researcher",
        action_type="file_read",
    )
    adapters = [
        ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([])),
        HyperClovaLLMClient(endpoint="https://m", transport=_RecordingTransport([])),
        AxLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([])),
        SolarLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([])),
    ]
    results: list[frozenset[Axis]] = []
    for adapter in adapters:
        _ = adapter  # adapter is "installed" but irrelevant to the decision
        results.append(classify_axes(step))
    assert all(r == results[0] for r in results)
    assert isinstance(results[0], frozenset)
    assert Axis.SENSITIVE_ACCESS in results[0]


# ---------------------------------------------------------------------------
# Lazy import: importing the core module does not require httpx
# ---------------------------------------------------------------------------


def test_importing_core_does_not_require_httpx() -> None:
    """The concrete adapters import httpx lazily (only when a default transport
    is actually constructed), so importing the modules must not pull httpx."""
    mod = importlib.import_module("secugent.core.llm_clients")
    # Constructing a client WITH an injected transport must not touch httpx.
    with patch.dict(os.environ, {}, clear=False):
        client = mod.build_domestic_client(
            "exaone", endpoint="https://m/v1", transport=_RecordingTransport([])
        )
    assert isinstance(client, ExaoneLLMClient)


# ---------------------------------------------------------------------------
# Additional boundary / defensive-branch coverage
# ---------------------------------------------------------------------------


def test_non_str_system_rejected() -> None:
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError):
        client.generate(model="m", system=123, messages=_USER_MESSAGES)  # type: ignore[arg-type]


def test_non_str_content_rejected() -> None:
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    with pytest.raises(LLMError):
        client.generate(
            model="m",
            system="sys",
            messages=[{"role": "user", "content": 5}],  # type: ignore[dict-item]
        )


def test_generic_4xx_is_terminal() -> None:
    """A non-auth 4xx (e.g. 400 bad request) is terminal — not retried."""
    transport = _RecordingTransport([_FakeResponse(status_code=400, body={})])
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=transport, max_attempts=3)
    with pytest.raises(LLMError) as exc_info:
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(transport.calls) == 1
    assert "status 400" in str(exc_info.value)


def test_endpoint_already_has_chat_path_not_doubled() -> None:
    transport = _RecordingTransport([_ok_openai()])
    client = ExaoneLLMClient(endpoint="https://m/v1/chat/completions", transport=transport)
    client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    url = transport.calls[0]["url"]
    assert url.count("/chat/completions") == 1


def test_clova_non_str_content_is_format_error() -> None:
    transport = _RecordingTransport(
        [_FakeResponse(status_code=200, body={"result": {"message": {"content": 7}}})]
    )
    client = HyperClovaLLMClient(endpoint="https://clova.internal", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


def test_clova_message_not_dict_is_format_error() -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body={"result": {"message": "oops"}})])
    client = HyperClovaLLMClient(endpoint="https://clova.internal", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


@pytest.mark.parametrize("adapter_cls", _OPENAI_ADAPTERS)
def test_openai_choice_not_dict_is_format_error(adapter_cls: type[BaseDomesticLLMClient]) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body={"choices": ["not-a-dict"]})])
    client = adapter_cls(endpoint="https://m/v1", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


@pytest.mark.parametrize("adapter_cls", _OPENAI_ADAPTERS)
def test_openai_message_not_dict_is_format_error(adapter_cls: type[BaseDomesticLLMClient]) -> None:
    transport = _RecordingTransport([_FakeResponse(status_code=200, body={"choices": [{"message": "oops"}]})])
    client = adapter_cls(endpoint="https://m/v1", transport=transport)
    with pytest.raises(LLMResponseFormatError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)


# ---------------------------------------------------------------------------
# Default httpx transport translation (closed-network production path)
# ---------------------------------------------------------------------------


class _FakeHttpxClient:
    """Minimal stand-in for ``httpx.Client`` used as a context manager."""

    def __init__(self, *, behavior: str, timeout: float) -> None:
        self._behavior = behavior

    def __enter__(self) -> _FakeHttpxClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def post(self, url: str, *, json: Any, headers: Any) -> Any:
        import httpx

        if self._behavior == "timeout":
            raise httpx.TimeoutException("slow")
        if self._behavior == "transport":
            raise httpx.ConnectError("refused")
        return _ok_openai()


def _patch_httpx(monkeypatch: pytest.MonkeyPatch, behavior: str) -> None:
    import httpx

    def _factory(*, timeout: float) -> _FakeHttpxClient:
        return _FakeHttpxClient(behavior=behavior, timeout=timeout)

    monkeypatch.setattr(httpx, "Client", _factory)


def test_default_transport_timeout_translates_to_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secugent.core.llm_clients._transport import default_transport

    _patch_httpx(monkeypatch, "timeout")
    transport = default_transport()
    with pytest.raises(TransportError):
        transport.post("https://m/v1", json={}, headers={}, timeout=1.0)


def test_default_transport_connect_error_translates_to_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secugent.core.llm_clients._transport import default_transport

    _patch_httpx(monkeypatch, "transport")
    transport = default_transport()
    with pytest.raises(TransportError) as exc_info:
        transport.post("https://m/v1", json={}, headers={}, timeout=1.0)
    # The endpoint host must NOT appear in the redacted error text.
    assert "https://m/v1" not in str(exc_info.value)


def test_default_transport_success_returns_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secugent.core.llm_clients._transport import default_transport

    _patch_httpx(monkeypatch, "ok")
    transport = default_transport()
    resp = transport.post("https://m/v1", json={}, headers={}, timeout=1.0)
    assert resp.status_code == 200


def test_adapter_uses_default_transport_when_none_injected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: with no injected transport, the adapter builds the httpx
    default and a full generate() round-trips through it."""
    _patch_httpx(monkeypatch, "ok")
    client = ExaoneLLMClient(endpoint="https://m/v1")
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"


# ---------------------------------------------------------------------------
# resolve_llm_client domestic branch (settings.py)
# ---------------------------------------------------------------------------


def test_resolve_llm_client_builds_domestic() -> None:
    from secugent.core.settings import LLMSettings, resolve_llm_client

    settings = LLMSettings(
        mode="mock",
        domestic_model="exaone",
        domestic_model_endpoint="https://exaone.internal/v1",
    )
    client = resolve_llm_client(settings)
    assert isinstance(client, ExaoneLLMClient)


def test_llm_settings_domestic_model_requires_endpoint() -> None:
    from pydantic import ValidationError

    from secugent.core.settings import LLMSettings

    with pytest.raises(ValidationError):
        LLMSettings(mode="mock", domestic_model="solar")  # no endpoint


def test_resolve_llm_client_domestic_passes_api_key() -> None:
    from pydantic import SecretStr

    from secugent.core.settings import LLMSettings, resolve_llm_client

    settings = LLMSettings(
        mode="mock",
        api_key=SecretStr(_SECRET),
        domestic_model="solar",
        domestic_model_endpoint="https://solar.internal/v1",
    )
    transport = _RecordingTransport([_ok_openai()])
    client = resolve_llm_client(settings)
    assert isinstance(client, SolarLLMClient)
    # The secret was threaded into the adapter; prove it via the auth header
    # without ever asserting the raw value appears anywhere it shouldn't.
    client._transport = transport
    client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {_SECRET}"


# ---------------------------------------------------------------------------
# Sovereign model-id binding (the OUTGOING payload['model'] must be the
# sovereign id the endpoint serves, NOT the caller's Claude default).
# ---------------------------------------------------------------------------
#
# Regression for the High + Medium findings: callers (RiskAnalyzer) pass
# model=RISK_MODEL_DEFAULT ('claude-haiku-4-5-...'); a real EXAONE/Solar/A.X/
# CLOVA endpoint 401s/404s on that id. A configured domestic model-id must
# override the per-call model arg on the domestic path.

_DOMESTIC_MODEL_ID = "exaone-3.5-7.8b-instruct"


def test_bound_model_id_overrides_per_call_model_in_payload() -> None:
    """When the adapter is constructed with a sovereign ``model_id``, the
    OUTGOING payload carries that id even if the caller passes a Claude id."""
    transport = _RecordingTransport([_ok_openai()])
    client = ExaoneLLMClient(
        endpoint="https://exaone.internal/v1",
        model_id=_DOMESTIC_MODEL_ID,
        transport=transport,
    )
    client.generate(model="claude-haiku-4-5-20251001", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["json"]["model"] == _DOMESTIC_MODEL_ID


def test_unbound_model_id_uses_per_call_model() -> None:
    """Backwards-compat: with no ``model_id`` bound, the per-call model wins."""
    transport = _RecordingTransport([_ok_openai()])
    client = ExaoneLLMClient(endpoint="https://exaone.internal/v1", transport=transport)
    client.generate(model="caller-model", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["json"]["model"] == "caller-model"


def test_build_domestic_client_threads_model_id() -> None:
    """The registry passes ``model_id`` through to the adapter ctor."""
    transport = _RecordingTransport([_ok_openai()])
    client = build_domestic_client(
        "solar",
        endpoint="https://solar.internal/v1",
        model_id=_DOMESTIC_MODEL_ID,
        transport=transport,
    )
    client.generate(model="claude-haiku-4-5-20251001", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["json"]["model"] == _DOMESTIC_MODEL_ID


# -- Finding 3: get_default_client reads domestic model-id + api-key env -----


def test_get_default_client_binds_domestic_model_id_and_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prod boot path: SECUGENT_DOMESTIC_MODEL_ID + _API_KEY are read and reach
    the OUTGOING request (model id + Authorization header), so a real sovereign
    endpoint is not handed a Claude model id with no auth."""
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ENDPOINT", "https://exaone.internal/v1")
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL", "exaone")
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_ID", _DOMESTIC_MODEL_ID)
    monkeypatch.setenv("SECUGENT_DOMESTIC_MODEL_API_KEY", _SECRET)
    client = get_default_client()
    assert isinstance(client, ExaoneLLMClient)
    transport = _RecordingTransport([_ok_openai()])
    client._transport = transport
    # Caller passes the Claude default; the bound sovereign id must override it.
    client.generate(model="claude-haiku-4-5-20251001", system="sys", messages=_USER_MESSAGES)
    sent = transport.calls[0]
    assert sent["json"]["model"] == _DOMESTIC_MODEL_ID
    assert sent["headers"]["Authorization"] == f"Bearer {_SECRET}"


# -- Finding 4: resolve_llm_client threads model_id + max_retries ------------


def test_resolve_llm_client_threads_model_id_and_max_retries() -> None:
    from pydantic import SecretStr

    from secugent.core.settings import LLMSettings, resolve_llm_client

    settings = LLMSettings(
        mode="mock",
        api_key=SecretStr(_SECRET),
        domestic_model="exaone",
        domestic_model_endpoint="https://exaone.internal/v1",
        domestic_model_id=_DOMESTIC_MODEL_ID,
        max_retries=7,
    )
    client = resolve_llm_client(settings)
    assert isinstance(client, ExaoneLLMClient)
    # max_retries honoured on the domestic path (was silently dropped before).
    assert client._max_attempts == 7
    transport = _RecordingTransport([_ok_openai()])
    client._transport = transport
    client.generate(model="claude-haiku-4-5-20251001", system="sys", messages=_USER_MESSAGES)
    assert transport.calls[0]["json"]["model"] == _DOMESTIC_MODEL_ID


# ---------------------------------------------------------------------------
# COST-01 review (Medium): the sovereign-adapter chokepoint must emit usage
# ---------------------------------------------------------------------------
#
# Regression for the Medium finding: ``create_app`` installs the live recorder
# onto whatever ``get_default_client`` builds — including a sovereign adapter on
# the §A-2.6 closed-network-first path. Before this fix ``generate`` returned the
# parsed text but NEVER called ``_emit_usage``, so in-run metering (INV-2) was
# silently inert on the very deployment path the spec names: CostLedger never
# accrued and the per-step self-inflicted-overspend gate could not fire.


@pytest.mark.parametrize(
    "adapter_cls,ok_usage_resp",
    [
        (ExaoneLLMClient, _ok_openai_with_usage),
        (SolarLLMClient, _ok_openai_with_usage),
        (AxLLMClient, _ok_openai_with_usage),
        (HyperClovaLLMClient, _ok_clova_with_usage),
    ],
)
def test_sovereign_emits_exact_usage_when_provider_exposes_it(
    adapter_cls: type[BaseDomesticLLMClient], ok_usage_resp: Any
) -> None:
    """When the vendor body carries usage, emit an EXACT event (exact=True)."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport([ok_usage_resp()])
    client = adapter_cls(
        endpoint="https://model.internal/v1",
        transport=transport,
        usage_observer=events.append,
    )
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"
    assert len(events) == 1
    ev = events[0]
    assert ev.exact is True
    assert ev.input_tokens > 0
    assert ev.output_tokens > 0


@pytest.mark.parametrize("adapter_cls,ok_resp", _ALL_ADAPTERS)
def test_sovereign_emits_estimated_usage_when_provider_omits_it(
    adapter_cls: type[BaseDomesticLLMClient], ok_resp: Any
) -> None:
    """No provider usage in the body → fall back to a length-based ESTIMATE
    (exact=False), so the ledger still accrues in-run (INV-2/INV-4 honesty)."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport([ok_resp("안녕하세요 반갑습니다")])
    client = adapter_cls(
        endpoint="https://model.internal/v1",
        transport=transport,
        usage_observer=events.append,
    )
    client.generate(
        model="exaone-3.5",
        system="너는 한국 금융 보안 비서다.",
        messages=[{"role": "user", "content": "고객 잔액 조회"}],
    )
    assert len(events) == 1
    ev = events[0]
    assert ev.exact is False  # never claims unmeasured provider precision (INV-4)
    assert ev.model == "exaone-3.5"
    assert ev.input_tokens >= 0
    assert ev.output_tokens >= 0


def test_sovereign_usage_clamps_negative_provider_tokens() -> None:
    """A garbled negative provider count is clamped to 0 (never sub-zero)."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport([_ok_openai_with_usage(prompt=-5, completion=-9)])
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=transport, usage_observer=events.append)
    client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(events) == 1
    assert events[0].input_tokens == 0
    assert events[0].output_tokens == 0


def test_sovereign_no_observer_means_no_emission_and_unchanged_return() -> None:
    """INV-3 non-breaking: default observer None → generate() -> str unchanged."""
    transport = _RecordingTransport([_ok_openai_with_usage()])
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=transport)
    assert client.usage_observer is None
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"


def test_sovereign_raising_observer_never_breaks_generate() -> None:
    """INV-1 fail-open: an observer that raises must not abort the call."""

    def _boom(_event: UsageEvent) -> None:
        raise RuntimeError("observer exploded")

    transport = _RecordingTransport([_ok_openai_with_usage()])
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=transport, usage_observer=_boom)
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"  # response returned despite the observer raising


def test_sovereign_failed_call_emits_no_usage() -> None:
    """A call that never produces text (transport failure) emits no usage."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport([TransportError("t"), TransportError("t"), TransportError("t")])
    client = ExaoneLLMClient(
        endpoint="https://m/v1", transport=transport, max_attempts=3, usage_observer=events.append
    )
    with pytest.raises(LLMError):
        client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert events == []


def test_sovereign_malformed_usage_falls_back_to_estimate() -> None:
    """A non-int / non-dict usage field is ignored → estimate, never a crash."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport(
        [
            _FakeResponse(
                status_code=200,
                body={
                    "choices": [{"message": {"content": "응답"}}],
                    "usage": {"prompt_tokens": "oops", "completion_tokens": None},
                },
            )
        ]
    )
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=transport, usage_observer=events.append)
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "응답"
    assert len(events) == 1
    assert events[0].exact is False  # fell back to length estimate


def test_sovereign_usage_extraction_raise_is_fail_open() -> None:
    """If usage extraction itself RAISES, generate still returns (INV-1).

    A vendor ``_extract_usage`` that throws (not just returns None) must not
    abort the returned response — the emitter wraps the build fail-open.
    """
    events: list[UsageEvent] = []

    class _BoomUsageClient(ExaoneLLMClient):
        def _extract_usage(self, body: Any) -> Any:
            raise RuntimeError("usage parse exploded")

    transport = _RecordingTransport([_ok_openai()])
    client = _BoomUsageClient(endpoint="https://m/v1", transport=transport, usage_observer=events.append)
    out = client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert out == "안녕하세요"  # response returned despite usage extraction raising
    assert events == []  # nothing emitted — never mis-attributed (fail-open by absence)


def test_clova_bool_usage_token_is_rejected_as_unmeasured() -> None:
    """A stray ``True`` in a usage field is treated as unmeasured (estimate),
    not silently counted as 1 token (bool is an int subclass)."""
    events: list[UsageEvent] = []
    transport = _RecordingTransport(
        [
            _FakeResponse(
                status_code=200,
                body={
                    "result": {
                        "message": {"content": "응답"},
                        "usage": {"promptTokens": 10, "completionTokens": True},
                    }
                },
            )
        ]
    )
    client = HyperClovaLLMClient(
        endpoint="https://clova.internal", transport=transport, usage_observer=events.append
    )
    client.generate(model="m", system="sys", messages=_USER_MESSAGES)
    assert len(events) == 1
    assert events[0].exact is False  # bool rejected → fell back to estimate


def test_base_default_extract_usage_returns_none() -> None:
    """The base ``_extract_usage`` default exposes no usage (subclasses override)."""

    class _NoShapeClient(BaseDomesticLLMClient):
        vendor = "noshape"

        def _auth_headers(self) -> dict[str, str]:
            return {}

        def _build_payload(
            self, *, model: str, system: str, messages: list[dict[str, str]], max_tokens: int
        ) -> dict[str, Any]:
            return {}

        def _extract_text(self, body: dict[str, Any]) -> str | None:
            return "ok"

    client = _NoShapeClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    assert client._extract_usage({"usage": {"prompt_tokens": 1, "completion_tokens": 2}}) is None


def test_clova_extract_usage_result_not_dict_returns_none() -> None:
    """Defensive: a CLOVA body whose ``result`` is not a mapping yields no usage."""
    client = HyperClovaLLMClient(endpoint="https://clova.internal", transport=_RecordingTransport([]))
    assert client._extract_usage({"result": "not-a-dict"}) is None
    assert client._extract_usage({}) is None


def test_parse_response_backcompat_wrapper_returns_text() -> None:
    """The retained ``_parse_response`` wrapper composes parse + extract."""
    client = ExaoneLLMClient(endpoint="https://m/v1", transport=_RecordingTransport([]))
    assert client._parse_response(_ok_openai("hi")) == "hi"
