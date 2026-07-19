# SPDX-License-Identifier: Apache-2.0
"""COST-01 — usage observer hook on the LLM client (PUBLIC, cost-agnostic).

Proves:
* default observer ``None`` ⇒ ``generate() -> str`` is 100% unchanged (INV-3),
* MockLLMClient emits an ESTIMATED UsageEvent (exact=False) per call so a ledger
  can be proven to grow,
* ``usage_override`` test hook pins a precise event,
* the AnthropicLLMClient usage extraction reads ``response.usage`` (exact=True)
  via the pure ``_extract_usage`` helper (no SDK / network needed),
* a raising observer can NEVER break generate (fail-open, INV-1),
* the client module never imports the private ``secugent.cost`` tier (closure).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from secugent.core.llm_client import (
    LLMError,
    MockLLMClient,
    UsageEvent,
    _extract_usage,
)


def test_default_observer_is_none_and_generate_unchanged() -> None:
    client = MockLLMClient(["hello-world"])
    assert client.usage_observer is None
    out = client.generate(model="m", system="sys", messages=[{"role": "user", "content": "hi"}])
    assert out == "hello-world"


def test_mock_emits_estimated_usage() -> None:
    events: list[UsageEvent] = []
    client = MockLLMClient(["abcdefgh"], usage_observer=events.append)  # output len 8 → 8//4 = 2
    client.generate(
        model="claude-haiku",
        system="0123",  # len 4
        messages=[{"role": "user", "content": "4567"}],  # len 4 → input chars 8 → 8//4 = 2
    )
    assert len(events) == 1
    ev = events[0]
    assert ev.model == "claude-haiku"
    assert ev.exact is False  # estimate, never claims provider precision (INV-4)
    assert ev.input_tokens == 2
    assert ev.output_tokens == 2


def test_mock_emits_per_call_so_ledger_can_grow() -> None:
    events: list[UsageEvent] = []
    client = MockLLMClient(["aaaa", "bbbbbbbb"], usage_observer=events.append)
    client.generate(model="m", system="s", messages=[{"role": "user", "content": "x"}])
    client.generate(model="m", system="s", messages=[{"role": "user", "content": "x"}])
    assert len(events) == 2  # one event per generate → an accumulating ledger grows


def test_usage_override_hook() -> None:
    events: list[UsageEvent] = []
    pinned = UsageEvent(model="exact-model", input_tokens=100, output_tokens=50, exact=True)
    client = MockLLMClient(
        ["resp"],
        usage_observer=events.append,
        usage_override=lambda model, system, messages, output: pinned,
    )
    client.generate(model="ignored", system="s", messages=[{"role": "user", "content": "x"}])
    assert events == [pinned]


def test_failure_path_emits_no_usage() -> None:
    events: list[UsageEvent] = []
    client = MockLLMClient(["never"], fail_n=1, usage_observer=events.append)
    with pytest.raises(LLMError):
        client.generate(model="m", system="s", messages=[{"role": "user", "content": "x"}])
    # The call raised before producing output → no usage emitted (edge case).
    assert events == []


def test_raising_observer_never_breaks_generate() -> None:
    """INV-1 fail-open: an observer that raises must not abort the call."""

    def _boom(_event: UsageEvent) -> None:
        raise RuntimeError("observer exploded")

    client = MockLLMClient(["survived"], usage_observer=_boom)
    out = client.generate(model="m", system="s", messages=[{"role": "user", "content": "x"}])
    assert out == "survived"  # the response is returned despite the observer raising


def test_raising_usage_override_never_breaks_generate() -> None:
    """INV-1 fail-open: a usage_override that raises must not abort the call.

    Regression for the review Low — the mock built the UsageEvent OUTSIDE the
    fail-open boundary (it was the argument to _emit_usage), so a raising
    override escaped generate() and would break a real run. The estimate is now
    built inside the try/except.
    """

    def _boom(_m: str, _s: str, _msgs: list[dict[str, str]], _out: str) -> UsageEvent:
        raise RuntimeError("override exploded")

    events: list[UsageEvent] = []
    client = MockLLMClient(["survived"], usage_observer=events.append, usage_override=_boom)
    out = client.generate(model="m", system="s", messages=[{"role": "user", "content": "x"}])
    assert out == "survived"  # returned despite the override raising
    assert events == []  # estimation failed → no usage emitted, no propagation


# --------------------------------------------------------------------------- #
# Anthropic usage extraction (pure helper — exact=True, no SDK)
# --------------------------------------------------------------------------- #


class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeResponse:
    def __init__(self, usage: object | None) -> None:
        self.usage = usage


def test_extract_usage_exact_from_anthropic_response() -> None:
    resp = _FakeResponse(_FakeUsage(input_tokens=321, output_tokens=123))
    ev = _extract_usage(resp, model="claude-opus")
    assert ev == UsageEvent(model="claude-opus", input_tokens=321, output_tokens=123, exact=True)


def test_extract_usage_missing_usage_returns_none() -> None:
    assert _extract_usage(_FakeResponse(None), model="m") is None
    assert _extract_usage(object(), model="m") is None  # no .usage attribute at all


def test_extract_usage_clamps_negative_tokens() -> None:
    ev = _extract_usage(_FakeResponse(_FakeUsage(-5, -9)), model="m")
    assert ev is not None
    assert ev.input_tokens == 0
    assert ev.output_tokens == 0


def test_extract_usage_non_int_tokens_returns_none() -> None:
    assert _extract_usage(_FakeResponse(_FakeUsage("10", "20")), model="m") is None  # type: ignore[arg-type]


def test_llm_client_module_does_not_import_secugent_cost() -> None:
    src = Path("secugent/core/llm_client.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("secugent.cost"), alias.name
        elif isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("secugent.cost"), node.module
