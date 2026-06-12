# SPDX-License-Identifier: Apache-2.0
"""Property-based invariants for connector_action (deterministic, §B-4a).

The qualified-action string space is wide; these properties pin the build_effect
contract and ApprovalScope determinism across it:

  * **first-dot split** — a target that splits on its FIRST dot into two
    non-empty tokens ⇒ ``build_effect`` produces a ``CONNECTOR_ACTION`` Effect;
    any other shape ⇒ ``AmbiguousEffectError``.
  * **fingerprint determinism** — equal connector_action steps always yield an
    identical Effect fingerprint.
  * **ApprovalScope determinism** — connector_action / unknown are *always*
    rejected in ``allowed_action_types``; everything else is always accepted.
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from secugent.core.contracts import ApprovalScope, Step
from secugent.core.sec.canonicalize import AmbiguousEffectError
from secugent.core.sec.effects import EffectKind, SinkClass
from secugent.core.tenancy import TenantId
from secugent.io.broker.effect_bridge import build_effect

_PLAIN_ACTIONS = ["file_read", "file_write", "http_get", "desktop", "compute"]


def _step(target: str | None) -> Step:
    return Step(
        tenant_id=TenantId("acme"),
        run_id="r1",
        actor="sub:x",
        action_type="connector_action",
        target=target,
    )


def _splits_into_two_nonempty(token: str) -> bool:
    """True iff ``token`` partitions on its FIRST '.' into two non-empty parts —
    this is exactly the bridge's acceptance predicate."""
    head, sep, tail = token.partition(".")
    return bool(sep) and bool(head) and bool(tail)


# A token alphabet that excludes the canonical-target forbidden chars (NUL,
# backslash, all Unicode whitespace / control characters) so the property
# isolates the dot-split invariant.  Unicode whitespace categories:
#   Zs (space separators), Zl (line separators), Zp (paragraph separators).
# Control categories: Cc (ASCII + C1 controls incl. U+0085 NEL), Cf, Cs, Co, Cn.
# We also explicitly blacklist common ASCII whitespace and U+00A0 NBSP.
_token = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cc", "Cf", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"),
        blacklist_characters="\x00\\ \t\n\r\x85\xa0",
    ),
    min_size=0,
    max_size=24,
)


@settings(max_examples=300)
@given(target=_token)
def test_build_effect_first_dot_split_invariant(target: str) -> None:
    normalized = unicodedata.normalize("NFC", target.strip())
    if normalized and _splits_into_two_nonempty(normalized):
        eff = build_effect(_step(target), sandbox_roots=[])
        assert eff.kind is EffectKind.CONNECTOR_ACTION
        assert eff.sink_class is SinkClass.EXTERNAL
        assert eff.target == normalized.partition(".")[0]
        assert eff.action == normalized
    else:
        with pytest.raises(AmbiguousEffectError):
            build_effect(_step(target), sandbox_roots=[])


@settings(max_examples=200)
@given(
    connector=st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=12),
    action=st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=12),
)
def test_build_effect_fingerprint_is_deterministic(connector: str, action: str) -> None:
    target = f"{connector}.{action}"
    a = build_effect(_step(target), sandbox_roots=[])
    b = build_effect(_step(target), sandbox_roots=[])
    assert a.fingerprint() == b.fingerprint()


def _scope(actions: list[str]) -> ApprovalScope:
    return ApprovalScope(
        tenant_id=TenantId("acme"),
        run_id="r1",
        step_ids=["s1"],
        allowed_action_types=actions,  # type: ignore[arg-type]
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
    )


@settings(max_examples=200)
@given(actions=st.lists(st.sampled_from(_PLAIN_ACTIONS + ["connector_action", "unknown"]), max_size=6))
def test_approval_scope_rejects_iff_forbidden_present(actions: list[str]) -> None:
    has_forbidden = any(a in ("connector_action", "unknown") for a in actions)
    if has_forbidden:
        with pytest.raises(ValidationError):
            _scope(actions)
    else:
        scope = _scope(actions)
        assert scope.allowed_action_types == actions


# ---------------------------------------------------------------------------
# Regression: SG-FIX-01 — internal Unicode whitespace must raise
# AmbiguousEffectError, never raw ValueError.
# Before the fix these raise ValueError (from Effect.__post_init__) which
# bypasses EgressBroker's `except AmbiguousEffectError` fail-closed path.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        # NEL (U+0085) *inside* connector_name — outer .strip() does NOT remove it
        # because it is not at the boundary; this causes connector_name='0\x85'
        # which triggers ValueError in Effect.__post_init__ without the fix.
        "0\x85.0",
        # NBSP (U+00A0) *inside* connector_name
        "a\xa0.b",
        # NEL *inside* action_name (after the dot)
        "a.\x85b",
        # FORM FEED (U+000C, Cc) *inside* connector_name
        "a\x0c.b",
        # VERTICAL TAB (U+000B, Cc) *inside* connector_name
        "a\x0b.b",
    ],
)
def test_unicode_whitespace_target_raises_ambiguous_not_value_error(target: str) -> None:
    """build_effect must raise AmbiguousEffectError (not raw ValueError) for
    connector_action targets whose NFC-normalised token still contains Unicode
    whitespace or control characters after outer .strip().

    Regression for SG-FIX-01: EgressBroker's fail-closed path catches only
    AmbiguousEffectError; a raw ValueError leaked from Effect.__post_init__
    would escape the broker unhandled.
    """
    with pytest.raises(AmbiguousEffectError):
        build_effect(_step(target), sandbox_roots=[])
