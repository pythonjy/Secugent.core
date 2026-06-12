# SPDX-License-Identifier: Apache-2.0
"""EM-01 — reversibility classification unit tests (deterministic).

Covers EM-01 §5 tests 9-11 + fail-closed default + determinism.
"""

from __future__ import annotations

import logging

import pytest

from secugent.core.sec.reversibility import (
    ActionManifest,
    ManifestRegistry,
    ReversibilityClass,
)


def test_class_values() -> None:
    assert ReversibilityClass.REVERSIBLE == "reversible"
    assert ReversibilityClass.COMPENSATABLE == "compensatable"
    assert ReversibilityClass.IRREVERSIBLE == "irreversible"


# --------------------------------------------------------------------------- #
# fail-closed default (test 9)
# --------------------------------------------------------------------------- #


def test_unregistered_action_is_irreversible(caplog: pytest.LogCaptureFixture) -> None:
    reg = ManifestRegistry()
    with caplog.at_level(logging.WARNING):
        result = reg.classify("smtp.send_external")
    assert result is ReversibilityClass.IRREVERSIBLE
    assert any("smtp.send_external" in r.getMessage() for r in caplog.records)


def test_classify_deterministic_100x() -> None:
    reg = ManifestRegistry()
    reg.register(ActionManifest("fs.write", ReversibilityClass.REVERSIBLE))
    seen = {reg.classify("fs.write") for _ in range(100)}
    seen_unreg = {reg.classify("nope.unregistered") for _ in range(100)}
    assert seen == {ReversibilityClass.REVERSIBLE}
    assert seen_unreg == {ReversibilityClass.IRREVERSIBLE}


# --------------------------------------------------------------------------- #
# COMPENSATABLE requires compensating_action (test 10)
# --------------------------------------------------------------------------- #


def test_compensatable_requires_compensating_action() -> None:
    with pytest.raises(ValueError):
        ManifestRegistry().register(ActionManifest("slack.post_message", ReversibilityClass.COMPENSATABLE))


def test_compensatable_with_compensating_action_ok() -> None:
    reg = ManifestRegistry()
    reg.register(
        ActionManifest(
            "slack.post_message",
            ReversibilityClass.COMPENSATABLE,
            compensating_action="slack.delete_message",
        )
    )
    assert reg.classify("slack.post_message") is ReversibilityClass.COMPENSATABLE


def test_compensating_action_only_for_compensatable() -> None:
    with pytest.raises(ValueError):
        ActionManifest("fs.write", ReversibilityClass.REVERSIBLE, compensating_action="x")


def test_empty_action_rejected() -> None:
    with pytest.raises(ValueError):
        ActionManifest("  ", ReversibilityClass.IRREVERSIBLE)


# --------------------------------------------------------------------------- #
# register/classify roundtrip (test 11)
# --------------------------------------------------------------------------- #


def test_register_classify_roundtrip() -> None:
    reg = ManifestRegistry()
    reg.register(ActionManifest("smtp.send", ReversibilityClass.IRREVERSIBLE))
    reg.register(ActionManifest("fs.write", ReversibilityClass.REVERSIBLE))
    assert reg.classify("smtp.send") is ReversibilityClass.IRREVERSIBLE
    assert reg.classify("fs.write") is ReversibilityClass.REVERSIBLE


def test_register_override_last_wins() -> None:
    reg = ManifestRegistry()
    reg.register(ActionManifest("x.do", ReversibilityClass.REVERSIBLE))
    reg.register(ActionManifest("x.do", ReversibilityClass.IRREVERSIBLE))
    assert reg.classify("x.do") is ReversibilityClass.IRREVERSIBLE


def test_manifest_for_returns_full_manifest() -> None:
    reg = ManifestRegistry()
    m = ActionManifest("slack.post", ReversibilityClass.COMPENSATABLE, compensating_action="slack.del")
    reg.register(m)
    assert reg.manifest_for("slack.post") == m
    assert reg.manifest_for("absent") is None
