# SPDX-License-Identifier: Apache-2.0
"""Strengthen-only ``data_labels`` merge (deterministic, §B-4a).

Triple harness part 1/2: unit (all branches) + scenario regression + 100×
determinism. Property-based invariants live in
``tests/property/test_label_merge_props.py``.

The tenant override merge for ``data_labels`` must mirror the existing
``banned_paths``/``banned_commands``/``connector_policies`` strengthen-only
guards: a tenant may *raise* severity, *add* ``hard_block``, *add* new labels,
and *narrow* ``allowed_actions`` — but never *downgrade* severity, *remove*
``hard_block``, or *widen* ``allowed_actions`` (which loosens the allowlist that
``mechanical_oversight._match_data_label`` consumes). Any relaxation raises
:class:`RegulationsSchemaError` (fail-closed).

Korean enterprise fixture (§C-3): 전자금융감독규정 critical+hard_block 라벨을
테넌트가 완화하려는 시도 → 거부.
"""

from __future__ import annotations

import pytest

from secugent.core.contracts import ActionType
from secugent.core.regulations import DataLabel, Regulations
from secugent.regulations.tenant_loader import (
    RegulationsLoader,
    RegulationsSchemaError,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _label(
    rule_id: str,
    *,
    label: str = "lbl",
    severity: str = "medium",
    hard_block: bool = False,
    allowed_actions: list[ActionType] | None = None,
    path_patterns: list[str] | None = None,
) -> DataLabel:
    return DataLabel(
        rule_id=rule_id,
        label=label,
        severity=severity,  # type: ignore[arg-type]  # narrowed to Severity by validator
        hard_block=hard_block,
        allowed_actions=allowed_actions or [],
        # Distinguish "not provided" (default scope) from an explicit empty list
        # so path_patterns edge cases are expressible.
        path_patterns=["*/x/*"] if path_patterns is None else path_patterns,
    )


def _merge(base: list[DataLabel], override: list[DataLabel]) -> list[DataLabel]:
    return RegulationsLoader._merge_data_labels(base, override)


# --------------------------------------------------------------------------- #
# severity axis
# --------------------------------------------------------------------------- #


def test_severity_equal_allowed() -> None:
    merged = _merge([_label("r", severity="high")], [_label("r", severity="high")])
    assert {m.rule_id: m.severity for m in merged} == {"r": "high"}


def test_severity_upgrade_allowed() -> None:
    merged = _merge([_label("r", severity="medium")], [_label("r", severity="critical")])
    assert merged[0].severity == "critical"


def test_severity_downgrade_rejected() -> None:
    with pytest.raises(RegulationsSchemaError, match="severity"):
        _merge([_label("r", severity="critical")], [_label("r", severity="low")])


# --------------------------------------------------------------------------- #
# hard_block axis
# --------------------------------------------------------------------------- #


def test_hard_block_preserved_when_override_keeps_it() -> None:
    merged = _merge([_label("r", hard_block=True)], [_label("r", hard_block=True)])
    assert merged[0].hard_block is True


def test_hard_block_add_allowed() -> None:
    merged = _merge([_label("r", hard_block=False)], [_label("r", hard_block=True)])
    assert merged[0].hard_block is True


def test_hard_block_removal_rejected() -> None:
    with pytest.raises(RegulationsSchemaError, match="hard_block"):
        _merge([_label("r", hard_block=True)], [_label("r", hard_block=False)])


# --------------------------------------------------------------------------- #
# allowed_actions axis (widening = loosening allowlist → rejected)
# --------------------------------------------------------------------------- #


def test_allowed_actions_narrowing_allowed() -> None:
    # base allows {read, write}; override allows only {read} → stricter → OK.
    merged = _merge(
        [_label("r", allowed_actions=["file_read", "file_write"])],
        [_label("r", allowed_actions=["file_read"])],
    )
    assert merged[0].allowed_actions == ["file_read"]


def test_allowed_actions_equal_allowed() -> None:
    merged = _merge(
        [_label("r", allowed_actions=["file_read"])],
        [_label("r", allowed_actions=["file_read"])],
    )
    assert merged[0].allowed_actions == ["file_read"]


def test_allowed_actions_widening_rejected() -> None:
    # base allows only {read}; override adds {write} → more permissive → rejected.
    with pytest.raises(RegulationsSchemaError, match="allowed_actions"):
        _merge(
            [_label("r", allowed_actions=["file_read"])],
            [_label("r", allowed_actions=["file_read", "file_write"])],
        )


def test_allowed_actions_empty_base_to_nonempty_rejected() -> None:
    # Empty allowed_actions = strictest (every action violates per
    # _match_data_label). Adding any action loosens → rejected.
    with pytest.raises(RegulationsSchemaError, match="allowed_actions"):
        _merge(
            [_label("r", allowed_actions=[])],
            [_label("r", allowed_actions=["file_read"])],
        )


def test_allowed_actions_nonempty_base_to_empty_allowed() -> None:
    # Going to empty (strictest) is a strengthening → allowed.
    merged = _merge(
        [_label("r", allowed_actions=["file_read"])],
        [_label("r", allowed_actions=[])],
    )
    assert merged[0].allowed_actions == []


# --------------------------------------------------------------------------- #
# path_patterns axis (removing a pattern = narrowing protected scope → rejected)
#
# ``mechanical_oversight._match_data_label`` raises a violation
# only when one of ``label.path_patterns`` matches the normalised path. More
# patterns ⇒ MORE paths matched ⇒ MORE protection. Dropping a pattern is a
# silent deny-by-default relaxation, so the override's path_patterns must be a
# SUPERSET of base's.
# --------------------------------------------------------------------------- #


def test_path_patterns_removal_rejected() -> None:
    # base protects two path families; override drops one → narrowing → rejected.
    with pytest.raises(RegulationsSchemaError, match="path_patterns"):
        _merge(
            [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*"])],
            [_label("r", path_patterns=["*/대외비/*"])],
        )


def test_path_patterns_addition_allowed() -> None:
    # Adding a pattern widens coverage = strengthens → allowed.
    merged = _merge(
        [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*"])],
        [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*", "*/secret/*"])],
    )
    assert set(merged[0].path_patterns) == {"*/대외비/*", "*/internal-only/*", "*/secret/*"}


def test_path_patterns_equal_allowed() -> None:
    merged = _merge(
        [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*"])],
        [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*"])],
    )
    assert merged[0].path_patterns == ["*/대외비/*", "*/internal-only/*"]


def test_path_patterns_reorder_allowed() -> None:
    # Same set, different order → still a superset → allowed (order/dup ignored).
    merged = _merge(
        [_label("r", path_patterns=["*/대외비/*", "*/internal-only/*"])],
        [_label("r", path_patterns=["*/internal-only/*", "*/대외비/*"])],
    )
    assert set(merged[0].path_patterns) == {"*/대외비/*", "*/internal-only/*"}


def test_path_patterns_empty_base_to_nonempty_allowed() -> None:
    # Empty base = no protected scope; adding patterns can only strengthen.
    merged = _merge(
        [_label("r", path_patterns=[])],
        [_label("r", path_patterns=["*/대외비/*"])],
    )
    assert merged[0].path_patterns == ["*/대외비/*"]


def test_path_patterns_nonempty_base_to_empty_rejected() -> None:
    # Dropping ALL patterns removes the entire protected scope → rejected.
    with pytest.raises(RegulationsSchemaError, match="path_patterns"):
        _merge(
            [_label("r", path_patterns=["*/대외비/*"])],
            [_label("r", path_patterns=[])],
        )


def test_path_patterns_removed_listed_in_base_order() -> None:
    # Determinism: the removed-pattern report is sorted by base order.
    with pytest.raises(RegulationsSchemaError) as exc:
        _merge(
            [_label("r", path_patterns=["*/a/*", "*/b/*", "*/c/*"])],
            [_label("r", path_patterns=["*/b/*"])],  # drops a and c
        )
    # base order: a precedes c.
    assert "'*/a/*'" in str(exc.value)
    assert str(exc.value).index("'*/a/*'") < str(exc.value).index("'*/c/*'")


# --------------------------------------------------------------------------- #
# structural / edge cases
# --------------------------------------------------------------------------- #


def test_empty_base_keeps_override_new_labels() -> None:
    merged = _merge([], [_label("a"), _label("b")])
    assert [m.rule_id for m in merged] == ["a", "b"]


def test_empty_override_keeps_base() -> None:
    merged = _merge([_label("a"), _label("b")], [])
    assert [m.rule_id for m in merged] == ["a", "b"]


def test_new_rule_id_appended_after_base_order() -> None:
    merged = _merge([_label("a"), _label("b")], [_label("c"), _label("a", severity="high")])
    # base order preserved (a, b), genuinely-new override labels appended (c).
    assert [m.rule_id for m in merged] == ["a", "b", "c"]
    assert {m.rule_id: m.severity for m in merged}["a"] == "high"  # in-place strengthen


def test_both_empty() -> None:
    assert _merge([], []) == []


def test_deterministic_order_with_many_labels() -> None:
    base = [_label(f"r{i}") for i in range(50)]
    override = [_label(f"r{i}", severity="high") for i in range(0, 50, 2)] + [
        _label(f"new{i}") for i in range(10)
    ]
    merged = _merge(base, override)
    expected = [f"r{i}" for i in range(50)] + [f"new{i}" for i in range(10)]
    assert [m.rule_id for m in merged] == expected


# --------------------------------------------------------------------------- #
# Scenario regression — Korean 전자금융감독규정 (§C-3)
# --------------------------------------------------------------------------- #


def test_korean_efs_critical_hardblock_relaxation_rejected() -> None:
    """전자금융감독규정: 고객 금융정보(critical, hard_block) 라벨을 테넌트가
    severity를 medium으로, hard_block을 해제하려는 시도 → 거부."""
    base = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="critical",
            hard_block=True,
            allowed_actions=["file_read"],
            path_patterns=["*/고객정보/*", "*/financial/*"],
        )
    ]
    relax_override = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="medium",  # downgrade
            hard_block=False,  # remove hard_block
            allowed_actions=["file_read", "file_write", "connector_action"],  # widen
            path_patterns=["*/고객정보/*"],  # drops */financial/* → narrows scope
        )
    ]
    with pytest.raises(RegulationsSchemaError):
        _merge(base, relax_override)


def test_korean_efs_path_pattern_drop_only_rejected() -> None:
    """전자금융감독규정: 다른 모든 축(severity/hard_block/allowed_actions)을 동일하게
    유지한 채 path_patterns에서 보호 경로 하나만 제거하는 테넌트 override → 거부.

    핵심 회귀: 3축이 동일하면 가드를 통과하던 무검출 완화."""
    base = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="critical",
            hard_block=True,
            allowed_actions=["file_read"],
            path_patterns=["*/고객정보/*", "*/financial/*"],
        )
    ]
    drop_path_only = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="critical",  # unchanged
            hard_block=True,  # unchanged
            allowed_actions=["file_read"],  # unchanged
            path_patterns=["*/고객정보/*"],  # only difference: drops */financial/*
        )
    ]
    with pytest.raises(RegulationsSchemaError, match="path_patterns"):
        _merge(base, drop_path_only)


def test_korean_efs_strengthen_accepted() -> None:
    """동일 전자금융감독규정 라벨을 더 강하게(이미 critical 유지 + hard_block 유지
    + allowed_actions 축소) 만드는 테넌트 override는 허용."""
    base = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="high",
            hard_block=False,
            allowed_actions=["file_read", "file_write"],
            path_patterns=["*/고객정보/*"],
        )
    ]
    strengthen = [
        _label(
            "efs-customer-financial",
            label="고객금융정보",
            severity="critical",  # upgrade
            hard_block=True,  # add hard_block
            allowed_actions=["file_read"],  # narrow
            path_patterns=["*/고객정보/*"],
        )
    ]
    merged = _merge(base, strengthen)
    assert merged[0].severity == "critical"
    assert merged[0].hard_block is True
    assert merged[0].allowed_actions == ["file_read"]


# --------------------------------------------------------------------------- #
# determinism — 100 runs (identical input → identical output incl. order)
# --------------------------------------------------------------------------- #


def test_merge_data_labels_determinism_100_runs() -> None:
    base = [
        _label("a", severity="medium", hard_block=False, allowed_actions=["file_read", "file_write"]),
        _label("b", severity="high", hard_block=True),
        _label("c", severity="low"),
    ]
    override = [
        _label("a", severity="critical", hard_block=True, allowed_actions=["file_read"]),
        _label("d", severity="medium"),  # new
    ]
    expected = _merge(base, override)
    expected_repr = [(m.rule_id, m.severity, m.hard_block, tuple(m.allowed_actions)) for m in expected]
    for _ in range(100):
        got = _merge(base, override)
        got_repr = [(m.rule_id, m.severity, m.hard_block, tuple(m.allowed_actions)) for m in got]
        assert got_repr == expected_repr


# --------------------------------------------------------------------------- #
# end-to-end through the loader (_merge wiring)
# --------------------------------------------------------------------------- #


def test_loader_merge_routes_through_data_labels_guard() -> None:
    base = Regulations(
        version="1",
        data_labels=[_label("r", severity="critical", hard_block=True, allowed_actions=["file_read"])],
    )
    override = Regulations(
        version="o",
        data_labels=[_label("r", severity="low", hard_block=False)],  # relaxation
    )
    with pytest.raises(RegulationsSchemaError):
        RegulationsLoader._merge(base, override)


# --------------------------------------------------------------------------- #
# end-to-end through the real OversightEngine — BLOCK must stay BLOCK
#
# The reviewer proved that dropping a path_patterns entry flips
# /srv/internal-only/secret.txt from allowed=False(hard_block) → allowed=True.
# With the superset guard the merge now raises, so the BLOCK→ALLOW hole closes.
# --------------------------------------------------------------------------- #


def test_e2e_path_pattern_drop_rejected_keeps_oversight_block() -> None:
    from secugent.core.contracts import Step
    from secugent.core.mechanical_oversight import OversightEngine
    from secugent.core.tenancy import TenantId

    base = [
        _label(
            "label-confidential",
            label="confidential",
            severity="high",
            hard_block=True,
            allowed_actions=["file_read"],
            path_patterns=["*/대외비/*", "*/internal-only/*"],
        )
    ]
    # override keeps rule_id/severity/hard_block/allowed_actions identical and
    # only drops '*/internal-only/*' — the exact reviewer relaxation.
    drop_override = [
        _label(
            "label-confidential",
            label="confidential",
            severity="high",
            hard_block=True,
            allowed_actions=["file_read"],
            path_patterns=["*/대외비/*"],
        )
    ]

    step = Step(
        tenant_id=TenantId("acme"),
        run_id="r-e2e",
        actor="sub:worker",
        action_type="file_write",
        target="/srv/internal-only/secret.txt",
    )

    # Sanity: base still BLOCKs the write (hard_block, action not in allowlist).
    base_result = OversightEngine(Regulations(version="b", data_labels=base)).evaluate(step)
    assert base_result.allowed is False

    # The merge that would have produced an ALLOW now fails closed.
    with pytest.raises(RegulationsSchemaError, match="path_patterns"):
        _merge(base, drop_override)
