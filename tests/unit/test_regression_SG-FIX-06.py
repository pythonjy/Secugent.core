# SPDX-License-Identifier: Apache-2.0
"""Regression tests for SG-FIX-06: _match_data_label deny-overrides + order independence.

Root cause: the original _match_data_label returned None (allow) on the FIRST
matching label that allowed the action, without ever inspecting later labels that
might deny the same path with higher priority (e.g. hard_block=True).

Fix invariant: for any set of matching labels, if ANY matching label denies the
action, the most-severe deny label is returned (hard_block > severity desc >
rule_id asc), regardless of the order labels appear in data_labels list.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.contracts import Step
from secugent.core.mechanical_oversight import OversightEngine, OversightResult
from secugent.core.regulations import DataLabel, Regulations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_regs(*labels: DataLabel) -> Regulations:
    return Regulations(version="sg-fix-06-test", data_labels=list(labels))


def _step_file_read(target: str) -> Step:
    return Step(
        tenant_id="legacy-default",
        run_id="r",
        actor="sub:1",
        action_type="file_read",
        target=target,
    )


# ---------------------------------------------------------------------------
# (a) permissive-broad (앞) + restrictive-narrow hard_block (뒤) 2-라벨
#     /data/secret/x 에 file_read → hard_block 위반이어야 한다.
#
#     수정 전: 앞 라벨(broad, allow file_read)에서 단락 → None(allow) FAIL
#     수정 후: 뒤 라벨(narrow, hard_block deny)이 이겨야 함
# ---------------------------------------------------------------------------

# 한국 금융·공공 맥락 픽스처: 전자금융감독규정 — 고객계좌 기밀 경로
_BROAD_LABEL = DataLabel(
    rule_id="kr-efin-broad",
    label="내부용",  # 내부 사용(internal_use) — 한국 금융공공 분류
    path_patterns=["*/data/*"],
    allowed_actions=["file_read"],  # file_read를 허용하는 넓은 라벨
    severity="low",
    hard_block=False,
    description="전자금융감독규정: 내부 데이터 경로 (읽기 허용)",
)

_NARROW_LABEL = DataLabel(
    rule_id="kr-efin-secret",
    label="기밀",  # 기밀(secret) — 한국 금융공공 최고 분류
    path_patterns=["*/data/secret/*"],
    allowed_actions=[],  # 어떤 액션도 허용하지 않음 (deny-all)
    severity="critical",
    hard_block=True,
    description="전자금융감독규정: 고객 계좌 기밀 경로 (모든 접근 차단)",
)


def test_narrow_hard_block_overrides_broad_allow_when_narrow_is_last() -> None:
    """broad(allow) 앞, narrow(hard_block deny) 뒤 → hard_block 위반 반환."""
    regs = _make_regs(_BROAD_LABEL, _NARROW_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/secret/고객계좌정보.csv"))
    assert result.allowed is False, (
        "SG-FIX-06: /data/secret/ 경로의 file_read는 hard_block deny여야 하나 "
        f"allowed={result.allowed!r} 반환됨 (deny-overrides 미적용)"
    )
    assert result.hard_block is True, f"hard_block이 True여야 하나 {result.hard_block!r} 반환됨"
    assert result.violation is not None
    assert result.violation.category == "data_label"
    assert result.violation.rule_id == "kr-efin-secret", (
        f"가장 엄격한 라벨(kr-efin-secret)이 선택돼야 하나 {result.violation.rule_id!r} 반환"
    )


def test_narrow_hard_block_overrides_broad_allow_when_narrow_is_first() -> None:
    """narrow(hard_block deny) 앞, broad(allow) 뒤 → 기존 동작과 동일하게 hard_block."""
    regs = _make_regs(_NARROW_LABEL, _BROAD_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/secret/고객계좌정보.csv"))
    assert result.allowed is False
    assert result.hard_block is True
    assert result.violation is not None
    assert result.violation.rule_id == "kr-efin-secret"


def test_only_broad_matches_non_secret_path_is_allowed() -> None:
    """좁은 라벨이 매칭되지 않는 경로는 넓은 라벨 기준으로 allow."""
    regs = _make_regs(_BROAD_LABEL, _NARROW_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/report.xlsx"))
    assert result.allowed is True, "/data/report.xlsx 는 broad(allow file_read)만 매칭 → allow여야 함"


def test_single_allow_label_still_allows() -> None:
    """단일 allow 라벨 → None(allow) — 기존 동작 불변."""
    regs = _make_regs(_BROAD_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/report.xlsx"))
    assert result.allowed is True


def test_single_deny_label_still_denies() -> None:
    """단일 deny 라벨 → 위반 — 기존 동작 불변."""
    regs = _make_regs(_NARROW_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/secret/비밀.pdf"))
    assert result.allowed is False
    assert result.hard_block is True
    assert result.violation is not None
    assert result.violation.rule_id == "kr-efin-secret"


def test_no_matching_label_is_allowed() -> None:
    """매칭 라벨 없음 → None(allow) — 기존 동작 불변."""
    regs = _make_regs(_BROAD_LABEL, _NARROW_LABEL)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/logs/access.log"))
    assert result.allowed is True


# ---------------------------------------------------------------------------
# (b) hypothesis: 라벨 순열 불변 속성 — 결정성 보장 (§B-4a)
#
#     3개 라벨(넓은-allow, 좁은-hard_block, 중간-deny-no-hard_block)을 임의 순서로
#     섞어도 동일 결정(deny, rule_id=kr-efin-secret)이 나와야 한다.
# ---------------------------------------------------------------------------

_MIDDLE_LABEL = DataLabel(
    rule_id="kr-efin-medium",
    label="대외비",  # 대외비(confidential) — 한국 분류
    path_patterns=["*/data/secret/*"],
    allowed_actions=[],
    severity="high",
    hard_block=False,  # deny이지만 hard_block 아님
    description="전자금융감독규정: 비밀 데이터 경로 (접근 제한)",
)

_THREE_LABELS = [_BROAD_LABEL, _MIDDLE_LABEL, _NARROW_LABEL]


@given(st.permutations(_THREE_LABELS))
@settings(max_examples=200)
def test_deny_overrides_order_independent_hypothesis(
    permuted_labels: list[DataLabel],
) -> None:
    """임의 순열에 대해 deny 결정과 선택 rule_id가 항상 동일해야 한다(§B-4a 결정성)."""
    regs = _make_regs(*permuted_labels)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/data/secret/고객계좌정보.csv"))

    # 세 라벨 중 두 개가 /data/secret/ 경로를 deny → 반드시 deny여야 한다
    assert result.allowed is False, (
        f"순열 {[lbl.rule_id for lbl in permuted_labels]} 에서 allow가 반환됨 (deny-overrides 미적용)"
    )
    # hard_block=True 인 kr-efin-secret이 항상 선택돼야 한다
    assert result.hard_block is True, (
        f"순열 {[lbl.rule_id for lbl in permuted_labels]} 에서 hard_block=False 반환"
    )
    assert result.violation is not None
    assert result.violation.rule_id == "kr-efin-secret", (
        f"순열 {[lbl.rule_id for lbl in permuted_labels]} 에서 "
        f"rule_id={result.violation.rule_id!r} 반환 (kr-efin-secret 이어야 함)"
    )


# ---------------------------------------------------------------------------
# (c) deny 충돌 시 총순서(hard_block > severity > rule_id) 결정성
# ---------------------------------------------------------------------------

_DENY_MEDIUM = DataLabel(
    rule_id="deny-b-medium",
    label="제한",
    path_patterns=["*/shared/비밀/*"],
    allowed_actions=[],
    severity="medium",
    hard_block=False,
)

_DENY_HIGH = DataLabel(
    rule_id="deny-a-high",
    label="제한-고",
    path_patterns=["*/shared/비밀/*"],
    allowed_actions=[],
    severity="high",
    hard_block=False,
)

_DENY_CRITICAL_HARD = DataLabel(
    rule_id="deny-c-critical",
    label="차단",
    path_patterns=["*/shared/비밀/*"],
    allowed_actions=[],
    severity="critical",
    hard_block=True,
)


@given(st.permutations([_DENY_MEDIUM, _DENY_HIGH, _DENY_CRITICAL_HARD]))
@settings(max_examples=100)
def test_total_order_hard_block_wins(permuted: list[DataLabel]) -> None:
    """hard_block=True 라벨이 hard_block=False보다 항상 우선한다."""
    regs = _make_regs(*permuted)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/shared/비밀/문서.docx"))
    assert result.hard_block is True
    assert result.violation is not None
    assert result.violation.rule_id == "deny-c-critical"


_DENY_SEVERITY_A = DataLabel(
    rule_id="deny-sev-aaa",  # rule_id 사전순 첫 번째
    label="제한A",
    path_patterns=["*/공유/기밀/*"],
    allowed_actions=[],
    severity="critical",
    hard_block=True,
)

_DENY_SEVERITY_B = DataLabel(
    rule_id="deny-sev-bbb",  # rule_id 사전순 두 번째
    label="제한B",
    path_patterns=["*/공유/기밀/*"],
    allowed_actions=[],
    severity="critical",
    hard_block=True,
)


@given(st.permutations([_DENY_SEVERITY_A, _DENY_SEVERITY_B]))
@settings(max_examples=10)
def test_total_order_rule_id_tiebreak(permuted: list[DataLabel]) -> None:
    """hard_block, severity 동률이면 rule_id 사전순 첫 번째가 선택된다."""
    regs = _make_regs(*permuted)
    engine = OversightEngine(regs)
    result = engine.evaluate(_step_file_read("/공유/기밀/설계서.pdf"))
    assert result.violation is not None
    assert result.violation.rule_id == "deny-sev-aaa", (
        f"rule_id 사전순 tiebreak 실패: {result.violation.rule_id!r}"
    )


# ---------------------------------------------------------------------------
# (d) 결정성 100회 — 동일 입력 100회 호출 → 동일 출력 (§B-4a)
# ---------------------------------------------------------------------------


def test_determinism_100_iterations() -> None:
    """동일 Regulations + Step으로 100회 평가 → 항상 동일 OversightResult."""
    regs = _make_regs(_BROAD_LABEL, _MIDDLE_LABEL, _NARROW_LABEL)
    engine = OversightEngine(regs)
    step = _step_file_read("/data/secret/고객계좌정보.csv")

    first: OversightResult = engine.evaluate(step)
    for i in range(99):
        result = engine.evaluate(step)
        assert result.allowed == first.allowed, f"iter {i + 2}: allowed 불일치"
        assert result.hard_block == first.hard_block, f"iter {i + 2}: hard_block 불일치"
        assert result.violation is not None and first.violation is not None
        assert result.violation.rule_id == first.violation.rule_id, (
            f"iter {i + 2}: rule_id 불일치 {result.violation.rule_id!r} != {first.violation.rule_id!r}"
        )
        assert result.violation.severity == first.violation.severity, f"iter {i + 2}: severity 불일치"
