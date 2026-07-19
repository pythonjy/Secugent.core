# SPDX-License-Identifier: Apache-2.0
"""S2 — LabelResolver: taint + LabelStore 실 라벨 해석 (단위 + 속성 + 결정성 100회).

INV-S2-2  라벨 단조 상한: result >= taint_ctx.current
INV-S2-3  fail-safe: LabelStore 예외 → CONFIDENTIAL (절대 PUBLIC 아님)
INV-S2-4  결정성: 동일 입력 → 동일 출력 100회
"""

from __future__ import annotations

import asyncio
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.sec.label_store import InMemoryLabelStore
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.taint import TaintContext
from secugent.core.tenancy import TenantId
from secugent.io.broker.label_resolver import LabelResolver, ResolvedLabel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TENANT = TenantId("test-tenant")
_LABELS = [DataLabel.PUBLIC, DataLabel.INTERNAL_USE, DataLabel.CONFIDENTIAL, DataLabel.SECRET]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _store(*items: tuple[str, DataLabel]) -> InMemoryLabelStore:
    """Build an InMemoryLabelStore with pre-tagged containers."""
    store = InMemoryLabelStore()
    for cid, label in items:
        _run(store.tag(_TENANT, cid, label))
    return store


# ---------------------------------------------------------------------------
# §U-1 기본 동작 — taint 없음, LabelStore 조회
# ---------------------------------------------------------------------------


def test_no_taint_public_container() -> None:
    store = _store(("doc-1", DataLabel.PUBLIC))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-1"))
    assert label == DataLabel.PUBLIC


def test_no_taint_confidential_container() -> None:
    store = _store(("doc-2", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-2"))
    assert label == DataLabel.CONFIDENTIAL


def test_no_taint_unregistered_container_returns_confidential() -> None:
    """미등록 container → InMemoryLabelStore default CONFIDENTIAL."""
    store = InMemoryLabelStore()
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="unknown-container"))
    assert label == DataLabel.CONFIDENTIAL


# ---------------------------------------------------------------------------
# §U-2 taint 상한 전파 — INV-S2-2
# ---------------------------------------------------------------------------


def test_taint_secret_overrides_public_store() -> None:
    """taint=SECRET, store=PUBLIC → result=SECRET (상한 우선)."""
    store = _store(("doc-3", DataLabel.PUBLIC))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-3", taint_ctx=ctx))
    assert label == DataLabel.SECRET


def test_taint_internal_use_overrides_public_store() -> None:
    store = _store(("doc-4", DataLabel.PUBLIC))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(DataLabel.INTERNAL_USE)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-4", taint_ctx=ctx))
    assert label >= DataLabel.INTERNAL_USE


def test_store_confidential_overrides_public_taint() -> None:
    """store=CONFIDENTIAL, taint=PUBLIC → result=CONFIDENTIAL (상한)."""
    store = _store(("doc-5", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(DataLabel.PUBLIC)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-5", taint_ctx=ctx))
    assert label == DataLabel.CONFIDENTIAL


def test_taint_and_store_same_label() -> None:
    store = _store(("doc-6", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(DataLabel.CONFIDENTIAL)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-6", taint_ctx=ctx))
    assert label == DataLabel.CONFIDENTIAL


# ---------------------------------------------------------------------------
# §U-3 fail-safe — INV-S2-3
# ---------------------------------------------------------------------------


class _BrokenStore:
    """LabelStore that always raises on get()."""

    async def tag(self, tenant_id: TenantId, container_id: str, label: DataLabel) -> None: ...

    async def get(self, tenant_id: TenantId, container_id: str) -> DataLabel:
        raise RuntimeError("backend unavailable")


def test_broken_store_returns_confidential_no_taint() -> None:
    """LabelStore 예외 → CONFIDENTIAL 폴백 (절대 PUBLIC 아님)."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="x"))
    assert label >= DataLabel.CONFIDENTIAL


def test_broken_store_with_public_taint_returns_at_least_confidential() -> None:
    """LabelStore 예외 시에도 결과 ≥ CONFIDENTIAL."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    ctx = TaintContext()
    ctx.observe_read(DataLabel.PUBLIC)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="x", taint_ctx=ctx))
    assert label >= DataLabel.CONFIDENTIAL


def test_broken_store_with_secret_taint_returns_secret() -> None:
    """LabelStore 예외, taint=SECRET → result=SECRET (상한 보존)."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    ctx = TaintContext()
    ctx.observe_read(DataLabel.SECRET)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="x", taint_ctx=ctx))
    assert label == DataLabel.SECRET


def test_never_returns_public_on_broken_store_without_taint() -> None:
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id=""))
    assert label != DataLabel.PUBLIC


# ---------------------------------------------------------------------------
# §U-4 한국어 픽스처 (§C-3 필수 — KST·한국 도메인)
# ---------------------------------------------------------------------------


def test_korean_finance_confidential_doc_external_block() -> None:
    """한국 금융 기관 기밀 문서 container가 CONFIDENTIAL 라벨을 올바르게 반환한다.

    실제 egress 차단은 broker의 may_egress 게이트에서 이루어지지만,
    LabelResolver가 CONFIDENTIAL을 반환하는 것이 차단의 전제조건이다.
    (전자금융감독규정 §C-3 픽스처)
    """
    store = InMemoryLabelStore()
    # 한국 금융 기관의 고객 정보 문서
    _run(store.tag(_TENANT, "고객_개인정보_20260623.pdf", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="고객_개인정보_20260623.pdf"))
    assert label == DataLabel.CONFIDENTIAL
    # CONFIDENTIAL > max_external(INTERNAL_USE) → egress denied
    from secugent.core.sec.effects import SinkClass
    from secugent.core.sec.labels import may_egress

    decision = may_egress(label, SinkClass.EXTERNAL, max_external=DataLabel.INTERNAL_USE)
    assert not decision.allow, "한국 금융 기밀 문서는 외부 egress가 차단되어야 한다"


def test_korean_finance_secret_doc_external_block() -> None:
    """신용정보법 대상 영업비밀 문서 → SECRET → 외부 egress 차단."""
    store = InMemoryLabelStore()
    _run(store.tag(_TENANT, "영업비밀_내부보고서_2026Q2.docx", DataLabel.SECRET))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="영업비밀_내부보고서_2026Q2.docx"))
    assert label == DataLabel.SECRET
    from secugent.core.sec.effects import SinkClass
    from secugent.core.sec.labels import may_egress

    decision = may_egress(label, SinkClass.EXTERNAL, max_external=DataLabel.INTERNAL_USE)
    assert not decision.allow, "SECRET 문서는 외부 egress가 차단되어야 한다"


# ---------------------------------------------------------------------------
# §P-1 속성 기반 테스트 — INV-S2-2 단조 상한 (hypothesis)
# ---------------------------------------------------------------------------

_label_st = st.sampled_from(_LABELS)


@given(taint_label=_label_st, store_label=_label_st)
@settings(max_examples=200)
def test_result_is_max_of_taint_and_store(taint_label: DataLabel, store_label: DataLabel) -> None:
    """result = max(taint_label, store_label) — 항상 상한 (INV-S2-2)."""
    store = _store(("prop-doc", store_label))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(taint_label)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="prop-doc", taint_ctx=ctx))
    expected = max(taint_label, store_label)
    assert label == expected


@given(store_label=_label_st)
@settings(max_examples=200)
def test_no_taint_returns_store_label(store_label: DataLabel) -> None:
    """taint 없음 → store_label 그대로 반환."""
    store = _store(("prop-doc-2", store_label))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="prop-doc-2"))
    assert label == store_label


@given(taint_label=_label_st)
@settings(max_examples=200)
def test_broken_store_result_ge_confidential_or_taint(taint_label: DataLabel) -> None:
    """LabelStore 예외 시 result >= max(CONFIDENTIAL, taint_label)."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    ctx = TaintContext()
    ctx.observe_read(taint_label)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="x", taint_ctx=ctx))
    assert label >= max(DataLabel.CONFIDENTIAL, taint_label)


# ---------------------------------------------------------------------------
# §D-1 결정성 100회 테스트 — INV-S2-4
# ---------------------------------------------------------------------------


def test_determinism_100_runs() -> None:
    """동일 입력 → 동일 출력 100회 (INV-S2-4)."""
    store = _store(("det-doc", DataLabel.INTERNAL_USE))
    resolver = LabelResolver(store)
    ctx = TaintContext()
    ctx.observe_read(DataLabel.CONFIDENTIAL)

    expected = _run(resolver.resolve(tenant_id=_TENANT, container_id="det-doc", taint_ctx=ctx))
    for _ in range(99):
        result = _run(resolver.resolve(tenant_id=_TENANT, container_id="det-doc", taint_ctx=ctx))
        assert result == expected, f"결정성 위반: run {_ + 2}, got {result}, expected {expected}"


def test_determinism_no_taint_100_runs() -> None:
    """taint 없음 + 동일 container → 100회 동일."""
    store = _store(("det-doc-2", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    expected = _run(resolver.resolve(tenant_id=_TENANT, container_id="det-doc-2"))
    for _ in range(99):
        result = _run(resolver.resolve(tenant_id=_TENANT, container_id="det-doc-2"))
        assert result == expected


def test_determinism_broken_store_100_runs() -> None:
    """LabelStore 예외 경로도 100회 동일 (CONFIDENTIAL 폴백 결정론적)."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    expected = _run(resolver.resolve(tenant_id=_TENANT, container_id="x"))
    for _ in range(99):
        result = _run(resolver.resolve(tenant_id=_TENANT, container_id="x"))
        assert result == expected


# ---------------------------------------------------------------------------
# §U-5 provenance (F3) — fail-safe 유래 라벨 식별
# ---------------------------------------------------------------------------


def test_provenance_normal_store_not_fail_safe() -> None:
    """정상 store → fail_safe False, label 은 실제 분류값."""
    store = _store(("doc-p1", DataLabel.CONFIDENTIAL))
    resolver = LabelResolver(store)
    resolved = _run(resolver.resolve_with_provenance(tenant_id=_TENANT, container_id="doc-p1"))
    assert resolved == ResolvedLabel(label=DataLabel.CONFIDENTIAL, fail_safe=False)


def test_provenance_broken_store_is_fail_safe() -> None:
    """store 예외 → fail_safe True (분류 권위 보증 불가), label ≥ CONFIDENTIAL."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    resolved = _run(resolver.resolve_with_provenance(tenant_id=_TENANT, container_id="x"))
    assert resolved.fail_safe is True
    assert resolved.label >= DataLabel.CONFIDENTIAL


def test_resolve_delegates_to_provenance_label() -> None:
    """resolve() 는 resolve_with_provenance().label 과 동일 (하위호환 위임)."""
    store = _store(("doc-p2", DataLabel.INTERNAL_USE))
    resolver = LabelResolver(store)
    label = _run(resolver.resolve(tenant_id=_TENANT, container_id="doc-p2"))
    resolved = _run(resolver.resolve_with_provenance(tenant_id=_TENANT, container_id="doc-p2"))
    assert label == resolved.label
    # And on the broken path too.
    broken = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    b_label = _run(broken.resolve(tenant_id=_TENANT, container_id="x"))
    b_resolved = _run(broken.resolve_with_provenance(tenant_id=_TENANT, container_id="x"))
    assert b_label == b_resolved.label


@given(label=st.sampled_from(_LABELS))
@settings(max_examples=50)
def test_provenance_flag_iff_store_failed(label: DataLabel) -> None:
    """속성: fail_safe 는 store 실패와 정확히 동치 (정상 store 는 절대 fail_safe 아님)."""
    ok = LabelResolver(_store(("c", label)))
    ok_resolved = _run(ok.resolve_with_provenance(tenant_id=_TENANT, container_id="c"))
    assert ok_resolved.fail_safe is False
    broken = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    broken_resolved = _run(broken.resolve_with_provenance(tenant_id=_TENANT, container_id="c"))
    assert broken_resolved.fail_safe is True


def test_determinism_provenance_broken_store_100_runs() -> None:
    """provenance 경로도 100회 동일 (fail_safe True + label 안정)."""
    resolver = LabelResolver(_BrokenStore())  # type: ignore[arg-type]
    expected = _run(resolver.resolve_with_provenance(tenant_id=_TENANT, container_id="x"))
    assert expected.fail_safe is True
    for _ in range(99):
        result = _run(resolver.resolve_with_provenance(tenant_id=_TENANT, container_id="x"))
        assert result == expected
