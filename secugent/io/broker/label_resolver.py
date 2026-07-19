# SPDX-License-Identifier: Apache-2.0
"""S2 — LabelResolver: taint + LabelStore 실 라벨 해석 (EM-02 확장).

``EgressBroker.dispatch()``가 사용하는 단일 라벨 결정 경로. 기존 하드코딩
``DataLabel.CONFIDENTIAL``을 대체해 다음 두 소스의 **상한(max)** 을 반환한다:

1. ``TaintContext.label_for_output()`` — 한 스텝에서 읽은 라벨들의 상한.
2. ``LabelStore.get(tenant_id, container_id)`` — 컨테이너별 분류.

**불변조건:**
- 라벨 단조 상한: ``result >= taint_ctx.current`` (taint가 있을 때).
- fail-safe: ``LabelStore.get()`` 예외 → ``CONFIDENTIAL`` 반환 (PUBLIC 불가).
- 결정성: 동일 입력 → 동일 출력 (100회 검증).

``LabelStore`` 미주입 시 ``default_label`` 폴백(하위호환).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from secugent.core.sec.label_store import LabelStore
from secugent.core.sec.labels import DataLabel, merge
from secugent.core.sec.taint import TaintContext
from secugent.core.tenancy import TenantId

__all__ = ["LabelResolver", "ResolvedLabel"]

_log = logging.getLogger("secugent.io.broker.label_resolver")

# Conservative fail-safe floor: any LabelStore failure returns at least this.
_FAIL_SAFE_FLOOR = DataLabel.CONFIDENTIAL


@dataclass(frozen=True, slots=True)
class ResolvedLabel:
    """A resolved egress label plus its provenance.

    ``fail_safe`` is True when the label was floored by a ``LabelStore`` failure —
    the container's classification could NOT be authoritatively determined. Such a
    label must never egress through an EXTERNAL sink regardless of the operator
    ``max_external`` ceiling (F3, enforced in :meth:`EgressBroker._run_gates`):
    "cannot classify" is not "safe to send out". ``fail_safe`` is False on the
    normal path (the label is a real classification, subject to the ceiling).
    """

    label: DataLabel
    fail_safe: bool


class LabelResolver:
    """Resolves the effective egress label for one broker dispatch call.

    Combines a ``TaintContext`` (step-scoped read history) with a persistent
    ``LabelStore`` lookup.  The result is always the **maximum** (most
    restrictive) of both sources.

    Args:
        store: A :class:`~secugent.core.sec.label_store.LabelStore` (sync or
            async) for per-container classification.  ``InMemoryLabelStore`` is
            the default; persistent backends implement the same Protocol.
        default_label: Fallback label used when neither taint nor store has a
            value (used for compatibility with callers that pass neither).
            Defaults to ``CONFIDENTIAL`` (conservative, fail-safe).
    """

    def __init__(
        self,
        store: LabelStore,
        *,
        default_label: DataLabel = DataLabel.CONFIDENTIAL,
    ) -> None:
        self._store = store
        self._default_label = default_label

    async def resolve_with_provenance(
        self,
        *,
        tenant_id: TenantId,
        container_id: str,
        taint_ctx: TaintContext | None = None,
    ) -> ResolvedLabel:
        """Return the effective egress label *and its provenance* for this dispatch.

        1. Fetch the container's registered label from the store.
        2. Merge with the taint upper-bound (if a ``TaintContext`` is supplied).
        3. On any store exception, fall back to ``max(CONFIDENTIAL, taint_label)``
           — never silently returns ``PUBLIC`` (fail-safe, INV-S2-3) — and flag the
           result ``fail_safe=True`` so the broker denies EXTERNAL egress regardless
           of the ceiling (F3, INV-D).

        The result label is the **maximum** (most restrictive) of all sources:
        ``result >= taint_ctx.current`` (INV-S2-2).

        Raises:
            Never raises — exceptions are caught and the fail-safe floor is returned.
        """
        store_ok = True
        try:
            store_label = await self._store.get(tenant_id, container_id)
        except Exception as exc:  # noqa: BLE001 - fail-safe: store error → conservative floor
            _log.warning(
                "LabelStore.get(%s, %r) failed; falling back to CONFIDENTIAL: %s",
                tenant_id,
                container_id,
                exc,
            )
            store_label = _FAIL_SAFE_FLOOR
            store_ok = False

        if taint_ctx is not None:
            taint_label = taint_ctx.label_for_output()
            result = merge(store_label, taint_label)
        else:
            result = store_label

        # INV-S2-3: fail-safe floor — a store error must never allow PUBLIC to
        # slip through (even if taint_ctx was absent or also PUBLIC).
        if not store_ok:
            result = merge(result, _FAIL_SAFE_FLOOR)

        return ResolvedLabel(label=result, fail_safe=not store_ok)

    async def resolve(
        self,
        *,
        tenant_id: TenantId,
        container_id: str,
        taint_ctx: TaintContext | None = None,
    ) -> DataLabel:
        """Backward-compatible label-only accessor (delegates to provenance path).

        Kept for callers that only need the effective label (the resolver's
        original contract, unchanged). Callers that must honour F3 provenance use
        :meth:`resolve_with_provenance`.

        Raises:
            Never raises — see :meth:`resolve_with_provenance`.
        """
        resolved = await self.resolve_with_provenance(
            tenant_id=tenant_id, container_id=container_id, taint_ctx=taint_ctx
        )
        return resolved.label
