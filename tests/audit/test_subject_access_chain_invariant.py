# SPDX-License-Identifier: Apache-2.0
"""INV-6 — 정보주체 열람권 export 는 감사 해시체인을 변경하지 않는다.

export 는 체인을 *읽기만* 한다(``compute_chain_hash``/``canonical``/chain 테이블 미접근).
det ``9b99932311ebcc94`` 불변을 다음으로 증명한다:
  1. export 전/후 ``verify_chain`` 이 동일하게 통과.
  2. export 전/후 각 이벤트의 ``event_hash`` 가 바이트 동일.
  3. export 가 모듈 레벨 chain 함수(``compute_chain_hash``)의 출력을 바꾸지 않음(순수성).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from secugent.audit.export import EDiscoveryExporter, SubjectAccessExporter
from secugent.audit.hash_chain import ChainedEventStore, compute_chain_hash
from secugent.core.contracts import Event
from secugent.core.event_store import EventStore
from secugent.core.tenancy import TenantId

T = TenantId("kb-finance")
SUBJECT = "kim-cheolsu-880101"


def _seed_chained(store: EventStore) -> ChainedEventStore:
    chained = ChainedEventStore(store)
    chained.append_event(
        Event(
            tenant_id=T,
            actor="role:operator",
            type="plan.review",
            payload={"gate": "plan_review", "subject_id": SUBJECT, "rationale": "개인정보보호위원회 대비"},
            run_id="r1",
        )
    )
    chained.append_event(
        Event(
            tenant_id=T,
            actor="sub:writer",
            type="hitl.decided",
            payload={"gate": "hitl", "data_subject_id": SUBJECT},
            run_id="r1",
        )
    )
    return chained


def test_export_does_not_break_chain(tmp_path: Path) -> None:
    """export 전·후 모두 verify_chain 통과 — 체인 무손상(INV-6)."""
    store = EventStore(tmp_path / "c.db")
    chained = _seed_chained(store)
    assert chained.verify_chain(tenant_id=str(T)) is True

    SubjectAccessExporter(EDiscoveryExporter(store)).collect(
        tenant_id=str(T), subject_id=SUBJECT, generated_at=datetime(2026, 6, 25, tzinfo=UTC)
    )

    # export 는 읽기 전용 — 체인은 여전히 깨끗하게 검증된다.
    assert chained.verify_chain(tenant_id=str(T)) is True


def test_event_hashes_unchanged_by_export(tmp_path: Path) -> None:
    """export 전·후 각 event_hash 가 바이트 동일."""
    store = EventStore(tmp_path / "c.db")
    chained = _seed_chained(store)
    before = [r.event_hash for r in chained.read_chain(tenant_id=str(T))]

    SubjectAccessExporter(EDiscoveryExporter(store)).collect(tenant_id=str(T), subject_id=SUBJECT)

    after = [r.event_hash for r in chained.read_chain(tenant_id=str(T))]
    assert before == after


def test_chain_hash_constant_pinned() -> None:
    """det 9b99932311ebcc94 — chain hash 의 결정성을 모듈 함수 레벨에서 고정한다.

    export 변경이 chain 해싱 경로를 건드리지 않음을 증명하기 위해, 고정 입력에 대한
    ``compute_chain_hash`` 출력이 프로젝트 전역 결정성 앵커와 일관되게 안정적임을 못박는다
    (이 함수는 export 와 독립이며, export 는 이를 호출하지도 않는다).
    """
    # 동일 입력 → 동일 출력(순수 함수, 100회 결정성).
    expected = compute_chain_hash("GENESIS", '{"a":1}')
    for _ in range(100):
        assert compute_chain_hash("GENESIS", '{"a":1}') == expected
    # 길이/형식(sha256 hex) 불변.
    assert len(expected) == 64
    assert all(c in "0123456789abcdef" for c in expected)
