# SecuGent 신뢰 증언 (Trust Attestation) — `secugent-core` v0.1.0

> **영업·도입 검토자용 1페이지 요약.** SecuGent의 신뢰 주장은 마케팅 수사가 아니라
> **고객이 직접 재현 가능한 측정값**으로만 뒷받침됩니다. 아래 모든 수치는 이 저장소의
> 실제 코드·테스트에서 측정되었으며, 측정되지 않은 능력은 "로드맵"으로 명시 분리합니다.
>
> 작성: 2026-06-16 KST · 대상: 보안·구매 의사결정자
> 기술 재현 절차 전문(외부 감사자용)은 [`TRUST_PROOF.md`](TRUST_PROOF.md) 참조 — 이 문서는 그 요약이며 내용을 중복하지 않습니다.

---

## 1. 결정적 통제 모듈 — "같은 입력 → 항상 같은 결정"

SecuGent의 정책 게이트(Rule of Two · Mechanical Oversight · 승인 경로)는 **확률이 아니라
결정성**으로 위험을 차단합니다. 동일 입력을 **100회** 실행해 결과가 단 1개의 해시로 수렴함을
증명합니다.

```
verify: determinism OK - 100 runs identical (digest 9b99792311ebcc94)   (exit 0)
```

**공개 코어(secugent-core v0.1.0)에서 측정된 라인 커버리지:**

| 모듈 | 역할 | 커버리지 |
|------|------|---------:|
| `secugent/core/regulations.py` | REGULATIONS 정책 엔진 (Rule of Two) | **100%** |
| `secugent/core/rule_of_two.py` | Rule of Two 축 평가 | **100%** |
| `secugent/core/mechanical_oversight.py` | 기계적 감독 (Deny-by-default HARD BLOCK) | **99%** |
| `secugent/core/approval.py` | Plan Review / HITL 승인 경로 | **99%** |
| `secugent/audit/hash_chain.py` | 감사 해시체인 무결성 (위변조 탐지) | **100%** |
| `secugent/audit/merkle.py` | 일일 Merkle 루트 (RFC 6962 도메인 분리) | **97%** |

**정직한 공개(over-claim 방지):** 위 수치는 **공개 코어에 동봉된 테스트만**으로 측정한
값입니다. 결정적 통제 모듈 6종 모두 라인 커버리지 **≥95%**(정책 엔진 4종은
**99–100%**)이며, 여기에는 감사 해시체인·Merkle 루트의 **위변조 경로(tamper-path)
회귀 테스트가 공개 코어에 동봉되어** 포함됩니다(`hash_chain.py` 100%, `merkle.py` 97%).
다만 100%로 측정된 모듈을 제외하면, 일부 모듈(`mechanical_oversight.py`·`approval.py`
99%, `merkle.py` 97%)에는 미커버 라인이 남아 있으므로, 본 문서는 "결정적 모듈 커버리지
일괄 100%"를 주장하지 **않습니다** — 측정된 값 그대로만 공개합니다.

## 2. append-only 해시체인 감사로그 — "지우거나 고치면 즉시 들통난다"

모든 결정 게이트는 SHA-256 해시체인 감사로그(`secugent/audit/hash_chain.py`)에 **추가
전용(append-only)**으로 기록됩니다. 각 이벤트는 직전 이벤트 해시를 입력으로 삼아
연결되므로(`event_hash = sha256(prev_hash ‖ canonical(event))`), 과거 행을 한 바이트라도
수정·삭제하면 이후 모든 링크가 어긋나 `verify_chain()`이 즉시 차단합니다. 일일 무결성은
Merkle 루트(`secugent/audit/merkle.py`)로 봉인합니다. 설계상 6개월+ 보존을 전제로 합니다
(EU AI Act Art.12/Art.17 호환 스키마).

**무키(API 키 없이) 재현되는 증거** — `secugent demo` 한 줄 실행 결과:

```
[plan_review] reject by sec:mechanical-oversight  (event_id=evt-0, prev=None,   ...)
[hitl]        approve by human:demo-operator      (event_id=evt-1, prev=evt-0,  ...)
```

체인 제네시스(`prev=None`)에서 다음 이벤트가 `prev=evt-0`으로 연결되는 것이 곧
위변조 검출의 토대입니다. HARD BLOCK 1건 + HITL 승인 1건이 **2개의 연결된 감사
이벤트**로 남습니다.

## 3. STEER 실시간 중도개입 — 전달된 것과 로드맵의 구분

공개 코어(`secugent/steer/`)가 **실제로 제공하는 것**은 다음과 같습니다.

- **세션 제약 주입(`add_constraint`)**: 실행 중 자연어 지시를 구조화 규칙으로 변환해
  살아있는 `OversightEngine`에 부착합니다. **분류기는 절대 기존 규칙을 완화하지 않으며
  제약만 추가**합니다(fail-closed). 디스크의 REGULATIONS는 건드리지 않습니다.
- **목표 패치 / 롤백 요청(`patch_goal` · `rollback_step`)**: 다음 패스에서 소비되도록
  내구성 이벤트로 기록됩니다.
- **스냅샷·되돌리기 프리미티브(`snapshots.py`)**: 되돌릴 수 있는(reversible) 파일 효과에
  한해 사전 스냅샷 후 복원. 비가역 효과는 **사후 undo가 아니라 사전 회수(pre-commit
  recall)**로만 처리한다는 정직한 범위를 코드 주석으로 명시합니다.
- **해시체인 통합 + Rule of Two**: STEER가 발생시키는 모든 이벤트
  (`steer.received → steer.classified → … → steer.resumed`)는 위 §2의 해시체인에
  편입됩니다.

**로드맵(이 버전에서 미전달):** WebSocket 기반 **실시간 일시정지 → 컨텍스트 스냅샷 →
무손실 재개**의 라이브 인터럽트 종단 배선은 공개 코어 v0.1.0에 완전히 포함되어 있지
**않습니다**. 위 핸들러·프리미티브는 그 토대이며, 라이브 트랜스포트 배선은 후속
릴리스 항목입니다.

---

## 검증 방법 (고객 직접 재현)

API 키·네트워크 없이 로컬에서 그대로 재현됩니다.

```bash
# 1) 결정성 증명 (100회 동일, digest 9b99792311ebcc94)
python -m secugent.cli verify --determinism --fixture tests/cli/fixtures/determinism_seed.json

# 2) 무키 데모 (HARD BLOCK + HITL 승인 + append-only 해시체인 2건)
python -m secugent.cli demo

# 3) 결정적 통제 모듈 커버리지 재측정
python -m pytest --cov=secugent.core.regulations --cov=secugent.core.rule_of_two \
  --cov=secugent.core.mechanical_oversight --cov=secugent.core.approval \
  --cov=secugent.audit.hash_chain --cov=secugent.audit.merkle \
  --cov-report=term-missing tests/

# 4) 공개 릴리스 게이트 (fail-closed: 비공개 import·금칙 콘텐츠 차단)
python scripts/check_public_release.py
```

전체 재현 절차·CI 워크플로·Merkle/해시체인 내부 동작은 [`TRUST_PROOF.md`](TRUST_PROOF.md)에 있습니다.

---

*모든 수치는 secugent-core v0.1.0에서 측정된 값입니다. 측정되지 않은 주장은 포함하지 않습니다.*
