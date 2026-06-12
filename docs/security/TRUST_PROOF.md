# SecuGent 신뢰 증명 (Trust Proof) — v0.1.0

> 이 문서는 SecuGent의 첫 번째 공개 릴리스(`secugent-core v0.1.0`)를 위한
> **외부 재현 가능 신뢰 증명** 절차 및 근거 문서다.
> 영업·파트너십·독립 보안 감사를 위한 1차 신뢰 아티팩트(BDP_05 항목 4).
>
> 작성: 2026-06-10 KST | 대상 독자: 보안 검토자·감사자·통합 파트너

---

## 1. 신뢰 증명이란 무엇인가

SecuGent는 "에이전트를 통제하는 신뢰 레이어(Trust & Control Plane)"를 표방한다.
그 주장을 자체 진술(self-assertion)이 아니라 **외부에서 독립 재현 가능한 두 가지 수학적 증명**으로 뒷받침한다.

| 증명 | 질문 | 방법 |
|------|------|------|
| **결정성 증명** (Determinism Proof) | "같은 입력에 항상 같은 결정을 내리는가?" | 동일 fixture를 100회 실행 → 해시가 1개 (I2) |
| **감사 해시체인 증명** (Audit Chain Proof) | "감사 로그가 위변조 없이 온전한가?" | SHA-256 해시체인 링크를 처음부터 끝까지 독립 재계산 (I3) |

두 증명 모두 **API 키·네트워크 없이** 로컬 또는 CI에서 재현된다 (Invariant I1: 무키 재현).

---

## 2. 전제 조건

```bash
# Python 3.11 이상 필요
python -m pip install .          # 또는 pip install -e ".[dev]" (개발 환경)
```

환경 변수 불필요. `ANTHROPIC_API_KEY` 를 명시적으로 빈 값으로 두어도 동작한다.

```bash
export ANTHROPIC_API_KEY=""      # 선택 사항 — 없어도 Mock 모드로 동작
```

---

## 3. 신뢰 증명 한 줄 재현

```bash
secugent verify --determinism --fixture tests/cli/fixtures/determinism_seed.json
```

### 기대 출력 (성공 시)

```
verify: determinism OK - 100 runs identical (digest <16자리 16진수>)
```

- exit code `0` = 성공 (모든 100회 실행이 바이트-동일).
- exit code `1` = 실패 (결정성 위반; 메시지에 불일치 회차·해시 포함).
- exit code `2` = 입력 오류 (fixture 경로 없음 등).

---

## 4. 결정성 증명 상세 절차

### 4.1 작동 원리

```
[seed fixture JSON]
       │
       ▼
┌─────────────────────────────────────────────┐
│  classify_axes()  +  OversightEngine.evaluate()  │  ← 결정적 코어
└─────────────────────────────────────────────┘
       │   100회 반복
       ▼
canonical_output = json.dumps(decisions, sort_keys=True, separators=(",",":"))
       │
       ▼
 sha256(canonical_output)  →  digest
```

`secugent verify --determinism` 은 `secugent/cli/verify.py::verify_determinism()` 을
호출한다. 이 함수는:

1. fixture JSON 을 읽어 `regulations` + `steps` 를 파싱한다.
2. `load_regulations_from_dict()` 로 정책 객체를 생성한다 (결정적 로더).
3. 각 step에 대해 `classify_axes()` + `OversightEngine.evaluate()` 를 실행한다.
4. 결과를 `json.dumps(sort_keys=True, separators=(",",":"))` 로 정규화한다.
5. 위 1–4를 `samples` 회(기본 100회) 반복하고, 출력이 모두 동일한지 확인한다.
6. `DeterminismReport` 를 반환한다: `ok=True` iff `distinct_outputs == 1`.

**Invariant I2**: 100회 중 단 1회라도 해시가 다르면 `ok=False` + 불일치 회차·해시를 출력하고 exit 1.

### 4.2 CI 재현 (두 독립 프로세스 바이트-동일 검증)

GitHub Actions `.github/workflows/determinism.yml` 의 `determinism` job은:

1. `Determinism run #1` — 독립 Python 프로세스에서 100회 실행 → `run1.json`.
2. `Determinism run #2` — 동일하게 100회 → `run2.json`.
3. `Assert byte-identical across runs` — `diff run1.json run2.json` + `assert r1 == r2`.

두 실행 결과가 바이트-동일하면 **결정성이 외부적으로 재현**된다.

---

## 5. 감사 해시체인 증명 상세 절차

### 5.1 작동 원리

```
[감사 SQLite store]
       │
       ▼
 event_chain 테이블: (seq, prev_hash, event_hash, body_canonical)
       │
       ▼
┌──────────────────────────────────────────────────────┐
│  verify_audit_chain() — 읽기 전용(mode=ro URI)        │
│  ① prev_hash 링크 재확인                              │
│  ② event_hash = sha256(prev_hash || body_canonical)  │
│     재계산·대조                                       │
│  ③ body_canonical ↔ events 테이블 실제 페이로드 교차  │
│     검증                                              │
└──────────────────────────────────────────────────────┘
       │
       ▼
  ChainReport { ok, events_checked, first_violation }
```

**Invariant I1 (읽기 전용)**: store는 `mode=ro` URI 플래그로 열린다. 테이블 생성, 마이그레이션, 단 1바이트의 쓰기도 발생하지 않는다.

**Invariant I3 (fail-closed)**: 첫 번째 불일치를 발견하면 즉시 `ok=False` + 위치(seq) 보고. 조용한 통과(silent pass)는 없다.

### 5.2 실행 예시

```bash
# 1단계: 감사 store 생성 (데모 round)
secugent demo          # 임시 디렉토리에 append-only store 생성 후 정리

# 실제 store가 있다면:
secugent verify --chain --tenant <테넌트ID> --store <경로/events.db>
```

### 5.3 기대 출력 (성공 시)

```
verify: chain OK - <N> events link cleanly for tenant '<테넌트ID>'
```

빈 체인 (이벤트 0건) — 공집합도 유효한 intact 상태:

```
verify: chain OK but EMPTY - tenant '<테넌트ID>' has 0 events (vacuously intact)
```

실패 예:

```
verify: chain FAILED for tenant '<테넌트ID>' - event_hash mismatch at seq=3 — chain record tampered
```

---

## 6. 해시체인 / 머클 트리 구조 설명

### 6.1 append-only 해시체인

`secugent/audit/hash_chain.py` 의 `ChainedEventStore` 는 모든 감사 이벤트를 다음 방식으로 기록한다.

```
GENESIS = sha256("secugent:chain:genesis")   ← 고정 초기값

event_hash[0] = sha256( GENESIS         || canonical(event[0]) )
event_hash[1] = sha256( event_hash[0]   || canonical(event[1]) )
event_hash[2] = sha256( event_hash[1]   || canonical(event[2]) )
        ...
```

- `canonical()` 은 이벤트를 JSON-정규화(sort_keys, separators)하여 바이트-결정적 문자열로 변환한다.
- 각 체인 행(chain row)은 `(seq, prev_hash, event_hash, body_canonical)` 을 저장한다.
- append-only: SQLite `INSERT` 만 사용하며 기존 행은 절대 `UPDATE` 되지 않는다.

이 구조에서 체인의 임의 행을 수정하면 그 이후 모든 `event_hash` 가 불일치하므로 `verify_audit_chain()` 이 즉시 탐지한다.

### 6.2 SBOM (소프트웨어 자재 명세서)

`scripts/gen_sbom.py` 는 CycloneDX 1.5 JSON 형식의 SBOM을 생성한다.
타임스탬프 없이 생성하면 **바이트-결정적** (동일 환경에서 두 번 실행해도 diff 없음):

```bash
python scripts/gen_sbom.py --output sbom.json
```

CI `determinism.yml` 의 `SBOM is deterministic` 단계가 두 독립 생성 결과를 `diff` 로 검증한다.

태그 릴리스 시 SBOM은 GitHub Release asset으로 자동 첨부된다 (아래 §7).

---

## 7. 릴리스 검증 체크리스트 (태그 릴리스)

`v*` 태그를 푸시하면 GitHub Actions `determinism.yml` 이 추가로:

1. 기존 determinism proof (2회 바이트-동일), audit-chain proof, SBOM determinism 검증을 실행한다.
2. 아래 세 파일을 GitHub Release asset으로 업로드한다:

| 파일 | 설명 |
|------|------|
| `sbom.json` | CycloneDX SBOM (공급망 투명성) |
| `docs/security/threat_model.md` | STRIDE 위협 모델 |
| `SECURITY.md` | 취약점 보고 정책 및 공개 SLA |

3. 릴리스 다운로드자는 세 파일을 다운로드하고 독립적으로 신뢰 증명을 재실행할 수 있다.

---

## 8. 재현 불가 시 대응 방법

| 증상 | 원인 가능성 | 확인 방법 |
|------|-------------|-----------|
| `distinct_outputs > 1` | 비결정적 코드 경로(시간·랜덤·해시 순서) | `git bisect` 로 회귀 커밋 탐지 |
| `event_hash mismatch at seq=N` | 체인 행 또는 이벤트 행 수정 | `SELECT * FROM event_chain WHERE seq=N` 직접 확인 |
| `event missing from store` | archive 미완료 또는 행 삭제 | `events` + `events_archive` 두 테이블 합산 확인 |
| `VerifyInputError: cannot open store` | store 경로 오류 또는 write-lock | `mode=ro` URI 확인, 경로 점검 |

---

## 9. 코어 모듈 경계 (공개 / 비공개)

이 v0.1.0 공개 릴리스는 **Core 레이어만** 공개한다 (`Apache-2.0`).
Enterprise 레이어(`secugent.cost`, `secugent.enterprise`, `secugent.api` 등)는 별도 라이선스(`BSL-1.1`)로 비공개 유지된다.

공개 Core에는 다음이 포함된다:
- `secugent/core/` — 정책 엔진, Rule of Two, Mechanical Oversight, 결정적 게이트 전체
- `secugent/audit/` — SHA-256 해시체인·머클 프리미티브 (이 문서에서 증명하는 핵심)
- `secugent/cli/verify.py`, `secugent/cli/demo.py` — 무키 재현 진입점
- 전체 목록: `release/public_manifest.yaml` 참조

Core 공개 파일이 비공개 패키지를 import하지 않음은 `scripts/check_public_release.py` (import-closure 게이트)로 CI에서 강제된다.

---

## 10. 관련 문서

| 문서 | 위치 | 내용 |
|------|------|------|
| STRIDE 위협 모델 | `docs/security/threat_model.md` | 공격자 관점 위협 분석 |
| 취약점 보고 정책 | `SECURITY.md` | 공개 SLA·연락처 |
| 오픈코어 경계 표 | `docs/OPEN_CORE.md` | 공개/비공개 모듈 분류 |
| SBOM | `sbom.json` (릴리스 asset) | CycloneDX 공급망 명세 |

---

*이 문서의 모든 주장은 실제 CLI·CI 동작에서 검증 가능하다.
측정되지 않은 주장은 이 문서에 포함하지 않는다.*
