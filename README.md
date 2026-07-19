# SecuGent Core v0.1 — 프레임워크·모델 중립 에이전트 신뢰·통제 레이어 (OSS)

## 신뢰 증명 한 줄 재현 (Trust Proof — API 키 불필요)

```bash
pip install .
secugent verify --determinism --fixture tests/cli/fixtures/determinism_seed.json
# 기대 출력: verify: determinism OK - 100 runs identical (digest xxxxxxxxxxxxxxxx)
```

100회 동일 결정 = 정책 엔진이 결정론적으로 동작함을 외부에서 독립 재현.
감사 해시체인 무결성 검증: `secugent verify --chain --tenant <id> --store <path.db>`
자세한 절차·해시체인 구조·릴리스 asset 목록: [`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md)

---

SecuGent는 어떤 프레임워크·모델 위에서든 동작하는 에이전트 **신뢰·통제 레이어(Trust & Control Plane)** 다.
이 저장소(`secugent-core`, Apache-2.0)는 그 **결정적 통제 코어를 라이브러리 · `secugent` CLI · 임베드 SDK**
형태로 공개한다 — 결정론적 Mechanical Oversight, Rule of Two 정책 엔진, append-only 감사 해시체인,
STEER 실시간 중도개입, grounding 신뢰 경계를 코드로 강제한다.

> **이 저장소가 담는 것**: 라이브러리 + CLI + SDK (부팅 가능한 HTTP 서버 없음).
> **담지 않는 것 (Enterprise 티어, 비공개)**: HTTP REST/WebSocket API 서버(`secugent.api`), 웹 콘솔 UI,
> 외부 커넥터·멀티테넌트 관리·비용 강제 엔진, 그리고 배포 산출물(`deploy/` Docker·Helm·에어갭 번들).
> 전체 공개/비공개 티어 경계는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md) 참조.

취약점 신고 절차는 [`SECURITY.md`](SECURITY.md), 외부 재현 가능한 신뢰 증명은
[`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md)를 따른다.

## 5분 퀵스타트 (API 키·네트워크 불필요)

폐쇄망(에어갭) 우선. `ANTHROPIC_API_KEY` 없이 mock 모드로 "정책 HARD BLOCK → HITL 승인 → 감사로그"
1회전이 그대로 돈다.

```bash
# 1) 설치 (코어, Apache-2.0)
python -m pip install .

# 2) 무키 데모 실행 — REGULATIONS HARD BLOCK + HITL 승인 + 감사 이벤트 요약
secugent demo

# 3) 감사로그 무결성 확인 (읽기 전용 결정성·해시체인 증명)
secugent verify --chain --tenant <tenant> --store <path-to.db>
```

`secugent demo` 가 출력하는 감사 이벤트는 감사 스키마(`event_id`·`prev_event_id` 해시체인·
`rule_of_two_axes`·`decision` …, [`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md) 참조)를
만족하며 append-only 해시체인에 기록된다.
실행 가능한 예제는 [`examples/`](examples/) 참고:

- [`examples/quickstart/`](examples/quickstart/) — 최소 에이전트 1회전(정책 로드 + 데모).
- [`examples/policy_demo/`](examples/policy_demo/) — 한국어 정책 REGULATIONS HARD BLOCK 결정성 시연.
- [`examples/langchain_demo/`](examples/langchain_demo/) — LangChain 통합 embed SDK. `langchain` 설치
  여부와 무관하게 키 없이 실행되며, 정책 위반 도구 호출을 Mechanical Oversight로 HARD BLOCK 한다.

## 주요 특징
- **결정론 우선**: Mechanical Oversight(deterministic) 통과 후에만 RISKANALYZER 호출.
- **HITL 단일 진실원**: 모든 승인 토큰은 SQLite 기반 durable event store에 기록되며 재시작 후 복구된다.
- **Fail-closed**: REGULATIONS 파싱 실패, 경로 정규화 실패, LLM 응답 파싱 실패는 자동 실행하지 않고 차단/HITL.
- **승인 토큰 scope**: `run_id`, `plan_id`, `step_ids`, `allowed_action_types`, `max_risk`, `expires_at` + nonce 1회용.
- **Grounding 신뢰 경계**: 외부 RAG/검색 결과는 `Evidence` 스키마로만 admit되고, taint 추적으로 근거 없는 고영향 결정을 차단(`secugent/core/grounding.py`). SecuGent는 RAG 엔진을 만들지 않고 경계 계약만 소유한다(§A-1 Non-goal).
- **Egress 상한(ceiling)**: `EgressBroker`가 taint 라벨과 컨테이너 분류의 상한(max)으로 외부 전송 데이터 등급을 fail-closed 결정(`secugent/io/broker/`).
- **STEER 실시간 중도개입**: 실행 중 정지 → 스냅샷 → 재지시 → 재개를 별도 인터럽트 상태기계로 관리(`secugent/steer/`).
- **v0.1 안전 기본값**: 실제 데스크톱 조작은 stub/sandbox-only, EVOLUTION 은 `--dry-run` 기본.

## 빠른 시작
```bash
python -m pip install -r requirements.txt
pytest tests/unit -v
```

## 모델 환경변수
| 변수 | 기본값 | 용도 |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | (없음) | 없으면 **Mock Mode** 로 진행 (로그·README 명시) |
| `SECUGENT_RISK_MODEL` | `claude-haiku-4-5-20251001` | RISKANALYZER 용 경량 모델 |
| `SECUGENT_PLANNER_MODEL` | `claude-opus-4-7` | HEAD 플래너 모델 (config 로 교체 가능) |
| `SECUGENT_DB_PATH` | `.secugent/secugent.db` | durable event store 경로 |

> **Mock Mode 알림**: `ANTHROPIC_API_KEY` 가 비어 있으면 `LLMClient` 는 결정론적 Mock 응답을 반환한다.
> CI 와 단위 테스트는 항상 Mock 으로 동작한다.

## 디렉토리 구조 요약
```
secugent/
├── core/          # contracts, regulations, oversight, rule-of-two, approval, grounding, event store, logger
├── regulations/   # 규제 로더(tenant_loader) + 정책 packs
├── audit/         # append-only 감사 해시체인·머클·export·retention
├── steer/         # 실시간 중도개입(STEER) + 인터럽트 상태기계·스냅샷
├── io/            # egress 브로커·라벨 해석·트랜스포트·staging
├── agents/        # HEAD planner, SUB executor, dispatcher
├── orchestrator/  # 계획→승인→디스패치 오케스트레이션 (HTTP API 표면은 Enterprise 제외)
├── tools/         # tool router + builtin tools + connectors
├── db/            # SQLite→PostgreSQL 감사 마이그레이션·store facade
├── sdk/           # 임베드·채택 SDK (decorators, gate, middleware)
├── cli/           # secugent 진입점 (verify, demo, run, 운영 명령)
├── observability/ # 비용·토큰·런 관측 메트릭
examples/          # 무키 실행 예제 (quickstart, policy_demo, langchain_demo)
tests/             # unit + integration + release 게이트
```

> Enterprise 티어(API 서버·비용 강제 엔진·멀티테넌트 관리 등, BSL-1.1)는 비공개이며 이 저장소에
> 포함되지 않는다. 전체 공개/비공개 티어 표는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)를 참조.

## v0.1 안전 기본값
- 실제 OS 마우스/키보드 자동 조작 **금지** — stub 또는 sandbox-only.
- EVOLUTION 은 `--dry-run` 으로만 실행되며 자동 commit/tag 를 수행하지 않는다.
- 정책 REGULATIONS 예제는 [`examples/policy_demo/`](examples/policy_demo/) 를 시작점으로 사용한다.

취약점 신고 절차는 [SECURITY.md](SECURITY.md) 를 참조한다.

## 라이브러리·SDK로 임베드

공개 Core는 **부팅 가능한 HTTP 서버 없이** 라이브러리·CLI·SDK로 사용한다. 임베드 SDK
(`secugent/sdk/`)는 기존 에이전트·도구 호출 경로에 결정적 통제 게이트를 끼워 넣는다:

- `secugent.sdk.decorators` — 함수/도구 호출을 Mechanical Oversight + Rule of Two 게이트로 감싼다.
- `secugent.sdk.gate` — 계획/스텝을 명시적으로 평가해 allow / HARD BLOCK / HITL-필요 판정을 받는다.
- `secugent.sdk.middleware` — 프레임워크 미들웨어로 통제·감사 훅을 주입한다.

정책 위반 도구 호출을 프레임워크와 무관하게 HARD BLOCK 하는 실행 예제는
[`examples/langchain_demo/`](examples/langchain_demo/) 참고(키 없이 동작).

## `secugent` CLI

무키(API 키 불필요) 검증·시연 및 감사 store 운영 명령을 제공한다.

| 명령 | 설명 |
| --- | --- |
| `secugent verify --determinism` | 결정성 100회 검증 (동일 입력 → 동일 출력) |
| `secugent verify --chain` | append-only 감사 해시체인 무결성 독립 재계산 |
| `secugent demo` | 무키 데모: 정책 HARD BLOCK → HITL 승인 → 감사 이벤트 |
| `secugent run "<goal>"` | 최소 에이전트 1회전 (mock 클라이언트) |
| `secugent backup` / `restore` | 감사 event store의 lock-safe 스냅샷·복원 |
| `secugent migrate-store` | SQLite → PostgreSQL 감사 체인 마이그레이션 (체인 재검증) |
| `secugent rotate-secret` | 관리 시크릿 로테이션 |
| `secugent sign-policy-bundle` | egress 정책 번들 오프라인 서명 |

## Enterprise 티어 (이 저장소에 미포함)

아래는 상용 Enterprise 티어(`LicenseRef-SecuGent-Enterprise`, 비공개)로 제공되며 이 공개
저장소에는 **포함되지 않는다**:

- **HTTP REST/WebSocket API 서버**(`secugent.api`) — `POST /command`, `GET /runs/{id}/events`
  (SSE), `POST /runs/{id}/approve` 등 오케스트레이션 실행 표면 전체.
- **웹 콘솔 UI** — Plan Review·모니터링·승인 큐 프론트엔드.
- **외부 커넥터·멀티테넌트 관리·비용 강제 엔진**, 그리고 **배포 산출물**(`deploy/` Docker·Helm·에어갭 번들).

전체 공개/비공개 모듈 티어 경계는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)에서 확인한다.

## 가상 데스크톱 백엔드 (스키마만 공개)

공개 Core는 `VirtualDesktopConfig` 스키마(`secugent/config.py`)만 제공하고, 데스크톱/컴퓨트
백엔드의 *구현체*(Docker·Windows Sandbox)는 번들하지 않는다(Enterprise-인접 티어,
[`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)). 백엔드가 주입되지 않은 채 데스크톱 스텝이 들어오면
`DesktopBackendUnavailableError` 로 **fail-closed** 되며, 실제 OS 마우스/키보드 자동 조작은
언제나 `RealDesktopDisabledError` 로 차단된다(툴 우선·데스크톱 최후수단).

## License

- **Core** — Apache-2.0 ([`LICENSE`](LICENSE)). 이 저장소의 공개 코드는 전부 Apache-2.0이며,
  각 소스 파일에 `SPDX-License-Identifier: Apache-2.0` 헤더가 부여되어 있다.
- **Enterprise tier** — `LicenseRef-SecuGent-Enterprise` (BSL-1.1 기반 상용 라이선스, 비공개)
  ([`LICENSE.enterprise`](LICENSE.enterprise)).

공개/비공개 모듈 티어 경계는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)에서 확인할 수 있다.

