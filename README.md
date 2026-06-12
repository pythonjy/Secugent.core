# SecuGent v0.1 — Human-in-the-loop Enterprise Agent Platform

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

SecuGent는 HEAD/SUB 에이전트 + 결정론적 Mechanical Oversight + 확률적 RISKANALYZER + HITL 승인을 결합한
엔터프라이즈 에이전트 통제·신뢰 레이어다. 공개 Core는 Apache-2.0이며, 취약점 신고 절차는
[`SECURITY.md`](SECURITY.md), 외부 재현 가능한 신뢰 증명은
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
- [`examples/langchain_demo/`](examples/langchain_demo/) — LangChain 통합(항목4 embed SDK에서 완성, 현재 stub).

Docker 한 줄로도 데모가 된다(서버 기본 부팅을 깨지 않음):

```bash
docker build -f deploy/Dockerfile -t secugent .
docker run --rm secugent secugent demo     # CLI 데모 (기본 CMD인 uvicorn 서버를 override)
```

## 주요 특징
- **결정론 우선**: Mechanical Oversight(deterministic) 통과 후에만 RISKANALYZER 호출.
- **HITL 단일 진실원**: 모든 승인 토큰은 SQLite 기반 durable event store에 기록되며 재시작 후 복구된다.
- **Fail-closed**: REGULATIONS 파싱 실패, 경로 정규화 실패, LLM 응답 파싱 실패는 자동 실행하지 않고 차단/HITL.
- **승인 토큰 scope**: `run_id`, `plan_id`, `step_ids`, `allowed_action_types`, `max_risk`, `expires_at` + nonce 1회용.
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
├── core/          # contracts, regulations, oversight, risk, event store, approval, logger
├── agents/        # HEAD planner, SUB executor, dispatcher
├── steer/         # 인간 중도 개입 처리기
├── audit/         # append-only 감사 해시체인·머클·export
├── tools/         # tool router + builtin tools
├── observability/ # 비용·토큰·런 관측
examples/          # 무키 실행 예제 (quickstart, policy_demo)
tests/             # unit + integration + release 게이트
```

> Enterprise 티어(API 서버·비용 강제 엔진·멀티테넌트 관리 등, BSL-1.1)는 비공개이며 이 저장소에
> 포함되지 않는다. 전체 공개/비공개 티어 표는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)를 참조.

## v0.1 안전 기본값
- 실제 OS 마우스/키보드 자동 조작 **금지** — stub 또는 sandbox-only.
- EVOLUTION 은 `--dry-run` 으로만 실행되며 자동 commit/tag 를 수행하지 않는다.
- 정책 REGULATIONS 예제는 [`examples/policy_demo/`](examples/policy_demo/) 를 시작점으로 사용한다.

취약점 신고 절차는 [SECURITY.md](SECURITY.md) 를 참조한다.

## Background Orchestrator

`POST /command` 는 더 이상 단순히 `command.received` 만 발행하지 않는다.
백그라운드 오케스트레이터([secugent/orchestrator/runner.py](secugent/orchestrator/runner.py))가
다음 파이프라인을 끝까지 자동으로 진행한다:

```
command.received → plan.created → plan.awaiting_approval(*) → plan.approved
  → dispatcher.routed → run.completed
```

`(*)` 는 `auto_approve=False` 일 때만. 클라이언트는 별도 폴링 없이
`GET /runs/{id}/events` (SSE) 로 실시간 이벤트를 받는다.

### REST 표면

| 메서드 | 경로 | 설명 |
| --- | --- | --- |
| `POST` | `/command` | `{goal}` 입력 → `{run_id, status="accepted"}` 반환, 백그라운드 파이프라인 시작 |
| `GET`  | `/runs/{id}` | 현재 상태 + plan + 누적 이벤트 요약 |
| `GET`  | `/runs/{id}/events` | SSE 스트림. terminal 이벤트 도착 시 자동 종료 |
| `POST` | `/runs/{id}/approve` | Plan Review Gate 통과 |
| `POST` | `/runs/{id}/reject` | run 즉시 CANCELLED |
| `POST` | `/runs/{id}/amend` | 추가 지시로 PLANNING 회귀 + 재계획 |

### 설정 키 (`secugent/config.py`)

| 키 | 기본값 | 비고 |
| --- | --- | --- |
| `orchestrator.auto_approve` | `False` | True 면 Plan Review Gate 건너뜀 |
| `orchestrator.approval_timeout_sec` | `600` | 초과 시 FAILED(reason="approval_timeout") |
| `orchestrator.max_concurrent_runs` | `10` | `asyncio.Semaphore` 로 강제 |
| `orchestrator.run_state_backend` | `"memory"` | `"sqlite"` 는 skeleton(미구현) |
| `orchestrator.fail_fast` | `True` | 일부 SUB 실패 시 run 즉시 FAILED |

### 에러 처리 규칙
- HEAD 예외 → `RunState.FAILED`, `failure_reason="planning_error: <type>: <msg>"`
- Dispatcher 예외 → `failure_reason="dispatch_error: …"`
- SUB 실패 + `fail_fast=True` → run FAILED, `failure_reason="sub_error: …"`
- SUB 실패 + `fail_fast=False` → 다른 SUB 결과 보존, run FAILED 그대로
- Orchestrator `stop()` → 진행 중 run 모두 CANCELLED, 신규 enqueue → `OrchestratorStoppedError`

## Docker Virtual Desktop Backend

> **티어 안내**: `secugent/desktop/` 백엔드 구현(Docker·Windows Sandbox)은 deferred(Enterprise-인접)
> 티어로 **이 공개 저장소에는 포함되지 않는다**([`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)). 공개 Core는
> config 스키마와 stub 인터페이스만 제공하며, `backend="docker"` 사용 시 `DesktopBackendUnavailableError`
> 로 fail-closed된다. 아래 설명은 Enterprise 티어에서 제공되는 백엔드의 설계 참고용이다.

`VirtualDesktopStub` 대신 추상 인터페이스(`VirtualDesktopBackend`)가 들어왔다.
기본은 여전히 `StubBackend` 이며, 운영 배포는 `backend="docker"` 로 전환한다.

### 설치
```bash
pip install 'secugent[desktop-docker]'
```

### 설정 키 (`secugent/config.py::VirtualDesktopConfig`)

| 키 | 기본값 | 비고 |
| --- | --- | --- |
| `virtual_desktop.backend` | `"stub"` | `"docker"`, `"windows_sandbox"` 선택 가능 |
| `virtual_desktop.lifecycle` | `"per_run"` | `"per_sub"`, `"persistent"` |
| `virtual_desktop.docker.image` | `"secugent/sandbox:latest"` | 트러스트 이미지 prefix 외에는 경고 |
| `virtual_desktop.docker.network_mode` | `"none"` | `"host"` 는 fail-closed 거부 |
| `virtual_desktop.docker.memory_limit` | `"1g"` | 빈 문자열 거부 |
| `virtual_desktop.docker.cpu_limit` | `1.0` | 0 이하 거부 |
| `virtual_desktop.docker.read_only_root` | `True` | False 면 WARN |
| `virtual_desktop.docker.mount_paths` | `[]` | `rw` 마운트는 sandbox_roots 안에 있어야 함 |
| `virtual_desktop.docker.sandbox_roots` | `[]` | rw 교차 검증 기준 |
| `virtual_desktop.docker.cap_add` | `[]` | 비어있지 않으면 fail-closed 거부 |

### 보안 디폴트 (DockerBackend)

- `cap_drop=["ALL"]` (추가 capability 금지)
- `security_opt=["no-new-privileges"]`
- `user="nobody"`
- `read_only=True` (config로 풀 수 있으나 WARN 로그)
- `network_mode="none"` (config로 `bridge_restricted` 만 추가 허용; `host` 는 영구 금지)

`validate_security()` 가 위 옵션 위반을 모두 `BackendConfigurationError` 로 막는다.
실제 데스크톱 마우스/키보드 자동 조작은 여전히 `RealDesktopDisabledError` 로 차단된다 — Docker 백엔드는 *컨테이너 안*의 명령 실행만 다룬다.

### 첫 실행

```bash
docker pull alpine:3.20   # 또는 운영 이미지
export SECUGENT_DOCKER_TEST_IMAGE=alpine:3.20
pytest tests/integration/test_docker_backend.py
```

Docker 데몬이 없으면 통합 테스트는 자동 skip 되어 CI 가 실패하지 않는다.

## License

- **Core** — Apache-2.0 ([`LICENSE`](LICENSE)). 이 저장소의 공개 코드는 전부 Apache-2.0이며,
  각 소스 파일에 `SPDX-License-Identifier: Apache-2.0` 헤더가 부여되어 있다.
- **Enterprise tier** — `LicenseRef-SecuGent-Enterprise` (BSL-1.1 기반 상용 라이선스, 비공개)
  ([`LICENSE.enterprise`](LICENSE.enterprise)).

공개/비공개 모듈 티어 경계는 [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)에서 확인할 수 있다.

