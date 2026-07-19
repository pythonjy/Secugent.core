# Changelog

`secugent-core`의 주요 변경 사항을 기록합니다. 형식은
[Keep a Changelog](https://keepachangelog.com/)를 따르며, 날짜는 KST 기준입니다.
이 저장소는 Apache-2.0 오픈코어 — 결정적 통제 코어만을 공개 범위로 합니다.

## [Unreleased]

### Added

- **Grounding 신뢰 경계(trust-layer)** — 외부 RAG/검색 결과를 `Evidence` 스키마로만 admit하고
  taint 추적으로 근거 없는 고영향 결정을 차단하는 경계 계약(`secugent/core/grounding.py`).
  SecuGent는 RAG 엔진을 구축하지 않고 admit 경계만 소유한다.
- **Evidence-binding 생산자 브리지** — 커넥터/도구 payload의 `evidence` 를 재검증해 run 컨텍스트·
  plan에 결정적으로 연결하는 fail-closed 브리지
  (`secugent/orchestrator/evidence_binding.py`, `grounding_context.py`).
- **Egress 브로커 상한(ceiling) / LabelResolver** — `EgressBroker.dispatch()` 가 taint 라벨과
  컨테이너 분류의 상한(max)으로 외부 전송 데이터 등급을 결정하는 단일 라벨 해석 경로
  (`secugent/io/broker/label_resolver.py`).
- **STEER 인터럽트 상태(interrupt-state)** — 실행 중 정지 → 재지시 → 재개를 RunRecord의 additive
  필드로 관리하는 별도 상태기계(`secugent/steer/interrupt_state.py`).
- **DB 마이그레이션 라이브러리 + 동기 store facade** — append-only 감사 체인을 SQLite →
  PostgreSQL로 체인 순서대로 이관하고 PG 측에서 해시체인을 재검증하는 마이그레이터
  (`secugent/db/migrate_sqlite_to_pg.py`, `store_facade.py`).
- **운영 CLI 명령** — `secugent backup` / `restore`(감사 store lock-safe 스냅샷·복원),
  `migrate-store`(SQLite→PG 마이그레이션), `rotate-secret`(시크릿 로테이션),
  `sign-policy-bundle`(egress 정책 번들 오프라인 서명).
- **관측(observability) 메트릭** — 비용·토큰 귀속 및 런 관측 메트릭 프리미티브
  (`secugent/observability/`).

### Changed

- **배포 산출물을 공개 배포 범위에서 제외** — `deploy/`(Dockerfile·docker-compose·`.env.example`
  등)를 공개 저장소에서 제거. `secugent-core` 는 이제 **라이브러리 + CLI + SDK**로만 배포되며,
  부팅 가능한 HTTP API 서버·웹 콘솔 UI·엔터프라이즈 커넥터는 상용 Enterprise 티어에 속한다.

## [0.1.0] - 2026-06-13

최초 공개 OSS 릴리스(Apache-2.0 오픈코어). SecuGent는 어떤 프레임워크·모델 위에서든
작동하는 에이전트 **통제·신뢰 레이어(Trust & Control Plane)** 이며, `secugent-core`는
그 **결정적 통제 코어**를 공개합니다. 이번 릴리스는 결정적 Mechanical Oversight,
Rule of Two 정책 엔진, REGULATIONS 엔진, 승인 경로, append-only 감사 해시체인 + Merkle,
무키 CLI, 공급망·릴리스 신뢰 인프라를 포함합니다.

### Added

- **결정적 Mechanical Oversight** — 명시적 정책 위반을 위험점수와 무관하게
  **HARD BLOCK** 하는 deny-by-default 통제 엔진. 동일 입력 → 동일 출력을 100회 검증.
- **Rule of Two 정책 엔진** — `[비신뢰 입력 / 민감 접근 / 상태변경·외부통신]` 세 축 중
  최대 2개만 허용하고, 셋 다 필요한 액션은 HITL 승인을 강제.
- **REGULATIONS 엔진** — 결정적 규칙 평가 + 정책 버전(`regulations_version`, semver) 추적.
  겹치는 라벨에서도 deny-overrides + 순서 독립으로 판정해 deny 우회를 차단.
- **승인 경로(approval)** — Plan Review / HITL 단일 결정 게이트. 부분 승인을 지원하며
  모든 결정이 감사 이벤트로 기록됨.
- **append-only 감사 해시체인** — `prev_event_id` 기반 SHA-256 체인으로 위변조를 검출하고,
  외부에서 독립적으로 재계산·검증 가능.
- **Merkle 트리 증명** — 감사 이벤트 집합에 대한 포함 증명을 제공해 부분 공개·외부 검증 지원.
- **무키 CLI(`secugent`)** — API 키 없이 동작하는 검증·시연 명령:
  - `secugent verify --determinism` — 결정성 100회 검증
    (기대 출력: `verify: determinism OK - 100 runs identical (digest <16자리-hex>)`).
  - `secugent verify --chain` — 감사 해시체인 무결성 독립 재계산.
  - `secugent demo` — 무키 데모(정책 HARD BLOCK → HITL 승인 → append-only 감사 이벤트 2건).
- **출처(provenance) 추적** — 통제 결정에 입력·근거의 출처를 결정적으로 연결.
- **오픈코어 경계 + import-closure 릴리스 게이트** — 공개/비공개 manifest를
  단일 진실 원천으로 두고, fail-closed import-closure 검사로 비공개 티어·시크릿·내부 전략
  문서가 공개 집합으로 누출되는 것을 차단. 위반이 1건이라도 있으면 비0 종료로 릴리스를 막음.
- **서명 릴리스 + SBOM + 결정성 CI 파이프라인** — sigstore keyless 서명(Rekor 투명 로그) +
  OIDC PyPI Trusted Publishing(API 토큰 미사용) + CycloneDX SBOM(byte-identical 재현) +
  결정성·해시체인 검증을 CI 게이트로 강제.
- **신뢰 증명·보안 문서** — [`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md)
  (외부 재현 가능 결정성·해시체인 증명), [`docs/security/threat_model.md`](docs/security/threat_model.md)
  (위협 모델), [`SECURITY.md`](SECURITY.md)(취약점 신고 절차),
  [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md)(오픈코어 티어 경계).

### Security

- **deny-by-default 통제** — 정책에 명시되지 않은 액션은 기본 거부. allowlist 기반으로만 허용.
- **결정성 보장** — 결정적 통제 모듈은 동일 입력에 대해 100회 동일 출력을 CI에서 강제 검증.
- **append-only 감사 무결성** — 감사 로그는 추가 전용이며 해시체인으로 위변조를 검출.
- **fail-closed 릴리스 경계** — import-closure·금지 콘텐츠 스캔이 단 한 건이라도 위반을
  발견하면 릴리스를 차단(우회 불가).
- **공급망 신뢰** — 릴리스 자산에 sigstore 서명과 SBOM을 첨부해 누구나 독립적으로 검증 가능.

### Notes

- 0.x pre-GA 릴리스입니다. 공개 API는 향후 변경될 수 있습니다.
- Enterprise 티어(비용 강제 엔진, API 서버, 멀티테넌트 관리 등)는 공개 범위에 포함되지 않습니다.
- 라이브 트래픽 PostgreSQL cutover, end-to-end 3축 HITL 라이브 강제는 후속 릴리스에서 완성됩니다.
