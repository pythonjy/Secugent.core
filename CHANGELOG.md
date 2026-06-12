# Changelog

All notable changes to SecuGent are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); dates are KST.

## [Unreleased]

## [0.1.0] — 2026-06-13 KST

secugent-core 최초 공개 OSS 릴리스 (Apache-2.0 오픈코어). 아래 항목이 v0.1.0에 포함됩니다 —
결정적 통제 코어(mechanical_oversight·regulations·approval, 라인 커버리지 ≥95%·결정성 100회),
append-only 감사 해시체인, 공개/비공개 manifest + import-closure fail-closed 릴리스 게이트,
서명 릴리스 파이프라인(sigstore keyless·OIDC PyPI·CycloneDX SBOM), 신뢰 증명 문서, OSS 거버넌스 인프라.
공개 Core 전 파일에 SPDX `Apache-2.0` 헤더를 부여하고, 추출 스크립트의 경로 이식성을 수정했다.

### 다중 Opus 4.8 에이전트 오류 탐지·수정 사이클 (2026-06-11)

5개 읽기 전용 Opus 4.8 탐지 에이전트(ruff·mypy·pytest·security T1-T8·concurrency)를
동시 팬아웃해 전체 코드베이스를 스캔하고, Medium 이상 결함을 Sonnet 4.6 fixer가 TDD로
수정. 적대적 재검증(3렌즈)으로 신규 결함 미도입 확인. 상세: `Review/2026-06-10-multi-opus-scan.md`.

- **Fixed (Medium 이상 8건)**:
  - `SG-FIX-01` (High, io/broker/effect_bridge.py): connector_action 비정규 타깃(내부 유니코드
    공백 NEL 등)이 `Effect`에서 raw `ValueError`를 누출해 EgressBroker의 fail-closed
    `except AmbiguousEffectError`를 우회하던 계약 위반을 `AmbiguousEffectError`로 일원화(결정적 §B-4a).
  - `SG-FIX-02` (Medium, core/tenancy.py): SSE teardown에서 ContextVar reset 교차-Context
    `ValueError` 크래시(후속 테스트 오염)를 방어 흡수+로깅(§B-8).
  - `SG-FIX-03/04` (Medium, desktop/{docker,windows_sandbox}_backend.py): 정리 경로의
    `except: pass` 무음 흡수 → warning 로깅(좀비 컨테이너/고아 프로세스 누수 가시화, §B-8).
  - `SG-FIX-05` (Medium, orchestrator/runner.py): `enqueue` 태스크 클레임을 `_lifecycle_lock`
    안에서 원자화(stop()과의 TOCTOU로 인한 종료 후 고아 파이프라인 태스크 제거).
  - `SG-FIX-06` (Medium, core/mechanical_oversight.py): `_match_data_label`을 첫-매칭 단락에서
    deny-overrides + 순서 독립 결정적 선택으로 전환(겹치는 라벨에서 deny 우회 차단, 결정적 §B-4a).
  - `SG-FIX-07/08` (Medium): 결정적 모듈 분기 커버리지 게이트 회복 — approval.py 93%→99%,
    mechanical_oversight.py 94%→100% (§B-4a 95% 게이트).
- **Tests**: stale RBAC 테스트를 강화된 operator+tenant 계약으로 갱신 + viewer 403 박제(`SG-FIX-09`);
  CompositeNotifier 테스트를 현행 async `channels=` API로 정합(`SG-FIX-10`); RUN_LATENCY 테스트
  고정 sleep→결정적 terminal 대기로 안정화. 각 결함에 회귀 테스트(`tests/**/test_regression_SG-FIX-*.py`).
- **Style**: 전체 repo ruff/format zero-out(`ruff check .` = 0; 213 auto-fix + 70 reformat +
  수동 17 정리, RunState→StrEnum 직렬화 안전 검증).
- **게이트**: ruff 0 · ruff format 0 · mypy strict 0 · 결정적 모듈 커버리지 ≥95%. 잔여 7개 pytest
  실패는 범위 외 — 5개는 미커밋 release.yml WIP(determinism_workflow), 2개는 풀스위트 전역상태
  오염 기존 flake(metrics_runner, 소스 정상).
- **Deferred(별도 명세 권고)**: Rule of Two 축①(untrusted_input) 라이브 생산자 배선(문서화된
  Stage-6 deferral, 다중 파일 기능 — §B-1 명세 우선).

### BDP_05 항목 5 — 서명 릴리스 파이프라인 + 거버넌스 manifest 보강 (2026-06-10)

서명된 릴리스 파이프라인 + 공개 OSS 기여 인프라를 추가하는 BDP_05 항목 5 PREP.
모듈 로직 변경 없음 — 릴리스 엔지니어링·거버넌스·CI 파이프라인만 추가.

- **`.github/workflows/release.yml` (신규)**: `v*` 태그 푸시 트리거. 4개 잡 순서
  `gate → build → publish → sign-release`로 직렬 의존(`needs:`) — `gate`가 실패하면
  `build`·`publish`·`sign-release` 모두 물리적으로 실행 불가(I2 fail-closed).
  - `gate` 잡: ruff check · ruff format --check · mypy · pytest(unit+enterprise+release+ops) ·
    `python scripts/check_public_release.py`(출구 코드 0 필수) · 태그↔pyproject 버전 일치 검증.
  - `build` 잡: `python -m build`(wheel+sdist) · `python scripts/gen_sbom.py --output sbom.json` ·
    `test_core_wheel_excludes_enterprise_packages` 재실행(I3) · `actions/upload-artifact@v4`.
  - `publish` 잡: OIDC Trusted Publishing(`pypa/gh-action-pypi-publish@release/v1`) —
    API 토큰 미사용(I1 공급망 신뢰). `permissions: id-token: write` + `environment: pypi`.
    PyPI 프로젝트에 trusted publisher 사전 등록 필요(RUNBOOK 참조).
  - `sign-release` 잡: sigstore keyless signing(`sigstore/gh-action-sigstore-python@v3`) —
    OIDC 임시 키 + Rekor 투명 로그 기록, 누구나 `sigstore verify`로 독립 재현 가능(I1).
    `softprops/action-gh-release@v2`로 dist/*.whl + dist/*.tar.gz + *.sigstore.json +
    sbom.json + SECURITY.md + docs/security/threat_model.md를 GitHub Release에 첨부.
    릴리스 노트에 신뢰 증명 섹션 포함(서명 검증 명령·SBOM·결정성 재현 명령).
  - 최소 권한 원칙: `id-token: write`는 publish·sign-release 잡만, `contents: write`는
    sign-release 잡만, 나머지는 기본 read-only. 시크릿 로그 출력 없음.
- **`release/public_manifest.yaml` 수정**: 항목 5 거버넌스 파일 4개를 `include`에 추가.
  deny-by-default(I4) 원칙상 이 항목들은 별도 추가 없이는 공개 repo에 도달하지 않음.
  추가한 glob: `"CONTRIBUTING.md"` · `"CODE_OF_CONDUCT.md"` ·
  `".github/ISSUE_TEMPLATE/**"` · `".github/PULL_REQUEST_TEMPLATE.md"`.
  `release.yml`은 기존 `".github/workflows/**"` 글롭으로 이미 커버됨.
  수정 후 `python scripts/check_public_release.py` 종료 0 확인.
- **`tests/ops/test_release_workflow.py` (신규)**: release.yml 구조 + manifest 보강 검증.
  8개 invariant 클래스(I_TRIGGER·I_ORDER·I_GATE·I_OIDC·I_SBOM·I_SIG·I_WHEEL·I_MANIFEST)
  29개 테스트 — 태그 트리거 존재 / publish·sign-release가 gate→build 체인 후 실행 /
  check_public_release.py 단계가 gate 잡 안에 존재 / id-token:write 권한 확인 /
  sbom·sigstore 서명이 GitHub Release에 첨부 / wheel-excludes-enterprise 단계 존재 /
  manifest 4개 거버넌스 경로가 is_public_path() 통과.
- **게이트 결과**: yaml.safe_load(release.yml) 유효 ✓ · ruff check + ruff format --check
  (tests/ops/test_release_workflow.py 스코프) ✓ · mypy ✓ · pytest tests/ops -q ✓ ·
  `python scripts/check_public_release.py` 종료 0 ✓.
- **불변조건(§5.4)**: I1(서명·출처) · I2(브랜치 보호·필수 게이트 선행) ·
  I3(공개 wheel 단독 설치·Enterprise 미포함) · I4(OIDC-only publish) · I5(거버넌스 문서 공개).
- **비범위(PREP)**: 실제 PyPI 퍼블리시 실행 없음 · sigstore 실제 서명 실행 없음 ·
  GitHub 브랜치 보호 실제 설정 없음(admin 권한 필요, RUNBOOK 참조) ·
  CONTRIBUTING.md·CODE_OF_CONDUCT.md·이슈/PR 템플릿 파일 본문 작성은 impl A(병렬 레인) 담당.

### 릴리스 게이트 import-closure 보강 — excluded-sibling 누락 차단 (2026-06-10, fixer)

기존 import-closure 게이트는 **비공개 _티어_** import만 검사해, 공개 집합에 포함된
파일이 manifest가 파일 단위로 _제외_ 한 형제 모듈(예: 공개 `orchestrator/__init__.py`가
제외된 `orchestrator/runner.py`)을 로드-타임 import하는 경우를 잡지 못했다(fail-open).
추출본은 그 형제 파일이 없어 `import secugent.orchestrator` 등이 `ModuleNotFoundError`로
깨졌으나(`pytest --collect-only` 31개 collection error), 게이트는 0 위반으로 통과시켰다(I2/I8 위반).

- **`scripts/check_public_release.py`**: `assert_import_closure`가 공개 집합에 없지만
  워킹트리에는 존재하는 파일(`_excluded_existing_files`)로 해석되는 로드-타임 import를
  추가 위반으로 보고(`imports excluded-from-public module …`). TYPE_CHECKING/함수-지역
  지연 import는 기존과 동일하게 면제(런타임 미실행).
- **티어 재분류 — `orchestrator/runner.py`·`orchestrator/errors.py`는 이제 공개**:
  둘 다 import-closed로 만들고(선택적 `secugent.cost` 쿼터 티어를 TYPE_CHECKING/지연
  참조로 격리) 공개 manifest에 포함. 공개 어댑터(`adapters.py`/`a2a_adapter.py`/`wiring.py`)가
  이들의 **비용 무관 심볼**(`PlanLike`, 플래너/디스패처 오류 클래스)을 런타임에 의존하므로
  제외 시 추출본 단독 import가 깨졌다(I8). 비용 _강제 엔진_(`CostLedger`)은 여전히 비공개
  `secugent/cost/**`.
- **`models/__init__.py`·`agents/dispatcher.py`**: 제외 유지인 `models/router.py`·
  `agents/sub_agent.py`(각각 eager `secugent.cost` import) 참조를 각각 PEP 562 `__getattr__`
  지연 재export·TYPE_CHECKING 주석으로 전환 → 공개 패키지가 import-closed.
- **`secugent.agents.sub_agent`를 import하는 시험 12개 + `tests/deploy/**` manifest 제외**:
  추출본 `pytest -q`에서 ModuleNotFoundError/FileNotFoundError 방지(I8).
- **`tests/release/...`·`tests/unit/test_open_core_boundary.py`**: 추출본에서 부재하는
  제외 파일을 읽는 시험에 `exists()/skip` 가드 추가. 실증 회귀 추가 — public_files() 실체화
  후 핵심 모듈 단독 import 성공 + `pytest --collect-only` 0 에러(게이트 자기보고가 아닌 실제 I8).

### 공개/비공개 manifest + import-closure + 금지콘텐츠 게이트 (2026-06-10)

오픈코어 공개 OSS repo를 안전하게 추출하기 위한 결정적(fail-closed) 릴리스 게이트.
기존 모듈 로직 변경 없음 — 릴리스 아티팩트만 추가.

- **`release/public_manifest.yaml` (신규)**: 공개 OSS repo의 단일 진실 원천. include/exclude
  글롭으로 deny-by-default(I4) 화이트리스트 선언. 혼합 패키지(orchestrator/agents/models)는
  파일 단위로 include하여 Enterprise 결합 파일(runner.py·errors.py·sub_agent.py·router.py,
  클로저 리스크 R1~R4)을 공개 집합에서 배제. CLAUDE.md·SECURITY_CONTRACT.md·Review/·docs/specs/·
  BDP_REFORMED/·한글 전략 HTML(시장진단·로우리스크)·`.env`·키/인증서·`.claude/`·`data/` 차단.
- **`scripts/check_public_release.py` (신규, 결정적 게이트)**: 위반 ≥1건 → 비0 종료(fail-closed).
  - `load_manifest`/`public_files`(정렬·결정적, I6)/`assert_import_closure`(AST, 상대 import를
    절대로 해석해 `secugent.{enterprise,compliance,cost,api}`·`ui` 참조 차단, I2)/
    `scan_forbidden_content`(내부전략 파일명·한글 부분문자열·시크릿 정규식, I5)/`main`.
  - **중요 정정**: `PurePosixPath.match`의 `**` 처리가 Python 3.14에서 깊은 경로·한글을 누락(R12)
    → 결정적 glob→정규식 변환기로 교체. 시크릿 정규식은 코드 토큰(`Token[X]`·`self._api_key)`)
    false-positive를 엔트로피 검증으로 제거하고 `change-me-*` 플레이스홀더를 비밀로 보지 않음.
  - **클로저 검증으로 발견·해소한 실제 누출**: ① `tests/{api,cost,enterprise,compliance,identity,
    evolution}/` 등 비공개/이연 tier 전용 테스트와 desktop 단위 테스트가 비공개 tier를 import →
    공개 집합에서 배제(I8 자기완결). ② `secugent/tools/router.py`의 `secugent.desktop` 최상위
    import를 `TYPE_CHECKING`+지연(lazy) import로 리팩터 → 공개 Core가 desktop tier 없이도 단독
    import 가능(I8). ③ import-closure 금지 prefix가 manifest가 제외하는 모든 top-level
    `secugent` tier(desktop/evolution/identity/integrations 포함)를 덮도록 확장하고, 두 집합이
    다시 어긋나지 않도록 게이트가 자체 일관성을 검증(fail-closed). closure 스캔은 모듈 로드 시
    실제 실행되는 import만 위반으로 판정(`TYPE_CHECKING`·함수 내부 지연 import는 런타임 미실행이라
    제외; 최상위 금지 import는 그대로 차단).
- **`tests/release/test_public_release_manifest.py` + `tests/release/__init__.py` (신규)**:
  단위 + 속성(`hypothesis`, include∖exclude 동치) + 결정성 100회 byte-identical + 시나리오 회귀
  (실제 repo에서 `main()==0`·closure==[]·forbidden==[]) + deny-set⇔manifest 동치·정밀 closure
  RED/GREEN 회귀 — 전량 그린, 분기 커버리지 95%+.
- **CI 배선**: `.github/workflows/secugent.yml`에 `release-check` 잡 추가 —
  `python scripts/check_public_release.py` + `pytest tests/release tests/ops`를 매 push/PR 실행
  (이전엔 어떤 워크플로우에서도 수집되지 않던 dead gate였음).
- **게이트**: ruff ✓ / ruff format ✓ / mypy(strict, `Any`·`type: ignore`·`cast` 0) ✓ /
  pytest 그린 / 현재 repo에서 `check_public_release.py` 종료 0.
- **불변조건**: I2(일방향 의존) · I4(deny-by-default) · I5(무시크릿) · I6(결정성) · I8(자기완결).

### 신뢰 증명 릴리스 검증 (TRUST_PROOF + 태그 릴리스 asset) (2026-06-10)

외부에서 재현 가능한 신뢰 증명(결정성·감사 해시체인) + 태그 릴리스 시 증빙 asset 자동 업로드.
기존 결정적 모듈 로직 변경 없음.

- **`docs/security/TRUST_PROOF.md` (신규)**: 외부 재현 가능 신뢰 증명 절차 문서(영업자료 본문).
  결정성 증명(100회 동일 해시), 감사 해시체인 증명(append-only SHA-256 체인 독립 재계산),
  해시체인/SBOM 구조 설명, 릴리스 asset 체크리스트, 코어 모듈 경계 요약 포함.
  모든 주장이 실제 CLI(`secugent verify`)·CI(`determinism.yml`) 동작과 대조 검증됨.
- **`README.md` 최상단 "신뢰 증명 한 줄 재현" 블록 추가**: `pip install . && secugent verify
  --determinism --fixture tests/cli/fixtures/determinism_seed.json` 무키 재현 명령 + 기대
  출력 + TRUST_PROOF.md 링크. 전략·내부 문서 노출 없음.
- **`.github/workflows/determinism.yml` 태그 트리거 + 릴리스 asset 업로드 추가**:
  `on.push.tags: ["v*"]` 트리거 추가(기존 `branches: [main]` + `pull_request` 유지).
  태그 푸시 시(`startsWith(github.ref, 'refs/tags/v')` 조건) `softprops/action-gh-release@v2`
  로 `sbom.json` + `docs/security/threat_model.md` + `SECURITY.md` 3개 파일을 GitHub
  Release asset으로 자동 업로드. 기존 determinism·chain·SBOM 검증 job/step은 일절 변경 없음.
- **`tests/ops/__init__.py` (신규, 빈 파일)**: ops 테스트 패키지 초기화.
- **`tests/ops/test_determinism_workflow.py` (신규)**: determinism.yml YAML 구조 검증 테스트.
  태그 트리거 존재(I_TAG), 2x 결정성 diff 단계 존재(I_DET), SBOM·threat_model·SECURITY.md
  릴리스 asset 단계 존재(I_SBOM/I_TM/I_SEC), 릴리스 단계 태그 조건 검사(I_COND), 그리고 UTF-8
  인코딩 견고성 회귀(`TestWorkflowEncodingRobustness`) — workflow 파일이 유효한 UTF-8이며
  (em-dash·§·한국어 감사 픽스처 포함) 프로덕션 리더는 `encoding="utf-8"`로 파싱하고, cp949
  (Windows 기본 로캘) 디코드는 byte 0xe2에서 실패함을 고정해 "로캘 기본 인코딩으로 열어
  UnicodeDecodeError" 회귀를 차단 — 15개 테스트 전량 그린.
- **불변조건**: I1(무키 재현) · I2(결정성 100회) · I3(SBOM+threat_model+SECURITY.md 릴리스 asset).

### 공개 repo 추출 스크립트 + 런북 (스크립트·정적 검증만) (2026-06-10)

공개 repo 추출 자동화 스크립트 + 단계별 릴리스 절차서. 스크립트·문서 작성 + 정적 검증만 —
라이브 repo 추출·PyPI·서명 실행은 별도 세션.

- **`scripts/extract_public_repo.sh` (신규)**: 공개 repo 추출 자동화 스크립트 (POSIX sh/bash).
  - `--mode snapshot` (기본·권장): 공개 파일만 새 빈 repo에 복사 → git init → 단일 커밋 →
    `v0.1.0` 태그. git history = 0 → Invariant I7(히스토리 무유출) 구조적 보장.
  - `--mode filter` (대안·비권장): git filter-repo 사용. dangling object · filter miss 누출
    위험 문서화 + 필수 `git gc --aggressive --prune=now` + post-filter 누출 스캔 강제.
  - `--dry-run`: 사전 게이트만 실행 후 공개 파일 목록 출력 (추출·git 초기화 없음).
  - 내장 4단계 게이트: ① `check_public_release.py` 사전 검증(종료 코드 1·abort) ②
    공개 파일 목록 결정적 산출 (`public_files()` 호출) ③ 추출본 내부 게이트를 **인수 없이**
    재실행해 import-closure·시크릿 재검증(추출본의 `__file__` 기반 `_REPO_ROOT`가 추출 디렉터리로
    해석됨; 종료 코드 4) ④ `git log --all -- <비공개경로>` 히스토리 누출 스캔 (공집합 이어야
    통과; 종료 코드 4). 게이트 실패 시 fail-closed, 출력 디렉터리 자동 삭제 금지.
  - `set -euo pipefail` 적용. 함수 정의 후 호출 순서 보장. `bash -n` 정적 검증 통과.
- **`release/PUBLIC_RELEASE_RUNBOOK.md` (신규)**: 전체 스냅샷 릴리스 절차서 (한국어 기본·KST).
  - §0 용어 정의 · §1 전역 릴리스 차단 게이트(G1~G6) · §2 전제 조건 pre-flight checklist ·
    §3 사전 게이트 단독 실행 · §4 snapshot 추출 + 누출 스캔 수동 재확인 · §5 설치·검증(I8·I9·I10) ·
    §6 퍼블리시 핸드오프(GitHub + PyPI, 수동·별도 세션) · §7 릴리스 완료 체크리스트 ·
    §8 filter 모드 절차(대안·비권장) · §9 자주 묻는 질문.
  - ⛔ 전역 릴리스 차단 게이트 6개 명시: G1 미분류 0 · G2 closure 위반 0 · G3 시크릿 0 ·
    G4 히스토리 공집합 · G5 무키 demo·verify·pytest 그린 · G6 서명 릴리스.
  - §5 결정성 검증 절차의 기대 출력을 실제 CLI 출력 형식
    (`verify: determinism OK - 100 runs identical (digest <16자리-hex>)`)으로 정정.
  - §9 FAQ의 한글 파일명 탐지 설명을 실제 구현(`_glob_to_regex` 커스텀 변환기 +
    `_FORBIDDEN_HANGUL_SUBSTRINGS` 직접 부분문자열 검사)으로 정정.
  - `secugent verify --determinism`(100회) · `secugent demo` · `pip install -e ".[dev]" && pytest -q`
    무키 재현 절차 포함.
- **불변조건 커버**: I7(히스토리 무유출) — snapshot 구조·게이트 4 이중 보장.
  I8(자기완결 설치) · I9(무키 재현) · I10(결정성 100회) — §5 검증 절차로 커버.
- **정적 검증**: `bash -n scripts/extract_public_repo.sh` 통과. shellcheck 환경 미설치(N/A).
- **비범위 (이 항목에서 실행하지 않음)**: 라이브 repo 추출 실행, `../secugent-core` 생성,
  PyPI 퍼블리시, GitHub 릴리스, 서명 실행.

### 모듈 티어 확정 (미분류 0 게이트) (2026-06-10)

오픈코어 split을 위해 모든 `secugent/*` 패키지를 공개 Core / 비공개 Enterprise 티어로 확정하고,
신규 패키지가 티어 미지정으로 추가되지 못하게 강제하는 게이트. 기존 모듈 로직 변경 없음.

- **`docs/OPEN_CORE.md` 티어 표 전면 갱신**: 전체 `secugent/*` 패키지에 대한 AST 스캔(금지
  import 탐지) + 이연 패키지 결정을 반영한 완전 티어 표 추가. 이전 표는 `secugent/core/`,
  `secugent/audit/`, `secugent/observability/` 3개만 명시했으며, 나머지 패키지가 미분류
  상태였다. 갱신 후 미분류 0.
- **`tests/unit/test_open_core_boundary.py` 상수 및 테스트 추가**:
  - `PUBLIC_CORE_PACKAGES: frozenset[str]` — 공개 Core 패키지 집합 (16개; 혼합 패키지
    orchestrator/agents/models 포함, 실제 manifest는 파일 수준 정밀도로 exclude_files 적용).
  - `ENTERPRISE_PACKAGES: frozenset[str]` — 완전 비공개 패키지 집합 (8개).
  - `test_every_top_level_package_has_a_tier()` — 두 집합이 서로소·합집합이 실제 디스크
    패키지 전체를 커버함을 검증. 신규 패키지 추가 시 티어 지정 강제 (I1 미분류 0 게이트).
  - `test_tier_sets_match_open_core_doc()` — `PUBLIC_CORE_PACKAGES`/`ENTERPRISE_PACKAGES`와
    `docs/OPEN_CORE.md` 표가 드리프트 없이 동기화됐는지 검증 (I3 티어 일관성 게이트).
- **이연(deferred) 4개 패키지 ENTERPRISE 유지**:
  - `secugent/evolution/` — 옵셔널. AST clean이나 자기개선 로직 가치/리스크 검토 필요.
  - `secugent/identity/` — 옵셔널. `registry.py`가 `secugent.api.rbac` 주석·설계 의존.
  - `secugent/integrations/` — 옵셔널. 외부 커넥터(Slack 승인 등) 출시 범위 미확정.
  - `secugent/desktop/` — 데스크톱 자동화는 최후수단(과투자 방지)이라 공개 범위에서 제외.
- **혼합 패키지 처리**: `secugent/orchestrator/`, `secugent/agents/`, `secugent/models/`은
  패키지 자체를 PUBLIC_CORE로 분류. `runner.py`·`errors.py`·`sub_agent.py`·`router.py`는
  `secugent.cost.accounting` import로 manifest exclude 대상(`release/public_manifest.yaml`).
- **게이트**: `mypy tests/unit/test_open_core_boundary.py` ✓ · `ruff check/format` ✓ ·
  `pytest tests/unit/test_open_core_boundary.py -q` 28/28 통과(신규 2건 포함).

### BDP Phase 4 / 항목 14c — SOC2 Type II · ISMS-P 통제 매핑 계획 (PLAN-ONLY) (2026-06-09)

P2(확장·옵셔널리티). 시장 갭 = 디자인파트너 요구 시의 인증 옵션(§A-3 P2-5). 문서 전용.
**조기 풀인증 금지(§A-1 포커스 보호)** 에 따라 항목 14c 는 **계획만 기록**한다 — 인증 작업·
감사 증적·심사는 착수하지 않는다.

- **신규 계획 스텁(문서 전용, 코드 변경 0)**:
  - `docs/compliance/soc2/README.md` — SOC 2 Type II 통제 매핑 계획. Trust Services
    Criteria → 저장소에 **이미 존재하는** 증거 위치(append-only 감사 해시 체인
    `secugent/audit/`, deny-by-default 정책 `secugent/core/regulations.py`, HITL/승인
    `secugent/core/approval.py`, RBAC/OIDC `secugent/api/`)로 사전 매핑.
  - `docs/compliance/ismsp/README.md` — ISMS-P(한국 공공·금융 맥락) 통제 매핑 계획.
    동일 형태로 ISMS-P 통제를 기존 저장소 증거에 매핑.
- **명시 상태**: 두 문서 모두 **STATUS = PLAN-ONLY**, **TRIGGER = 서명된 유료
  디자인파트너 LOI**. 인증 취득·감사 의견·통제 효과성은 **주장하지 않으며**, 인증
  산출물은 **생성하지 않는다**(트리거 충족 전까지).

### BDP Phase 4 / 항목 14d — 그룹웨어·SAP·문서 커넥터 (정책 게이트 경유) (2026-06-09)

P2(확장·옵셔널리티). 시장 갭 = 수요 견인 시 사내 시스템 연동 확장(§A-3 P2-4). 일반(커넥터).
기존 `tools/connectors/{jira,notion,slack}.py` 패턴 위에 신규 커넥터 3종을 추가하되 **통제
로직은 단 한 줄도 복제하지 않는다** — 어떤 액션이 존재하는가(Rule of Two 멤버십)·감사 추적은
중앙 `io/broker/connector_transport.py`가 유일 권위(single source of truth)다.

- **신규 커넥터(`base.py` 패턴 준수, SDK 없는 air-gapped 부팅)**:
  - `secugent/tools/connectors/groupware.py` `GroupwareConnector` — 사내 그룹웨어(메신저·공지·
    전자결재 알림). `allowed_channels` allow-none 화이트리스트(채널). 액션:
    `post_message`·`post_approval`·`list_channels`·`read_thread`.
  - `secugent/tools/connectors/docs.py` `DocsConnector` — 사내 문서함·전자결재 문서. 기존
    `ConnectorPolicy` 필드 재사용(`allowed_workspace_ids`=워크스페이스, `allowed_database_ids`
    =문서함/폴더) → **정책 스키마 불변**. 액션:
    `create_document`·`update_document`·`read_document`·`search`.
  - `secugent/tools/connectors/sap.py` `SapConnector` — ERP 전표·구매요청(고영향 재무 액션).
    기존 필드 재사용(`allowed_projects`=회사코드, `allowed_transitions`=트랜잭션코드). 액션:
    `post_document`·`create_purchase_req`·`read_document`·`search`. **회사코드 allow-none
    플로어는 모든 액션(읽기·`search`·변경)에 적용** — 빈/오설정 정책은 전 액션 HARD BLOCK이라
    회사코드를 가로지르는 재무 데이터 열람이 불가하다(jira의 connector-wide allow-none 미러,
    SG-14d-1/4). 변경 액션은 레지스트리에서 보수적으로 `IRREVERSIBLE`로 분류된다.
    - **정직한 범위(2-phase staging)**: `IRREVERSIBLE` 커넥터 변경의 staging divert는
      `io/broker/broker.py` `EgressBroker`에만 존재하며, **EM-06 커넥터 egress가 `main.py`에
      배선되어야 도달**한다. 라이브 `ConnectorTransport.dispatch` 경로에는 **아직 미적용**이므로
      커넥터 staging은 보장하지 않는다(go-live diff, 이전 항목들과 동일하게 연기). "변경 액션이
      2-phase staging을 경유한다"는 통제 주장은 그 배선이 들어오기 전까지 코드로 강제되지 않는다.
- **불변조건**:
  - **I1 (우회 경로 0)**: 모든 커넥터 액션은 `ConnectorTransport.dispatch`의 정책 게이트
    (deny-by-default 멤버십 + allow-none 화이트리스트)를 통과해야만 `execute`에 도달한다.
    미선언 액션(멤버십 위반)·화이트리스트 미스는 **HARD BLOCK**, 커넥터는 실행되지 않으며
    `connector.denied` 감사가 1건 기록된다(테스트로 단정).
  - **I2 (외부 호출 감사)**: 허용 액션은 `connector.dispatched` 1건, 차단은 `connector.denied`
    1건. 시크릿은 어떤 감사 payload에도 누출되지 않는다(§C-2).
  - **MCP/A2A 표준 경유**(§A-2.4): 독자 프로토콜 신설 없음. 외부 전송은 주입식
    `http_transport` 시임 — 선택적 벤더 SDK(pyrfc/OData 등)는 콜러블 내부 **lazy import**
    (extras)로, 코어 임포트가 절대 요구하지 않는다.
- **DRY(§B-6)**: 동일 `_take_rate_token` 본문이 4회 복제되던 패턴을 `base.py`
  `_RateLimitedConnector` 믹스인으로 추출(신규 3종만 상속, 기존 4종은 스코프 밖이라 미개조 →
  바이트 동일).
- **테스트**: `tests/tools/connectors/test_new_connectors.py` — 단위+통합+속성(채널 deny
  불변)+100회 결정성. 한국어 픽스처(채널 `사내-공지`, 문서함 `전자결재함`, 회사코드 `1000`,
  트랜잭션 `FB60`). 신규 코드 분기 커버리지 95~100%.
- **게이트**: `mypy secugent` clean 유지(163 files), ruff check/format clean(변경 파일),
  신규 베이스라인 실패 0(기존 `effects.py:111` NEL `\x85` hypothesis 엣지는 범위 밖·미악화).

### BDP Phase 4 / 항목 13 — 온프레미스·에어갭 배포 하드닝 (PG HA 기본화) (2026-06-09)

P1(온프레 배포 마감). 시장 갭 = 폐쇄망/에어갭 운영 마감(북극성 §A-2.6). 일반(인프라) +
HA 단일-writer 차익 로직은 결정적 불변조건이라 속성 기반 테스트로 고정. 명세:
`docs/specs/2026-06-09-bdp04-item13-airgap-ha-hardening.md`.

- **PG HA 기본화(opt-in → 기본)**:
  - `deploy/helm/values.yaml` — `replicaCount: 2`(앱 티어 HA) + 신규 `ha` 블록
    (`enabled: true`). `postgresql.ha`(스트리밍 복제 `replicaHost`)를 PG 경로의 **기본
    형상**으로 추가. 앱의 리더 리스(`secugent/orchestrator/lease.py` + `event_store_pg.py`
    `pg_advisory_lock`)는 **단일 PG 인스턴스에 대해** writer를 직렬화한다.
    - **정직한 범위**: ① 리더 리스에 자동 만료(TTL)가 **없고** ② 단일-writer 게이트
      (`HaWriterArbiter`)는 provisioned 상태로 라이브 쓰기 경로에 **아직 미배선**이며
      ③ 두 독립 PG 서버(primary/standby)를 가로지르는 split-brain 펜싱이 **아니다**.
      따라서 자동 페일오버가 아니라 **운영자/오케스트레이터 주도 승격**이고, 네트워크
      분단 시 구 primary 펜싱(STONITH) 또는 동기 복제로 막아야 한다. "I3, split-brain
      방지" 주장은 단일 PG 인스턴스 writer 직렬화 + read-only standby 수준으로 정정.
  - `deploy/helm/templates/deployment.yaml` — 소비처 없는 `SECUGENT_LEASE_TTL_SECONDS`·
    `DATABASE_REPLICA_URL` env를 **제거**(앱이 읽지 않아 silent no-op이었음 — 운영자에게
    잘못된 통제감을 주는 dead config). fail-closed 시크릿 가드 유지. 실제 소비처(읽기
    fan-out / TTL+heartbeat 리더 리스)가 생기면 재도입.
  - `deploy/docker-compose.yml` — `postgres`(writable primary, WAL/복제 설정 +
    신규 `postgres/init-replication.sh`로 REPLICATION 역할·`host replication` pg_hba
    엔트리·복제 슬롯 생성) + `postgres-standby`(hot standby, `pg_basebackup` 부트스트랩,
    alpine 호환 위해 `sh -c`)를 **기본 토폴로지**로. dev override는 standby `replicas: 0`.
- **에어갭 오프라인 번들**:
  - 신규 `deploy/airgap/bundle.sh` — `docker save`(앱+UI+외부 베이스 이미지) + `helm
    package` + constraints + `MANIFEST.sha256`(+선택 cosign 서명)를 자기완결적 tar로 묶음.
    인자 없이 실행 시 사용법 출력 + 비-0 종료(파괴적 동작 0).
  - 신규 `deploy/airgap/README.md` — **한국 폐쇄망 설치 절차**(반입→체크섬 검증→이미지
    적재→HA 부팅, KST 운영). 체크섬 불일치 시 **설치 거부**.
  - 신규 `deploy/constraints.txt` — 모든 런타임 의존성 **정확 고정**(`name==version`,
    byte-reproducible 목표; 불변조건 I2).
- **재현 가능 이미지 + 서명**: `deploy/Dockerfile` — `pip install -c constraints.txt`로
  정확 버전 고정(이전 "재현성 caveat" 해소), cosign 이미지 서명 절차 문서화(빌드 호스트
  단계). UI 이미지·헬스체크·비-루트 계약 불변.
- **신규 로직 모듈(코어 격리, 옵셔널 의존 0)**:
  - `secugent/deploy/airgap.py` — `build_manifest`/`verify_bundle`(무결성: 체크섬·크기·
    누락·여분 변조 전부 거부, I3), `parse_constraints`(정확-고정만 허용, 범위/마커/extras
    거부, I2), `HaWriterArbiter`(기존 lease 위 단일-writer 게이트 — 새 lease 로직 재구현
    0, deny-by-default `assert_writer`는 비-acquiring 순수 검사 `LeaseManager.is_leader`로
    구현해 "assert"가 리더를 부작용으로 점유하던 fail-open 결함 제거. 게이트는 라이브
    append 경로에 아직 미배선 — provisioned 상태). `secugent/deploy/errors.py`(`AirgapError` 계층).
    `import secugent.deploy`는 boto3/hvac/cosign를 요구하지 않음(폐쇄망 우선).
- **테스트**(`tests/deploy/test_airgap_bundle.py`, 36 통과/1 docker-skip, 신규 코드 분기
  커버리지 **100%**): 단위(매니페스트 결정성·4종 변조 거부·constraints 정확-고정/거부) +
  속성(라운드트립 항상 검증·단일 변조 항상 거부·동시 승격 writer≤1, hypothesis) +
  HA 결정성 100회 + bash 게이트 `bundle.sh` 사용법 + 인프라-게이트 통합(라이브 PG 페일오버·
  오프라인 부팅은 `-m docker`/bash 부재 시 skip). 한국어 픽스처(README 절차 + constraints
  한국어 주석 파싱).
- **§C-1 감사 보존 불변**: 본 작업은 `secugent/audit/retention.py`를 건드리지 않으며,
  6개월+ 보존 기본값(`DEFAULT_RETAIN_DAYS >= 180`)을 회귀 테스트로 고정. 단일 PG 인스턴스
  안에서는 해시체인 무결성이 보존되나, 위에 명시한 대로 **펜싱 없는 2-서버 분단**은 체인
  분기 위험이 있으므로 운영 절차(펜싱/동기 복제)로 막는다 — 코드만으로 보장되지 않음.

### BDP Phase 4 / 항목 14a — EVOLUTION dry-run + 관리자 승인 게이트 + 버전 태깅 (확률적) (2026-06-09)

P2(옵셔널리티·확장). 시장 갭 = EVOLUTION 자기개선의 **자동 적용 금지 + 관리자 승인 게이트**(§A-1
Non-goal "EVOLUTION 자동 적용" 차단의 코드 강제). 확률적 모듈(§B-4b): 한국어 골든셋 + F1/Precision/
Recall 임계 게이트. 명세: `docs/specs/2026-06-09-bdp04-item14a-evolution-approval-gate.md`.

- **신규 `secugent/evolution/approval_gate.py`** — 기존 evolution 프리미티브 위에 결선한 얇은 승인
  게이트 래퍼. 제어 결정(차단 규칙·4-eyes·relaxation·해시체인)을 **재구현하지 않고 호출**한다.
  - `EvolutionGate.propose_evolution(*, candidate, baseline, golden, proposer)` — A/B 시뮬레이션
    (baseline·candidate를 골든셋에 대해 **단일 `OversightEngine` 평가 패스**로 동시 채점 →
    메트릭과 회귀 카운트를 한 번에 도출, **시뮬레이터 포크 금지**) + 한국어 골든셋
    F1/Precision/Recall 게이트로 **proposal만** 생성. 정책을 절대 변경하지 않는다(I1). regulations
    candidate는 기존 `ProposalRepository.create(baseline=...)`의 **no-relaxation 가드**를 통과해야
    하므로 약화 제안은 `RelaxationRejected`로 거부된다(I6). 골든셋 채점은 항상 결정적
    `OversightEngine`을 경유한다(I3 단일 진실원 — 차단 규칙 재정의 없음).
  - `EvolutionGate.apply_evolution(proposal_id, *, approver)` — 관리자 **명시 승인**(기존
    `ProposalRepository.approve`의 admin·MFA·4-eyes 강제)을 통과한 뒤에만 `regulations_version`을
    semver patch +1로 증가·태깅(`RegulationVersion`)하고, §C-2 감사 이벤트를 발행한다. 승인 거부
    (4-eyes/admin/MFA)는 예외로 전파되며 정책·버전은 **절대 변하지 않는다**(I1 하드 단언 테스트).
    proposable=False proposal은 승인과 무관하게 `EvolutionNotProposable`로 거부(I2). 적용 완료된
    proposal은 repo에서 `merged`로 전이되고 재적용은 `InvalidProposalTransition`으로 거부 — 멱등 누수 없음(I4).
  - **§C-2 감사**: `gate="evolution_approval"`, `decision="approve"`, `regulations_version`(새 버전),
    `prev_event_id`(**실제 테넌트 체인 꼬리에서 유도**), `rule_of_two_axes`(②③ — 민감 접근+상태변경),
    `input_hash`, KST `timestamp`(+09:00), `rationale`(한국어)를 append-only 해시체인
    (`ChainedEventStore`)에 기록. `verify_chain` 통과를 테스트로 고정. 새 게이트 값·로그 필드는 추가하지 않음.
  - **폐쇄망**: KST는 고정 `timezone(+09:00)`로 처리(tzdata 의존 없음). optional extra·외부 SaaS
    의존 없음 — 전부 코어 프리미티브 호출.
- **테스트** `tests/evolution/test_approval_gate.py` (20건): I1~I6 하드 단언 + 한국어 골든셋 F1 게이트
  + 속성 기반(hypothesis: 버전 단조 strictly-increasing, 메트릭 ∈ [0,1]) + 방어적 엣지(비semver
  fail-fast). 신규 코드 **분기 커버리지 100%**.
- **리뷰 후속 하드닝(reviewer⇄fixer)** — 적대적 검토 8건 결함 수정:
  - **§C-1 감사 fail-closed**: 적용 경로에서 감사 sink(store)가 없으면 정책을 바꾸기 전에
    `EvolutionAuditUnavailable`로 거부한다(이전엔 store=None이면 감사 이벤트 없이 정책이 조용히
    변경될 수 있었음 — fail-OPEN 제거). 감사는 버전/정책 cutover **전에** 기록(append-audit-then-mutate).
  - **승인 복구성(no consumed-approval)**: 감사 쓰기 실패 시 cutover는 중단되지만 승인은 'approved'로
    보존되어 재시도로 적용을 완수한다(이전엔 `repo.approve` 이후 감사 실패 시 proposal이 영구
    `approved`로 굳어 모든 재시도가 차단됨).
  - **회귀 게이팅 실효화**: `regression.missed_blocks`(baseline 차단 경로의 신규 누락)를 결정에 실제
    반영 — 집계 F1이 높아도 차단 coverage를 줄이는 candidate는 `proposable=False`(이전엔 회귀 산출이
    버려지고 집계 F1만 비교).
  - **퇴화 골든셋 가드**: 음성(allow) 케이스가 없거나 표본 < 2인 골든셋은 과차단을 검출할 수 없으므로
    deny-by-default로 거부(이전엔 `pattern='*'` 과차단 candidate가 F1=1.0으로 통과).
  - **타입 안전 감사 sink**: `store: object | None`을 구조적 `_AuditSink`/`_ChainReader` Protocol로
    교체하고 `# type: ignore[attr-defined]` 제거 — §C-2 쓰기 지점이 정적 검증됨(§B-3).
  - **prev_event_id 정합성**: 게이트 인스턴스 로컬 필드 대신 store의 실제 테넌트 체인 꼬리에서 유도해
    공유 체인의 실제 append 순서와 §C-2 논리 체인을 일치시킴.
- **2차 적대적 검토 하드닝(reviewer⇄fixer, +6 회귀 테스트)** — 승인 게이트 우회 3건 수정:
  - **[High] 감사-복구 경로의 승인 우회 차단**: 감사 쓰기 실패로 proposal이 'approved'(미적용)로 굳은 뒤
    재시도 시, `state=='approved'`를 'authz 불필요'로 취급해 `repo.approve`(admin·MFA·4-eyes의 유일한 강제
    지점)를 건너뛰던 결함을 수정. 복구 경로에서도 `_guard_four_eyes`를 재강제하고, **직전 승인을 기록한 바로
    그 관리자**만 미완 적용을 완수할 수 있게 검증(`_assert_resumes_prior_approval`) — 비-admin·원 제안자·다른
    admin의 적용 가로채기 봉쇄(§A-1 EVOLUTION 자동 적용 금지 유지).
  - **[High] 테넌트 바인딩(교차 테넌트 승인 차단)**: 게이트가 소유 테넌트를 묶지 않아 다른 테넌트 admin이
    승인·적용하고 §C-2 감사가 엉뚱한(공격자) 테넌트 체인에 적재되던 결함을 수정. proposal 생성 시 제안자
    테넌트를 소유 테넌트로 바인딩하고, `apply_evolution`에서 `approver.tenant_id == owner_tenant`를 fail-closed로
    강제하며, 감사 이벤트·`prev_event_id`를 **소유 테넌트 체인**(approver 자칭 테넌트가 아님)에 기록(테넌트 격리).
  - **[Medium] 회귀 분류 단일 진실원**: 회귀 삼중 분류(neutral/false_block/missed_block)를
    `policy_regression.classify_block_pair` 순수 함수로 추출하고 `PolicyRegressionRunner.evaluate`와 게이트
    A/B 채점기가 **공유 호출** — 인라인 byte-identical 포크 제거(spec I3 "PolicyRegressionRunner 재사용" 충족).

### BDP Phase 4 / 항목 14b — NHI/에이전트 ID 거버넌스 레지스트리 (시간제한 권한·감사가능 접근) (2026-06-09)

P2(옵셔널리티·확장). 시장 갭 = 비인간 ID(NHI)·에이전트 ID 거버넌스(레지스트리·시간제한 권한·
감사가능 접근, §A-3 P2.2). 결정적 모듈(거버넌스): 동일 입력+동일 시계 → 동일 판정. 명세:
`docs/specs/2026-06-09-bdp04-item14b-nhi-registry.md`.

- **신규 `secugent/identity/registry.py`** — 비인간 ID(에이전트/서비스 계정) 레지스트리.
  - `NhiRegistry.register/grant/revoke/check_access` — NHI 등록 + **시간제한 권한 부여**
    (`expires_at` KST) + fail-closed 접근 판정. 권한 *결정*은 rbac/core가 단일 출처이며 본
    모듈은 **NHI 축만**(등록 여부·만료·소유 테넌트) 판정한다 — 결정 재구현 없음(I4).
  - **I1 deny-by-default**: 미등록 ID → `unregistered`, grant 없음 → `no_grant`, 만료 →
    `expired`, 테넌트 불일치 → `tenant_mismatch`. 판정은 좁은 `AccessReason` `Literal`에 대해
    **소진적**이라 알 수 없는 상태가 allow로 떨어지지 않는다(잘못된 상태 표현 불가).
  - **fail-fast 부여 가드**: 미등록 ID 부여·이미 만료된 `expires_at`은 `ValueError`로 즉시
    거부(허공 권한·죽은 grant 0). `PermissionGrant` 모델 검증으로 `expires_at <= granted_at`
    윈도우와 오형식 permission 토큰을 시스템 경계에서 차단(§B-8).
  - **I3 만료 단조성(닫힌 만료)**: `now < expires_at` ⇔ 유효, 경계 `now == expires_at`은
    만료(거부). hypothesis 속성 테스트로 ±1일 오프셋 전역 고정 + 100회 결정성 증명.
- **§C-2 감사(I2)** — 모든 `check_access`는 `gate="nhi_access"`, `decision∈{approve,reject}`,
  `rule_of_two_axes`, `regulations_version`, `input_hash`(id+permission+tenant), KST `ts`를
  *요청 테넌트* 체인에 기록(allow·deny 모두). 기존 append-only/해시체인 스토어
  (`EventStoreAccessAuditSink`)를 **재사용**(새 감사 스키마 0) — `record_access`만 추가.
  sink 실패는 로깅하되 판정을 약화하지 않음(거부는 거부 유지, fail-closed). 접근 이벤트
  `ts`는 레지스트리 시계(KST `+09:00`)를 **명시 전달** — `Event` UTC 기본값 폴백을 제거해
  형제 `_denial_audit_event`(rbac)와 동일 타임존 계약을 보장(체인 내 NHI 행 시간정렬 일치).
- **rbac 결선(수정 `secugent/api/rbac.py`, 재구현 금지)** — `require_nhi_permission(*roles,
  registry, permission, nhi_resolver, nhi_audit_sink=None, ...)` 가드 추가. 기존
  `require_role`(역할·테넌트 단일 출처)을 **호출**해 인간 RBAC를 먼저 통과시키고, 그 위에 NHI
  축을 **AND**로 합성한다. 역할 통과+NHI 만료 → 403, 미해결 NHI(resolver=None) → fail-closed
  403. 응답은 최소 `"forbidden"`(역할·테넌트·nhi 누출 0). sync/async resolver 모두 지원.
  **I2 합성 경계 fail-fast**: `nhi_audit_sink`를 레지스트리에 전파(`attach_audit_sink`)하거나
  레지스트리가 자체 sink를 보유해야 하며, 둘 다 없으면 가드 구성 시 `ValueError`로 즉시 거부
  (감사 없이 접근이 통치되는 무감사 구멍 차단). `audit_sink`는 인간 RBAC 거부만 감사하므로
  NHI 축 감사를 보장하지 못한다는 점을 명시 차단.
- **테스트** `tests/identity/test_registry.py` (35건): 단위(등록·부여·취소·5종 거부 사유) +
  통합(rbac 합성 가드 4상태·해시체인 편입·async resolver) + **가드 경계 I2**(`require_nhi_permission`
  end-to-end allow/deny가 해시체인에 정확히 1건의 `nhi_access` 이벤트를 적재 + 무감사 가드 구성
  fail-fast) + **KST ts 계약 고정**(in-memory 이벤트 `ts.utcoffset()==+09:00`) + 속성(만료 단조성)
  + 100회 결정성 + audit-sink 실패 fail-closed 하드 단언. 신규 코드 **분기 커버리지 100%**.
  한국어 픽스처: KB국민은행 야간 정산 배치 서비스 계정(§C-3).
- **폐쇄망 우선**: 레지스트리는 인메모리·의존 0(에어갭 안전), KST는 고정 `timezone(+09:00)`
  (tzdata 의존 없음). 감사 durability만 주입 sink에 위임.

### BDP Phase 3 / 항목 8 — 엔터프라이즈 콘솔: UI ↔ 백엔드 와이어링 + AuditExplorer (2026-06-09)

P1(GA). 상용 티어의 얼굴인 엔터프라이즈 콘솔을 완성. 칸반 + 위험 타임라인 + STEER 입력 +
승인 큐 + **감사 탐색기**를 실 백엔드에 결선하고 로딩/에러/빈/정상 4상태를 모두 처리한다.
**서버가 권위**: UI는 서버 결정을 표시만 하고 클라이언트측 재판정을 절대 하지 않는다(I1).

- **신규 `ui/src/components/AuditExplorer.tsx`** + 단위 테스트 10건: 감사 이벤트 표(필터: actor/type/
  run_id/gate) + **해시체인 검증 상태 배지**(검증됨/불일치/확인 불가, aria-live). `pages/AuditExplorer.tsx`
  라우트 셸과 구분되는 **재사용 패널**. 4상태(로딩/에러/빈/정상) 전부 처리, WCAG AA(필터 라벨·표 scope·
  role="grid"·aria-live·키보드 페이지네이션).
- **`ui/src/components/ApprovalQueue.tsx` 재결선**: `lib/consoleApi` 경유로 4상태 처리 + RESTful
  `POST /api/approvals/{id}/grant|reject` 사용(기존 잘못된 `/api/approve`·`/api/approvals/pending` 경로 정정).
  단위 테스트 6건(로딩/에러/빈/정상 + grant/reject 경로 + viewer 비활성).
- **신규 `ui/src/lib/consoleApi.ts`**: 콘솔 REST 클라이언트 + 타입(`AuditEvent`·`PendingApproval`·
  `RiskPoint`…). 서버를 전송만 — 승인/위험점수를 재판정하지 않음. `ConsoleApiError(status)`로 상태코드 분기.
- **누락 콘솔 엔드포인트(`secugent/api/main.py`, 전부 기존 서비스 위임 — 신규 통제 로직 0)**:
  - `GET /api/approvals?status=pending` → `EventStore.list_pending_approvals`(테넌트 필터). status는 `Literal`
    이라 다른 값은 경계에서 **422**(절대 "전체 승인"으로 확대 안 함).
  - `POST /api/approvals/{id}/grant|reject` → **단일 출처** `_apply_approval_decision` 헬퍼로 위임(legacy
    `POST /approve`와 **동일한 통제+감사 경로** 공유 — consumed-set 이중지불 가드·§C-2 `approval.{decision}`
    이벤트 append, I1/I2). 이중 grant → **409**, viewer → **403**, 미존재 id → **400**.
  - `GET /api/risk/timeline?run=` → `EventStore.list_events(event_type="step.risk")`를 `_risk_points_from_events`
    순수 투영(`{ts,total,decision,step_id}`, ts ASC)으로 집계. **score 없는 이벤트는 스킵**(크래시 0, fail-soft).
  - `GET /api/audit/events?gate=` → gate 필터를 **SQL 쿼리에 push-down**(`EventStore.list_events(gate=)` +
    `count_events`). OFFSET/LIMIT·total·pages가 **필터링된 집합 위에서** 계산되므로, 일치 이벤트가 뒷 페이지에
    있어도 1페이지에서 노출된다(이전엔 페이지 슬라이스 *후* 필터를 적용해 빈 1페이지+pages>1 발생).
    동시에 죽은 `import math` 제거.
- **I2 (감사)**: 승인/거부는 서버측 **§C-2 완전 준수** `approval.{decision}` 이벤트를 남긴다 — `gate="hitl"`,
  `decision`, `rationale`(사유), `rule_of_two_axes`, `regulations_version`, `input_hash`(scope sha256)를 모두
  스탬프(HITL 라우트와 동일 페이로드). 이로써 EU AI Act / KR AI 기본법 증빙 리포트(`compliance/report.py`
  `_extract_gate` deny-by-default)에 콘솔 승인이 **누락 없이** 포함된다. STEER는 기존
  `ws.py` WS + `POST /steer` 경로 재사용(추가 변경 없음).
- **해시체인 편입 수정(SECURITY_CONTRACT §10.1, High)**: 콘솔 `approval.{approve,reject}`·머지된
  HITL `hitl.decided`·`audit.chain_verified` 결정 게이트 이벤트가 **원시 `EventStore.append_event`로 append돼
  해시체인을 우회**하던 결함을 수정. `verify_chain`은 `event_chain` row만 순회하므로, 우회된 이벤트는 체인
  **밖**에 있어 내부자가 콘솔 grant/reject 감사 row를 삭제·변조해도 검증이 여전히 valid로 보고됐다(§C-2
  위변조 검출·EU AI Act Art.12 무효화). `AppState.audit_chain`(단일 캐시 `ChainedEventStore`, STEER 핸들러와
  동일 인스턴스 공유)을 도입하고 4개 결정 게이트 appender 전부를 이 경유로 전환 — 이제 콘솔 승인 이벤트가
  체인에 편입되고, 저장 payload 변조 시 `verify_chain`이 `AuditChainBrokenError`로 fail-closed한다. 회귀
  테스트 `tests/api/test_console_audit_chain.py`(체인 커버리지·변조 검출·소스 게이트 5건). **주의**: 별개의
  기존(HEAD 선존) 결함으로 `POST /api/audit/verify` 라우트는 function-local `BaseModel` + `from __future__
  import annotations` 탓에 body가 query로 오바인딩돼 HTTP 422 — 본 finding 범위 밖이며 체인 불변식은 엔진
  레벨(`audit_chain.verify_chain`)로 입증.
- **`pages/AuditExplorer.tsx` 라이브 결선**: `#/audit` 라우트가 이제 백엔드 결선 패널(`components/AuditExplorer`)을
  렌더한다 — 페이지 셸은 `<main>` 랜드마크 + 헤딩만 제공하는 **얇은 래퍼**. 이전의 `{items}`-읽기 포크(서버는
  `{events}` 반환 → 프로덕션 0행)는 제거. 인증 헤더를 패널 관례(`X-User-Role`)로 일원화(Bearer↔role 분기 해소).
- **`RiskTimeline` 결선**: `role`+`runId`가 주어지면 `GET /api/risk/timeline`(run-scoped 내구 이력)을 소비해
  WS 라이브 스트림과 병합 — 이전엔 엔드포인트+`fetchRiskTimeline`이 호출부 없는 dead code였다.
- **AuditExplorer fail-closed(SECURITY_CONTRACT §10.1)**: 해시체인이 `broken`이면 빨간 배너만 렌더하고
  **이벤트 표·필터·페이지네이션을 전부 withhold**(무결성 손상 데이터 비노출). 필터는 서버에 `gate`로 전달돼
  **전체 테넌트 이력**을 검색(디바운스 + 필터 변경 시 1페이지 리셋) — 이전엔 현재 50행 페이지만 검색.
- **신규 E2E `ui/src/e2e/console_flow.spec.ts`** (Playwright) + `ConsoleHarness.tsx`(test-only, `import.meta.env.DEV`
  가드로 프로덕션 번들에서 tree-shake): 승인 큐→grant→감사 뷰 갱신→STEER 입력의 **UI 흐름 스모크 테스트**를
  인메모리 백엔드 스텁(sessionStorage 지속)으로 백엔드 오프라인에서도 결정적으로 검증한다. **주의**: 이 스텁은
  자신이 푸시한 이벤트를 다시 읽으므로 **서버측 §C-2 감사 방출(I2)을 증명하지 않는다** — I2의 권위 있는 검증은
  Python 통합 테스트(`test_console_endpoints.py`: grant/reject가 `approval.{decision}` 이벤트를 남기고 payload가
  §C-2 필드를 담는지 단언)가 담당한다. **헤드리스 Windows에서 3/3 통과**.
- **테스트**: API 통합 18건(`tests/api/test_console_endpoints.py`) + 스토어 단위(gate 필터/페이지네이션 회귀 3건) +
  UI 컴포넌트(AuditExplorer 13·ApprovalQueue 6·DisplayPanels 8) + E2E 3건. **한국 금융 픽스처**(`kb-bank`/
  `shinhan-bank`, 한국어 사유 문자열). 게이트: ruff ✓ / mypy strict clean(무회귀) / pytest 베이스라인 부분집합
  (신규 실패 0) / tsc ✓ / vitest ✓.

### BDP Phase 3 / 항목 11 — 멀티테넌트 SSO/OIDC + RBAC 엔터프라이즈 티어 (2026-06-09)

P1(GA). `tenant_loader`·`tenancy`(Principal/TenantId/contextvar) 토대 위에 엔터프라이즈
**SSO(OIDC) + 역할 기반 접근통제(RBAC)**를 패키징. 통제 판정을 재구현하지 않고 기존
출처만 호출한다 — 인증은 `api/security.current_principal`, 테넌시는 `core/tenancy`,
토큰 검증/JWKS는 `api/auth.OIDCAuthenticator`. UI/래퍼는 결정하지 않고 서버가 권위.

- **신규 `secugent/api/rbac.py`**: `Role(StrEnum){ADMIN, APPROVER, VIEWER, OPERATOR}` 엔터프라이즈
  권한 어휘 + `require_role(*allowed, audit_sink=None)` 엔드포인트 가드(FastAPI 의존성).
  권한 부족 → **403(정보 최소화: detail="forbidden", 역할/테넌트 미노출)**, 동시에 **테넌트 경계 강제**.
  4번째 역할 `APPROVER`는 기존 3-역할 `Principal`을 건드리지 않고 명시 그룹(`sg-approvers`)에서
  **가산적**으로만 승격(역할을 절대 강등하지 않는 monotone).
- **신규 `secugent/api/oidc.py`**: OIDC **discovery**(`.well-known/openid-configuration`) 파싱 +
  `authenticator_from_discovery(...)` 빌더. 토큰 검증은 기존 `OIDCAuthenticator`를 **재사용**(crypto 포크 0).
  discovery·JWKS fetcher 모두 **주입형** → 자체 IdP/에어갭에서 외부 SaaS 없이 동작(I3). httpx는 lazy import.
- **I1 (테넌트 격리)**: 한 테넌트 사용자는 다른 테넌트 데이터 접근 불가 — `enforce_tenant_boundary`가
  단일 출처. 경계는 **리소스 소유 테넌트**로 판정: `{tenant_id}` 경로 파라미터가 있으면 그것을, 없으면
  (지배 라우트 `/runs/{run_id}`·`/api/hitl/{approval_id}`) 주입 `tenant_resolver`가 id→소유 테넌트를 조회.
  `require_tenant=True`면 소유 테넌트 증명 불가 시 **fail-closed(403)** — URL 문자열만 보던 silent no-op
  (교차 테넌트 IDOR) 차단. 교차 테넌트 → 403(대상 테넌트 id 미노출).
- **I2 (Deny-by-default)**: 미상/미지정 역할 → 최소권한 VIEWER(절대 승격 0). `allowed`가 비면 deny-all.
  미인증은 기존 `current_principal` 경로로 401.
- **I3 (폐쇄망)**: discovery·검증이 주입 fetcher로 에어갭 동작. 만료/서명 불일치 → 401(OIDCError),
  토큰/키 material 미노출. discovery 실패 → `OIDCDiscoveryError`(fail-closed, 원인 타입만).
- **I3a (transport 신뢰)**: `discover`가 issuer를 **https 강제**(`allow_insecure_transport` opt-in 시에만 http)
  + `jwks_uri`·`token_endpoint`·`authorization_endpoint`를 issuer **origin(scheme+host)에 핀** → 변조된
  `.well-known`이 `jwks_uri`만 공격자 키로 바꿔 토큰 위조하는 key-substitution 경로 차단.
- **I4 (§C-2 감사)**: 권한/접근 거부(역할·테넌트 경계)는 §C-2 결정-게이트 이벤트(`gate="rbac"`,
  `decision="reject"`, `rule_of_two_axes`, `regulations_version`, `input_hash`, KST ts)로 기록(주입
  `EventStoreAccessAuditSink` 경유). **sink에 `ChainedEventStore`를 주입하면 변조-증거 sha256 해시
  체인에 편입**(SECURITY_CONTRACT §10.1, `verify_chain`로 검증·1바이트 변조 탐지) — 평문 `EventStore`
  주입은 체인 밖 단순 append(dev/test). **감사 sink 실패가 보안 결정을 약화시키지 않음**(403 유지).
- **와이어링**: `api/security.require_rbac_role`(기존 rank-기반 `require_role` 미잠식) +
  `api/auth.authenticator_from_issuer`(discovery→authenticator) 브리지 추가. 기존 17개 라우트·테스트 무회귀.
- **테스트**(신규 `tests/api/test_rbac.py` 24건 + `test_oidc.py` 13건): 단위(역할 매핑·경계·deny-all) +
  통합(VIEWER→ADMIN 403, 교차 테넌트 거부, OIDC 정상/만료/서명무효) + discovery(에어갭 파싱·누락필드·
  fetcher 예외) + 속성기반 hypothesis(역할 매핑 전역성·경계 불변) + **한국 금융 픽스처**(`kb-bank`/`shinhan-bank`).
  신규 코드 **라인·분기 커버리지 100%**. mypy strict clean. 베이스라인 실패셋 부분집합(신규 실패 0).

### BDP Phase 3 / 항목 9 — 컴플라이언스 증빙 자동생성 (EU AI Act·AI기본법·N²SF) (2026-06-09)

P1(GA). 규제 순풍을 직접 돈으로 바꾸는 고가치 상용 기능. append-only 감사로그를
규제 프레임워크 섹션으로 **집계**해 증빙 리포트를 자동 생성한다. **사실 집계만**(법률
자문 생성 아님), **읽기 전용**(새 감사 스키마 도입 0 — 기존 §C-2 결정-게이트 이벤트만
읽음), **결정적**(동일 입력 → 바이트 동일 리포트). 통제 판정은 재구현하지 않고 기존
`audit/export.py`의 `EDiscoveryExporter.iter_events` 1차 출처만 호출.

- **신규 `secugent/compliance/`**(`__init__.py`·`report.py`, Enterprise 티어): `build_report(*, framework,
  tenant_id, period, exporter, generated_at=None) -> ComplianceReport`. `ComplianceReport`는
  `framework: Literal["eu_ai_act","kr_ai_basic_law","n2sf"]`의 **frozen dataclass**.
  - **EU AI Act** — Art.11(기록 보유)·Art.12(로깅 카운트)·Art.14(인간 감독: HITL/STEER/Plan Review).
  - **한국 AI 기본법** — 고영향 영향평가(HITL/Plan Review + 설명 첨부) + 인간 감독(STEER/HITL).
  - **N²SF** — 접근 통제·감사 로깅·인간 검토 통제 매핑.
- **I1 추적성(날조 0)**: 모든 섹션의 모든 주장은 실제 `event_id`로 역추적(`source_event_ids ⊆`
  공급된 이벤트 id). 어떤 섹션도 존재하지 않는 id를 만들지 않는다.
- **I2 결정성**: 모든 리스트 `event_id` 사전순 안정 정렬. `generated_at` 명시 주입 시 타임스탬프까지
  결정적 → **100회 결정성 테스트**로 바이트 동일 증명.
- **I3 한국어·KST**(§C-3): AI기본법·N²SF 리포트는 섹션 제목/본문 한국어, 생성 시각 KST(+09:00).
  기간 경계도 이벤트 UTC ts를 **KST 날짜로 변환** 후 `[from, to]` 포함성 판정.
- **§C-1 워터마크**: 모든 리포트 헤더에 AI 산출물 식별 마커(`AI_WATERMARK`). 고영향 의사결정에
  설명(rationale)·결정·Rule of Two 축 요약 첨부.
- **결손/빈 기간**: 근거 0개 섹션은 생략하지 않고 `status="no_evidence"`로 "증빙 없음" 명시.
  빈 기간(이벤트 0)은 크래시 없이 전 섹션 no_evidence 리포트. 잘못된 framework 문자열 → `ValueError`
  (fail-fast). 비결정-게이트 이벤트(payload에 gate 없음)는 Art.12 로깅 카운트에만 포함.
- **격리**: compliance는 core/audit의 import 그래프에 **포함되지 않음**(단방향 compliance→audit.export).
  회귀 테스트가 core/audit 소스에 `secugent.compliance` 미참조를 검증.
- **신규 템플릿**(`docs/compliance/templates/{eu_ai_act,kr_ai_basic_law,n2sf_mapping}.md`).
- **테스트**(신규 `tests/compliance/test_report.py` 32건): 단위(필수 섹션 완전성·framework 검증·
  워터마크·결손·고영향 설명 첨부) + 속성기반 hypothesis(임의 이벤트셋에서 I1 날조0·I2 결정성) +
  시나리오 골든 3종(프레임워크별 안정 회귀) + 100회 결정성 + **한국 금융 픽스처**(전자금융감독규정
  맥락 결정 게이트). 신규 코드 **라인·분기 커버리지 100%**.
- **하드닝(적대적 리뷰, 2026-06-09)** — 규제 제출 산출물로서의 누출/완전성 갭 10건 정정:
  - **PII 마스킹**(findings 1·8): 자유서술 `rationale`/`decision`/`gate`를 렌더 전
    `audit.export.scrub_pii_for_disclosure`(email/KR RRN/**KR 휴대폰**)로 마스킹. write-time
    `redact_string`이 놓치는 KR 휴대폰 형식까지 e-discovery `--redact pii`와 동등 강도 보장.
  - **마크다운 인젝션 중화**(finding 4): payload의 개행을 한 줄로 평탄화 + 줄머리 제어문자
    이스케이프 → 위조 섹션 헤더/불릿이 문서 구조로 승격 불가(I1 렌더 계층).
  - **대량 이벤트 완전성**(findings 3·6·7·10): 100k 캡 `iter_events` 대신 신규
    `iter_all_events`로 소진까지 페이징 + 기간 시작 UTC `since` 푸시다운 → 가장 오래된 기간 내
    이벤트 미누락, Art.12/N²SF 카운트 정확(BDP §9.7 대량 스트리밍).
  - **뒤집힌 기간 fail-fast**(finding 5): `start > end` → `ValueError`(거짓 음성 'no_evidence' 방지).
  - **테넌트 검증/인가 계약**(finding 2): `tenant_id`를 `TenantId` 정규식으로 경계 검증.
  - **해시체인 무결성 증명**(finding 9): 주입형 `verify_integrity` 검증기로 체인 검증 후 헤더에
    무결성 단정. 검증 통과 시에만 'append-only is active' 단정, 실패/미주입 시 'UNVERIFIED'/
    'unknown'으로 한정(과대주장 금지, fail-closed). 격리 유지(라우트가 `verify_chain` 주입).
  - 회귀 테스트 9건 추가(tests/compliance/test_report.py, 총 41건).

### BDP Phase 3 / 항목 12 — 비용·예산 가드레일 강제 와이어링 + 외부 KMS 서명자 (결정적·merkle) (2026-06-08)

P1(GA). 수익화 애드온의 무결성 보증축. (a) 이미 존재하던 `CostLedger.enforce_or_raise`를
실행 파이프라인에 **fail-closed로 결선**, (b) `merkle.py` 스켈레톤이었던 외부 KMS 서명자
(`AwsKmsProvider`·`VaultTransitProvider`)를 **실서명자로 완성**. 통제 판정은 재구현하지
않고 기존 코어 원장·머클 1차 출처만 호출(불변 단일 출처).

- **예산 가드레일 와이어링**(`secugent/orchestrator/runner.py`): 비용 쿼터 검사를 **사람
  승인 게이트 *앞*으로 이동**. 기존엔 승인 후에만 enforce했기에 `auto_approve=False`인
  초과 런이 `AWAITING_APPROVAL`에 영구 정체했다(절대 받아선 안 될 승인을 기다리며).
  이제 PLANNING 직후 `_quota_exceeded(run_id, tenant_id)` 헬퍼가 `enforce_or_raise`
  ─판정 단일 출처─를 호출해 초과 시 즉시 `FAILED("quota_exceeded")`로 거부하고 디스패처에
  **도달하지 않음**(§12.6 I1, silent 통과 0). 리뷰어가 어차피 예산이 거부할 계획을 승인할
  일도 없어짐. 원장 미부착(legacy) ⇒ 게이트 없음(하위호환). malformed tenant_id는 런을
  크래시시키지 않고 검사 skip. 이로써 `test_runner_quota.py::test_quota_exceeded_run_fails_without_exception_propagation`
  베이스라인 실패가 **해소**(이제 PASS).
- **외부 KMS 서명자 완성**(`secugent/enterprise/kms.py`, `# SPDX: LicenseRef-SecuGent-Enterprise`):
  `AwsKmsProvider(*, region, client=None)`는 AWS KMS Sign/Verify(`MessageType=DIGEST` —
  머클 루트는 이미 SHA-256 다이제스트), `VaultTransitProvider(*, url, client=None, token=None)`는
  Vault Transit `sign_data`/`verify_signed_data`(`prehashed=True`). 둘 다 코어
  `KmsProvider` Protocol(`sign(*, root_bytes, key_id)->bytes`,
  `verify(*, root_bytes, signature_bytes, key_id)->bool`)을 정확히 준수 → `SignedMerkleRoot.verify_against`가
  Local↔AWS↔Vault **단일 추상화로 동작**(I3). `boto3`/`hvac`는 **지연·호출시점 옵션 임포트**
  (`require_enterprise` 게이트) — 모듈 import 시 둘을 부르지 않으므로 슬림 설치에서도
  `import secugent.enterprise.kms`와 코어 `LocalHmacKmsProvider` 경로 정상. 스켈레톤
  `pragma: no cover` 제거.
- **fail-closed 서명 정책**(§B-8): KMS 무응답/권한오류/빈응답(서명필드 누락)은 **sign 경로에서
  명시 예외 `KmsSignatureError`**(삼키지 않음 — 빈 서명으로 seal하지 않음). **verify 경로**의
  미등록 키·백엔드 불일치는 `False`로 surface(무결성 불일치를 *감지*, `LocalHmacKmsProvider.verify`와
  동형) — 감사 읽기 경로가 크래시 대신 확정 판정 반환. 미설치 extra 가드(`EnterpriseFeatureUnavailable`)는
  transport 래퍼에 가려지지 않고 그대로 전파(설정오류 ≠ KMS오류).
- **테스트**(신규 `tests/audit/test_kms_providers.py` 40건 + `tests/cost/test_quota_enforcement.py` 6건):
  §B-4a 3중 하네스 — 단위(sign/verify 라운드트립·원바이트 passthrough·모든 실패 명시 raise) +
  속성기반(임의 루트 라운드트립 True/변조 False) + 시나리오 회귀(Local↔AWS↔Vault 단일 Protocol
  interop) + **결정성 100회**(동일 루트·키 → 동일 sign/verify, distinct==1). **KMS transport
  (boto3/hvac client) 모킹** — 라이브 클라우드 호출 0. 지연 임포트 가드(extra 부재 시
  `EnterpriseFeatureUnavailable`)·실 클라이언트 빌드 경로 모두 커버. 쿼터 측은 default
  config(`auto_approve=False`)로 초과런 fail-closed·감사기록(run.failed)·실원장 캡 도달 후 차단·
  하위호환 검증. 한국어 픽스처(`kb-bank` / KB국민은행 일일 감사 seal 키, §C-3). 신규
  `enterprise/kms.py` 라인·분기 커버리지 **100%**, `audit/merkle.py` 97%(기존 LocalHmac
  미등록키 1라인 제외). 기존 `test_aws_kms_skeleton_raises`는 구현 완료에 맞춰 갱신.

#### 적대적 검토 후속 수정 (2026-06-09)

- **malformed/누락 tenant_id는 이제 fail-CLOSED**(`runner.py`, findings 1·6): 이전 게이트는
  `TenantId(tenant_id)` ValueError 시 검사를 **skip**(=허용)했다 — deny-by-default(A-2 #2)
  위반·예산 우회. `_quota_exceeded`를 `_quota_gate`로 교체해 ① 원장 부착 상태에서 tenant_id
  누락 ② 정규식 위반(빈문자·대문자·선행하이픈·63자초과·제어/경로문자)을 **`FAILED("invalid_tenant")`**로
  거부, 디스패처 미도달. 누락 tenant가 전역 `"unknown"` 예산을 암묵 공유하던 L465 경로도 차단.
- **스펙 명령 per-step 캡 구현**(`sub_agent.py::_run_step`, findings 2·5·9·10): 런 레벨 1회
  게이트만으론 admission 시 예산내였다가 실행 중 캡을 넘는 다중스텝 런이 무한 초과 가능했다.
  `SubAgent`에 `CostLedger`를 결선하고 각 스텝 **착수 전** `enforce_or_raise_sync(step.tenant_id)`로
  재검사 → 초과 시 `quota_exceeded` 아웃컴으로 **스텝 거부·런 halt(fail-closed)**, 부작용 미발생.
  SUB는 스레드풀 워커(이벤트루프 無)이므로 **동기** 원장 표면(`enforce_or_raise_sync`/`quota_check_sync`)을
  추가하되 판정은 `_decide`/`_raise_if_exceeded` 단일 출처 공유(중복 구현 0). 런너 사전 게이트는
  **빠른 거부**로 유지(대체 아님). 프로덕션 `api/main.py::_sub_factory`에 원장 주입.
- **verify() 가용성 오류 ≠ 변조 판정**(`kms.py`, finding 7): 이전 `except Exception: return False`는
  네트워크 타임아웃·throttle·5xx를 *변조*로 오판했다. AWS는 botocore `Error.Code`(KMSInvalidSignature/
  NotFound 등)로, Vault는 예외 클래스명(InvalidPath/Forbidden/InvalidRequest)으로 **확정 무결성
  판정만 `False`**, 그 외 transport/가용성 오류는 신규 **`KmsVerificationUnavailable`**로 raise →
  감사 리더가 '변조'가 아닌 '검증불가'를 표시(§C-1). 비ascii Vault 서명은 확정 malformed→False.
- **KMS transport 정적 타입화**(`kms.py`, finding 4): `Any`였던 `_client`/`_kms()`/`_vault()`를
  최소 `Protocol`(`_AwsKmsClient`/`_VaultClient`)로 교체 → boto3/hvac 호출 kwarg명·반환shape를
  mypy --strict가 정적 검증(오타·키명 변경 catch). 백엔드 응답은 coercion 전 `isinstance` 검증.
  주입 fake·지연 빌드 모두 그대로 동작.
- **동시 admission race = 정직한 잔여로 문서화**(`accounting.py`/`runner.py`, finding 8/edge 12.7):
  최초안의 투기적 atomic 예약 admission 원시기능(예약 상태 딕셔너리 + 예약·해제 API)은 **어떤
  라이브 경로에도 결선되지 않은 과추상화**(finding 1)였으므로 **제거**했다 — 런너 사전게이트
  (`_quota_gate`)와 `SubAgent`는 모두 racy한 순수 read 표면(`enforce_or_raise` 계열)을 쓴다.
  동시 동일테넌트 admission이 같은 pre-spend를 읽고 함께 캡을 넘길 수 있는 동시성 초과는
  **방어심층이 아니라 정직한 잔여(documented residual)**로 남긴다: 현재 바운드는 **이미 기록된
  (외부/이전·cross-run) 지출뿐**이고, in-run 자가발생 지출은 유일한 per-call 레코더
  (`ModelCascadeRouter.record_call`→`CostLedger.record`)가 라이브 디스패치에서 아직 호출되지 않아
  **라이브로 기록되지 않는다**. per-run 지출은 admission 시점에 미상이므로(모델 콜 단위 측정)
  예약량이 임의가 되어 strict atomic 예약은 **의도적으로 미탑재**. 이 잔여는 `_quota_gate`
  docstring과 `test_no_unwired_reservation_api.py`가 요구하는 정직한 표현 그대로다
  (§B-8 fail-fast, §12.6 I1 — 통제 강도를 부풀린 감사기록 0).
- **테스트 추가**(findings 회귀): `test_per_step_enforcement.py`(per-step halt·동기/비동기 판정
  parity 속성테스트) 신규 + `test_no_unwired_reservation_api.py`(제거된 예약 API·과장 docstring·
  과장 CHANGELOG 감사기록이 되살아나지 않도록 고정하는 삭제 가드) 신규, `test_quota_enforcement.py`에
  malformed/누락 tenant fail-closed 7+1건 추가. `tests/audit/test_kms_providers.py`는
  `mypy --strict` 0(finding 3: `importlib.util` 전역 직접 패치로 전환).

### BDP Phase 2 / 항목 4 — 임베드 SDK(@require_oversight) + 미들웨어 + LangChain 어댑터 (2026-06-08)

P1(GA). OEM/라이선싱(수익 경로)의 전제 = 남의 스택에 끼워지는 것. SI·벤더가 **기존
에이전트/툴을 감싸** 모든 액션이 SecuGent oversight를 통과하게 하는 **프레임워크 중립
임베드 SDK**(§A-2.3 북극성의 실현체). SDK는 통제 판정을 **재구현하지 않고** 기존 코어
결정 경로만 호출한다(불변 I1, deny-by-default 단일 출처).

- **단일 게이트**(`secugent/sdk/gate.py`, `# SPDX-License-Identifier: Apache-2.0`):
  `OversightGate`가 코어 결정을 `SubAgent._run_step`과 **동일한 순서**로 합성 —
  ① `OversightEngine.evaluate(step).raise_if_blocked()`(REGULATIONS deny-by-default →
  HARD BLOCK), ② `classify_axes`+`requires_hitl`(Rule of Two 3축 충족 시 주입된
  `HitlGateway`로 HITL 강제; reject/modify/timeout → **fail-closed** `OversightBlocked`),
  ③ §C-2 감사 이벤트 1건 emit(불변 I2). 모든 공개 표면이 이 한 곳을 거쳐 **oversight를
  우회하는 실행 경로가 없음**(§4.8 경계). 게이트는 자체 정책을 더하지 않음 — 판정은
  코어 엔진과 바이트 동일(결정성 테스트로 검증). step id는 입력 기반 content-address로
  재현 가능.
- **데코레이터**(`secugent/sdk/decorators.py`): `require_oversight(*, action_type, gate, …)`
  가 동기/비동기 콜러블 양쪽을 래핑 — 본문 실행 **전** 게이트를 강제하고, 래핑된 함수
  자신의 예외는 **변형 없이 재전파**(§B-8 삼키지 않음). **중첩 래핑 이중 평가 방지**:
  같은 게이트가 한 콜스택에서 재진입하면 `ContextVar` 센티넬로 안쪽 래핑은 재평가를
  건너뜀(감사 이벤트 1건). 호출 인자에서 REGULATIONS target을 추출(`target_from`, 기본
  첫 위치인자).
- **미들웨어/툴 래퍼**(`secugent/sdk/middleware.py`): `OversightMiddleware`(콜러블/ASGI
  요청 단위 oversight) + `wrap_tool(fn)`. 둘 다 같은 코어 게이트를 거치며, deny 시 하류
  앱/툴에 **절대 도달하지 않음**(경계 보증).
- **공개 표면**(`secugent/sdk/__init__.py`): `require_oversight`·`OversightMiddleware`·
  `wrap_tool`·`OversightGate`·`OversightBlocked` 재노출. **langchain을 import하지 않음**
  (불변 I3). 기존 `HeadPlannerAdapter`/`DispatcherAdapter`도 임베드 SDK 표면으로 재노출
  (정의 출처는 `orchestrator/adapters.py` 단일, 로직 변경 없음).
- **LangChain 어댑터**(`secugent/orchestrator/adapters_langchain.py`): `SecuGentCallbackHandler`
  `on_tool_start`가 같은 코어 게이트로 툴 실행을 차단(미통과 → raise). **langchain은 지연
  임포트**(`importlib.import_module`, `langchain_core` 우선·레거시 `langchain.callbacks`
  폴백) — 미설치 시 `secugent.sdk`/`secugent.core` import 실패 0, *사용* 시에만 `pip install
  secugent[langchain]` 힌트를 담은 명확한 `ImportError`. 콜백 핸들러는 base가 호출 시점에만
  존재하므로 `type()`로 동적 생성. `wrap_langchain_tool`은 `wrap_tool`의 얇은 별칭.
- **extra**(`pyproject.toml`): `[project.optional-dependencies]`에 `langchain`
  (`langchain-core>=0.2`) extra 추가 — 격리된 옵션, 코어 의존성 아님.
- **데모**(`examples/langchain_demo/`): BDP_01 stub 완성. langchain **설치 여부와 무관하게
  exit 0** — 설치 시 실제 `SecuGentCallbackHandler` 차단, 미설치 시 힌트 출력 + 동일 코어
  차단(`wrap_langchain_tool`) 시연(`tests/examples/test_examples_smoke.py` 그린 유지).
- 테스트(단위+통합 32건): 위반 HARD BLOCK·미실행, 정상 통과+감사 1건, 3축→HITL 게이트
  호출(AutoReject/timeout/modify/게이트웨이 없음 → fail-closed; AutoApprove → 통과), 동기·
  비동기 래핑, 중첩 단일 평가, 래핑 예외 그대로 재전파, **모든 요청 경로 게이트 통과**(경계),
  **langchain 부재 시 코어 import 0**(I3) + 지연 임포트 힌트, on_tool_start 차단, **SDK 판정 =
  코어 직접 호출 동일**(결정성). 한국어 픽스처(`대외비`/`기밀` 정책). 신규 sdk/ 커버리지
  98–100%.

### BDP Phase 2 / 항목 7 — opt-in 채택 텔레메트리 (자가호스팅 친화, 기본 off) (2026-06-08)

P1(GA). 6개월 "채택 지표" KPI와 OEM 피치의 근거를 PII·정책 내용을 박스 밖으로 절대
내보내지 않고 마련(§A 프라이버시, §A-2.6 폐쇄망 우선). 통제 로직과 완전 분리 — 감사
해시체인·REGULATIONS를 import하지 않는다.

- **수집기**(`secugent/observability/telemetry.py`, `# SPDX-License-Identifier: Apache-2.0`):
  `TelemetryCollector`. `record_feature(name)`는 **기본 off일 때 완전 no-op**(아무것도
  생성/버퍼/전송 안 함, 불변 I1). opt-in 시 기능 *이름* 카운트만 증가하며, 이름은
  `[a-z0-9._]{1,64}` 식별자로 **구조 검증**해 위반 시 거부 — 이메일·주민번호·경로·비ASCII
  등 자유 텍스트(PII)를 이름 채널로 밀반입 불가(불변 I2를 규약이 아닌 코드로 강제,
  deny-by-default §A-2.2). 구별 이름 수는 `max_features`로 상한, 초과분은 overflow 버킷으로
  합쳐 메모리·라벨 카디널리티 무한 증가 차단. `snapshot()`은 `{feature: count}` 익명 집계만
  반환. `instance_hash()`는 설치/호스트 값의 **키드 HMAC-SHA256**(설치별 비밀키, 기본 랜덤·
  미노출) — 동일 id+동일 비밀=동일 다이제스트인 **가명(pseudonym)**이며, 비밀키를 모르는
  공격자에게만 역추적이 어렵다(불변 I3). 저엔트로피 호스트명을 공개 상수 솔트로 SHA-256한
  값은 사전공격으로 복원 가능하므로 "irreversible/역추적 불가"라 주장하지 않는다. 원문은
  페이로드에 절대 미노출.
- **로컬 우선·fail-soft·in-memory/sink-only**: 최소 `TelemetrySink` 구조적 Protocol(로컬
  버퍼/파일 flush). 디스크 가득·IO 오류는 텔레메트리 경계에서 삼켜 앱에 영향 0(broad catch가
  정당화되는 유일 지점, debug 로깅·미전파). 외부 SaaS 강제 전송 없음, **Prometheus 내보내기
  없음**. 동시 `record_feature`는 락으로 카운트 일관성 보장.
- **설정**(`secugent/core/settings.py`): `TelemetrySettings`(`opt_in` 기본 False) +
  `from_env`로 `SECUGENT_TELEMETRY_OPTIN`(1/true/yes/on=on, 그 외=off) 파싱.
- **메트릭 비등록**(`secugent/observability/metrics.py`): 텔레메트리는 Prometheus 메트릭이
  **아니다**. 전역 기본 레지스트리에 카운터를 등록하면 opt-in off에서도 import 시점에
  `/metrics`에 HELP/TYPE가 노출돼 불변 I1을 위반하고, 수집기 내부 카운터와 이중화되므로
  `TELEMETRY_FEATURE` 카운터를 **제거**했다(in-memory/sink-only 단일 소스).
- 문서: `docs/OPEN_CORE.md`에 프라이버시 1절(기본 off·구조 검증 무 PII·가명 인스턴스ID·
  로컬 우선·Prometheus 비노출) 추가.
- 테스트(`tests/observability/test_telemetry.py`, 65건): opt-out no-op·sink 무호출, opt-in
  카운트만, **feature 이름 구조 검증**(이메일·RRN·경로·대문자·비ASCII·64자 초과·한글 자유텍스트
  거부 — property 포함)·**카디널리티 상한**(overflow 버킷, 알려진 이름은 자기 버킷 유지),
  인스턴스ID **키드 HMAC**(동일 id 다른 비밀=다른 다이제스트, 공개정보만으로 재현 불가,
  기본 설치별 랜덤), 플러시 페이로드=snapshot 정확히(원문·다이제스트 미노출), 런타임 토글·
  sink 미설정·디스크 가득 fail-soft·동시성 일관, 한국어 ascii 식별자(자유텍스트 거부),
  속성기반(snapshot은 정확한 발생 카운트 dict)·설정 env 파싱·**전역 Prometheus 노출 0**
  (opt-in 무관)·`TELEMETRY_FEATURE` 미존재. telemetry.py 커버리지 100%.

### BDP Phase 2 / 항목 10 — 국산·소버린 모델 BYO 어댑터 (EXAONE·HyperCLOVA X·A.X·Solar) (2026-06-08)

P1(GA). 폐쇄망·소버린 수요(정부 ₩5,300억 프로그램)에 대응하는 구체 국산모델 클라이언트를
`LLMClient` 추상(§A-2.3 모델 중립 코어)으로만 추가. 코어 결정 로직은 어댑터를 직접 import
하지 않고 레지스트리/추상으로만 사용(격리 불변 I2), 어댑터는 통제 판정을 재구현하지 않는다.

- **국산 어댑터 4종**(`secugent/core/llm_clients/`): `ExaoneLLMClient`·`SolarLLMClient`·
  `AxLLMClient`(OpenAI 호환 `/v1/chat/completions` 공유 베이스) + `HyperClovaLLMClient`(NAVER
  CLOVA Studio `result.message.content`·`maxTokens` 봉투). 각 파일 `# SPDX-License-Identifier:
  Apache-2.0`(Core 티어). 전부 ABC `generate(*, model, system, messages, max_tokens,
  response_format)` 시그니처·예외 계약을 정확히 준수(불변 I1).
- **주입형 HTTP 전송**(`_transport.py`): `HttpTransport`/`HttpResponse` 구조적 프로토콜 +
  지연 `httpx` 기본 전송(`default_transport`). 코어 import가 `httpx`를 요구하지 않음(폐쇄망
  지연 임포트). 테스트는 가짜 전송을 주입.
- **공유 베이스**(`_base.py`): 입력 검증·정규화, 경계 재시도(transient TransportError/5xx만
  재시도, 401/403 인증실패·4xx는 즉시 종료), 토큰/비용 한도(>8192 fail-closed), 비밀/PII 비노출
  (api_key·원문 바디를 예외 메시지에 절대 미삽입), 비JSON/부분 응답→`LLMResponseFormatError`,
  무응답→재시도 후 `LLMError`(삼키지 않음 §B-8/§B-10). 4개 어댑터가 중복 없이 공유(§B-6).
- **레지스트리 결선**(`llm_clients/__init__.py`): `build_domestic_client(model, *, endpoint,
  **kw)` — `{exaone,hyperclova,ax,solar}`→구체 클라이언트, 미지원→`LLMError`(통제 로직 0).
  `get_default_client()` 도메스틱 분기를 실연결: prod/dev 모두 `SECUGENT_DOMESTIC_MODEL` 선택 시
  구체 클라이언트 반환(Mock 금지), prod에서 엔드포인트만 있고 모델 미선택/미지원→부팅 거부
  (fail-closed, 불변 I3). `settings.py`에 `SECUGENT_DOMESTIC_MODEL`(Literal exaone|hyperclova|
  ax|solar) 선택자 + 엔드포인트 필수 검증.
- 테스트(`tests/core/test_llm_clients.py`, 67건): 계약 준수·정상/실패·비JSON/부분/비객체→형식오류·
  경계 재시도·인증 종료·입력 검증·토큰 한도·비밀 비노출·한국어 프롬프트 픽스처·레지스트리·prod
  fail-closed·코어 격리(AST import 검사)·모델 무관 통제 결정(`classify_axes` 불변)·httpx 지연
  임포트. 베이스라인 `test_prod_with_domestic_endpoint_does_not_raise`를 해소(구체 클라이언트 반환).

### BDP Phase 2 / 항목 6 — 한국어 정책 팩 라이브러리 + REGULATIONS 변환 안정화 (결정적) (2026-06-08)

P1(GA). 한국 폐쇄망 맥락 해자 — 채택자가 "설치 후 바로 통제됨"을 경험하도록 즉시 적용
가능한 정책 템플릿(전자금융감독규정·신용정보법·개인정보보호법·국정원 N²SF)을 제공하고,
팩 → `Regulations` 로딩·병합 경로를 안정화. 기존 `Regulations` 스키마만 사용(신규 필드 0).

- **한국어 정책 팩 4종**(`secugent/regulations/packs/kr_*.yaml`): `kr_efin_supervision`(계좌정보·
  거래내역 접근 차단·금융 PII 외부전송 차단), `kr_credit_info`(개인신용정보 처리·제3자 제공 통제),
  `kr_pipa`(고유식별정보·민감정보·자동화 의사결정), `kr_n2sf_mapping`(기밀(C)/민감(S) 망분리 반출
  차단). 전 팩 한국어 자연어 라벨 + 출처 규정 주석(§C-3). `packs/README.md`(사용·strengthen-only
  병합 규칙·출처 규정 표).
- **팩 로딩·병합 경로**(`secugent/regulations/tenant_loader.py`): `default_packs_dir()`,
  `load_pack()`(YAML→검증된 `Regulations`, 손상/스키마위반→`RegulationsLoadError` fail-closed),
  `load_packs_from_dir()`(파일명 정렬 → 결정적 순서, 빈 디렉토리→`[]`), `merge_packs()`(기존
  strengthen-only `RegulationsLoader._merge` 재사용 — 통제 union·완화 거부, 병합 로직 재구현 0).
  다중 팩 fold 시 `version` 64자 상한을 결정적으로 보존(`_bound_version_for_merge`, 통제 불변).
- **불변**: I1 강화 단조(병합은 통제 강화만, 완화는 `_reject_data_label_relaxation`로 거부),
  I2 결정성(동일 팩→동일 `checksum()`, 100회 동일), I3 한국어 라벨+출처 주석.
- 결정적 3중: 단위(팩 로딩·손상 YAML·빈 팩·다중 팩 union·중복 정책명 강화) + 속성기반(임의
  base+팩 병합은 base의 상위집합·라벨 민감도 하향 항상 거부) + 결정성 100회(distinct==1) +
  규정별 HARD BLOCK 시나리오 회귀(계좌정보/개인신용정보/고유식별정보/기밀자료 외부전송 →
  위험점수 무관 차단, §C-1). `tenant_loader.py` 커버리지 99%(신규 함수 100%).

### BDP Phase 1 / 항목 1 — 오픈코어 경계 + 라이선스 분리 (Apache-2.0 Core / BSL-1.1 Enterprise) (2026-06-07)

P0(베타 진입). 오픈코어 전략의 물리적 전제 — 무엇이 OSS 코어(신뢰 자산)이고 무엇이 상용
애드온인지를 라이선스·패키지 경계로 확정. 이 경계가 이후 모든 BDP 항목의 파일 경로·티어 기준.

- **라이선스 파일**: `LICENSE`(Apache-2.0, 코어), `LICENSE.enterprise`(BSL-1.1 참조),
  `NOTICE`(서드파티 고지), `docs/OPEN_CORE.md`(모듈→티어 매핑표).
- **엔터프라이즈 티어 분리**(`secugent/enterprise/` 신설): `tenant_admin.py`(was `core/`),
  외부 KMS `AwsKmsProvider`·`VaultTransitProvider`(was `audit/merkle.py`)를 이전. 코어
  `audit/merkle.py`에는 `KmsProvider` Protocol + `LocalHmacKmsProvider`만 잔류(의존성 역전 —
  audit는 추상에만 의존, 엔터프라이즈 구현은 절대 import 안 함).
- **지연 임포트 가드**(`secugent/__init__.py`): `EnterpriseFeatureUnavailable` +
  `require_enterprise()` — 미설치 시 `pip install 'secugent[enterprise]'` 안내 예외, import
  시 부작용 0(코어는 fail-soft로 정상 동작).
- **패키징 경계**: `pyproject.toml [project.optional-dependencies].enterprise`(boto3·hvac).
- **경계 강제 CI 게이트**: `tests/unit/test_open_core_boundary.py` — AST로 `core/`·`audit/`가
  enterprise 심볼을 import하면 실패(I2, fail-closed). I1 단독 부팅 + I3 SPDX 헤더 검증 포함.
- **SPDX 스탬퍼**: `scripts/apply_spdx.py`(멱등, 티어별 헤더). I3는 **생성/수정한 파일에 한정**
  (전 130파일 일괄 스탬프는 Non-scope — 리뷰 가능 diff·게이트 그린 유지).
- 불변: I1 코어 단독 설치·mock 부팅, I2 코어→엔터프라이즈 단방향 의존(위반 0), I3 SPDX 일관.
  로직 변경 0(이동·재패키징·마킹만) — 결정적 모듈 회귀 0(mypy clean, 영향 테스트 그린).

### BDP Phase 1 / 항목 2 — 신뢰 증명 패키지 + 읽기전용 `secugent verify` (결정성·감사체인 증명) (2026-06-07)

P0(베타 진입). 초기 단계 신뢰 확보를 투명성(공개·외부 재현 검증)으로 해결. 첫 영업자료.

- **`secugent verify`**(`secugent/cli/verify.py`): `verify_determinism(*, samples=100,
  seed_fixture)` → `DeterminismReport`, `verify_audit_chain(*, tenant_id, store_path)` →
  `ChainReport`. **읽기전용**(sqlite `mode=ro` — 어떤 상태도 변경 안 함, I1), 1회라도 불일치
  시 ok=False(I2), 체인 위반 시 비0 종료 + 첫 위반 지점 명시(I3, 침묵 통과 금지).
- **신뢰 산출물**: `SECURITY.md`(제보·공개 정책·SLA), `docs/security/threat_model.md`(STRIDE +
  SECURITY_CONTRACT 교차참조), `scripts/gen_sbom.py`(결정적 CycloneDX 1.5, 정렬·타임스탬프 생략).
- 결정적 3중: 단위(1-bit 변조→ok=False, 빈 체인 무결, 멀티테넌트 격리) + 속성기반(append→
  verify 항상 True·단일바이트 변조 항상 탐지) + 결정성 100회(distinct_outputs==1) + 한국어
  체인 시나리오 회귀. 한국어 픽스처(대외비 금융·공공).
- CI `.github/workflows/determinism.yml`: 2회 독립 실행 산출 **byte-identical** 비교 +
  감사체인 CLI 종료코드 증명 + SBOM 재현성.

### BDP Phase 1 / 항목 3 — 5분 퀵스타트 + CLI 데모/run + examples (2026-06-07)

P0(베타 진입). OSS 채택의 첫 실행 마찰 제거. API 키·네트워크 없이(mock, 폐쇄망 우선)
"정책 HARD BLOCK → HITL 승인 → 감사로그" 1회전이 도는 단일 명령 데모.

- **`secugent` CLI 디스패처 확장**(`secugent/cli/__main__.py`): `run | demo | verify`.
  `demo`는 `secugent.cli.demo.run_demo`, `run`은 동일 엔진으로 최소 키리스 1회전, `verify`는
  항목2에 위임. 미지원/누락 서브커맨드는 종료코드 2(fail-closed).
- **키리스 데모**(`secugent/cli/demo.py`): `run_demo(*, steps=3, emit_audit=True) -> DemoResult`.
  MockLLMClient + 임시 EventStore. 한국어 REGULATIONS HARD BLOCK + 단계 전용 HITL 승인 +
  §C-2 스키마 감사 이벤트(`event_id`·`prev_event_id` 해시체인·`rule_of_two_axes`·`decision`).
  고정 시드로 byte-identical 재현. append-only `ChainedEventStore`에 기록되어
  `secugent verify --chain`으로 재현 가능.
- **examples 3종**: `examples/quickstart/`(최소 에이전트+정책 JSON+실행 스크립트),
  `examples/policy_demo/`(한국어 정책 HARD BLOCK 결정성 시연, §C-3),
  `examples/langchain_demo/`(항목4 embed SDK 의존 — stub + TODO). 모두 스모크 테스트.
- **README 최상단 "5분 퀵스타트"**: 설치 → `secugent demo` → 감사로그 확인 3스텝.
- **Dockerfile**: 기본 CMD(uvicorn 서버) 유지하면서 `docker run <img> secugent demo` 로
  CLI 도달 가능(ENTRYPOINT 미설정 → 위치 인자 override). 서버 부팅·HEALTHCHECK 불변.
- 테스트: 단위(차단·승인·감사·C-2 스키마·prev_event 체인·해시체인 verify) + 통합(서브프로세스
  무키 exit 0 + 요약) + 결정성(고정 시드 동일 출력) + examples 스모크.

### BDP Phase 2 / 항목 5 — Rule of Two 축①(untrusted_input) provenance 자동화 (결정적★) (2026-06-08)

P0(베타 진입). 핵심 통제 규칙 Rule of Two의 축①(`untrusted_input`)이 그동안 **수동 선언**만
인정(`rule_of_two.py`의 "Stage 6 / G-C4 — axis① live producer 부재" 연기 주석)했던 것을 해소.
비신뢰 출처(웹 fetch·커넥터 응답·비신뢰 파일)에서 파생된 입력이 **결정적으로** 축①을 켜는
**provenance 자동 도출 엔진**을 완성(`from_step` 단일 리더).

> ⚠️ **정직한 범위 주석**: 데이터 흐름 *프로듀서*(`mark_untrusted_source`/`mark_derived_from`)는
> 아직 라이브 planning(`plan`/`_parse_plan`)·dispatcher에서 호출되지 않는다(테스트만 호출). 즉
> 라이브 실행에서 provenance 블록은 LLM 플랜이 직접 넣을 때만 리더에 도달한다 — 도출 엔진은
> 실제·검증됨이나, **라이브 프로듀서 배선은 후속(deferred)**. 3축 강제 HITL "end-to-end 실효화"는
> 프로듀서 배선 완료 시점에 성립한다.

- **신규 결정적 코어**(`secugent/core/provenance.py`, Apache-2.0): `TaintSource` StrEnum
  (`web_fetch`·`connector_response`·`file_untrusted`·`user_direct`[유일 신뢰]),
  `is_untrusted(source)`(순수), `derive_taint(parent_tainted, source)`(전파 규칙). **단조(I1)**:
  taint는 켜지기만 — 어떤 파생도 끄지 못함. **deny-by-default(I3)**: None/모호 출처는 기존
  taint를 절대 clear하지 않음.
- **live 와이어링**(`secugent/core/rule_of_two.py`): `RuleOfTwoContext.from_step`이 `Step.context`의
  `provenance` 블록(top-level 또는 `rule_of_two` 중첩)을 읽어 축①을 결정적으로 도출, 기존 explicit
  선언과 **OR 결합**(explicit True still wins, 자동 taint는 ADD만·clear 불가). `classify_axes`의
  축②③ 로직·`Axis` 문자열 값·`requires_hitl(3축)` 경계는 **불변(I4)** — 기존 G-C2 시나리오 회귀 0.
- **프로듀서 헬퍼(라이브 미배선)**: `head_agent.mark_untrusted_source(step, source)`(비신뢰 출처
  스텝에 provenance 메타 주입) + `head_agent.mark_derived_from(child, parent)`(부모의 resolved
  taint를 자식에 단조 전파). 둘 다 원본 불변(`model_copy`)·단조(I1: 기존 taint를 절대 낮추지
  않음 — 이미 tainted한 스텝을 USER_DIRECT로 재표시해도 축① OFF로 못 뒤집음). **단, 아직
  `plan`/`_parse_plan`·dispatcher에서 호출되지 않음(테스트 전용, 후속 배선)**. `sub_agent._run_step`·
  `approval._enforce_scope`는 단일 출처(`from_step`) 경유라 **통제 판정 로직 변경 0**.
- **결정적 3중 + 100회**(§B-4a): 단위(진리표·web_fetch 파생→축① 활성·파생 체인 유지) + 속성기반
  (hypothesis, **단조성** — tainted 부모의 모든 후손은 tainted, taint 절대 clear 안 됨) + 결정성
  100회(distinct_outputs==1) + 시나리오 회귀(자동 taint→3축→HITL 강제, audit `rule_of_two_axes`에
  `untrusted_input` 기록). 커버리지 `provenance.py` 100% / `rule_of_two.py` 100%.
- **한국어 픽스처**(§C-3): 한국 금융 웹 fetch 파생 비신뢰 입력(주민등록번호 PII)→사내 메신저
  외부전송→3축→HITL 강제 E2E. §C-1: Rule of Two 위반 액션 HITL 없이 실행 불가 통과.

### Wave W1 — 런 연속성·HA ∥ 결정적 신규 모듈 ∥ 신원·권한 (BDP `_02`·`_04`·`_05`: G-C7·G-C8·G-C2·G-H2·G-C5·G-C6, 2026-06-06)

P0. Stage 1(PG 데이터 평면) 위에 5개 출시차단 갭을 5레인 병렬(워크트리)로 구현 → 직렬
머지 → 5-lens 적대적 검토 ⇄ fix(Medium+ 0까지)로 완주. 핫스팟 `api/main.py`는 단일
integration 레인으로 직렬 합류. **라이브 트래픽은 W1에서도 SQLite 유지**(PG cutover는 후속).

- **G-C7 (run-state 배선):** `orchestrator/wiring.resolve_run_state_store(cfg, *, is_dev)` —
  완성돼 있던 `SQLiteRunStateStore`를 부팅에 주입. prod+memory → `RunStateConfigError`
  (조용한 인메모리 폴백 금지, deny-by-default). `OrchestratorConfig.run_state_backend`를
  `None` 센티넬화 → prod 명시 `"memory"`는 진짜 fail-fast(미설정만 sqlite 승격). pg는
  `NotImplementedError`(Stage 1에 PgRunStateStore 부재). 재시작 무손실 복원 통합 테스트.
- **G-C8 (복구·HA 리스):** 미호출이던 `plan_recovery`를 부팅 복구 드라이버(`run_recovery`,
  멱등)로 연결 — resumable 재enqueue / unsafe→FAILED / `run.handover` 기록. `PgLeaseManager`
  어댑터(기존 PG advisory-lock 프리미티브 위임). runner에 리스 게이트 디스패치 +
  **백그라운드 lease 갱신(ttl/3)** — TTL 초과 런의 leader-singleton 보장, 갱신 실패 시
  fail-closed FAILED. 복구는 leader/리스 게이팅(라이브 lease-보유 런 미훼손). worker_id
  노드별 고정(재시작 시 자기 리스 재획득). 리더 단일성·복구 멱등 속성(hypothesis) 테스트.
- **G-C2 (Rule of Two 3축, 결정적):** 신규 `core/rule_of_two.py` — `Axis`/`classify_axes`(순수)/
  `requires_hitl`(≥3축). 단일축(connector_action) 특례를 3축 일반화(sub_agent·approval·
  head_agent), 감사 payload에 `rule_of_two_axes` 생산(§C-2 새 필드/게이트 무추가). 단위+
  속성+시나리오(한국 금융 인젝션)+100회 결정성, 라인 커버리지 100%. **axis①(untrusted_input)
  의 라이브 provenance 생산자는 Stage 6(G-C4) HITL 게이트웨이와 결합 예정**(프롬프트 _04 경계).
- **G-H2 (감사 보존, 결정적):** 신규 `audit/retention.py` — `plan`(순수: sealed ∧ retain_days
  초과만 purge 후보)/`apply`(archive→무결성 검증→검증 성공시만 purge, 원자적). append-only
  보존: `events_archive` 테이블 패턴(체인 행 미삭제, verify_chain 보존). 미봉인/기간내 purge 0.
  스케줄러 봉인 후 훅(fail-closed). wire 시점 `retain_days` 검증. 100회 plan 결정성, 커버리지 100%.
- **G-C5 (OIDC/JWT + RBAC):** dead였던 `OIDCAuthenticator`를 `current_principal` 컷오버로 연결 —
  dev(SECUGENT_ENV 미설정)는 헤더 인증 하위호환, prod는 검증된 JWT 강제(미검증/위조/만료→401,
  헤더 무시). RS256 + JWKS(HTTPS 또는 에어갭 `SECUGENT_OIDC_JWKS_FILE`), prod에서 HS*·빈/약한
  secret 부팅 거부. WS 핸드셰이크 토큰 검증 + Principal 바인딩. `/policy/sign` MFA는 위조가능
  헤더가 아닌 `principal.mfa_satisfied` 기반.
- **G-C6 (멀티테넌트 격리·관리):** 신규 `core/tenant_admin.TenantAdminService`(create/soft_delete/
  assign_regulations/set_budget, **platform-admin 전용**·감사·소프트삭제) + `scripts/secugent_admin.py`
  CLI. PG RLS를 ENABLE만→ **FORCE ROW LEVEL SECURITY**(owner-bypass 차단, drift-0 자동 파생).
  요청경로 테넌트 파생: `_LEGACY_TENANT` 하드코딩 7개 사이트 → `principal.tenant_id`(async
  tenant ContextVar 바인딩). 교차테넌트 관리·누출 차단.
- **INT (`api/main.py` 배선):** run-state 주입(양 인스턴스화 경로) + lifespan 복구·리스 부트
  (pg_store 설정 후 resolve로 PG HA 부팅 가능) + `wire_auth` + tenant 미들웨어 + admin 라우트 5종.
  `state.list_open_runs()`·`OrchestratorConfig.ha_enabled/ha_backend` 추가. main.py ruff 드리프트 24→6.
- **검토:** Batch1 5-lens(7 findings 수정+axis① Stage6 연기) → S2-B+INT 5-lens(9 blocking 수정:
  MFA·교차테넌트 권한상승·PG리스 부팅·리스갱신·HS*약키·worker_id·명시memory fail-fast·복구 leader게이팅)
  → 재검토 0 Medium+(5 Low/Info 중 ASYNC240·alg대소문자·renew fail-closed·로그위생 수정). 회귀 테스트 +90건.
- **게이트:** mypy strict clean(128 files) · pytest 1641 passed/32 skipped/0 failed(baseline 1386 → +255)
  · 결정적 모듈 커버리지 ≥95%(rule_of_two/retention 100%, tenant_admin 98%) · repo ruff 드리프트 순감소(-19).

### Infrastructure — Stage 1 PG data plane foundation (BDP `_01`: G-C9 · G-M8 · G-H14, 2026-06-06)

P0 · 폐쇄망/감사 가능성/온프레미스 재현성. PG 데이터 평면을 계약 동치·해시체인·
마이그레이션 관리 백엔드로 완성하고 부팅에서 구성·검증한다. **라이브 트래픽은 Stage 1
에서도 SQLite 유지** — async 재배선·`AppState.store` 교체는 Stage 2(G-C7/C8) cutover.

- **G-C9 (event_store_pg):** `PgEventStore`에 `AsyncEventStore` CRUD 7종 구현
  (`append`/`query`/`upsert_run`/`get_run`/`save_approval`/`get_approval`/
  `list_pending_approvals`) — 동기 `EventStore` 시맨틱 1:1(ts DESC / pending FIFO /
  미존재 None / append-only / nonce UNIQUE→`EventStoreError`). 각 트랜잭션에
  `set_config('app.tenant_id', …, true)`(파라미터 바인딩 = SQL 인젝션 차단) + 명시
  `WHERE tenant_id`(심층방어). payload는 `redact()` 후 JSONB. `append_event_atomic`
  async 원자 훅 추가.
- **G-C9 (event_store_async):** 신규 `SqliteAsyncEventStore` — 동기 `EventStore`
  위 얇은 비동기 어댑터(`asyncio.to_thread`, 프로토콜명↔동기명·인자 매핑). 계약 동치
  SQLite 쪽 + Stage 2 cutover seam. HA 리스는 `NotImplementedError`(fail-closed).
- **G-C9 (boot):** `create_app`에 `_resolve_pg_store()`(DATABASE_URL 시 PG 구성,
  pg extra 부재/DSN 불량 → **fail-fast** `PgEventStoreError`, 조용한 SQLite 폴백
  금지) + `AppState.pg_store` 필드. lifespan startup: dev면 `ensure_schema`, prod면
  자동 DDL 금지 + `SELECT 1` 연결 검증(불가 시 부팅 중단). 기존 warn-only 블록을
  구성결과 INFO 로그로 대체. 주입 state는 `pg_store=None` 유지(기존 스위트 무영향).
- **G-M8 (hash_chain):** 순수 체인 함수 공개 승격 `GENESIS`/`stored_view`/
  `canonical`/`compute_chain_hash`(기존 `_`함수는 별칭 유지 — 하위호환, 기존 테스트
  불변). **백엔드 무관·결정성 보증의 단일 원천.** 라인+분기 커버리지 100%.
- **G-M8 (event_store_pg):** 신규 `PgChainedEventStore` — `append`가 명세 §4.4
  트랜잭션(`pg_advisory_xact_lock(hashtext(tenant))` per-tenant 직렬화 → tail SELECT
  → `compute_chain_hash` → event+chain 행 단일 트랜잭션 원자 INSERT). `verify_chain`
  불일치 → `AuditChainBrokenError`. 신규 `event_chain` 테이블 DDL+RLS를 `_DDL`/
  `_RLS_POLICY`에 추가(기존 4테이블 verbatim 보존). SQLite 체인 == PG 체인 byte-동일.
- **G-H14 (alembic):** `alembic.ini` + `migrations/env.py`(동기/비동기·offline/online·
  DATABASE_URL 주입) + `migrations/versions/0001_baseline.py`(drift-0: `UPGRADE_SQL`이
  `_DDL`+`_RLS_POLICY`에서 파생 → `ensure_schema()`와 정확히 일치). `pg` extra에
  `alembic>=1.13` 추가, `migrations/` ruff per-file-ignores(E402). `ensure_schema`는
  dev 전용 격하(운영 자동 DDL 금지, alembic 경로).
- **테스트:** 계약 동치(sqlite_async CI 상시 + pg DB게이트) · 비동기 어댑터 단위 ·
  체인 공개함수 3중(단위+hypothesis+100회 결정성, 95%↑→100%) · PG CRUD/RLS/nonce ·
  PG 체인 링크/변조검출/SQLite==PG/동시 직렬화/원자 롤백 · drift-0 정적+alembic 왕복 ·
  부팅 fail-fast/None. 한국어 픽스처(시행사 `financial-kr`/운용사 `securities-kr`).
  DB게이트는 `DATABASE_URL`+`pg` extra 시에만 실행(미설치 환경에서 26 skip).

### Security — Stage 3 deny-by-default boot recovery (SG-S3-DENY-BOOT, 2026-06-06)

- **G-M3 (regulations):** `RegulationsLoader._merge` now merges `data_labels`
  strengthen-only via `_merge_data_labels`, mirroring the `banned_paths` /
  `banned_commands` guards. Tenant overrides can no longer silently downgrade a
  label's `severity`, remove `hard_block`, or widen `allowed_actions` (a wider
  allowlist is more permissive in `mechanical_oversight._match_data_label`); any
  relaxation raises `RegulationsSchemaError` (fail-closed). Deterministic,
  base-order-preserving. Triple harness + 100× determinism; `tenant_loader.py`
  line coverage 99%.
- **G-M3 fix (SG-20260606-01):** the `data_labels` strengthen-only guard now also
  guards the **`path_patterns`** axis. `mechanical_oversight._match_data_label`
  raises a violation only when a path pattern matches, so more patterns = more
  protected paths = more protection. An override's `path_patterns` must be a
  **superset** of base's; removing any pattern narrowed the protected scope
  silently (a deny-by-default relaxation — a tenant could flip a hard-blocked
  path from BLOCK→ALLOW while keeping severity/hard_block/allowed_actions
  identical) and now raises `RegulationsSchemaError` (removed list reported in
  base order for determinism). Added unit + property (hypothesis) + E2E
  (OversightEngine BLOCK stays BLOCK) + Korean 전자금융감독규정 regression.
- **G-C1 (api boot):** `create_app()` / `AppState(auto_build_pipeline=True)` and
  the STEER handler no longer assemble an empty (allow-all) `OversightEngine`
  when no regulations are injected. New `_resolve_boot_regulations`: explicit
  injection wins; else `SECUGENT_REGULATIONS_PATH` loads real rules (fail-fast on
  load error); else dev → empty engine + loud warning; else production →
  `BootPolicyError` (refuse allow-all boot). Dev default (`SECUGENT_ENV` unset)
  preserves prior behaviour.
- **G-H7 (egress broker):** `_install_egress_broker` no longer always installs a
  permissive in-memory dev policy. New `_resolve_broker_policy`:
  `SECUGENT_POLICY_BUNDLE_PATH` loads a signed bundle via `load_active_policy`
  (forged signature / unauthorized key / missing file → `PolicyLoadError`,
  fail-fast); else dev → permissive dev policy + warning; else production →
  `empty_deny_policy()` (deny-all). Broker installs only when
  `enable_egress_broker=True`.
- **G-H4 (per-run oversight):** `RegulationsLoader.for_run` is now wired into live
  SUB execution. `DispatcherAdapter.dispatch` resolves
  `for_run(run_id, tenant_id)` once per dispatch and builds ONE fresh
  `OversightEngine(bundle.effective)` for that run, threaded **explicitly** into
  the SUB factory (the SG-20260603-01 pattern, alongside `envelope_hash`) — never
  via closure/contextvar. The `SubFactory` alias was extended in lockstep across
  `runner.py` / `dispatcher.py` / `adapters.py` to carry `oversight` +
  `regulations_version`. Dir-mode boots now capture the `RegulationsLoader`
  (`AppState.regulations_loader`) instead of discarding it; file-mode / dev /
  explicit-injection keep `loader=None` and reuse the (fail-closed, G-C1) boot
  engine byte-for-byte. A corrupt/relaxing tenant policy raises
  `RegulationsLoadError` / `RegulationsSchemaError` → surfaced as
  `DispatcherResultMalformed` (the run fails) — **never** an allow-all fallback.
  STEER routing (option A): `AppState._run_engines` registers the per-run engine
  for the dispatch lifetime (removed in a `finally`); `SteerHandler` resolves the
  target run's engine from the registry (falling back to its default engine when
  none is registered) so a constraint reaches the correct run's engine and never
  silently no-ops. The effective `bundle.effective.version` is threaded to
  `SubAgent` and stamped into the **payload** of `step.oversight_violation` /
  `alert.hard_block` (and every SUB event), populating the existing §C-2
  `regulations_version` field (no new schema field). Per-tenant differential is
  LATENT until G-C6 (live `tenant_id` is hardcoded `legacy-default`); the
  mechanism is proven by fixtures (dispatch-boundary differential + 100×
  determinism + fail-closed-on-relaxation + STEER isolation + dir-mode e2e audit).
  `tenant_loader.py` coverage 99%; `orchestrator/adapters.py` 99%.
- **G-H4 fix (SG-20260606-10, concurrency):** `OversightEngine` session patches
  are now read/written race-free. Because G-H4 routes a STEER `add_constraint` to
  the SAME live per-run engine the SUB workers concurrently evaluate against,
  `add_session_patch` (called on its own `asyncio.to_thread`) and the matcher
  reads (in the Dispatcher `ThreadPoolExecutor`) raced on a plain in-place
  `_patches` list — CPython would not crash, but an in-flight step could miss a
  just-added STEER constraint (timing-dependent enforcement), weakening the P0
  real-time-stop guarantee and falsifying spec invariant 2 ("per-run engine
  read-only shared → race-free") on the STEER path. Fix: `add_session_patch`
  builds a NEW list and atomically rebinds `self._patches` under a
  `threading.Lock` (copy-on-write, never in-place mutation); `_match_banned_path`
  / `_match_banned_command` take a single lock-free local snapshot at entry and
  iterate that — so a concurrent swap never tears an in-flight evaluation and
  every evaluation that *starts* after a patch is published sees it (happens-
  before, no lost STEER constraint). Lock only orders concurrent writers;
  determinism (same input → same output) is unchanged. Added a 4-test concurrency
  regression suite (`tests/core/test_oversight_patch_concurrency.py`) including a
  deterministic mid-iteration-write torn-read probe that fails on the old in-place
  code and passes after the fix. Corrected the `OversightEngine` /
  `dispatcher._run_groups` docstrings (STEER write = lock+CoW serialised; matcher
  read = immutable per-evaluation snapshot).

No audit/log schema changes (§C-2): boot refusals and policy warnings are
operational logs, not decision-gate audit events. G-H4 **populates** the existing
`regulations_version` field (previously the `"n/a"` placeholder in
`audit/scheduler.py`) in event payloads — no new top-level field or gate.
