# SecuGent 공개 릴리스 런북 — secugent-core v0.1.0

> 작성: 2026-06-10 KST | 언어 기본값: 한국어
>
> 이 문서는 `secugent-core v0.1.0` 공개 OSS 릴리스를 **수동 수행자가 단계별로
> 실행하는 절차서**입니다. 스크립트 자동화 범위와 수동 핸드오프 범위를 명확히 구분합니다.
>
> 퍼블리시 전 반드시 **§1 전역 릴리스 차단 게이트**를 통과해야 합니다.

---

## §0. 용어 정의

| 용어 | 설명 |
|------|------|
| **소스 repo** | `D:/Project_Secugent` (또는 CI/CD 환경의 내부 원본 저장소) |
| **공개 repo** | 추출 후 생성되는 `../secugent-core` 디렉터리 (추후 GitHub에 업로드) |
| **manifest** | `release/public_manifest.yaml` — 공개 파일 화이트리스트·블랙리스트 |
| **게이트 스크립트** | `scripts/check_public_release.py` — import-closure·시크릿 스캔 |
| **추출 스크립트** | `scripts/extract_public_repo.sh` — 공개 repo 생성 자동화 |
| **I7** | 불변조건: 공개 repo `git log --all`에 비공개 경로·내용 0건 |
| **I8** | 불변조건: 공개 repo 단독 `pip install . && pytest -q` 통과 |
| **I9** | 불변조건: API 키 없이 `secugent demo` · `secugent verify` 성공 |
| **I10** | 불변조건: `secugent verify --determinism` 100회 전부 동일 해시 |

---

## §1. 전역 릴리스 차단 게이트 ⛔

아래 6개 게이트 중 **하나라도 실패하면 퍼블리시 금지**입니다.
각 게이트 결과를 이 문서 §7 체크리스트에 기록하십시오.

| # | 게이트 | 확인 방법 | 담당 |
|---|--------|-----------|------|
| G1 | 미분류 모듈 0 | `pytest tests/unit/test_open_core_boundary.py -q` | 자동 |
| G2 | import-closure 위반 0 | `python scripts/check_public_release.py` | 자동 |
| G3 | 내부 전략·시크릿 스캔 0 | `python scripts/check_public_release.py` (G2와 동시) | 자동 |
| G4 | 히스토리 누출 스캔 공집합 | 추출 스크립트 게이트 4 또는 §4.3 수동 스캔 | 자동+수동 |
| G5 | 추출본 무키 demo·verify·테스트 그린 | §5 설치 후 검증 | 수동 |
| G6 | 서명 릴리스 | §6 퍼블리시 핸드오프 | 수동 (별도 세션) |

---

## §2. 전제 조건 (Pre-flight Checklist)

추출 스크립트 실행 전 아래 항목을 점검합니다.

### 2.1 도구 설치 확인

```bash
# Python 3.11 이상 필요
python3 --version            # 3.11+

# git 2.38 이상 권장 (--initial-branch 지원)
git --version                # 2.38+

# PyYAML 필요 (check_public_release.py 의존)
python3 -c "import yaml; print(yaml.__version__)"

# (선택) shellcheck — 스크립트 정적 분석
shellcheck --version

# (filter 모드 전용) git-filter-repo
pip show git-filter-repo
```

### 2.2 소스 repo 상태 확인

```bash
cd D:/Project_Secugent          # 또는 소스 repo 경로

# 1. 미커밋 변경 없음 확인
git status --short
# → 출력 없음이어야 함 (변경 있으면 커밋 또는 스태시 후 진행)

# 2. 릴리스 대상 커밋이 모두 main에 있음 확인
git log --oneline -20

# 3. manifest 존재 확인
test -f release/public_manifest.yaml && echo "OK" || echo "MISSING"

# 4. 게이트 스크립트 존재 확인
test -f scripts/check_public_release.py && echo "OK" || echo "MISSING"
```

### 2.3 출력 경로 비어있음 확인

```bash
# 기본 출력 경로
ls ../secugent-core 2>/dev/null && echo "WARN: 이미 존재함 — 삭제 필요" || echo "OK"
```

---

## §3. 사전 게이트 단독 실행 (선택 — 추출 전 예비 점검)

추출 스크립트는 내부적으로 게이트를 자동 실행하지만, 사전에 수동으로 확인하려면:

```bash
cd D:/Project_Secugent

# import-closure 위반 + 내부 전략·시크릿 스캔 (게이트 G2·G3)
python3 scripts/check_public_release.py
# 기대 출력: "공개 안전: 위반 0건" + 종료 코드 0

# 단위 경계 테스트 (게이트 G1)
python3 -m pytest tests/unit/test_open_core_boundary.py -q
# 기대 출력: 전체 통과
```

두 명령 모두 오류 없이 종료하면 추출을 진행합니다.

---

## §4. 공개 repo 추출 — snapshot 모드 (권장)

### 4.1 snapshot 모드 실행

```bash
cd D:/Project_Secugent

# 기본 실행 (출력: ../secugent-core)
bash scripts/extract_public_repo.sh --mode snapshot --out ../secugent-core

# 커스텀 출력 경로 지정
bash scripts/extract_public_repo.sh --mode snapshot --out /tmp/secugent-core-preview
```

스크립트가 내부에서 아래 4단계 게이트를 순서대로 실행합니다.

| 게이트 | 내용 | 실패 시 |
|--------|------|---------|
| 게이트 1/4 | `check_public_release.py` 사전 검증 (G2·G3) | 종료 코드 1, 추출 안 함 |
| 게이트 2/4 | 공개 파일 목록 산출 (결정적·정렬) | 종료 코드 1 |
| 게이트 3/4 | 추출본 내부 재검증 | 종료 코드 4 |
| 게이트 4/4 | git 히스토리 누출 스캔 (G4) | 종료 코드 4 |

### 4.2 dry-run 모드 (파일 목록만 확인)

```bash
bash scripts/extract_public_repo.sh --dry-run
# git 초기화·복사 없이 공개 파일 목록만 stdout에 출력
```

### 4.3 누출 스캔 수동 재확인

스크립트 완료 후 아래 명령으로 히스토리 누출을 **직접** 확인합니다.
모든 명령의 출력이 비어 있어야 합니다 (공집합 = 통과).

```bash
OUT=../secugent-core   # 실제 출력 경로로 변경

# 비공개 경로가 git history에 없음을 확인 (I7)
git -C "${OUT}" log --all --oneline -- CLAUDE.md
git -C "${OUT}" log --all --oneline -- Review
git -C "${OUT}" log --all --oneline -- docs/specs
git -C "${OUT}" log --all --oneline -- BDP_REFORMED
git -C "${OUT}" log --all --oneline -- DEPLOY_PROGRESS.md
git -C "${OUT}" log --all --oneline -- report_1.md
git -C "${OUT}" log --all --oneline -- "SecuGent_시장진단_대시보드.html"
git -C "${OUT}" log --all --oneline -- "SecuGent_로우리스크_기능우선순위.html"
git -C "${OUT}" log --all --oneline -- .claude
git -C "${OUT}" log --all --oneline -- data

# 전체 커밋 수는 반드시 1이어야 함 (단일 커밋 스냅샷)
git -C "${OUT}" rev-list --count HEAD
# 기대 출력: 1
```

---

## §5. 추출본 설치·검증 (게이트 G5)

아래 명령은 **공개 repo(`../secugent-core`)** 디렉터리 안에서 실행합니다.
API 키·내부 패키지 없이 모두 통과해야 합니다 (I8·I9·I10).

```bash
cd ../secugent-core

# 1. 설치 (가상환경 권장)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 2. 전체 테스트 통과 확인 (I8)
pytest -q
# 기대: 전체 그린, 0 failures

# 3. 결정성 100회 검증 (I10)
secugent verify --determinism --fixture tests/cli/fixtures/determinism_seed.json
# 기대 출력 (secugent/cli/verify.py 실제 출력 형식):
#   verify: determinism OK - 100 runs identical (digest <16자리-hex>)
# 종료 코드 0 이면 통과. (--determinism 은 --fixture <시드 경로> 가 필요합니다.)

# 4. 무키 데모 실행 (I9)
secugent demo
# 기대: 에러 없이 데모 완료, API 키 요구 없음

# 5. 임포트 완전성 확인
python3 -c "import secugent; print(secugent.__version__)"
# 기대: v0.1.0 (또는 현재 버전)
```

### 5.1 실패 시 대응

| 증상 | 원인 추정 | 조치 |
|------|-----------|------|
| `ImportError: secugent.cost` | Enterprise 파일 누락 없이 Core 파일이 cost 참조 | manifest exclude 재확인, R1~R4 클로저 리스크 점검 |
| `pytest` 실패: `ModuleNotFoundError` | `pyproject.toml` 의존 누락 또는 Enterprise extra 참조 | `pyproject.toml` 공개본 extra 점검 (§R6) |
| `secugent verify` 결정성 불일치 | 비결정적 코드 경로, 시간 의존성 | `secugent/core/mechanical_oversight.py` 결정성 테스트 확인 |
| API 키 요구 | `secugent demo`가 외부 LLM 호출 시도 | demo 커맨드가 로컬 mock/stub를 사용하도록 수정 |

---

## §6. 퍼블리시 핸드오프 (항목 5 — 수동, 별도 세션)

아래 단계는 **G5까지 전부 통과한 뒤에만** 진행합니다.

### 6.1 GitHub 저장소 생성

```bash
# GitHub에 secugent-core 저장소 생성 (Private → 공개 전 검토 → Public)
# 저장소 설정:
#   - License: Apache-2.0 (LICENSE 파일 참고)
#   - Branch protection: main 브랜치 보호 규칙 적용
#   - README: 이미 포함됨
```

### 6.2 원격 push

```bash
cd ../secugent-core

# GitHub 원격 설정
git remote add origin https://github.com/<org>/secugent-core.git

# main 브랜치 push
git push -u origin main

# 태그 push
git push origin v0.1.0
```

### 6.3 GitHub 릴리스 생성 (서명 포함 — 별도 세션)

```bash
# SBOM 첨부
gh release create v0.1.0 \
  --title "secugent-core v0.1.0" \
  --notes-file release/RELEASE_NOTES_v0.1.0.md \
  sbom.json \
  # (서명 파일 — 별도 세션에서 생성)
```

### 6.4 PyPI 퍼블리시 (선택 — 별도 세션)

```bash
cd ../secugent-core

# 배포 패키지 빌드
python3 -m build

# TestPyPI 검증 (권장)
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ secugent-core

# 본 PyPI 업로드
twine upload dist/*
```

---

## §7. 릴리스 완료 체크리스트

이 체크리스트를 인쇄하거나 복사해 실제 릴리스 실행 기록으로 사용하십시오.

```
릴리스 실행자  : ___________________________
실행 일시 (KST): ___________________________
소스 커밋 해시  : ___________________________
공개 커밋 해시  : ___________________________

[ ] G1 — 미분류 모듈 0  (test_open_core_boundary.py 통과)
[ ] G2 — import-closure 위반 0  (check_public_release.py exit 0)
[ ] G3 — 내부 전략·시크릿 스캔 0  (check_public_release.py exit 0)
[ ] G4 — 히스토리 누출 스캔 공집합  (게이트 4/4 통과 + §4.3 수동 확인)
[ ] G5a — 추출본 pytest -q 전체 그린
[ ] G5b — secugent verify --determinism: "determinism OK - 100 runs identical" (종료 0)
[ ] G5c — secugent demo 무키 성공
[ ] PRE-G6 — `grep -rl security@secugent.example` 가 공집합이 될 때까지 모든 매치(SECURITY.md · CODE_OF_CONDUCT.md · CONTRIBUTING.md)의 플레이스홀더를 실제 보안 연락 주소로 교체 (공개 전 필수)
[ ] G6  — (별도 세션) GitHub 릴리스 + 서명 완료

비고:
___________________________________________
```

---

## §8. filter 모드 절차 (대안 — 비권장)

> **주의**: filter 모드는 dangling object, filter miss, merge commit rewrite 등 누출 위험이
> 있습니다. snapshot 모드(`--mode snapshot`)를 강력히 권장합니다. 이 섹션은 filter 모드를
> 사용해야 하는 특수 상황(예: git history 보존이 요구사항인 경우)에만 참고하십시오.

### 8.1 실행

```bash
# git-filter-repo 설치 확인
pip install git-filter-repo

# filter 모드로 추출 (OUT_DIR에 git history 포함)
bash scripts/extract_public_repo.sh --mode filter --out ../secugent-core-filtered
```

### 8.2 filter 모드 필수 후속 조치

```bash
OUT=../secugent-core-filtered

# 1. dangling object 강제 제거
git -C "${OUT}" gc --aggressive --prune=now

# 2. reflog 만료 (잔존 객체 정리)
git -C "${OUT}" reflog expire --expire=now --all
git -C "${OUT}" gc --prune=now

# 3. §4.3 누출 스캔 수동 재확인 (snapshot보다 엄격히 실행)
# 모든 git log --all -- <비공개경로> 출력이 비어야 함

# 4. 객체 무결성 확인
git -C "${OUT}" fsck --strict 2>&1 | grep -v "^Checking" || echo "fsck 이상 없음"
```

### 8.3 filter miss 사전 예방

manifest `exclude` 목록의 각 패턴에 대해 아래 명령을 실행합니다.
출력이 공집합이 아니면 filter-repo 옵션을 수정한 뒤 재실행하십시오.

```bash
# 예시: docs/specs/ 누출 확인
git -C "${OUT}" log --all --oneline -- "docs/specs/"

# 예시: Enterprise 패키지 누출 확인
git -C "${OUT}" log --all --oneline -- "secugent/enterprise/"
git -C "${OUT}" log --all --oneline -- "secugent/cost/"
git -C "${OUT}" log --all --oneline -- "secugent/api/"
```

---

## §9. 자주 묻는 질문

**Q: snapshot 모드에서 git history가 없으면 기여자 credit은 어떻게 처리합니까?**
A: 공개 repo는 단일 커밋으로 시작합니다. 기여자 목록은 `NOTICE` 파일 또는
`CHANGELOG.md`에 명시합니다. git history 노출 없이 credit을 부여하는 표준 방식입니다.

**Q: v0.1.0 이후 패치를 공개 repo에 반영하는 절차는?**
A: 소스 repo에서 변경 후 manifest 갱신 → 게이트 통과 → 추출 스크립트 재실행
(`--out` 경로를 새 임시 경로로 지정) → §5 검증 → §6 핸드오프.
매 릴리스마다 이 런북을 처음부터 수행합니다.

**Q: `secugent/deploy/`에 배포 비밀이 없는지 어떻게 확인합니까?**
A: `check_public_release.py`의 `scan_forbidden_content()`가 `.env` 패턴·API 키 정규식으로
검사합니다. 추가로 `git -C ../secugent-core grep -r "password\|secret\|token" deploy/`를
수동 실행해 이상 여부를 확인하십시오.

**Q: 한글 파일명(`*시장진단*` 등) 블랙리스트가 실제로 동작합니까?**
A: 네. `check_public_release.py`는 `pathlib.Path.match()`를 쓰지 **않습니다** —
`Path.match()`의 `**`·한글 처리가 Python 3.14에서 일관적이지 않아(R12), 결정적
`**` 의미를 갖는 자체 glob→정규식 변환기(`_glob_to_regex`)로 매니페스트 글롭을
처리합니다. 추가로 한글 전략 파일명은 glob 엔진과 **무관하게** 파일명에 대한
직접 부분문자열 검사(`_FORBIDDEN_HANGUL_SUBSTRINGS` = `시장진단`·`로우리스크`·`전략`)로
이중 차단합니다 — glob 엔진 quirk가 있어도 누출되지 않습니다. 추출 후
`ls ../secugent-core` 에 한글 파일명이 없음을 시각적으로도 확인하십시오 (§4.3).

---

*런북 작성: 2026-06-10 KST | 다음 검토: v0.2.0 릴리스 전*
