#!/usr/bin/env bash
# =============================================================================
# scripts/extract_public_repo.sh
# SecuGent 공개 repo 추출 스크립트 — BDP_05 항목 3
#
# 사용법:
#   bash scripts/extract_public_repo.sh [OPTIONS]
#
# 옵션:
#   --mode snapshot|filter   추출 방식 (기본: snapshot; 권장)
#   --out <경로>             출력 디렉터리 (기본: ../secugent-core)
#   --dry-run                파일 목록만 출력 후 종료 (추출·git 초기화 안 함)
#   --help                   도움말 출력
#
# 히스토리 누출 위험:
#   snapshot (권장): 공개 파일만 새 빈 repo에 복사 → 단일 커밋.
#                    git history = 0 → I7(히스토리 무유출) 구조적 보장.
#   filter  (대안):  git filter-repo 사용. dangling object + filter miss 누출
#                    위험 존재. 반드시 post-filter 누출 스캔 필수 (§FILTER_CAVEAT).
#
# 의존:
#   - python3 (scripts/check_public_release.py, release/public_manifest.yaml)
#   - git
#   - git-filter-repo (filter 모드 전용; pip install git-filter-repo)
#
# 종료 코드:
#   0  성공 (공개 안전, 추출 완료)
#   1  사전 게이트 실패 — 퍼블리시 금지
#   2  인수 오류
#   3  의존 도구 누락
#   4  추출 후 재검증 실패 — 출력 디렉터리 삭제 금지, 수동 조사 필요
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────
# 0. 상수
# ─────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_OUT="${REPO_ROOT}/../secugent-core"
DEFAULT_MODE="snapshot"

# 공개 repo 커밋 메타데이터
COMMIT_AUTHOR_NAME="SecuGent Release Bot"
COMMIT_AUTHOR_EMAIL="release@secugent.io"
COMMIT_DATE_KST="$(TZ=Asia/Seoul date '+%Y-%m-%dT%H:%M:%S+09:00' 2>/dev/null \
                   || date -u '+%Y-%m-%dT%H:%M:%SZ')"
RELEASE_TAG="v0.1.0"

# 히스토리 누출 스캔 대상 (git log --all -- <pattern> 이 공집합이어야 통과)
LEAK_SCAN_PATHS=(
    "CLAUDE.md"
    "Review"
    "docs/specs"
    "BDP_REFORMED"
    "DEPLOY_PROGRESS.md"
    "report_1.md"
    "SecuGent_시장진단_대시보드.html"
    "SecuGent_로우리스크_기능우선순위.html"
    ".claude"
    "data"
)

# ─────────────────────────────────────────────────
# 1. 유틸 함수
# ─────────────────────────────────────────────────

log_info()  { echo "[INFO]  $*" >&2; }
log_warn()  { echo "[WARN]  $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

die() {
    local code="${1}"; shift
    log_error "$*"
    exit "${code}"
}

require_cmd() {
    local cmd="${1}"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_error "필수 명령어 '${cmd}'를 찾을 수 없습니다."
        return 1
    fi
}

usage() {
    cat <<'USAGE'
사용법: extract_public_repo.sh [--mode snapshot|filter] [--out <경로>] [--dry-run] [--help]

  --mode snapshot   공개 파일만 새 빈 repo에 복사 후 단일 커밋 (기본; 권장)
                    히스토리 누출 위험 = 0 (Invariant I7 구조적 보장)
  --mode filter     git filter-repo 사용 (대안; 누출 위험 있음 — §FILTER_CAVEAT)
  --out <경로>      출력 디렉터리 (기본: ../secugent-core)
  --dry-run         사전 게이트만 실행 + 공개 파일 목록 출력; 추출·git 초기화 없음
  --help            이 도움말 출력

종료 코드:
  0  성공   1  게이트 실패   2  인수 오류   3  의존 누락   4  추출 후 재검증 실패

※ 퍼블리시 전 반드시 RUNBOOK(release/PUBLIC_RELEASE_RUNBOOK.md) 전체 절차를 따르십시오.
USAGE
}

# ─────────────────────────────────────────────────
# 2. snapshot 모드 함수
# ─────────────────────────────────────────────────

extract_snapshot() {
    local out_dir="${1}"
    local repo_root="${2}"
    local file_list="${3}"
    local file_count="${4}"

    log_info "═══ [추출] snapshot 모드 시작 ═══"
    log_info "공개 파일 ${file_count}건을 ${out_dir}/ 로 복사합니다."

    local src_file dst_file dst_dir
    local copied=0
    local skipped=0

    while IFS= read -r rel_path; do
        # 후행 CR 제거 (Windows CRLF 목록 방어선 — python 측 LF 고정과 이중 보호).
        rel_path="${rel_path%$'\r'}"
        [[ -z "${rel_path}" ]] && continue
        src_file="${repo_root}/${rel_path}"
        dst_file="${out_dir}/${rel_path}"
        dst_dir="$(dirname "${dst_file}")"

        if [[ ! -f "${src_file}" ]]; then
            log_warn "파일 없음(건너뜀): ${rel_path}"
            skipped=$(( skipped + 1 ))
            continue
        fi

        mkdir -p "${dst_dir}"
        cp "${src_file}" "${dst_file}"
        copied=$(( copied + 1 ))
    done < "${file_list}"

    log_info "복사 완료: ${copied}건 성공, ${skipped}건 건너뜀."

    if [[ "${copied}" -eq 0 ]]; then
        die 1 "복사된 파일이 0건입니다. manifest를 확인하십시오."
    fi

    # git 초기화 + 단일 커밋 (히스토리 없는 새 repo)
    log_info "git 초기화: ${out_dir}"
    git -C "${out_dir}" init --initial-branch=main

    local today_kst
    today_kst="$(TZ=Asia/Seoul date '+%Y-%m-%d KST' 2>/dev/null || date -u '+%Y-%m-%d UTC')"

    GIT_AUTHOR_NAME="${COMMIT_AUTHOR_NAME}" \
    GIT_AUTHOR_EMAIL="${COMMIT_AUTHOR_EMAIL}" \
    GIT_COMMITTER_NAME="${COMMIT_AUTHOR_NAME}" \
    GIT_COMMITTER_EMAIL="${COMMIT_AUTHOR_EMAIL}" \
    GIT_AUTHOR_DATE="${COMMIT_DATE_KST}" \
    GIT_COMMITTER_DATE="${COMMIT_DATE_KST}" \
    git -C "${out_dir}" add -A

    GIT_AUTHOR_NAME="${COMMIT_AUTHOR_NAME}" \
    GIT_AUTHOR_EMAIL="${COMMIT_AUTHOR_EMAIL}" \
    GIT_COMMITTER_NAME="${COMMIT_AUTHOR_NAME}" \
    GIT_COMMITTER_EMAIL="${COMMIT_AUTHOR_EMAIL}" \
    GIT_AUTHOR_DATE="${COMMIT_DATE_KST}" \
    GIT_COMMITTER_DATE="${COMMIT_DATE_KST}" \
    git -C "${out_dir}" commit \
        --no-gpg-sign \
        -m "chore: initial public release secugent-core ${RELEASE_TAG}

SecuGent 오픈코어 첫 번째 공개 릴리스.
스냅샷 추출 — git history 없음 (Invariant I7 보장).
추출일: ${today_kst}"

    git -C "${out_dir}" tag "${RELEASE_TAG}"
    log_info "태그 생성: ${RELEASE_TAG}"
}

# ─────────────────────────────────────────────────
# 3. filter 모드 함수 (대안 — 누출 위험; 비권장)
# ─────────────────────────────────────────────────
# §FILTER_CAVEAT:
#   git filter-repo는 지정 경로를 히스토리에서 제거하지만:
#   1) dangling object: 필터링된 커밋/blob이 GC 전까지 객체 DB에 잔존.
#      'git gc --aggressive --prune=now' 필수 — 그래도 reflog 잔존 가능.
#   2) filter miss: 경로 패턴 누락 시 비공개 파일이 그대로 노출됨.
#   3) merge commit: 복잡한 merge 히스토리에서 partial rewrite 발생 가능.
#   → 필수 후속 조치: 아래 게이트 4 히스토리 스캔을 반드시 통과해야 함.
#   → snapshot 모드(--mode snapshot)를 강력히 권장합니다.

extract_filter() {
    local out_dir="${1}"
    local repo_root="${2}"
    local file_list="${3}"

    log_warn "filter 모드 — dangling object / filter miss 누출 위험이 있습니다."
    log_warn "snapshot 모드(--mode snapshot)를 강력히 권장합니다."

    if ! require_cmd git-filter-repo; then
        die 3 "filter 모드에는 git-filter-repo가 필요합니다. 설치: pip install git-filter-repo"
    fi

    log_info "═══ [추출] filter 모드 시작 ═══"

    # 원본 repo를 OUT_DIR로 복제
    log_info "원본 repo 복제: ${repo_root} → ${out_dir}"
    git clone --no-local -- "${repo_root}" "${out_dir}"

    # 공개 파일 목록에서 keep 경로 파일 생성 (filter-repo --paths-from-file 형식)
    local paths_file
    paths_file="$(mktemp /tmp/secugent_filter_paths_XXXXXX.txt)"
    # 각 공개 파일을 명시적으로 keep — glob 방식보다 누락 위험 낮음.
    # 후행 CR 제거: filter-repo keep 경로는 LF 인덱스 엔트리와 바이트 비교되므로
    # CRLF가 섞이면 모든 keep 매칭이 빗나간다(Windows 방어선).
    sed 's/\r$//' "${file_list}" > "${paths_file}"

    local path_count
    path_count="$(wc -l < "${paths_file}")"
    log_info "filter-repo 실행 — keep 경로 수: ${path_count}"

    git -C "${out_dir}" filter-repo \
        --paths-from-file "${paths_file}" \
        --force

    # dangling object 강제 제거
    log_info "dangling object 제거: git gc --aggressive --prune=now"
    git -C "${out_dir}" gc --aggressive --prune=now

    git -C "${out_dir}" tag "${RELEASE_TAG}" HEAD
    log_info "태그 생성: ${RELEASE_TAG}"

    rm -f "${paths_file}"

    log_warn "filter 모드 완료. 게이트 4(히스토리 누출 스캔)를 반드시 통과해야 합니다."
}

# ─────────────────────────────────────────────────
# 4. 인수 파싱
# ─────────────────────────────────────────────────

MODE="${DEFAULT_MODE}"
OUT_DIR="${DEFAULT_OUT}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            [[ $# -ge 2 ]] || die 2 "--mode 인수가 필요합니다 (snapshot 또는 filter)."
            MODE="$2"; shift 2
            ;;
        --out)
            [[ $# -ge 2 ]] || die 2 "--out 인수가 필요합니다."
            OUT_DIR="$2"; shift 2
            ;;
        --dry-run)
            DRY_RUN=1; shift
            ;;
        --help|-h)
            usage; exit 0
            ;;
        *)
            die 2 "알 수 없는 옵션: '$1'. --help 참고."
            ;;
    esac
done

if [[ "${MODE}" != "snapshot" && "${MODE}" != "filter" ]]; then
    die 2 "--mode는 'snapshot' 또는 'filter' 중 하나여야 합니다. 입력값: '${MODE}'"
fi

# ─────────────────────────────────────────────────
# 5. 사전 게이트 — check_public_release.py
# ─────────────────────────────────────────────────

GATE_SCRIPT="${REPO_ROOT}/scripts/check_public_release.py"

if [[ ! -f "${GATE_SCRIPT}" ]]; then
    die 3 "사전 게이트 스크립트를 찾을 수 없습니다: ${GATE_SCRIPT}
BDP_05 항목 2(Unit 2)가 먼저 완료되어야 합니다."
fi

log_info "═══ [게이트 1/4] import-closure + 시크릿 스캔 사전 게이트 ═══"
log_info "실행: python3 ${GATE_SCRIPT}"

# 진단 리포트는 stderr로 — dry-run의 stdout(기계 판독용 공개 파일 목록)과 분리한다.
if ! python3 "${GATE_SCRIPT}" >&2; then
    die 1 "사전 게이트 실패 — 퍼블리시 금지.
위반 목록을 확인하고 manifest 또는 소스를 수정한 뒤 재실행하십시오."
fi

log_info "사전 게이트 통과 (위반 0)."

# ─────────────────────────────────────────────────
# 6. 공개 파일 목록 산출 (결정적·정렬)
# ─────────────────────────────────────────────────

log_info "═══ [게이트 2/4] 공개 파일 목록 산출 ═══"

# Python 헬퍼: check_public_release 모듈의 public_files() 호출 후 줄당 경로 출력.
# 경로는 repo_root 상대 경로(POSIX). 정렬·결정적 (Invariant I4/I6).
# 주의: POSIX 경로(${REPO_ROOT})를 python 문자열에 직접 삽입하지 않는다.
#       대신 서브셸에서 REPO_ROOT를 cwd로 설정하고 python 내부에서
#       pathlib.Path.cwd()로 repo_root를 얻는다. scripts/__init__.py가 있으므로
#       scripts 패키지 import가 가능하다(Windows/Linux 모두 이식 가능).
#       또한 stdout을 LF-only로 고정한다 — Windows의 win32 python3는 text-mode
#       stdout이 '\n'을 '\r\n'으로 변환해 파일 목록에 후행 CR이 섞이고, 그 CR이
#       추출 read-loop의 [[ -f ]] 검사를 모두 빗나가게 해 0건 복사로 실패한다.
PY_FILE_LIST_CMD="
import pathlib, sys
sys.stdout.reconfigure(newline='\n')
from scripts.check_public_release import load_manifest, public_files

repo_root = pathlib.Path.cwd()
manifest = load_manifest(repo_root / 'release' / 'public_manifest.yaml')
for f in public_files(manifest, repo_root):
    print(f.relative_to(repo_root).as_posix())
"

TMP_FILE_LIST="$(mktemp /tmp/secugent_public_files_XXXXXX.txt)"
trap 'rm -f "${TMP_FILE_LIST}"' EXIT

if ! ( cd "${REPO_ROOT}" && python3 -c "${PY_FILE_LIST_CMD}" ) > "${TMP_FILE_LIST}"; then
    die 1 "공개 파일 목록 산출 실패 (check_public_release 임포트 오류)."
fi

FILE_COUNT="$(wc -l < "${TMP_FILE_LIST}" | tr -d ' ')"
log_info "공개 파일 ${FILE_COUNT}건 확인됨."

if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "── dry-run 모드: 공개 파일 목록 출력 후 종료 ──"
    cat "${TMP_FILE_LIST}"
    log_info "dry-run 완료. 추출 및 git 초기화는 수행되지 않았습니다."
    exit 0
fi

# ─────────────────────────────────────────────────
# 7. 출력 디렉터리 준비 (이미 존재하면 안전 차단)
# ─────────────────────────────────────────────────

if [[ -e "${OUT_DIR}" ]]; then
    die 1 "출력 경로가 이미 존재합니다: ${OUT_DIR}
기존 디렉터리를 수동으로 삭제한 뒤 재실행하십시오 (자동 삭제하지 않음 — 안전 보장)."
fi

log_info "출력 디렉터리 생성: ${OUT_DIR}"
mkdir -p "${OUT_DIR}"

# ─────────────────────────────────────────────────
# 8. 모드별 추출 실행
# ─────────────────────────────────────────────────

if [[ "${MODE}" == "snapshot" ]]; then
    extract_snapshot "${OUT_DIR}" "${REPO_ROOT}" "${TMP_FILE_LIST}" "${FILE_COUNT}"
else
    extract_filter "${OUT_DIR}" "${REPO_ROOT}" "${TMP_FILE_LIST}"
fi

# ─────────────────────────────────────────────────
# 9. 추출 후 재검증 — 이중 안전망
# ─────────────────────────────────────────────────

log_info "═══ [게이트 3/4] 추출본 import-closure + 시크릿 재검증 ═══"

GATE_IN_OUT="${OUT_DIR}/scripts/check_public_release.py"

if [[ -f "${GATE_IN_OUT}" ]]; then
    # Run the in-extract gate with NO arguments. check_public_release.main()
    # accepts only an optional positional MANIFEST path (no --repo-root flag); its
    # _REPO_ROOT is derived from __file__ (scripts/../ = the extract dir), so a
    # bare invocation re-scans the extracted copy correctly. Passing --repo-root
    # here would be misread as a manifest path and always fail (ManifestError).
    if ! python3 "${GATE_IN_OUT}"; then
        die 4 "추출본 재검증 실패 (import-closure/시크릿 스캔).
출력 디렉터리 ${OUT_DIR} 를 삭제하고 소스를 수정한 뒤 재실행하십시오."
    fi
    log_info "추출본 재검증 통과."
else
    log_warn "추출본에 check_public_release.py 없음 — 게이트 3 건너뜀."
    log_warn "manifest의 scripts/check_public_release.py 포함 여부를 확인하십시오."
fi

log_info "═══ [게이트 4/4] git 히스토리 누출 스캔 ═══"

LEAK_FOUND=0
for pattern in "${LEAK_SCAN_PATHS[@]}"; do
    HITS="$(git -C "${OUT_DIR}" log --all --oneline -- "${pattern}" 2>/dev/null || true)"
    if [[ -n "${HITS}" ]]; then
        log_error "히스토리 누출 탐지: '${pattern}'"
        log_error "  → ${HITS}"
        LEAK_FOUND=1
    fi
done

if [[ "${LEAK_FOUND}" -ne 0 ]]; then
    die 4 "히스토리 누출 스캔 실패 (Invariant I7 위반).
출력 디렉터리 ${OUT_DIR} 를 삭제하고 원인을 조사한 뒤 재실행하십시오.
snapshot 모드라면 이 오류는 발생하지 않아야 합니다 — 버그 리포트 필요."
fi

log_info "히스토리 누출 스캔 통과 (공집합 확인)."

# ─────────────────────────────────────────────────
# 10. 완료 보고
# ─────────────────────────────────────────────────

COMMIT_HASH="$(git -C "${OUT_DIR}" rev-parse HEAD 2>/dev/null || echo 'unknown')"

cat >&2 <<DONE
═══════════════════════════════════════════════════════════════
  secugent-core 공개 repo 추출 완료
───────────────────────────────────────────────────────────────
  모드          : ${MODE}
  출력 디렉터리 : ${OUT_DIR}
  파일 수       : ${FILE_COUNT}
  커밋 해시     : ${COMMIT_HASH}
  태그          : ${RELEASE_TAG}
───────────────────────────────────────────────────────────────
  다음 단계 (수동):
  1. cd ${OUT_DIR} && pip install -e ".[dev]" && pytest -q
  2. secugent verify --determinism  (100회 해시 일치 확인)
  3. secugent demo                  (무키 동작 확인)
  4. release/PUBLIC_RELEASE_RUNBOOK.md 섹션 6 퍼블리시 핸드오프 절차 수행
  전역 차단 게이트 미통과 시 퍼블리시 금지 (BDP_05)
═══════════════════════════════════════════════════════════════
DONE

exit 0
