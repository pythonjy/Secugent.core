# secugent-core v0.1.0 — 릴리스 노트

> 최초 공개 OSS 릴리스 (Apache-2.0 오픈코어). 작성: 2026-06-13 KST.

SecuGent는 에이전트를 *만드는* 빌더가 아니라, 어떤 프레임워크·모델 위에서든
작동하는 엔터프라이즈 에이전트 **통제·신뢰 레이어(Trust & Control Plane)** 입니다.
`secugent-core`는 그 결정적 통제 코어를 Apache-2.0으로 공개합니다.

## 이번 릴리스에 포함된 것 (Apache-2.0 Core)

- **결정적 Mechanical Oversight** — 명시적 위반은 위험점수와 무관하게 HARD BLOCK
  (deny-by-default). 동일 입력 → 동일 출력을 100회 검증.
- **Rule of Two 정책 엔진** — `[비신뢰 입력 / 민감 접근 / 상태변경·외부통신]` 중
  최대 2개만 허용, 셋 다면 HITL 강제.
- **append-only 감사 해시체인** — `prev_event_id` SHA-256 체인으로 위변조 검출,
  외부에서 독립 재계산 가능.
- **공개/비공개 manifest + import-closure 릴리스 게이트** — fail-closed로 비공개
  티어·시크릿·내부 전략 문서의 누출을 차단.
- **서명 릴리스 파이프라인** — sigstore keyless 서명(Rekor 투명 로그) + OIDC
  PyPI Trusted Publishing + CycloneDX SBOM.
- **신뢰 증명 문서** — `docs/security/TRUST_PROOF.md`.

## 설치 (Installation)

```bash
pip install secugent
```

## 무키 검증 (Verify — API 키 불필요)

```bash
# 결정성 100회 검증
secugent verify --determinism --fixture tests/cli/fixtures/determinism_seed.json
# 기대 출력: verify: determinism OK - 100 runs identical (digest <16자리-hex>)

# 무키 데모 (정책 HARD BLOCK → HITL 승인 → 감사 이벤트)
secugent demo
```

## 공급망 신뢰 검증 (Supply-chain trust)

릴리스 자산에 sigstore 서명(`.sigstore.json`)과 SBOM(`sbom.json`)이 첨부됩니다.

```bash
sigstore verify --bundle secugent-0.1.0-*.whl.sigstore.json secugent-0.1.0-*.whl
```

자세한 절차는 [`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md),
취약점 신고 절차는 [`SECURITY.md`](SECURITY.md)를 참조하세요.

## 라이선스 경계 (License boundary)

- **Core** — Apache-2.0 (이 저장소).
- **Enterprise tier** — `LicenseRef-SecuGent-Enterprise` (BSL-1.1 기반 상용 라이선스, 비공개).
  전체 티어 표: [`docs/OPEN_CORE.md`](docs/OPEN_CORE.md).

## 알려진 한계 (Known limitations)

- 0.x pre-GA 릴리스입니다. 공개 API는 향후 변경될 수 있습니다.
- Enterprise 티어(비용 강제 엔진, API 서버, 멀티테넌트 관리 등)는 공개 범위에 포함되지 않습니다.
- 라이브 트래픽 PostgreSQL cutover, end-to-end 3축 HITL 라이브 강제는 후속 릴리스에서 완성됩니다.
