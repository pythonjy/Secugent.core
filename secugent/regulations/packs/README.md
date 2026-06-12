# 한국어 정책 팩 (Korean Policy Packs)

설치 직후 "바로 통제됨"을 경험하도록 제공되는 즉시 적용 가능한 REGULATIONS 정책
템플릿 모음입니다. 각 팩은 기존 `secugent.core.regulations.Regulations` 스키마를
그대로 따르는 유효한 YAML 문서이며, 한국 폐쇄망·금융·공공 맥락(§C-3)에 맞춰
한국어 자연어 라벨과 출처 규정 주석을 포함합니다.

## 팩 목록 (출처 규정)

| 파일 | 규정 | 핵심 통제 |
| --- | --- | --- |
| `kr_efin_supervision.yaml` | 전자금융감독규정 (금융위·금감원) | 계좌정보·거래내역 접근 차단, 금융 PII 외부 전송 차단 |
| `kr_credit_info.yaml` | 신용정보법 | 개인신용정보 처리·제3자 제공 통제, 신용평가모델 변조 차단 |
| `kr_pipa.yaml` | 개인정보보호법 (PIPA) | 고유식별정보·민감정보 통제, 자동화 의사결정 기록 보호 |
| `kr_n2sf_mapping.yaml` | 국정원 N²SF | 기밀(C)/민감(S) 데이터 망분리 반출 차단 |

## 사용법

```python
from secugent.regulations.tenant_loader import (
    load_pack,
    load_packs_from_dir,
    merge_packs,
    default_packs_dir,
)
from secugent.core.regulations import load_regulations

# 1) 단일 팩 로드
regs = load_pack("secugent/regulations/packs/kr_pipa.yaml")

# 2) packs/ 디렉토리의 모든 팩 로드 (파일명 정렬 → 결정적 순서)
packs = load_packs_from_dir(default_packs_dir())

# 3) 조직 base 정책 위에 팩들을 strengthen-only 병합
base = load_regulations("regulations_examples/default.json")
effective = merge_packs(base, packs)
```

## 병합 규칙 (strengthen-only)

팩 병합은 기존 `RegulationsLoader._merge` 경로를 그대로 재사용하며, **통제를 강화만**
합니다. 새 통제 규칙은 union(합집합)으로 추가되고, 다음 완화 시도는 모두
`RegulationsSchemaError`로 **거부**됩니다.

- `data_labels` 민감도(severity) 하향, `hard_block` 해제,
  `allowed_actions` 확대, `path_patterns` 축소 → 거부 (`_reject_data_label_relaxation`).
- `banned_paths` / `banned_commands` severity 하향·`hard_block` 해제 → 거부.
- `domain_policy` allow_list → deny_list 전환 → 거부.
- 중복 `rule_id`는 강화 검증 후 병합되고, 다중 팩은 union으로 누적됩니다.

병합은 결정적입니다: 동일한 (base, 팩 집합) → 동일한 `Regulations.checksum()`.

## 주의

- 이 팩들은 **출발점 템플릿**입니다. 운영 환경의 실제 디렉토리 구조·도메인에 맞게
  `path_patterns`·`domains`를 조직별 override로 **강화**하여 사용하십시오 (완화는 불가).
- 손상되었거나 스키마를 위반한 YAML은 `RegulationsLoadError`로 fail-closed 됩니다.
