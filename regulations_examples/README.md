# REGULATIONS Examples

기계적 감독(Mechanical Oversight) 정책의 예시 REGULATIONS 파일 모음. 아래 JSON은
그대로 `secugent.core.regulations.Regulations` 로 로드해 정책 엔진을 구성할 수 있는
샘플 픽스처다(실배포용 정책이 아니라 형식/시나리오 참고용).

| 파일 | 시나리오 | 비고 |
| --- | --- | --- |
| `default.json` | 일반 기업 기본값 | `confidential/`, `secrets/` 경로 차단, allow-list 도메인 |
| `strict_finance.json` | 금융권 부동산금융(PF 심사) | 대외비/고객 신원/신용 평가 모델 차단, 외부 송신 명령 차단 |

두 파일 모두 한국 금융·공공 도메인을 기준으로 작성된 결정적(deny-by-default) 정책
예시이며, 비밀·자격증명 등 민감정보는 포함하지 않는다.
