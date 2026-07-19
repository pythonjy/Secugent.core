<!-- SPDX-License-Identifier: Apache-2.0 -->
# Closed-net egress policy bundle (B6)

`closed_net.json` is an **unsigned** `PolicyDoc` *template* for a closed-network
(폐쇄망 / air-gap) deployment. It is the starting point an operator reviews and
signs — it is **NOT** loadable as-is. `AppState._resolve_broker_policy`
(`SECUGENT_POLICY_BUNDLE_PATH`) loads only a **signed** `SignedBundle` through
`secugent.core.sec.policy.loader.load_active_policy`, which fails closed on a
missing file, malformed JSON, an unsigned `PolicyDoc`, a wrong/forged signature,
or a `key_id` outside `SECUGENT_POLICY_ALLOWED_KEY_IDS`
(`PolicyLoadError`). Deny-by-default is structural (`default: "deny"`).

## What it enforces

| Effect | Decision | Why |
|--------|----------|-----|
| `net_send`/`net_recv` to `https://*.kr-bank.internal/*` (sink `internal`) | **allow** | internal-only bank domain |
| any sink `external` | **hard_block** | closed-net: no external egress, §C-1 HARD BLOCK |
| everything else | **deny** | deny-by-default (`default: "deny"`) |

`*` in a `target_glob` spans `/` (a glob is not segment-anchored) — author allow
rules narrowly. Adapt the domain/sink rows to the tenant before signing.

## Operator sign-off (4-eyes / MFA) — required before deploy

Signing is a deterministic human gate, never automatic. Use
`secugent.core.sec.policy.authoring.sign_off`: it refuses unless (1) the approver
is an **admin** with **MFA satisfied** and (2) every supplied behavior fixture
passes against the compiled draft (`AuthoringError` otherwise). The LLM is never
in the trust path.

```python
import json
from secugent.core.sec.policy import PolicyDoc, write_signed_bundle
from secugent.core.sec.policy.authoring import sign_off
from secugent.core.sec.policy.fixtures import Fixture
# kms / key_id come from your production KMS (Vault Transit / AWS KMS / GCP KMS),
# NOT the dev HMAC default. The signature NEVER enters the audit hash chain.

draft = PolicyDoc.model_validate_json(open("closed_net.json", encoding="utf-8").read())
fixtures: list[Fixture] = [
    # at minimum: one internal-allow row and one external-hard_block row
]
bundle = sign_off(draft, fixtures, approver=admin_principal, kms=kms, key_id=key_id)
write_signed_bundle(bundle, "/secrets/policy/active.bundle.json")
```

Then mount the signed bundle and pin the signer:

- `SECUGENT_POLICY_BUNDLE_PATH=/secrets/policy/active.bundle.json`
- `SECUGENT_POLICY_ALLOWED_KEY_IDS=<key_id>[,<key_id>...]`

In Helm, set `policyBundle.signedBundleJson` (chart-managed ConfigMap) or
`policyBundle.existingConfigMap`, plus `policyBundle.allowedKeyIds`. With
`egressBroker.enabled` in a non-dev install and no bundle, the chart **fails the
render** and the app **refuses to boot** (`BootPolicyError`) — fail-closed.

> Never commit a real signature or KMS secret. This template carries neither.
