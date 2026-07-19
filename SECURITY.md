# Security Policy

SecuGent is an enterprise agent **trust & control plane**: a security product whose
entire value proposition is that it can be trusted to deterministically constrain
autonomous agents. We therefore treat security reports as first-class work.

This file is the **reporting and disclosure policy**. For the public Core, the
normative security *invariants* live in this file together with
[`docs/security/threat_model.md`](docs/security/threat_model.md) (attacker-centric
STRIDE analysis) and [`docs/security/TRUST_PROOF.md`](docs/security/TRUST_PROOF.md)
(externally reproducible determinism + audit-chain proofs). These three documents
are the authoritative security baseline shipped in this repository.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately by either channel:

- GitHub Security Advisories: use **"Report a vulnerability"** on the repository's
  *Security* tab (preferred — gives us a private, trackable thread).
- Email: **security@secugent.example** (replace with the operator's real address
  before publishing). Encrypt with our published PGP key when handling sensitive
  reproduction data.

Please include, where possible:

- affected version / commit (`git rev-parse HEAD`) and component
  (e.g. `secugent/core/mechanical_oversight.py`, `secugent/audit/`, `secugent/cli/`);
- a minimal reproduction (a failing `secugent verify` run, a crafted REGULATIONS
  document, a sample step/plan) — **never** include real production secrets, PII,
  or resident-registration numbers; redact per `secugent/core/logger.redact`;
- impact assessment mapped to a contract threat code (T1–T8) or invariant
  (I-A…I-E) where you can.

## Disclosure SLA

We follow **coordinated disclosure**. Targets (calendar days from receipt):

| Stage | Target |
| --- | --- |
| Acknowledge receipt | within **3 days** |
| Initial severity triage (CVSS + contract-threat mapping) | within **7 days** |
| Fix or documented mitigation for Critical / High | within **30 days** |
| Fix for Medium | within **90 days** |
| Public advisory + credit | coordinated with the reporter, by default at fix release |

If a fix will exceed these targets we will say so explicitly and agree a revised
date with you. We support a default **90-day** disclosure deadline; we will request
an extension only with justification.

## Severity

We score with CVSS v3.1 **and** map to the contract threat model. Any finding that
defeats a deterministic guarantee is treated as **at least High**, regardless of
CVSS, because determinism is the product's core trust claim:

- bypassing **Mechanical Oversight** HARD BLOCK (deny-by-default) — `T1`;
- forcing a **Rule of Two** 3-axis action to execute **without** HITL — `T1`/`T4`;
- forging, replaying, or expiring-then-using an **approval token** — `T6`;
- tampering with the **append-only audit hash chain** undetected, or making
  `verify_chain` / `secugent verify --chain` pass on a tampered store — `T7`, §10.1;
- leaking secrets/PII into logs, the chain table, or error messages — `T5`;
- prompt-injection that changes a control decision — `T2`/`T3`.

## Supported versions

SecuGent is pre-GA (`0.x`). During the `0.x` series:

| Version | Supported |
| --- | --- |
| latest `0.x` (current `main` release) | ✅ security fixes |
| previous `0.x` minor | ⚠️ critical fixes only, best-effort |
| older | ❌ — upgrade required |

On reaching `1.0` we will publish a longer support matrix (the air-gapped /
on-prem deployment model means operators pin a release for extended periods, so
LTS-style backports of Critical fixes are planned).

## Scope

**In scope**

- the SecuGent core (`secugent/`), the verification CLI (`secugent/cli/`), the
  audit chain/Merkle (`secugent/audit/`), the deterministic policy engines
  (`secugent/core/mechanical_oversight.py`, `regulations.py`, `rule_of_two.py`,
  `approval.py`);
- any defeat of a security invariant or fail-closed rule documented in this file
  or `docs/security/threat_model.md`;
- supply-chain integrity of the published artifacts (SBOM, signed release artifacts).

**Out of scope**

- vulnerabilities solely in third-party dependencies with no SecuGent-specific
  exploit path (report upstream; tell us so we can pin/patch);
- findings requiring a pre-compromised host, a malicious administrator, or
  physical access;
- the dev-only `LocalHmacKmsProvider` used as a KMS stand-in in tests (production
  uses an external KMS — see `secugent/audit/merkle.py`);
- social engineering, DoS via unbounded user-supplied input that is already
  rate/size limited, and theoretical issues without a reproduction.

## Reproduce trust claims yourself

Two of our central security claims are externally reproducible without contacting us:

```bash
# 1. Determinism: the deterministic decision path is byte-identical across runs.
secugent verify --determinism --fixture <fixture.json> --samples 100

# 2. Audit integrity: the append-only hash chain links cleanly (tamper => non-0).
secugent verify --chain --tenant <tenant-id> --store <events.db>

# 3. Supply chain: regenerate the (deterministic) SBOM and diff against ours.
python scripts/gen_sbom.py --output sbom.json
```

A non-zero exit from `secugent verify` is a **finding**: it means a determinism or
audit-integrity guarantee did not hold on your inputs. Please report it.

## Safe harbor

We will not pursue or support legal action against researchers who, in good faith,
follow this policy: act only against assets in scope, avoid privacy violations and
service degradation, do not exfiltrate data beyond the minimum needed to prove a
finding, and give us a reasonable time to remediate before public disclosure.
