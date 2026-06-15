# SecuGent Threat Model (STRIDE)

Status: living document. Date: 2026-06-07. Audience: security reviewers, auditors,
integrators evaluating SecuGent as a control plane.

This is the **attacker-centric** view of the public Core's security baseline. It
states the invariants and fail-closed rules and enumerates *who attacks what, how,
and which control stops them*, organised by STRIDE. Together with
[`SECURITY.md`](../../SECURITY.md) (reporting policy + disclosure SLA) and
[`docs/security/TRUST_PROOF.md`](TRUST_PROOF.md) (externally reproducible
determinism + audit-chain proofs), these documents are the authoritative security
baseline shipped in this repository.

Threat codes (`T1`–`T8`) and invariant references below are anchored to the
controls enforced in code (`secugent/core/`, `secugent/audit/`). If this document
disagrees with the enforcing code, **the code wins** — file a PR to reconcile.

## 1. What we are protecting (assets)

| Asset | Why it matters |
| --- | --- |
| Deterministic control decisions | The product *is* the guarantee that Mechanical Oversight + Rule of Two decide identically every time. Non-determinism = no trust. |
| Append-only audit chain (`secugent/audit/`) | Legal/regulatory evidence (EU AI Act Art.12/Art.26, 한국 AI 기본법). Must be tamper-evident. |
| REGULATIONS policy (`secugent/core/regulations.py`) | Deny-by-default allow-lists. Relaxing them silently defeats every downstream control. |
| Approval tokens (`secugent/core/approval.py`) | Single-use, scoped human authorization. Forgery/replay = unauthorized autonomous action. |
| Secrets & PII | Credentials (`secugent/core/secrets.py`), Korean RRNs, customer data. Must never leak to logs/chain/errors. |
| Effect-mediation envelope (EM, §11) | Bounds what a confirmed plan may actually do at runtime. |

## 2. Trust boundaries

```
[ untrusted: web/doc/tool output, uploaded files, LLM responses ]
        │  (T2 prompt injection enters here)
        ▼
[ HEAD planner ] ──plan──▶ [ Plan Review / HITL gate ] ──approval token──▶ [ Dispatcher ]
        │                                                                       │
        ▼                                                                       ▼
[ Mechanical Oversight (deny-by-default, deterministic) ] ◀── REGULATIONS ── [ SUB workers ]
        │                                                                       │
        ▼                                                                       ▼
[ Effect broker (EM, egress policy) ] ───────────────────────────────▶ [ external systems ]
        │
        ▼
[ append-only audit hash chain ] ──daily──▶ [ signed Merkle root → object-lock store ]
```

Boundaries crossed by an attacker:
- **B1** untrusted content → control logic (injection).
- **B2** caller → durable store (tamper / forgery).
- **B3** SUB role → tools beyond its grant (privilege).
- **B4** any actor → audit log (repudiation / tamper).
- **B5** process → secrets/PII sinks (disclosure).

## 3. STRIDE analysis

Each row maps to a contract threat code (T1–T8) / invariant and the enforcing module.

### S — Spoofing

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Forged approval token | Attacker mints/copies a token to authorize a step | Cryptographic single-use nonce + strict scope match + re-validation at execution | `approval.py`, contract §4, `T6` |
| Impersonating a SUB role | A SUB calls tools assigned to another actor | Dispatcher `assigned_subs` + token `allowed_action_types`; `connector_action`/`unknown` can never be pre-authorized | `contracts.py` `ApprovalScope`, `T4` |
| Spoofed Merkle signature | Fake daily root signature | `SignedMerkleRoot.verify_against(provider)` over an external KMS; dev HMAC provider is test-only | `audit/merkle.py`, §10.1 |

### T — Tampering

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Edit a stored event | Modify `events`/`event_chain` rows in SQLite/PG | SHA-256 hash chain (`prev_hash`→`event_hash`); any single-byte change desyncs the next link → `AuditChainBrokenError`; externally reproducible via `secugent verify --chain` | `audit/hash_chain.py`, §10.1, `T7` |
| Delete an event | Drop a chain/store row to hide an action | prev_hash linkage break + "missing from store" detection in `verify_chain` | `audit/hash_chain.py` |
| Relax REGULATIONS at runtime | Inject a session patch that *removes* a ban | Session patches are strengthen-only (additive); base policy is immutable per evaluation | `regulations.py`, `mechanical_oversight.py`, `T3` |
| Second-preimage on Merkle tree | Craft leaves that reproduce an internal node | RFC 6962 domain-separation prefixes; odd nodes carried up (no self-duplication) | `audit/merkle.py` (CVE-2012-2459 mitigation) |
| Tamper the SBOM / verify output | Swap the artifact to hide a malicious dep | Deterministic SBOM + CI determinism-reproduction job (two runs byte-identical) | `scripts/gen_sbom.py`, `.github/workflows/determinism.yml` |

### R — Repudiation

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Deny an action occurred | Claim a decision/approval never happened | Every decision gate writes a §C-2 schema event (actor, gate, input_hash, rationale, rule_of_two_axes, prev_event_id) to an append-only log, 6-month+ retention | contract §10.1, CLAUDE.md §C-2, `T7` |
| Backdate / reorder events | Forge an alternate history | Hash chain fixes order; daily Merkle root is signed and pushed to an object-lock store | `audit/hash_chain.py`, `audit/merkle.py` |

### I — Information disclosure

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Secrets/PII in logs | Token/RRN written to JSONL or SQLite | `logger.redact()` applied on both sinks; chain hashes the *redacted* `stored_view`, never plaintext | `core/logger.py`, `audit/hash_chain.py`, `T5` |
| PII in chain body | `body_canonical` carrying plaintext | Chain hashes the redacted/normalised event; regression-tested (SG-20260601-02) | `audit/hash_chain.py` |
| Leak via error messages | Verbose exceptions exposing internals | `VerifyInputError` and contract exceptions give a cause without dumping payloads; `secugent verify` is read-only and prints locations, not data | `cli/verify.py` |
| Cross-tenant leakage | One tenant reads another's events | All chain/store reads are scoped by `tenant_id`; verify queries are tenant-filtered | `cli/verify.py`, `audit/hash_chain.py` |
| Credential exfiltration via tool | Connector leaks a secret on-behalf-of | Credential non-exfiltration + on-behalf-of attribution (EM-06) | contract §11.3 |

### D — Denial of service

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Store write failure → keep running | Disk full / DB error mid-run | Event store append failure ⇒ **fail-closed** (execution halts) | contract §2.7, `T7` |
| Huge chain exhausts memory on verify | Attacker grows the chain | `verify_chain` / `secugent verify` streams per-event (constant memory) | `audit/hash_chain.py`, `cli/verify.py` |
| Unbounded LLM cost | Runaway agent loop | Token/cost budgets + retry caps (`secugent/cost/`, `llm_client`) | contract §2, `T8` |

### E — Elevation of privilege

| Threat | Vector | Control | Ref |
| --- | --- | --- | --- |
| Rule of Two 3-axis bypass | Run an untrusted+sensitive+egress step without HITL | Deterministic axis classification; all 3 active ⇒ HITL forced; `connector_action` always step-scoped HITL | `core/rule_of_two.py`, contract §8, `T1` |
| Score-down a banned action | RISKANALYZER lowers a clearly-forbidden action's risk | Mechanical Oversight runs **first** and HARD BLOCKs regardless of risk score (deny-by-default) | `mechanical_oversight.py`, `T1` |
| Path/domain normalization bypass | `..`, UNC, 8.3, punycode tricks | Defensive normalization; "cannot normalise" fails closed as a banned-path violation | `mechanical_oversight.py`, contract §2.2 |
| Pre-authorize a never-preauthorizable action | Bundle `connector_action`/`unknown` into a plan approval | `ApprovalScope` Pydantic validator rejects both | `contracts.py` |

## 4. Prompt injection (cross-cutting, T2/T3)

Injection is treated as **unfixable at the model layer** (CLAUDE.md §A-0): we do not
rely on "the LLM resisting it." Instead:

- system prompt and untrusted data are separated; LLM responses pass a validation
  harness (parse/field/score/confidence checks → HITL or hard block on failure, §2.4/2.8);
- a step whose input derives from untrusted content can declare Rule of Two axis ①
  (`untrusted_input`); when combined with sensitive access + egress, HITL is forced;
- REGULATIONS cannot be relaxed by content — only strengthened, admin-approved.

> Staged boundary: the automatic provenance-based axis-① *producer* (taint
> propagation) lands in Stage 6 (G-C4). Until then axis ① requires an explicit
> declaration; the deterministic engine, gate, and audit production are complete and
> tested. See `secugent/core/rule_of_two.py` module note. This is a known staged
> limitation, documented here for honest disclosure.

## 5. Residual risk / assumptions

- **Trusted administrator** — an operator who can rewrite the base REGULATIONS and
  rotate KMS keys is outside the attacker model (mitigated by EVOLUTION 4-eyes for
  policy changes, §10.2, and by the append-only audit trail of who changed what).
- **KMS integrity** — daily Merkle signing trusts the external KMS; the dev HMAC
  provider is never used in production.
- **Host integrity** — a compromised host below the process boundary (kernel,
  hypervisor) is out of scope; air-gapped/on-prem deployment narrows this surface.
- **Dependency trust** — bounded by the SBOM + pinned versions; supply-chain
  monitoring is operational, not code-level.

## 6. How to verify these claims

See [`SECURITY.md` § "Reproduce trust claims yourself"](../../SECURITY.md). The
read-only `secugent verify` CLI reproduces the determinism and audit-chain
guarantees from this model without trusting our build.
