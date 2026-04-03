# VAR-Core — Formal Security Guarantees

**Audience:** Security researchers, technical auditors, compliance reviewers.
**Spec version:** VAR Core v1.0, VAR-Money v1.0 | **Date:** 2026-03-17
**RFC 2119 key words** (MUST, MUST NOT, SHALL, SHOULD, MAY) apply throughout.

---

## 1. Receipt Chain Invariants

Source: RI-1 through RI-10, `docs/spec/var-core-v1.0.md §3`.

| ID | Invariant | Violation Signal | Enforcement |
|---|---|---|---|
| RI-1 | Every ALLOW'd money action MUST have exactly one terminal `post_receipt` | L4: FAIL `MISSING_POST_RECEIPT` | Proxy holds chain slot until outcome recorded |
| RI-2 | Null digest on TIMEOUT/ERROR/CANCELED is valid | Must not be flagged | Verifier exemption rule |
| RI-3 | Every terminal proxy state MUST produce a signed receipt; failure to write MUST fail closed | L2: `INCOMPLETE_CHAIN` (gap in hash chain) | Proxy write-or-refuse design |
| RI-4 | Unresolvable `amount_field` MUST produce STEP_UP | L4: FAIL | Pre-budget validation gate |
| RI-5 | Negative, NaN, or Infinity amounts MUST produce BLOCK | L4: FAIL | Pre-budget validation gate |
| RI-6 | `spent + reserved <= max_spend` MUST hold before every ALLOW | L4: FAIL `BUDGET_INVARIANT_VIOLATED` | In-memory budget state check |
| RI-7 | Duplicate dedupe tuple MUST NOT increase spent/reserved | L4: WARN `DUPLICATE_IDEMPOTENCY_KEY` | Dedupe index on `(tool_name, action_type, idempotency_key, account_context)` |
| RI-8 | Projection: omit_if_null first, transforms in order, JCS, SHA-256 | L4: FAIL `PROJECTION_HASH_MISMATCH` | Deterministic evaluation pipeline |
| RI-9 | Enforce money actions fail closed on crash; Attest fails closed for all; Observe fails open | L2: missing `recovery_event` | Mode-specific crash handler |
| RI-10 | Post-restart open-pre index MUST be integrity-checked; corrupt state requires STEP_UP | L2: WARN `RECOVERY_INCOMPLETE` | Bounded scan (30 min or 1000 receipts) |

**Operational invariant: Policy bundle hash binding.** `policy_bundle_hash` (SHA-256 of the active policy) is signed into every receipt. Any policy change produces a different hash. A verifier walking the chain SHALL identify the exact receipt at which policy changed — forensic traceability not available from policy-external audit logs.

---

## 2. Execution Authenticity — VAR Continuity

**response_entropy_hash.** SHA-256 of JCS-canonical upstream response content, embedded before signing. An offline fabricator cannot predict this value without executing the actual agent call — hash preimage resistance prevents reverse-engineering the response.

*Known limitation:* At temperature=0, deterministic models produce identical responses to identical prompts. A fabricator who knows the exact prompt can predict the hash. Mitigated by inter-receipt timing coherence as an independent mechanism.

**Inter-receipt timing coherence.** Timestamp distribution across a genuine chain reflects real execution cadence — network latency, inference time, tool round-trips. Batch-fabricated chains exhibit statistical anomalies (uniform spacing, sub-millisecond gaps, missing jitter) detectable by distribution analysis.

**Heartbeat receipts.** Periodic receipts during long sessions anchor the chain to wall-clock time. A fabricated chain cannot insert plausible heartbeats without access to the live signing process and its monotonic clock state.

---

## 3. Budget and Spend Enforcement

`spent + reserved <= max_spend` MUST hold before every ALLOW on a money action.

Reservation lifecycle: **reserve** (ALLOW: `reserved += amount`) then **commit** (SUCCESS: move to spent) or **release** (FAILED/CANCELED: release immediately; TIMEOUT: hold until `reservation_ttl_hours`, then release via signed `RESERVATION_EXPIRED` receipt).

On proxy crash: open-pre index integrity check. If corrupt: bounded scan, then `RECOVERY_INCOMPLETE` receipt, then STEP_UP required for all money actions until clean session (RI-10).

---

## 4. Enforcement Mode Guarantees

**Enforce mode** (`enforcement: true`): Every tool call evaluated. FAIL_CLOSED default. Receipts for every decision. Budget enforcement active. *Does not guarantee:* policy correctness (operator-declared), coverage of out-of-band credentials the agent holds.

**Observe mode** (`mode: "observe"`): Pure pass-through. No policy evaluation, no receipts beyond action_receipts. *Guarantees:* zero enforcement overhead, zero blocking. *Does not guarantee:* any governance property.

**Shadow mode** (`enforcement: false`): Receipts written, no blocking. *Guarantees:* continuous forensic record from day one. *Does not guarantee:* policy enforcement — ALLOW and BLOCK produce identical runtime behavior.

---

## 5. Documented Bypass Paths

Source: `docs/spec/run-mode-design.md §2`.

| Path | Scope | Classification |
|---|---|---|
| **Direct credential bypass** — agent holds API keys, calls upstreams directly | Enforce, Observe | By design |
| **Alternate network path** — egress routes bypass the proxy | Enforce, Observe | By design |
| **Out-of-band tool implementations** — tool registered via adapter and as raw HTTP | Enforce, Observe | Known gap (misconfiguration) |
| **Human backchannel** — agent asks human to act outside NonSudo | All modes | By design (unfixable at proxy layer) |
| **Observability-only config** — observe/shadow set accidentally | All modes | Misconfiguration (detectable via policy_bundle_hash) |

Attest mode (v1.1) closes the first three paths via secretless execution, workload identity, and constrained egress.

---

## 6. Known Gaps — Honest Statement

**Permission intersection for delegation chains.** Specified as `effective_perms = intersection(A.perms, B.perms)` with `MAX_DELEGATION_DEPTH=3`. Designed but not yet implemented. Required for Patent 2 (multi-agent chain of custody). Implementation in progress.

**Temperature-zero entropy prediction.** Described in Section 2. Mitigated by timing coherence.

**JTI replay protection.** Resolved March 2026 — approval receipts are deduplicated against a persistent consumed-approvals store via `approval-replay-guard.ts` in the nonsudo reference platform. Third-party VAR-Core implementations must implement equivalent JTI deduplication independently.

---

## 7. Independent Verification

A verifier SHALL verify any receipt without contacting NonSudo.

- **Public key:** proxy `/health` endpoint or `schemas.nonsudo.com/.well-known/keys/<key_id>.json`.
- **Timestamp:** RFC 3161 tokens from external TSAs, verifiable against TSA public infrastructure independently.
- **Chain verification:** clone this repo and run `cd python-verifier && pip install -e .` — language-agnostic L1–L4 verification, entirely offline.
- **Conformance vectors:** 21 test vectors at `schemas.nonsudo.com/var/v1/test-vectors.json`.
