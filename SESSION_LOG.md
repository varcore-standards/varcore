# VAR-Core — Session Log
# Repo: varcore-standards/varcore | /Desktop/varcore/
# Append only. Never edit past entries.
# Format: see CLAUDE.md

---

### 2026-03-16 — Repo setup
**Changed:** CLAUDE.md created. SESSION_LOG.md initialised.
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** No
**npm published:** No
**Platform needs to:** Nothing
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- response_hash: committed Phase 1 field, currently null in platform — highest priority
- schemas.nonsudo.com is the correct domain (not schemas.nonsudo.dev)

---

### 2026-03-16 — Read-only technical audit
**Changed:** No files modified. Audit only.
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** No
**npm published:** No
**Platform needs to:** Nothing
**Site needs to:** Nothing
**Open items:**
- AUDIT FINDINGS: 2 critical, 4 high, 4 medium, 5 low — await instruction before fixing anything
- C1 (CRITICAL): Patent grep STOP condition triggered — Ed25519/RFC 3161/JCS/hash-chained throughout docs/ and schema-server/; must resolve before public release
- C2 (CRITICAL): Key resolution URL in contract.md points to wrong domain (nonsudo.dev not nonsudo.com) — verifiers cannot resolve signing keys
- H1 (HIGH): response_hash still null in adapter-langchain; TODO(phase-1) unresolved
- H2 (HIGH): Unguarded JSON.parse in loadTsaSidecar() — crash-truncated NDJSON line will throw in verifyL3()
- H3 (HIGH): policy-schema.json $id uses wrong domain
- H4 (HIGH): canonicalize+hash logic triplicated across adapter-langchain, adapter-openai, policy packages

---

### 2026-03-16 — Audit remediation (all 8 fixes)
**Changed:** 10 source files modified across 5 packages + CLAUDE.md; 1 new file created (packages/core/src/canonical-hash.ts).
**Schema version:** 1.0.0
**Fields added/modified:** response_hash now populated in adapter-langchain action receipts (previously always null).
**Breaking change:** Yes (two breaking changes):
  - adapter-langchain: handleToolStart no longer writes the action_receipt; handleToolEnd now writes it with response_hash populated. Tests that call only handleToolStart must also call handleToolEnd to observe the receipt.
  - adapter-openai: wrapOpenAI() now throws instead of silently returning the unwrapped client.
**npm published:** No
**Platform needs to:** Update any code that depends on handleToolStart having already written the action_receipt synchronously — it is now written in handleToolEnd. Also handle the wrapOpenAI throw if platform used it (it should switch to createActionReceipt manual API).
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep still matches in packages/*/src/ — these are type literals and implementation comments (alg: "Ed25519", RFC 3161 section headers), not patent claims. Scope is now correctly limited to source packages (docs/ excluded).
- L1/L2 (structured logging + request IDs) deferred — not in this fix list.
- wrapOpenAI automatic interception (OpenAI adapter Phase 1) deferred — too complex for single session.

**Fixes applied this session:**
  FIX 1 (C1): CLAUDE.md patent grep scope updated — excludes docs/ and schema-server/ (done prior session, confirmed clean).
  FIX 2 (C2+H3+M1): 15 occurrences of schemas.nonsudo.dev replaced with schemas.nonsudo.com across 7 docs files (done prior session, confirmed clean).
  FIX 3 (H1): response_hash now populated in adapter-langchain. Two-phase write: handleToolStart pends, handleToolEnd finalizes with sha256(JCS(response)).
  FIX 4 (H2): loadTsaSidecar() malformed NDJSON lines now caught per-line; verification continues for remaining receipts.
  FIX 5 (H4): canonicalHash() centralised in packages/core/src/canonical-hash.ts. Three duplicated implementations removed from adapter-langchain, adapter-openai, policy.
  FIX 6 (L4): WorkflowSession.create() failure resets _sessionInit to null; next call retries.
  FIX 7 (L5): wrapOpenAI() now throws with descriptive error (Option B) — callers were silently receiving zero receipt coverage.
  FIX 8 (M3): @langchain/core upgraded to ^1.1.32 (major). langsmith SSRF vulnerability GHSA-v34v-rq6j-cj6p resolved. npm audit --audit-level=high: 0 vulnerabilities.

**Test count:** 188/188 passing before and after (test 9 updated to reflect two-phase write).

---

### 2026-03-16 — Session D: structured logging + trace IDs (L1/L2)
**Changed:** 6 source files modified across 3 packages; 1 new file created (packages/core/src/logger.ts).
**Schema version:** 1.0.0
**Fields added/modified:** None — logging only; no receipt fields changed.
**Breaking change:** No
**npm published:** No
**Platform needs to:** Nothing
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- PROJECTION_* violation codes declared in verifyL4 FAIL_CODES but zero code generates them — gap confirmed, deferred
- wrapOpenAI automatic interception deferred (Phase 1)
- Python verifier venv broken (dyld error) — tests cannot be run on this machine

**Changes applied this session:**
  L1: varcoreLog() created in packages/core/src/logger.ts — emits structured NDJSON JSON lines to stderr.
      Exported from @varcore/core. All 18 process.stderr.write() calls replaced across:
        - packages/receipts/src/index.ts (1 call: loadTsaSidecar malformed line warning)
        - packages/policy/src/params-evaluator.ts (16 calls: type-error and validation warnings)
        - packages/adapter-langchain/src/handler.ts (1 call: WorkflowSession.create failure)
  L2: run_id and workflow_id added as structured fields to log entries wherever available:
        - handler.ts: run_id included in handleToolStart/End/Error log events
        - session.ts: workflow_id bound via private log() helper; new debug-level lifecycle
          events added for workflow_manifest written, action_receipt written, dead_letter written.
          create() emits debug event with workflow_id + agent_id.
          finalizeActionReceipt() emits debug event with run_id + tool_name + decision.
          emitDeadLetter() emits debug event with tool_name + failure_reason.

**Test count:** 188/188 passing.

---

### 2026-03-17 — SECURITY_GUARANTEES.md + Terraform schema pack
**Changed:** 2 new files created, 1 file modified:
  - `SECURITY_GUARANTEES.md` (new): formal security guarantees document, 883 words, 7 sections (Receipt Chain Invariants, Execution Authenticity, Budget and Spend Enforcement, Enforcement Mode Guarantees, Documented Bypass Paths, Known Gaps, Independent Verification). RFC 2119 language throughout. Written for security researchers and auditors.
  - `packages/policy/src/schemas/terraform.ts` (new): Terraform Enforce schema pack with 7 rules (terraform_destroy BLOCK, terraform_apply STEP_UP/ALLOW, terraform_state_rm STEP_UP, terraform_workspace_delete STEP_UP, terraform_plan ALLOW, terraform_init ALLOW). Tool names use `terraform_*` snake_case convention matching existing packs.
  - `packages/policy/src/schemas/index.ts` (modified): registered `"terraform/enforce": terraformEnforce` in SCHEMA_PACKS.
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** No
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** `npm update @varcore/policy` after next publish. Terraform pack id: `"terraform/enforce"`.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep matches in packages/*/src/ are type literals (alg: "Ed25519", RFC refs), not patent claims — unchanged from prior session
- NOT published to npm — awaiting explicit instruction

**Test count:** 188/188 passing.

---

### 2026-03-18 — BUG-6 fix: approval_receipt signing + pending_approval_id
**Changed:** 2 source files modified, 0 new files created:
  - `packages/receipts/src/index.ts`:
    - Added `"pending_approval_id"` to `ACTION_RECEIPT_SIGNED_FIELDS` (after `billable_reason`). This field links an action_receipt to its pending approval — must be signed to prevent tampering of the authorization link.
    - Added `APPROVAL_RECEIPT_SIGNED_FIELDS` constant: `[...BASE_SIGNED_FIELDS, "action_receipt_id", "approval_receipt_id", "tool_name", "approval_outcome", "approver", "approval_dir", "wait_duration_ms"]`. Covers all non-base fields on `ApprovalReceiptFields`.
    - Added `approval_receipt` branch to `buildSigningPayload` if/else chain (before the `workflow_closed` fallback). Previously, `approval_receipt` fell through to `WORKFLOW_CLOSED_SIGNED_FIELDS` — approval-specific fields were excluded from signing, making them tamperable without detection.
  - `packages/receipts/src/__tests__/receipts.test.ts`:
    - Added 2 regression tests:
      1. `approval_receipt sign+verify round-trip succeeds with approval-specific fields` — creates, signs, verifies an approval_receipt; then tampers with `approval_outcome` and confirms signature fails.
      2. `pending_approval_id on action_receipt is signed — tampering invalidates signature` — creates an action_receipt with `pending_approval_id`, signs it, then tampers with the field and confirms signature fails.
**Schema version:** 1.0.0
**Fields added/modified:** `pending_approval_id` added to ACTION_RECEIPT_SIGNED_FIELDS (was already a field on ActionReceiptFields, now included in signing payload). No new fields defined.
**Breaking change:** Yes — receipts signed before this change did NOT include `pending_approval_id` in the signing payload. Existing signed action_receipts with `pending_approval_id` set will produce a different signing payload under the new field list. However, no existing golden vectors or test vectors use `pending_approval_id`, so no vector regeneration needed. Platform's proxy signs action_receipts with `pending_approval_id` — those receipts will need re-verification against the updated field list after platform picks up this change.
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** `npm update @varcore/receipts` after next publish. Verify that approval_receipt signing in the proxy produces valid signatures under the new field list. Run `npm test -- --runInBand` (240/240 required). Any existing receipt chains containing `pending_approval_id` will have a different canonical signing payload — re-sign or note as a one-time migration.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep matches in packages/*/src/ are type literals (alg: "Ed25519", RFC refs), not patent claims — unchanged
- NOT published to npm — awaiting explicit instruction

**Test count:** 190/190 passing (188 prior + 2 new BUG-6 regression tests).

---

### 2026-03-18 — BUG-4 varcore fix: computeContentEntropyHash extracted to @varcore/core
**Changed:** 3 source files modified, 0 new files created:
  - `packages/core/src/index.ts`:
    - Added `computeContentEntropyHash(content: string): string` — canonical hash of string content with JSON-parse-first semantics. If content is a valid JSON object/array, parses it first so key ordering does not affect the hash (JCS sorts keys via `canonicalHash`). Falls back to raw string for primitives and non-JSON. Uses existing `canonicalHash` from `./canonical-hash` — no new crypto code.
  - `packages/adapter-langchain/src/session.ts`:
    - Deleted local `responseCanonicalHash` function (lines 41-49).
    - Replaced call at line 172 with `computeContentEntropyHash(output)` imported from `@varcore/core`.
    - Import updated: `import { canonicalHash, computeContentEntropyHash, varcoreLog } from "@varcore/core"`.
  - `packages/receipts/src/__tests__/receipts.test.ts`:
    - Added 3 regression tests for `computeContentEntropyHash`:
      1. Same JSON object regardless of key order produces same hash (`{"b":1,"a":2}` === `{"a":2,"b":1}`)
      2. Non-JSON string produces a valid `sha256:<hex>` hash
      3. JSON primitive does not parse as object — number `42` and string `"42"` hash differently
**Schema version:** 1.0.0
**Fields added/modified:** None — this is a code-level deduplication, not a schema change.
**Breaking change:** No — `computeContentEntropyHash` is a new export (additive). The adapter-langchain `responseCanonicalHash` was private and never part of the public API. The hash output is identical (same algorithm: JSON.parse-first → canonicalHash).
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** After next `npm update @varcore/core`, platform can optionally import `computeContentEntropyHash` from `@varcore/core` instead of its local `computeResponseHash` in proxy.ts. Not a blocker — the platform's existing implementation already uses the equivalent approach (populated March 16). The shared function guarantees both codebases produce identical hashes.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep matches in packages/*/src/ are type literals — unchanged
- NOT published to npm — awaiting explicit instruction

**Test count:** 193/193 passing (190 prior + 3 new BUG-4 regression tests).

---

### 2026-03-18 — BUG-15 + BUG-16 fix: _emitQueue serialisation + close() on LangChain adapter
**Changed:** 2 source files modified, 0 new files created:
  - `packages/adapter-langchain/src/session.ts`:
    - BUG-15: Added `_emitQueue: Promise<void>` field to `WorkflowSession`. Renamed `emitActionReceipt` → `_doEmitActionReceipt` (private, no logic change). New `emitActionReceipt` routes all calls through `_emitQueue` via `.then()` chaining. Second `.then()` argument ensures a failed emit does not deadlock subsequent receipts. Identical treatment for `emitDeadLetter` → `_doEmitDeadLetter` with shared `_emitQueue`. Both methods share the same queue — they both update `prevReceipt` and must be serialised against each other.
    - BUG-16: Existing `close(): void` updated to `async close(): Promise<void>` — awaits `_emitQueue` before `this.writer.close()`, draining any in-flight emits before closing the writer.
    - Added JSDoc above `WorkflowSession` documenting the concurrency model.
  - `packages/adapter-langchain/src/handler.ts`:
    - BUG-16: Added `async close(): Promise<void>` to `NonSudoCallbackHandler` — delegates to `this._session.close()` if session exists. Consumers can now flush and close the receipt file.
  - `packages/adapter-langchain/src/__tests__/adapter.test.ts`:
    - Test 11: Sequential emits produce a valid chain — distinct `prev_receipt_hash` values, sequence numbers 0,1,2.
    - Test 12: Concurrent emits (3x `Promise.all` on `handleToolEnd`) do not fork the chain — all 4 receipts have distinct `prev_receipt_hash` values, sequence numbers 0,1,2,3. This is the exact BUG-15 scenario that would have failed before serialisation.
**Schema version:** 1.0.0
**Fields added/modified:** None — this is a concurrency fix, not a schema change.
**Breaking change:** No — `emitActionReceipt` and `emitDeadLetter` public signatures unchanged. `close()` return type changed from `void` to `Promise<void>` — callers that ignored the return (fire-and-forget) are unaffected; callers that `await` it now get queue drain semantics.
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** Nothing immediate. The proxy already has its own `writeQueue` serialisation. After next `npm update @varcore/adapter-langchain`, any platform code using the LangChain adapter directly benefits from the fix.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep matches in packages/*/src/ are type literals — unchanged
- NOT published to npm — awaiting explicit instruction

**Test count:** 195/195 passing (193 prior + 2 new BUG-15/BUG-16 concurrency tests).

---

### 2026-03-18 — npm publish: all 6 packages at 1.1.0
**Changed:** Version bump 1.0.0 → 1.1.0 in all 6 package.json files. No source changes — this publish captures all fixes from sessions since 1.0.0.
**Schema version:** 1.0.0
**Fields added/modified:** pending_approval_id added to ACTION_RECEIPT_SIGNED_FIELDS (from BUG-6 session). response_hash now populated in adapter-langchain (from audit remediation session).
**Breaking change:** Yes (carried from prior sessions):
  - adapter-langchain: handleToolStart no longer writes the action_receipt; handleToolEnd now writes it with response_hash populated.
  - adapter-openai: wrapOpenAI() now throws instead of silently returning the unwrapped client.
  - receipts: pending_approval_id now included in signing payload for action_receipts.
  - adapter-langchain: close() return type changed from void to Promise<void> (queue drain semantics).
**npm published:** Yes — all 6 packages at 1.1.0:
  - @varcore/core@1.1.0
  - @varcore/receipts@1.1.0
  - @varcore/policy@1.1.0
  - @varcore/store@1.1.0
  - @varcore/adapter-openai@1.1.0
  - @varcore/adapter-langchain@1.1.0
**Platform needs to:**
  - `npm update @varcore/policy` to pick up Terraform pack (`"terraform/enforce"`) and BUG-4 shared `computeContentEntropyHash` function
  - `npm update @varcore/receipts` — verify approval_receipt signing in the proxy produces valid signatures under the new field list (pending_approval_id now signed)
  - `npm update @varcore/adapter-langchain` — benefits from BUG-15 emit queue serialisation and BUG-16 close() drain semantics
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Patent grep matches in packages/*/src/ are type literals — unchanged
- Cloud backend (nonsudo.com/api/receipts/stats) throwing Cloudflare Worker exception — likely missing RECEIPTS_SYNC_TOKEN env var or migration not run

**Test count:** 195/195 passing.

**CROSS-REPO HANDOFF — varcore → platform — 2026-03-18**
What changed in varcore: All 6 packages published at 1.1.0. Includes BUG-4 (computeContentEntropyHash), BUG-6 (approval_receipt signing + pending_approval_id), BUG-15/16 (emit queue serialisation + close drain), Terraform schema pack, structured logging.
New npm versions: @varcore/core@1.1.0, @varcore/receipts@1.1.0, @varcore/policy@1.1.0, @varcore/store@1.1.0, @varcore/adapter-openai@1.1.0, @varcore/adapter-langchain@1.1.0
Action required: npm update @varcore/policy @varcore/receipts @varcore/adapter-langchain. Verify approval_receipt signing under new field list. Run npm test -- --runInBand (240/240 required).
Breaking change: yes — see session log entry for details.

---

### 2026-03-20 — Pre-launch cleanup (9 fixes)
**Changed:** 8 source/config files modified, 1 file deleted:
  - FIX 1: `docs/session-D-prompt.md` deleted — internal build session prompt (Cursor IDE references, internal state files). `docs/session-prompt-standard.md` kept — verified no internal references.
  - FIX 2 (BUG-1): `packages/receipts/src/index.ts` — `"nonsudo-key-1"` → `"varcore-default-key"` as the fallback keyId in signReceipt(). Removes proprietary brand from open-source default.
  - FIX 3: `packages/core/src/signing-provider.ts` — removed 2 JSDoc references to `@nonsudo/proxy`. Replaced with generic "runtime proxy" language. 0 @nonsudo references remain in packages/*/src/*.ts.
  - FIX 4: `packages/policy/package.json` — removed dead `canonicalize` dependency (never imported in policy source — policy uses `canonicalHash` from `@varcore/core`).
  - FIX 5: `scripts/gen-vectors.mjs` and `scripts/generate-test-vectors.ts` — output path corrected from `deploy/schema-server/public/...` to `schema-server/public/...`. The `deploy/` prefix was wrong — schema-server lives at `schema-server/` in this repo.
  - FIX 6 (BUG-9): `schema-server/src/index.ts` — record_type enum expanded from 3 types to 8: added `post_receipt`, `approval_receipt`, `recovery_event`, `budget_warning`, `reservation_expired`.
  - FIX 7: `.github/workflows/ci.yml` — added Lint step (`npm run lint`). `package.json` — added root `"lint"` script. ESLint was configured but never run in CI.
  - FIX 8 (H-7): `packages/adapter-langchain/src/session.ts` — added Ed25519 private key hex validation: `/^[0-9a-fA-F]{64}$/` regex check before `Buffer.from(hex)`. Invalid keys now throw with a clear error message at startup instead of producing garbage signatures.
  - FIX 9: `CLAUDE.md` — updated version references: current published 1.1.0, next planned 1.2.0.
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** Yes — `"nonsudo-key-1"` default changed to `"varcore-default-key"`. Any consumer relying on the implicit default keyId string will see a different value. No existing golden vectors or test vectors use the default (all provide explicit keyId).
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** Nothing — platform always provides explicit keyId and key_path. The default is never hit.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- NOT published to npm — awaiting explicit instruction

**Test count:** 195/195 passing.
**ESLint:** 0 violations across all packages.

---

### 2026-03-20 — README.md fixes (2 fixes)
**Changed:** 1 file modified:
  - `README.md`:
    - FIX 1: Quick Start wrong package name — `@varcore/recs` → `@varcore/receipts`. The package has always been `@varcore/receipts`; `recs` was a typo that would fail on `npm install`.
    - FIX 2: Conformance section referenced proprietary `@nonsudo/cli` (`npm install -g @nonsudo/cli && nonsudo conform`). Replaced with `npx @varcore/receipts test-vectors <url>` — uses only the open-source package. No dependency on closed-source CLI.
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** No
**npm published:** No — explicit instruction required before publishing
**Platform needs to:** Nothing
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- NOT published to npm — awaiting explicit instruction

**Test count:** 195/195 passing.

---

### 2026-03-20 — 5 new compliance control packs + package.json cleanup
**Changed:** 7 files created/modified:
  - `packages/policy/src/schemas/eu-ai-act.ts` (new): EU AI Act Article 12 enforce pack — 7 rules covering llm_inference, automated_decision, training_data_access, model_deployment. Risk classification gating, individual impact oversight, production deployment approval.
  - `packages/policy/src/schemas/hipaa.ts` (new): HIPAA enforce pack — 7 rules covering ehr_read, ehr_write, ehr_delete, phi_export, patient_message, audit_log_access. PHI access consent check, deletion prohibition, BAA-required export gating.
  - `packages/policy/src/schemas/soc2.ts` (new): SOC 2 enforce pack — 7 rules covering user_data_export, production_config_change, access_grant, access_revoke, encryption_key_rotate, backup_delete. Authorized access check, privileged role gating, backup retention.
  - `packages/policy/src/schemas/gdpr.ts` (new): GDPR enforce pack — 7 rules covering personal_data_collect, personal_data_transfer, data_subject_delete, data_subject_export, profiling_decision. Lawful basis check, adequacy decision country list (39 countries), automated decision blocking.
  - `packages/policy/src/schemas/iso27001.ts` (new): ISO 27001 enforce pack — 7 rules covering asset_delete, network_access_change, vulnerability_scan, incident_response_action, cryptographic_key_create, log_delete. Asset classification gating, production scan approval, audit log deletion prohibition.
  - `packages/policy/src/schemas/index.ts` (modified): registered all 5 new packs in SCHEMA_PACKS. Total: 10 packs.
  - `packages/policy/package.json` (modified): description changed from "NonSudo deterministic YAML policy engine" to "VAR-Core deterministic YAML policy engine with pre-built compliance control packs". Keywords replaced: removed "nonsudo", added "varcore", "compliance", "eu-ai-act", "hipaa", "soc2", "gdpr", "iso27001". Version bumped 1.2.0 → 1.2.1.
  - `packages/policy/src/__tests__/schema-packs.test.ts` (modified): added 10 new tests (SP17–SP26), 2 per pack — one BLOCK and one STEP_UP scenario each.
**Schema version:** 1.0.0
**Fields added/modified:** None — additive pack content only, no type or field changes.
**Breaking change:** No
**npm published:** Yes — @varcore/policy@1.2.1
**Platform needs to:** `npm update @varcore/policy` to pick up new packs. Available pack IDs: `"eu-ai-act/enforce"`, `"hipaa/enforce"`, `"soc2/enforce"`, `"gdpr/enforce"`, `"iso27001/enforce"`. Add to policy `schemas:` array to activate.
**Site needs to:** Update pack count references from 5 to 10 if any marketing copy references pack count.
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- `homepage` in policy package.json still points to nonsudo.com — correct (company URL, not protocol URL)

**Test count:** 205/205 passing (195 prior + 10 new SP17–SP26 pack tests).

**Total control packs:** 10
  - stripe/enforce (7 rules)
  - github/enforce (4 rules)
  - aws-s3/enforce (3 rules)
  - pci-dss/stripe (3 rules)
  - terraform/enforce (7 rules)
  - eu-ai-act/enforce (7 rules) — NEW
  - hipaa/enforce (7 rules) — NEW
  - soc2/enforce (7 rules) — NEW
  - gdpr/enforce (7 rules) — NEW
  - iso27001/enforce (7 rules) — NEW
  - Total rules: 59

---

### 2026-03-20 — CRITICAL FIX: file: → ^1.2.0 dependency references
**Changed:** 4 package.json files modified:
  - `packages/receipts/package.json`: `"@varcore/core": "file:../core"` → `"^1.2.0"`. Version 1.2.0 → 1.2.1.
  - `packages/policy/package.json`: `"@varcore/core": "file:../core"` → `"^1.2.0"`. Version 1.2.1 → 1.2.2.
  - `packages/adapter-openai/package.json`: `"@varcore/core": "file:../core"` and `"@varcore/receipts": "file:../receipts"` → `"^1.2.0"`. Version 1.2.0 → 1.2.1.
  - `packages/adapter-langchain/package.json`: `"@varcore/core": "file:../core"` and `"@varcore/receipts": "file:../receipts"` → `"^1.2.0"`. Version 1.2.0 → 1.2.1.
  - `packages/store/package.json`: NO CHANGE — store has no @varcore/* dependencies.
  - `packages/core/package.json`: NO CHANGE — core has no @varcore/* dependencies (it is the leaf).
**Root cause:** npm workspaces with `file:` protocol references are resolved locally during development but published verbatim to the registry. External consumers installing `@varcore/receipts` would get `"@varcore/core": "file:../core"` in their node_modules, which fails to resolve. This affected all versions published prior to this fix (1.0.0 through 1.2.0/1.2.1).
**Schema version:** 1.0.0
**Fields added/modified:** None
**Breaking change:** No — dependency resolution fix only.
**npm published:** Yes — 4 packages:
  - @varcore/receipts@1.2.1
  - @varcore/policy@1.2.2
  - @varcore/adapter-openai@1.2.1
  - @varcore/adapter-langchain@1.2.1
**Registry verified:** All 4 packages show `"@varcore/core": "^1.2.0"` on the npm registry (no `file:` refs).
**Platform needs to:** `npm update @varcore/receipts @varcore/policy @varcore/adapter-openai @varcore/adapter-langchain` to pick up fixed dependency references.
**Site needs to:** Nothing
**Open items:**
- TV-07: expected_l1 = FAIL (sequence gap 0→2) — known, do not fix without instruction
- varcore repo is PRIVATE — do not flip to public before patent clearance confirmed
- Prior published versions (1.0.0–1.2.0) still have broken `file:` refs on the registry — consider deprecating with `npm deprecate`

**Test count:** 205/205 passing.
