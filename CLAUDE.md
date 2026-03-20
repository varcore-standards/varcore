# VAR-Core — Claude Code Session Context
# /Desktop/varcore/ → varcore-standards/varcore

---

## What this repo is

Open source protocol implementation. Apache-2.0.
GitHub: varcore-standards/varcore (PRIVATE until patent clearance confirmed)
npm: @varcore/* (6 packages)
Current published version: 1.1.0
Next planned publish: 1.2.0 (this cleanup session)
npm publish requires explicit instruction

This repo is the SOURCE OF TRUTH for all field definitions, the normative
field list, the receipt schema, and the public interface contract.
nonsudo-platform and nonsudo-website are consumers. They do not define schema.

---

## Before touching any file — run these checks and report results

```bash
# 1. Patent safety grep — public-facing files
grep -r "Ed25519\|RFC 3161\|JCS\|hash-chained\|elliptic.curve" \
  src/ packages/*/src/ \
  --include="*.ts"
# Expected: 0 results
# docs/ and schema-server/ are intentionally excluded to avoid spec/test-vector noise

# 2. Domain check
grep -r "nonsudo\.dev\|schemas\.nonsudo\.dev\|specs\.nonsudo\.dev" .
# Expected: 0 results. Correct domain is schemas.nonsudo.com

# 3. Current test state
npm test
# Expected: all passing. Note any failures before proceeding.
```

Do not proceed if patent grep returns results. Fix first.

---

## Session plan for varcore

```
Session A (today, 20 min)
  → Fix all .dev → .com occurrences (C2, H3, M1)
  → Update CLAUDE.md patent grep to exclude docs/
  → npm test must stay 10/10

Session B (this week)
  → response_hash in LangChain adapter (H1)
  → Unguarded JSON.parse in TSA sidecar (H2)

Session C (before first customer)
  → Deduplicate canonicalize+hash into @varcore/core (H4)
  → Fix sticky session init (L4)
  → Implement or remove OpenAI adapter interception (L5)

Session D (before Series A)
  → npm audit fix for langsmith SSRF (M3)
  → Add structured logging + trace IDs (L1, L2)
```

---

## What lives here

| Package | Purpose |
|---|---|
| @varcore/core | Types, SigningProvider interface, zero runtime deps |
| @varcore/receipts | Signing, JCS, RFC 3161, L1/L2/L3 verification |
| @varcore/policy | YAML policy engine, schema packs (Stripe/GitHub/AWS/PCI) |
| @varcore/store | SQLite receipt store, retention |
| @varcore/adapter-openai | OpenAI function-calling integration |
| @varcore/adapter-langchain | LangChain integration |
| docs/spec/ | VAR-Core v1.0 spec (canonical) |
| docs/reference/public-contract.md | THE interface contract — update before every npm publish |
| python-verifier/ | Language-agnostic reference verifier |
| schema-server/ | Cloudflare Workers, hosts test vectors |

---

## Hard rules — never violate

1. ZERO imports from @nonsudo/* anywhere in this repo
2. ZERO pricing, licensing, or commercial feature flags
3. ZERO SaaS infrastructure (no Slack endpoints, no dashboard code)
4. ZERO deploy configs (no k8s, Caddy, nginx)
5. ZERO private key material or operator secrets
6. NEVER flip repo to public without explicit founder instruction
7. NEVER publish to npm without updating docs/reference/public-contract.md first

---

## Locked decisions — never reopen

| Decision | Status |
|---|---|
| License: Apache-2.0 | FINAL — BSL-1.1 evaluated and rejected |
| Signing: Ed25519 | FINAL |
| Canonicalization: JCS (RFC 8785) | FINAL |
| Timestamping: RFC 3161 | FINAL |
| response_hash | Committed Phase 1 field — not aspirational, must be populated |
| attestation_schema_hash | Reserved Phase 2 — do not remove or repurpose |
| delegation_receipt | Locked for multi-agent custody (Patent 2) — define before any multi-agent work |

---

## Known open item — do not fix without explicit instruction

TV-07: expected_l1 = FAIL (sequence gap 0→2)
Document it. Do not resolve silently.

---

## npm publish protocol — follow in order

```
1. Make changes
2. Run: npm test  — all must pass
3. Bump version in package.json (patch / minor / major as appropriate)
4. Update docs/reference/public-contract.md to reflect any API changes
5. Run patent safety grep — expected 0 results
6. Run domain grep — expected 0 results
7. npm publish
8. Write SESSION_LOG.md entry (see format below)
9. Note in SESSION_LOG: exactly what nonsudo-platform needs to do next
```

---

## Test commands

```bash
npm run build                              # builds all 6 packages
npm test                                   # full suite from repo root
npm test -- --testPathPattern=receipts    # single package
```

---

## Session log — append only, never edit past entries

File: SESSION_LOG.md
Append at end of every session:

```
### [YYYY-MM-DD]
**Changed:** [what was modified]
**Schema version:** [current version]
**Fields added/modified:** [list or "none"]
**Breaking change:** yes / no
**npm published:** yes / no — version x.x.x
**Platform needs to:** [specific action, or "nothing"]
**Site needs to:** [specific action, or "nothing"]
**Open items:** [anything incomplete]
```

---

## Cross-repo handoff note format

When platform or site needs to act on a varcore change, paste this into
the next session as context:

```
CROSS-REPO HANDOFF — varcore → [platform/site] — [date]
What changed in varcore: [description]
New npm version: @varcore/[package]@x.x.x
Action required: [exact steps]
Breaking change: yes / no
```
