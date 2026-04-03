import type { SchemaPackDefinition } from "../types";

/**
 * ACH Enforce schema pack.
 *
 * Covers the generic `ach_transfer` tool name (underscore convention matching
 * stripe_charge, stripe_transfer, etc.). No canonical ACH tool names exist in
 * this repo yet — operators MUST verify `ach_transfer` matches their Moov /
 * Modern Treasury / Increase tool implementation before enabling.
 *
 * Provider field mapping — providers use different field names for the same
 * concepts. This pack uses normalized field names (routing_number, account_id,
 * amount, sec_code, direction). Operators must map provider fields to these
 * names in their tool implementation layer, or write provider-specific rules
 * using merge_schema_params: true.
 *
 *   Provider          | Amount field   | Routing field                          | Account identifier
 *   ──────────────────|────────────────|────────────────────────────────────────|──────────────────────────
 *   Moov              | amount.value   | destination.bankAccount.routingNumber  | destination.bankAccount.accountNumber
 *                     | (cents, int)   |                                        | (raw account number)
 *   Modern Treasury   | amount         | routing_number (on receiving_account)  | receiving_account_id
 *                     | (cents, int)   |                                        | (internal platform ID)
 *   Increase          | amount         | routing_number                         | account_number
 *                     | (cents, int)   |                                        | (raw account number)
 *
 * Account identifier: the account_id field is an operator-defined identifier.
 * Whether this is a raw account number (Increase account_number, Moov
 * accountNumber) or an internal platform ID (Modern Treasury
 * receiving_account_id) depends on the operator's tool implementation. The
 * allowlist entries must match whatever the tool provides. Exact string
 * comparison only (not_in operator, === semantics).
 *
 * Transfer direction: Moov and Modern Treasury expose a direction field;
 * Increase uses separate endpoints (ach_transfers create for credits,
 * ach_debits for debits). This pack checks a normalized "direction" field.
 * If the operator's tool implementation cannot reliably populate this field,
 * the credit rules (11) will not fire and credit transfers will fall through
 * to default ALLOW — document this gap in operator configuration.
 *
 * Amounts are string-encoded cents (USD) — uses gt_bigint and not_match regex
 * guards so that malformed values produce STEP_UP rather than type_error BLOCK.
 *
 * Per-account max_amount_cents: NOT expressible in static schema pack rules.
 * The evaluator's AND-only condition logic cannot correlate a matched account
 * allowlist entry with its specific ceiling in a single static rule set.
 * Operators requiring per-account ceilings must add custom rules in their
 * policy YAML with merge_schema_params: true. Example:
 *   { tool: "ach_transfer", decision: "BLOCK",
 *     reason: "amount exceeds account ceiling",
 *     blast_radius: "HIGH", reversible: false,
 *     params: { conditions: [
 *       { field: "account_id", op: "eq", value: "acct_abc123" },
 *       { field: "amount", op: "gt_bigint", value: "1000000" }
 *     ] } }
 *
 * Policy YAML section:
 *   ach:
 *     routing_allowlist:
 *       - "021000021"
 *       - "011000138"
 *     account_allowlist:
 *       - account_id: "acct_abc123"
 *         name: "Treasury Account"
 *         max_amount_cents: 1000000
 *     max_amount_cents: 5000000
 *     step_up_threshold_cents: 100000
 *     allowed_sec_codes: ["CCD"]
 *     auto_approve_credits: false
 *     money_action: true
 */
export const achEnforce: SchemaPackDefinition = {
  id: "ach/enforce",
  name: "ACH Enforce",
  description:
    "ACH payment safety — enforces routing/account allowlists, amount ceilings, " +
    "SEC code restrictions, and credit direction controls. " +
    "Amounts are string-encoded cents (USD). " +
    "Tool name 'ach_transfer' is the convention — verify it matches " +
    "your Moov/Modern Treasury/Increase tool implementation before enabling.",
  rules: [
    // ── ach_transfer evaluation order ────────────────────────────────────────
    //  1. routing_number missing/whitespace → BLOCK
    //  2. routing_number not in allowlist → BLOCK
    //  3. account_id missing/whitespace → BLOCK
    //  4. account_id not in allowlist → BLOCK
    //  5. amount missing/whitespace/malformed → STEP_UP
    //  6. (per-account ceiling — OMITTED, see docblock)
    //  7. amount > max_amount_cents → BLOCK
    //  8. amount > step_up_threshold_cents → STEP_UP
    //  9. sec_code missing/whitespace → BLOCK
    // 10. sec_code not in allowed list → BLOCK
    // 11a. direction=credit + auto_approve_credits=true → ALLOW
    // 11b. direction=credit → STEP_UP
    //  → default passthrough
    //
    // Note on rule 11a: An explicit ALLOW is required because AND-only
    // conditions cannot express "direction=credit AND NOT auto_approve=true"
    // in a single rule — the catch-all STEP_UP (11b) would fire for approved
    // credits without this guard. This matches the openclaw escrow.release
    // pattern in this repo.

    // (1) routing_number missing
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "routing number missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "routing_number", op: "not_exists" }],
      },
    },
    // (1) routing_number whitespace-only
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "routing number missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "routing_number", op: "match", value: "^\\s*$" }],
      },
    },
    // (2) routing_number not in allowlist
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "routing number not in allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "routing_number", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },

    // (3) account_id missing
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "account identifier missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "account_id", op: "not_exists" }],
      },
    },
    // (3) account_id whitespace-only
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "account identifier missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "account_id", op: "match", value: "^\\s*$" }],
      },
    },
    // (4) account_id not in allowlist
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "account identifier not in allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "account_id", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },

    // (5) amount missing
    {
      tool: "ach_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_exists" }],
      },
    },
    // (5) amount whitespace-only
    {
      tool: "ach_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "match", value: "^\\s*$" }],
      },
    },
    // (5) amount not a positive integer string (catches floats, negatives, non-numeric, zero)
    {
      tool: "ach_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_match", value: "^[1-9]\\d*$" }],
      },
    },

    // (6) Per-account ceiling — OMITTED.
    // Not expressible in static schema pack rules. The evaluator's AND-only
    // condition logic cannot correlate a matched account entry with its
    // specific ceiling. Operators requiring per-account ceilings must add
    // custom rules in their policy YAML with merge_schema_params: true.
    // See docblock for example rule format.

    // (7) amount > max_amount_cents ($50,000)
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "amount exceeds global ceiling",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [
          { field: "amount", op: "gt_bigint", value: "5000000" },
        ],
      },
    },
    // (8) amount > step_up_threshold_cents ($1,000)
    {
      tool: "ach_transfer",
      decision: "STEP_UP",
      reason: "amount requires approval",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [
          { field: "amount", op: "gt_bigint", value: "100000" },
        ],
      },
    },

    // (9) sec_code missing
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "SEC code missing",
      blast_radius: "MED",
      reversible: false,
      params: {
        conditions: [{ field: "sec_code", op: "not_exists" }],
      },
    },
    // (9) sec_code whitespace-only
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "SEC code missing",
      blast_radius: "MED",
      reversible: false,
      params: {
        conditions: [{ field: "sec_code", op: "match", value: "^\\s*$" }],
      },
    },
    // (10) sec_code not in allowed list
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "SEC code not in allowlist",
      blast_radius: "MED",
      reversible: false,
      params: {
        conditions: [
          { field: "sec_code", op: "not_in", value: ["CCD"] },
        ],
      },
    },

    // (11a) Credit direction with auto_approve → ALLOW (bypass STEP_UP).
    // Required because AND-only conditions cannot express the negation.
    {
      tool: "ach_transfer",
      decision: "ALLOW",
      reason: "auto-approved credit transfer",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "direction", op: "eq", value: "credit" },
          { field: "auto_approve_credits", op: "eq", value: true },
        ],
      },
    },
    // (11b) Credit direction without auto_approve → STEP_UP
    {
      tool: "ach_transfer",
      decision: "STEP_UP",
      reason: "credit transfer requires approval",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "direction", op: "eq", value: "credit" },
        ],
      },
    },

    // Default passthrough — no explicit ALLOW rule.
  ],
};

/**
 * ACH Account Allowlist pack (legacy).
 *
 * Retained for backward compatibility. The achEnforce pack now includes
 * account allowlist rules inline. Operators migrating to "ach/enforce"
 * do not need this separate pack.
 */
export const achAccountAllowlist: SchemaPackDefinition = {
  id: "ach/account-allowlist",
  name: "ACH Account Allowlist",
  description:
    "Blocks ACH transfers to account IDs not in the operator allowlist. " +
    "CRITICAL: Ships with placeholder '__REPLACE_ME__'. Populate with approved account IDs before use. " +
    "WARNING: An empty not_in value array will BLOCK ALL DESTINATIONS — " +
    "the evaluator treats not_in([]) as matching everything. " +
    "Field name 'account_id' is the conventional parameter — verify against your tool implementation.",
  rules: [
    {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "account_id not in approved allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "account_id", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
  ],
};
