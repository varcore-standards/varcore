import type { SchemaPackDefinition } from "../types";

/**
 * UPI Enforce schema pack.
 *
 * Covers `upi_payment` and `upi_transfer` tool names (underscore convention
 * matching stripe_charge, ach_transfer, etc.). No provider-specific tool names
 * (razorpay_*, cashfree_*, phonepe_*) exist in this repo — operators MUST
 * verify that `upi_payment` / `upi_transfer` match their provider tool
 * implementation before enabling.
 *
 * Provider field mapping — providers use different field names for the same
 * concepts. This pack uses normalized field names (vpa, amount). Operators
 * must map provider fields to these names in their tool implementation layer,
 * or write provider-specific rules using merge_schema_params: true.
 *
 *   Provider   | Amount field    | VPA / payee field
 *   ───────────|─────────────────|──────────────────────────
 *   Razorpay   | amount (paise)  | vpa (UPI Virtual Payment Address)
 *   Cashfree   | amount (paise)  | vpa / beneficiary_vpa
 *   PhonePe    | amount (paise)  | vpa / merchantVpa
 *
 * Amounts are string-encoded paise (INR) — uses gt_bigint and not_match regex
 * guards so that malformed values produce STEP_UP rather than type_error BLOCK.
 *
 * VPA matching: uses not_in with exact string comparison (=== semantics).
 * UPI addresses are case-insensitive by spec, but this pack does NOT normalize
 * case. Operators MUST ensure consistent casing (lowercase recommended) in both
 * the allowlist and tool implementation.
 *
 * Policy YAML section:
 *   upi:
 *     vpa_allowlist:
 *       - "vendor@upi"
 *       - "supplier@okaxis"
 *     max_amount_paise: 1000000
 *     step_up_threshold_paise: 100000
 *     money_action: true
 */
export const upiEnforce: SchemaPackDefinition = {
  id: "upi/enforce",
  name: "UPI Enforce",
  description:
    "UPI payment safety — enforces VPA allowlists and amount ceilings. " +
    "Amounts are string-encoded paise (INR). " +
    "Tool names 'upi_payment' and 'upi_transfer' are conventions — verify they match " +
    "your Razorpay/Cashfree/PhonePe tool implementation before enabling.",
  rules: [
    // ── upi_payment evaluation order ────────────────────────────────────────
    //  1. vpa missing/whitespace → STEP_UP
    //  2. vpa not in allowlist → BLOCK
    //  3. amount missing/whitespace/malformed → STEP_UP
    //  4. amount > max_amount_paise (₹10,000) → BLOCK
    //  5. amount > step_up_threshold_paise (₹1,000) → STEP_UP
    //  → default passthrough

    // (1) vpa missing
    {
      tool: "upi_payment",
      decision: "STEP_UP",
      reason: "VPA field missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "vpa", op: "not_exists" }],
      },
    },
    // (1) vpa whitespace-only
    {
      tool: "upi_payment",
      decision: "STEP_UP",
      reason: "VPA field missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "vpa", op: "match", value: "^\\s*$" }],
      },
    },
    // (2) vpa not in allowlist
    {
      tool: "upi_payment",
      decision: "BLOCK",
      reason: "VPA not in allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "vpa", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },

    // (3) amount missing
    {
      tool: "upi_payment",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_exists" }],
      },
    },
    // (3) amount whitespace-only
    {
      tool: "upi_payment",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "match", value: "^\\s*$" }],
      },
    },
    // (3) amount not a non-negative integer string (catches floats, negatives, non-numeric)
    {
      tool: "upi_payment",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_match", value: "^\\d+$" }],
      },
    },

    // (4) amount > max_amount_paise (₹10,000)
    {
      tool: "upi_payment",
      decision: "BLOCK",
      reason: "amount exceeds ceiling",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [
          { field: "amount", op: "gt_bigint", value: "1000000" },
        ],
      },
    },
    // (5) amount > step_up_threshold_paise (₹1,000)
    {
      tool: "upi_payment",
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

    // ── upi_transfer evaluation order ───────────────────────────────────────
    // Same evaluation order as upi_payment.

    // (1) vpa missing
    {
      tool: "upi_transfer",
      decision: "STEP_UP",
      reason: "VPA field missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "vpa", op: "not_exists" }],
      },
    },
    // (1) vpa whitespace-only
    {
      tool: "upi_transfer",
      decision: "STEP_UP",
      reason: "VPA field missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "vpa", op: "match", value: "^\\s*$" }],
      },
    },
    // (2) vpa not in allowlist
    {
      tool: "upi_transfer",
      decision: "BLOCK",
      reason: "VPA not in allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "vpa", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },

    // (3) amount missing
    {
      tool: "upi_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_exists" }],
      },
    },
    // (3) amount whitespace-only
    {
      tool: "upi_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "match", value: "^\\s*$" }],
      },
    },
    // (3) amount not a non-negative integer string
    {
      tool: "upi_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [{ field: "amount", op: "not_match", value: "^\\d+$" }],
      },
    },

    // (4) amount > max_amount_paise (₹10,000)
    {
      tool: "upi_transfer",
      decision: "BLOCK",
      reason: "amount exceeds ceiling",
      blast_radius: "HIGH",
      reversible: false,
      money_action: true,
      params: {
        conditions: [
          { field: "amount", op: "gt_bigint", value: "1000000" },
        ],
      },
    },
    // (5) amount > step_up_threshold_paise (₹1,000)
    {
      tool: "upi_transfer",
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

    // Default passthrough — no explicit ALLOW rule.
  ],
};

/**
 * UPI VPA Allowlist pack (legacy).
 *
 * Retained for backward compatibility. The upiEnforce pack now includes
 * VPA allowlist rules inline. Operators migrating to "upi/enforce"
 * do not need this separate pack.
 */
export const upiVpaAllowlist: SchemaPackDefinition = {
  id: "upi/vpa-allowlist",
  name: "UPI VPA Allowlist",
  description:
    "Blocks UPI payments to VPAs (UPI IDs) not in the operator allowlist. " +
    "CRITICAL: Ships with placeholder '__REPLACE_ME__'. Populate with approved VPAs before use. " +
    "WARNING: An empty not_in value array will BLOCK ALL DESTINATIONS — " +
    "the evaluator treats not_in([]) as matching everything. " +
    "Field name 'vpa' is the conventional UPI parameter — verify against your tool implementation.",
  rules: [
    {
      tool: "upi_payment",
      decision: "BLOCK",
      reason: "VPA not in approved allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "vpa", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
    {
      tool: "upi_transfer",
      decision: "BLOCK",
      reason: "VPA not in approved allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "vpa", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
  ],
};
