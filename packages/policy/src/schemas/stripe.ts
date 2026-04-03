import type { SchemaPackDefinition } from "../types";

export const stripeEnforce: SchemaPackDefinition = {
  id: "stripe/enforce",
  name: "Stripe Enforce",
  description: "Stripe payment API safety — blocks large charges, flags $500+ for review",
  rules: [
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "charges over $1,000 require human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
    {
      tool: "stripe_charge",
      decision: "STEP_UP",
      reason: "charges over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "unsupported currency",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "currency", op: "not_in", value: ["usd", "eur", "gbp", "jpy", "cad", "aud"] },
        ],
      },
    },
    {
      tool: "stripe_create_charge",
      decision: "BLOCK",
      reason: "charges over $1,000 require human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
    {
      tool: "stripe_create_charge",
      decision: "STEP_UP",
      reason: "charges over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    // ── stripe_refund — guard rules (must precede existing STEP_UP) ────────
    // Evaluation order:
    //   a. charge_id missing/empty → BLOCK
    //   b. amount missing/empty → STEP_UP
    //   c. amount > max_refund_amount_cents ($5,000) → BLOCK
    //   d. (existing) amount > step_up_threshold → STEP_UP
    //
    // Note: non-numeric/float amounts that bypass (b) will hit (c) or (d) and
    // produce type_error → BLOCK (fail-closed), since existing rules use numeric gt.

    // (a) charge_id missing
    {
      tool: "stripe_refund",
      decision: "BLOCK",
      reason: "charge_id required for refunds",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "charge_id", op: "not_exists" }] },
    },
    // (a) charge_id empty string
    {
      tool: "stripe_refund",
      decision: "BLOCK",
      reason: "charge_id required for refunds",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "charge_id", op: "eq", value: "" }] },
    },
    // (b) amount missing
    {
      tool: "stripe_refund",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "not_exists" }] },
    },
    // (b) amount empty string
    {
      tool: "stripe_refund",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "eq", value: "" }] },
    },
    // (c) refund exceeds ceiling ($5,000)
    {
      tool: "stripe_refund",
      decision: "BLOCK",
      reason: "refund amount exceeds ceiling",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 500000 }] },
    },
    // (d) existing STEP_UP for amount > step_up_threshold ($500)
    {
      tool: "stripe_refund",
      decision: "STEP_UP",
      reason: "refunds over $500 flagged for review",
      blast_radius: "MED",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 50000 }] },
    },
    {
      tool: "stripe_update_customer",
      decision: "STEP_UP",
      reason: "production customer updates require review",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "metadata.env", op: "in", value: ["production", "prod"] },
        ],
      },
    },

    // ── stripe_transfer ─────────────────────────────────────────────────────
    // Evaluation order:
    //   a. destination missing/empty → BLOCK
    //   b. amount missing/empty/malformed → STEP_UP
    //   c. destination not in beneficiary_allowlist → BLOCK
    //   d. amount > step_up_threshold_cents ($500) → STEP_UP
    //
    // Amounts are string-encoded cents — uses gt_bigint and not_match regex
    // to enable STEP_UP (not BLOCK) for malformed values (floats, negatives, etc.).
    // Zero is allowed, consistent with existing Stripe conventions.

    // (a) destination missing
    {
      tool: "stripe_transfer",
      decision: "BLOCK",
      reason: "destination field missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "destination", op: "not_exists" }] },
    },
    // (a) destination empty or whitespace-only
    {
      tool: "stripe_transfer",
      decision: "BLOCK",
      reason: "destination field missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "destination", op: "match", value: "^\\s*$" }] },
    },
    // (b) amount missing
    {
      tool: "stripe_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "not_exists" }] },
    },
    // (b) amount empty string
    {
      tool: "stripe_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "eq", value: "" }] },
    },
    // (b) amount not a non-negative integer string (catches floats, negatives, non-numeric)
    {
      tool: "stripe_transfer",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "not_match", value: "^\\d+$" }] },
    },
    // (c) destination not in beneficiary allowlist
    {
      tool: "stripe_transfer",
      decision: "BLOCK",
      reason: "destination not in beneficiary allowlist",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "destination", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
    // (d) amount > step_up_threshold_cents ($500)
    {
      tool: "stripe_transfer",
      decision: "STEP_UP",
      reason: "transfer amount requires approval",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt_bigint", value: "50000" }] },
    },

    // ── stripe_payout ───────────────────────────────────────────────────────
    // Same evaluation order as stripe_transfer.

    // (a) destination missing
    {
      tool: "stripe_payout",
      decision: "BLOCK",
      reason: "destination field missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "destination", op: "not_exists" }] },
    },
    // (a) destination empty or whitespace-only
    {
      tool: "stripe_payout",
      decision: "BLOCK",
      reason: "destination field missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "destination", op: "match", value: "^\\s*$" }] },
    },
    // (b) amount missing
    {
      tool: "stripe_payout",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "not_exists" }] },
    },
    // (b) amount empty string
    {
      tool: "stripe_payout",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "eq", value: "" }] },
    },
    // (b) amount not a non-negative integer string
    {
      tool: "stripe_payout",
      decision: "STEP_UP",
      reason: "amount field missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "not_match", value: "^\\d+$" }] },
    },
    // (c) destination not in beneficiary allowlist
    {
      tool: "stripe_payout",
      decision: "BLOCK",
      reason: "destination not in beneficiary allowlist",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "destination", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
    // (d) amount > step_up_threshold_cents ($500)
    {
      tool: "stripe_payout",
      decision: "STEP_UP",
      reason: "payout amount requires approval",
      blast_radius: "CRITICAL",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt_bigint", value: "50000" }] },
    },

    // ── stripe_delete_customer ──────────────────────────────────────────────
    // ALLOW only when allow_customer_delete is true; otherwise BLOCK.

    {
      tool: "stripe_delete_customer",
      decision: "ALLOW",
      reason: "customer deletion approved by policy",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "allow_customer_delete", op: "eq", value: true }],
      },
    },
    {
      tool: "stripe_delete_customer",
      decision: "BLOCK",
      reason: "customer deletion requires allow_customer_delete: true",
      blast_radius: "HIGH",
      reversible: false,
    },
  ],
};

/**
 * Stripe Beneficiary Allowlist pack.
 *
 * Uses the `not_in` operator to block payments to destinations not in an
 * operator-configured allowlist.
 *
 * IMPORTANT — empty-array behavior:
 * The params evaluator treats `not_in` with an empty value array as matching
 * ALL values (because no value is "in" an empty list). This means that if an
 * operator enables this pack without populating the value arrays, ALL
 * stripe_charge and stripe_create_charge calls with a destination field will
 * be blocked. Operators MUST replace the empty arrays with their approved
 * recipient IDs before activating this pack.
 *
 * The field name "destination" follows the Stripe Connect API convention.
 * Operators should verify this matches their actual tool implementation's
 * parameter name and adjust if necessary.
 */
export const stripeBeneficiary: SchemaPackDefinition = {
  id: "stripe/beneficiary",
  name: "Stripe Beneficiary Allowlist",
  description:
    "Blocks Stripe payment tool calls where the destination is not " +
    "in an operator-configured allowlist. Operators MUST override the " +
    "'value' array in each rule with their own approved recipient IDs. " +
    "The field name 'destination' may need adjustment to match your " +
    "Stripe tool implementation's actual parameter name.",
  rules: [
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "destination not in approved beneficiary list",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          {
            field: "destination",
            op: "not_in",
            // Empty array blocks ALL destinations. Operators must populate
            // this list with approved customer/account IDs before use.
            value: [],
          },
        ],
      },
    },
    {
      tool: "stripe_create_charge",
      decision: "BLOCK",
      reason: "destination not in approved beneficiary list",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          {
            field: "destination",
            op: "not_in",
            // Empty array blocks ALL destinations. Operators must populate
            // this list with approved customer/account IDs before use.
            value: [],
          },
        ],
      },
    },
  ],
};
