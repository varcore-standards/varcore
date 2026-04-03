import type { SchemaPackDefinition } from "../types";

/**
 * OpenclawCash Enforce schema pack.
 *
 * Amounts are strings representing BigInt wei values — uses the gt_bigint
 * operator for all amount comparisons to avoid JavaScript number precision loss.
 *
 * Address matching: uses not_in with exact string comparison (=== semantics),
 * consistent with all other schema packs in this repo (Stripe/destination,
 * ACH/account_id, UPI/vpa). Ethereum addresses are hex and case-insensitive
 * for matching purposes; operators MUST normalize addresses to a consistent case
 * (lowercase recommended) in both the allowlist and tool implementation.
 *
 * Per-recipient max_amount_wei: not expressible in static schema pack rules.
 * The pack enforces a global max_amount_wei cap. Operators requiring per-recipient
 * caps should add custom rules in their policy YAML with merge_schema_params: true.
 *
 * Missing/malformed param handling: guard rules using not_exists, eq "", and
 * not_match fire BEFORE value-checking rules. Missing or unparseable amount_wei
 * produces STEP_UP; missing recipient/slippage_bps/output_token produces BLOCK.
 */
export const openclawEnforce: SchemaPackDefinition = {
  id: "openclaw/enforce",
  name: "OpenclawCash Enforce",
  description:
    "OpenclawCash on-chain payment safety — blocks large transfers, enforces recipient " +
    "allowlists, caps swap slippage, and gates escrow releases. " +
    "Amounts are string-encoded wei (BigInt). " +
    "Tool names follow the openclaw.agent.* convention — verify they match your " +
    "OpenclawCash tool implementation before enabling this pack.",
  rules: [
    // ── openclaw.agent.transfer ─────────────────────────────────────────────
    // Evaluation order:
    //   a. recipient missing/empty → BLOCK
    //   b. amount_wei missing/malformed → STEP_UP
    //   c. recipient not in allowlist → BLOCK
    //   d. amount_wei > global max → BLOCK
    //   e. amount_wei > step_up threshold → STEP_UP
    //   f. → ALLOW (policy default)
    //
    // Per-recipient max_amount_wei (rule d from spec) requires operator custom rules.

    // (a) Guard: recipient missing
    {
      tool: "openclaw.agent.transfer",
      decision: "BLOCK",
      reason: "recipient address missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [{ field: "recipient", op: "not_exists" }],
      },
    },
    // (a) Guard: recipient empty string
    {
      tool: "openclaw.agent.transfer",
      decision: "BLOCK",
      reason: "recipient address missing",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [{ field: "recipient", op: "eq", value: "" }],
      },
    },
    // (b) Guard: amount_wei missing
    {
      tool: "openclaw.agent.transfer",
      decision: "STEP_UP",
      reason: "amount_wei missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [{ field: "amount_wei", op: "not_exists" }],
      },
    },
    // (b) Guard: amount_wei not a valid decimal integer string
    {
      tool: "openclaw.agent.transfer",
      decision: "STEP_UP",
      reason: "amount_wei missing or malformed",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [{ field: "amount_wei", op: "not_match", value: "^\\d+$" }],
      },
    },
    // (c) Recipient not in allowlist
    {
      tool: "openclaw.agent.transfer",
      decision: "BLOCK",
      reason: "Recipient not in allowlist",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "recipient", op: "not_in", value: ["__REPLACE_ME__"] },
        ],
      },
    },
    // (d) Amount exceeds global max_amount_wei (5 ETH)
    {
      tool: "openclaw.agent.transfer",
      decision: "BLOCK",
      reason: "Transfer exceeds max_amount_wei (5 ETH)",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "amount_wei", op: "gt_bigint", value: "5000000000000000000" },
        ],
      },
    },
    // (e) Amount exceeds step_up_threshold_wei (0.1 ETH)
    {
      tool: "openclaw.agent.transfer",
      decision: "STEP_UP",
      reason: "Transfer above step_up_threshold_wei (0.1 ETH) — requires approval",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "amount_wei", op: "gt_bigint", value: "100000000000000000" },
        ],
      },
    },

    // ── openclaw.agent.swap ─────────────────────────────────────────────────
    // Evaluation order:
    //   a. slippage_bps missing → BLOCK
    //   b. slippage_bps > max → BLOCK
    //   c. output_token missing/empty → BLOCK
    //   d. output_token not in allowlist → BLOCK
    //   e. → ALLOW (policy default)

    // (a) Guard: slippage_bps missing
    {
      tool: "openclaw.agent.swap",
      decision: "BLOCK",
      reason: "slippage_bps missing or malformed",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "slippage_bps", op: "not_exists" }],
      },
    },
    // (b) Slippage exceeds max (50 bps)
    {
      tool: "openclaw.agent.swap",
      decision: "BLOCK",
      reason: "Slippage exceeds max_slippage_bps (50 bps)",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "slippage_bps", op: "gt", value: 50 }],
      },
    },
    // (c) Guard: output_token missing
    {
      tool: "openclaw.agent.swap",
      decision: "BLOCK",
      reason: "output_token missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "output_token", op: "not_exists" }],
      },
    },
    // (c) Guard: output_token empty string
    {
      tool: "openclaw.agent.swap",
      decision: "BLOCK",
      reason: "output_token missing",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "output_token", op: "eq", value: "" }],
      },
    },
    // (d) Output token not in allowlist
    {
      tool: "openclaw.agent.swap",
      decision: "BLOCK",
      reason: "Output token not in allowlist",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "output_token", op: "not_in", value: ["ETH", "USDC", "USDT"] },
        ],
      },
    },

    // ── openclaw.agent.checkout.escrow.release ──────────────────────────────
    // auto_approve_escrow_release: true in action args → ALLOW; otherwise STEP_UP
    {
      tool: "openclaw.agent.checkout.escrow.release",
      decision: "ALLOW",
      reason: "Auto-approved escrow release",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "auto_approve_escrow_release", op: "eq", value: true },
        ],
      },
    },
    {
      tool: "openclaw.agent.checkout.escrow.release",
      decision: "STEP_UP",
      reason: "Escrow release requires human approval",
      blast_radius: "CRITICAL",
      reversible: false,
    },

    // ── openclaw.agent.checkout.escrow.refund ───────────────────────────────
    {
      tool: "openclaw.agent.checkout.escrow.refund",
      decision: "ALLOW",
      reason: "Refunds are safe — funds return to buyer",
      blast_radius: "MED",
      reversible: true,
    },
  ],
};
