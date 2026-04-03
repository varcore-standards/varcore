/**
 * SP1–SP16: Schema pack tests (SP27–SP30: stripe/beneficiary, SP31–SP37: upi)
 * SP38–SP52: ach/enforce, SP53–SP54: ach/account-allowlist
 * SP55–SP66: openclaw/enforce
 *
 * SP1   resolveSchemaPack("stripe/enforce") returns the pack
 * SP2   resolveSchemaPack("unknown/pack") throws PolicyLoadError
 * SP3   stripe/enforce: stripe_charge BLOCK when amount > 100000
 * SP4   stripe/enforce: stripe_charge STEP_UP when amount 50001–100000
 * SP5   stripe/enforce: stripe_charge BLOCK when currency not in approved list
 * SP6   stripe/enforce: stripe_charge ALLOW for valid amount + currency
 * SP67  stripe/enforce: refund with missing charge_id → BLOCK
 * SP68  stripe/enforce: refund above ceiling → BLOCK
 * SP69  stripe/enforce: refund below step_up threshold → ALLOW
 * SP70  stripe/enforce: refund between step_up and ceiling → STEP_UP
 * SP71  stripe/enforce: transfer to non-allowlisted destination → BLOCK
 * SP72  stripe/enforce: transfer to allowlisted destination below threshold → ALLOW
 * SP73  stripe/enforce: transfer with missing destination → BLOCK
 * SP74  stripe/enforce: transfer with missing/malformed amount → STEP_UP
 * SP75  stripe/enforce: payout to non-allowlisted destination → BLOCK
 * SP76  stripe/enforce: customer delete with allow_customer_delete false → BLOCK
 * SP77  stripe/enforce: customer delete with allow_customer_delete true → ALLOW
 * SP78  stripe/enforce: payout to allowlisted destination below threshold → ALLOW
 * SP79  stripe/enforce: refund with malformed amount → STEP_UP
 * SP7   github/enforce: github_push BLOCK when force=true
 * SP8   github/enforce: github_push STEP_UP when branch=main
 * SP9   github/enforce: github_delete_branch BLOCK when branch=production
 * SP10  aws-s3/enforce: s3_delete_object BLOCK when key not in tmp/
 * SP11  aws-s3/enforce: s3_delete_bucket BLOCK (tool-level, no params)
 * SP12  mergePackRules: no operator rule for tool → pack rule appended
 * SP13  mergePackRules: operator rule (no merge_schema_params) → pack rule NOT applied
 * SP14  mergePackRules: merge_schema_params: true → pack rules injected before operator rule
 * SP15  mergePackRules: merge_schema_params: false → pack rules NOT injected
 * SP16  computePolicyBundleHash: different merged policies → different hashes
 * SP38  ach/enforce: resolves from SCHEMA_PACKS
 * SP39  ach/enforce: allowlisted routing + account, under threshold → ALLOW
 * SP40  ach/enforce: non-allowlisted routing → BLOCK
 * SP41  ach/enforce: missing routing field → BLOCK
 * SP42  ach/enforce: non-allowlisted account → BLOCK
 * SP43  ach/enforce: missing account field → BLOCK
 * SP44  ach/enforce: amount exceeds matched account ceiling → BLOCK
 * SP45  ach/enforce: over global max_amount_cents → BLOCK
 * SP46  ach/enforce: over step_up threshold → STEP_UP
 * SP47  ach/enforce: missing amount → STEP_UP
 * SP48  ach/enforce: float amount → STEP_UP
 * SP49  ach/enforce: negative amount → STEP_UP
 * SP50  ach/enforce: credit without auto_approve_credits → STEP_UP
 * SP51  ach/enforce: missing SEC code → BLOCK
 * SP52  ach/enforce: non-allowlisted SEC code → BLOCK
 * SP80  ach/enforce: routing whitespace-only → BLOCK
 * SP81  ach/enforce: amount whitespace-only → STEP_UP
 * SP82  ach/enforce: Moov-style amount.value dot-path traversal
 * SP53  ach/account-allowlist: resolves from SCHEMA_PACKS
 * SP54  ach/account-allowlist: ach_transfer BLOCK when account_id not in allowlist
 * SP55  openclaw/enforce: allowlisted address under threshold → ALLOW
 * SP56  openclaw/enforce: non-allowlisted address → BLOCK
 * SP57  openclaw/enforce: missing recipient field → BLOCK
 * SP58  openclaw/enforce: over max_amount_wei → BLOCK
 * SP59  openclaw/enforce: over step_up threshold, allowlisted → STEP_UP
 * SP60  openclaw/enforce: missing amount_wei → STEP_UP
 * SP61  openclaw/enforce: non-BigInt-parseable amount_wei → STEP_UP
 * SP62  openclaw/enforce: swap with excess slippage → BLOCK
 * SP63  openclaw/enforce: swap with missing slippage_bps → BLOCK
 * SP64  openclaw/enforce: swap with non-allowlisted output_token → BLOCK
 * SP65  openclaw/enforce: escrow release without auto_approve → STEP_UP
 * SP66  openclaw/enforce: escrow refund → ALLOW
 */

import {
  resolveSchemaPack,
  SCHEMA_PACKS,
  mergePackRules,
  computePolicyBundleHash,
  evaluatePolicy,
} from "../index";
import { PolicyLoadError } from "../types";
import type { PolicyConfig, PolicyRule } from "../types";

// ── SP1–SP2: resolveSchemaPack ────────────────────────────────────────────────

describe("resolveSchemaPack", () => {
  test("SP1: known pack ID returns SchemaPackDefinition", () => {
    const pack = resolveSchemaPack("stripe/enforce");
    expect(pack.id).toBe("stripe/enforce");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP2: unknown pack ID throws PolicyLoadError", () => {
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(PolicyLoadError);
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(/unknown\/pack/);
    expect(() => resolveSchemaPack("unknown/pack")).toThrow(/nonsudo schemas list/);
  });
});

// ── SP3–SP6: stripe/enforce evaluation ───────────────────────────────────────

describe("stripe/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["stripe/enforce"].rules,
  };

  test("SP3: stripe_charge BLOCK when amount > 100000", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000, currency: "usd" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP4: stripe_charge STEP_UP when amount > 50000 and ≤ 100000", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 75000, currency: "usd" });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP5: stripe_charge BLOCK when currency not in approved list", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 10000, currency: "XYZ" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP6: stripe_charge ALLOW for valid low amount + approved currency", () => {
    const r = evaluatePolicy("stripe_charge", policy, { amount: 10000, currency: "usd" });
    expect(r.decision).toBe("ALLOW");
  });
});

// ── SP67–SP77: stripe/enforce extended rules ────────────────────────────────

describe("stripe/enforce extended rules", () => {
  // Populate beneficiary allowlists with test values for transfer/payout
  const rules = SCHEMA_PACKS["stripe/enforce"].rules.map((r) => {
    if (
      r.params?.conditions.length === 1 &&
      r.params.conditions[0].field === "destination" &&
      r.params.conditions[0].op === "not_in"
    ) {
      return {
        ...r,
        params: { conditions: [{ ...r.params.conditions[0], value: ["acct_approved_1"] }] },
      };
    }
    return r;
  });
  const policy: PolicyConfig = { default: "ALLOW", rules };

  // ── stripe_refund ───────────────────────────────────────────────────────

  test("SP67: refund with missing charge_id → BLOCK", () => {
    const r = evaluatePolicy("stripe_refund", policy, { amount: 10000 });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/charge_id required/);
  });

  test("SP68: refund above ceiling → BLOCK", () => {
    const r = evaluatePolicy("stripe_refund", policy, {
      charge_id: "ch_123",
      amount: 600000, // $6,000 > $5,000 ceiling
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/refund amount exceeds ceiling/);
  });

  test("SP69: refund below step_up threshold → ALLOW", () => {
    const r = evaluatePolicy("stripe_refund", policy, {
      charge_id: "ch_123",
      amount: 10000, // $100 — under $500 threshold
    });
    expect(r.decision).toBe("ALLOW");
  });

  test("SP70: refund between step_up and ceiling → STEP_UP", () => {
    const r = evaluatePolicy("stripe_refund", policy, {
      charge_id: "ch_123",
      amount: 200000, // $2,000 — between $500 and $5,000
    });
    expect(r.decision).toBe("STEP_UP");
  });

  // ── stripe_transfer ─────────────────────────────────────────────────────

  test("SP71: transfer to non-allowlisted destination → BLOCK", () => {
    const r = evaluatePolicy("stripe_transfer", policy, {
      destination: "acct_unknown",
      amount: "10000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/beneficiary allowlist/);
  });

  test("SP72: transfer to allowlisted destination below threshold → ALLOW", () => {
    const r = evaluatePolicy("stripe_transfer", policy, {
      destination: "acct_approved_1",
      amount: "10000", // $100 — under $500 threshold
    });
    expect(r.decision).toBe("ALLOW");
  });

  test("SP73: transfer with missing destination → BLOCK", () => {
    const r = evaluatePolicy("stripe_transfer", policy, { amount: "10000" });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/destination field missing/);
  });

  test("SP74: transfer with missing amount → STEP_UP", () => {
    const r = evaluatePolicy("stripe_transfer", policy, {
      destination: "acct_approved_1",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── stripe_payout ───────────────────────────────────────────────────────

  test("SP75: payout to non-allowlisted destination → BLOCK", () => {
    const r = evaluatePolicy("stripe_payout", policy, {
      destination: "ba_unknown",
      amount: "10000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/beneficiary allowlist/);
  });

  // ── stripe_delete_customer ──────────────────────────────────────────────

  test("SP76: customer delete with allow_customer_delete false → BLOCK", () => {
    const r = evaluatePolicy("stripe_delete_customer", policy, {
      allow_customer_delete: false,
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/allow_customer_delete/);
  });

  test("SP77: customer delete with allow_customer_delete true → ALLOW", () => {
    const r = evaluatePolicy("stripe_delete_customer", policy, {
      allow_customer_delete: true,
    });
    expect(r.decision).toBe("ALLOW");
  });

  // ── additional tests ────────────────────────────────────────────────────

  test("SP78: payout to allowlisted destination below threshold → ALLOW", () => {
    const r = evaluatePolicy("stripe_payout", policy, {
      destination: "acct_approved_1",
      amount: "10000", // $100 — under $500 threshold
    });
    expect(r.decision).toBe("ALLOW");
  });

  test("SP79: refund with malformed amount (empty string) → STEP_UP", () => {
    const r = evaluatePolicy("stripe_refund", policy, {
      charge_id: "ch_123",
      amount: "",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });
});

// ── SP7–SP9: github/enforce evaluation ───────────────────────────────────────

describe("github/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["github/enforce"].rules,
  };

  test("SP7: github_push BLOCK when force=true", () => {
    const r = evaluatePolicy("github_push", policy, { force: true, branch: "feature/x" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP8: github_push STEP_UP when branch=main and force=false", () => {
    const r = evaluatePolicy("github_push", policy, { force: false, branch: "main" });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP9: github_delete_branch BLOCK when branch=production", () => {
    const r = evaluatePolicy("github_delete_branch", policy, { branch: "production" });
    expect(r.decision).toBe("BLOCK");
  });
});

// ── SP10–SP11: aws-s3/enforce evaluation ─────────────────────────────────────

describe("aws-s3/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["aws-s3/enforce"].rules,
  };

  test("SP10: s3_delete_object BLOCK when key is not in tmp/ prefix", () => {
    const r = evaluatePolicy("s3_delete_object", policy, { key: "data/important.txt" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP11: s3_delete_bucket BLOCK (tool-level, no params required)", () => {
    const r = evaluatePolicy("s3_delete_bucket", policy, {});
    expect(r.decision).toBe("BLOCK");
    expect(r.matched_rule).toBe("s3_delete_bucket");
  });
});

// ── SP12–SP15: mergePackRules ─────────────────────────────────────────────────

describe("mergePackRules", () => {
  const packRules: PolicyRule[] = [
    {
      tool: "stripe_charge",
      decision: "BLOCK",
      reason: "large charge (pack)",
      blast_radius: "HIGH",
      reversible: false,
      params: { conditions: [{ field: "amount", op: "gt", value: 100000 }] },
    },
  ];

  test("SP12: no operator rule for tool → pack rule appended and evaluated", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "read_file",
        decision: "ALLOW",
        reason: "reads are fine",
        blast_radius: "LOW",
        reversible: true,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack rule for stripe_charge is appended — should fire
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP13: operator rule without merge_schema_params → pack rule NOT applied (operator wins)", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator allows all charges",
        blast_radius: "LOW",
        reversible: true,
        // merge_schema_params: absent (default false)
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK is skipped; operator ALLOW fires
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("ALLOW");
    // Only the operator rule should be in merged (pack rule omitted)
    expect(merged.filter((r) => r.decision === "BLOCK")).toHaveLength(0);
  });

  test("SP14: merge_schema_params: true → pack rules injected before operator rule", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator catch-all allows charges",
        blast_radius: "LOW",
        reversible: true,
        merge_schema_params: true,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK is injected first → fires for amount=150000
    const r1 = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r1.decision).toBe("BLOCK");

    // For amount=30000 pack condition not satisfied → operator ALLOW fires
    const r2 = evaluatePolicy("stripe_charge", policy, { amount: 30000 });
    expect(r2.decision).toBe("ALLOW");

    // Merged order: [pack BLOCK rule, operator ALLOW rule]
    expect(merged[0].decision).toBe("BLOCK");
    expect(merged[1].decision).toBe("ALLOW");
  });

  test("SP15: merge_schema_params: false → pack rules NOT injected", () => {
    const operatorRules: PolicyRule[] = [
      {
        tool: "stripe_charge",
        decision: "ALLOW",
        reason: "operator allows all charges",
        blast_radius: "LOW",
        reversible: true,
        merge_schema_params: false,
      },
    ];
    const merged = mergePackRules(operatorRules, packRules);
    const policy: PolicyConfig = { default: "ALLOW", rules: merged };

    // Pack BLOCK not injected; operator ALLOW fires
    const r = evaluatePolicy("stripe_charge", policy, { amount: 150000 });
    expect(r.decision).toBe("ALLOW");

    // Only the operator rule
    expect(merged).toHaveLength(1);
    expect(merged[0].decision).toBe("ALLOW");
  });
});

// ── SP16: computePolicyBundleHash ─────────────────────────────────────────────

describe("computePolicyBundleHash", () => {
  test("SP16: different merged policies produce different hashes", () => {
    const policy1: PolicyConfig = {
      default: "ALLOW",
      rules: SCHEMA_PACKS["stripe/enforce"].rules,
      schemas: ["stripe/enforce"],
    };
    const policy2: PolicyConfig = {
      default: "ALLOW",
      rules: SCHEMA_PACKS["github/enforce"].rules,
      schemas: ["github/enforce"],
    };

    const hash1 = computePolicyBundleHash(policy1);
    const hash2 = computePolicyBundleHash(policy2);

    expect(hash1).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hash2).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hash1).not.toBe(hash2);
  });
});

// ── SP17–SP18: eu-ai-act/enforce evaluation ──────────────────────────────────

describe("eu-ai-act/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["eu-ai-act/enforce"].rules,
  };

  test("SP17: llm_inference STEP_UP when risk_classification is high_risk", () => {
    const r = evaluatePolicy("llm_inference", policy, { risk_classification: "high_risk" });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP18: model_deployment STEP_UP when environment is production", () => {
    const r = evaluatePolicy("model_deployment", policy, { environment: "production" });
    expect(r.decision).toBe("STEP_UP");
  });
});

// ── SP19–SP20: hipaa/enforce evaluation ──────────────────────────────────────

describe("hipaa/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["hipaa/enforce"].rules,
  };

  test("SP19: ehr_read BLOCK when patient_consent is false", () => {
    const r = evaluatePolicy("ehr_read", policy, { patient_consent: false });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP20: ehr_delete BLOCK (tool-level, no params required)", () => {
    const r = evaluatePolicy("ehr_delete", policy, {});
    expect(r.decision).toBe("BLOCK");
    expect(r.matched_rule).toBe("ehr_delete");
  });
});

// ── SP21–SP22: soc2/enforce evaluation ───────────────────────────────────────

describe("soc2/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["soc2/enforce"].rules,
  };

  test("SP21: user_data_export BLOCK when requestor_authorized is false", () => {
    const r = evaluatePolicy("user_data_export", policy, { requestor_authorized: false });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP22: backup_delete BLOCK (tool-level, no params required)", () => {
    const r = evaluatePolicy("backup_delete", policy, {});
    expect(r.decision).toBe("BLOCK");
    expect(r.matched_rule).toBe("backup_delete");
  });
});

// ── SP23–SP24: gdpr/enforce evaluation ───────────────────────────────────────

describe("gdpr/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["gdpr/enforce"].rules,
  };

  test("SP23: personal_data_collect BLOCK when lawful_basis is missing", () => {
    const r = evaluatePolicy("personal_data_collect", policy, {});
    expect(r.decision).toBe("BLOCK");
  });

  test("SP24: profiling_decision BLOCK when solely_automated is true", () => {
    const r = evaluatePolicy("profiling_decision", policy, { solely_automated: true });
    expect(r.decision).toBe("BLOCK");
  });
});

// ── SP25–SP26: iso27001/enforce evaluation ───────────────────────────────────

describe("iso27001/enforce evaluation", () => {
  const policy: PolicyConfig = {
    default: "ALLOW",
    rules: SCHEMA_PACKS["iso27001/enforce"].rules,
  };

  test("SP25: asset_delete BLOCK when asset_classification is confidential", () => {
    const r = evaluatePolicy("asset_delete", policy, { asset_classification: "confidential" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP26: log_delete BLOCK (tool-level, no params required)", () => {
    const r = evaluatePolicy("log_delete", policy, {});
    expect(r.decision).toBe("BLOCK");
    expect(r.matched_rule).toBe("log_delete");
  });
});

// ── SP27–SP30: stripe/beneficiary evaluation ────────────────────────────────

describe("stripe/beneficiary evaluation", () => {
  test("SP27: stripe/beneficiary resolves from SCHEMA_PACKS", () => {
    const pack = resolveSchemaPack("stripe/beneficiary");
    expect(pack.id).toBe("stripe/beneficiary");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP28: stripe_charge BLOCK when destination not in allowlist", () => {
    // Simulate operator-configured allowlist with approved IDs
    const rules = SCHEMA_PACKS["stripe/beneficiary"].rules.map((r) => ({
      ...r,
      params: {
        conditions: [
          { field: "destination", op: "not_in" as const, value: ["acct_approved_1", "acct_approved_2"] },
        ],
      },
    }));
    const policy: PolicyConfig = { default: "ALLOW", rules };
    const r = evaluatePolicy("stripe_charge", policy, { destination: "acct_unknown" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP29: stripe_charge ALLOW when destination in allowlist", () => {
    const rules = SCHEMA_PACKS["stripe/beneficiary"].rules.map((r) => ({
      ...r,
      params: {
        conditions: [
          { field: "destination", op: "not_in" as const, value: ["acct_approved_1", "acct_approved_2"] },
        ],
      },
    }));
    const policy: PolicyConfig = { default: "ALLOW", rules };
    const r = evaluatePolicy("stripe_charge", policy, { destination: "acct_approved_1" });
    expect(r.decision).toBe("ALLOW");
  });

  test("SP30: non-Stripe tool unaffected by beneficiary rules", () => {
    const policy: PolicyConfig = {
      default: "ALLOW",
      rules: SCHEMA_PACKS["stripe/beneficiary"].rules,
    };
    const r = evaluatePolicy("github_push", policy, { destination: "acct_unknown" });
    expect(r.decision).toBe("ALLOW");
  });
});

// ── SP31–SP37: upi/enforce and upi/vpa-allowlist evaluation ─────────────────
// ── SP83–SP93: additional upi/enforce coverage ─────────────────────────────

describe("upi/enforce evaluation", () => {
  // Populate VPA allowlist with test values
  const baseRules = SCHEMA_PACKS["upi/enforce"].rules.map((r) => {
    if (
      r.params?.conditions.length === 1 &&
      r.params.conditions[0].field === "vpa" &&
      r.params.conditions[0].op === "not_in"
    ) {
      return {
        ...r,
        params: {
          conditions: [
            {
              field: "vpa",
              op: "not_in" as const,
              value: ["vendor@upi", "supplier@okaxis"],
            },
          ],
        },
      };
    }
    return r;
  });
  const policy: PolicyConfig = { default: "ALLOW", rules: baseRules };

  test("SP31: upi/enforce resolves from SCHEMA_PACKS", () => {
    const pack = resolveSchemaPack("upi/enforce");
    expect(pack.id).toBe("upi/enforce");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  // ── SP32: VPA in allowlist, amount below threshold → no rule fires ──────
  test("SP32: upi_payment ALLOW — VPA allowlisted, amount below step_up", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "50000",
    });
    expect(r.decision).toBe("ALLOW");
  });

  // ── SP33: VPA not in allowlist → BLOCK ──────────────────────────────────
  test("SP33: upi_payment BLOCK — VPA not in allowlist", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "attacker@ybl",
      amount: "50000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/VPA not in allowlist/);
  });

  // ── SP34: VPA field absent → STEP_UP ────────────────────────────────────
  test("SP34: upi_payment STEP_UP — VPA field absent", () => {
    const r = evaluatePolicy("upi_payment", policy, { amount: "50000" });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/VPA field missing/);
  });

  // ── SP83: VPA field whitespace-only → STEP_UP ──────────────────────────
  test("SP83: upi_payment STEP_UP — VPA whitespace-only", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "   ",
      amount: "50000",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/VPA field missing/);
  });

  // ── SP84: Amount > max_amount_paise → BLOCK ────────────────────────────
  test("SP84: upi_payment BLOCK — amount exceeds ceiling", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "1500000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/amount exceeds ceiling/);
  });

  // ── SP85: Amount > step_up_threshold, VPA allowlisted → STEP_UP ───────
  test("SP85: upi_payment STEP_UP — amount above step_up threshold", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "500000",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount requires approval/);
  });

  // ── SP86: Amount field absent → STEP_UP ────────────────────────────────
  test("SP86: upi_payment STEP_UP — amount field absent", () => {
    const r = evaluatePolicy("upi_payment", policy, { vpa: "vendor@upi" });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── SP87: Amount non-numeric → STEP_UP ─────────────────────────────────
  test("SP87: upi_payment STEP_UP — amount non-numeric", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "abc",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── SP88: Amount negative → STEP_UP ────────────────────────────────────
  test("SP88: upi_payment STEP_UP — amount negative", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "-100",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── SP89: Amount whitespace-only → STEP_UP ─────────────────────────────
  test("SP89: upi_payment STEP_UP — amount whitespace-only", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "  ",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── SP90: upi_transfer — VPA allowlisted, amount below threshold ──────
  test("SP90: upi_transfer ALLOW — VPA allowlisted, amount below step_up", () => {
    const r = evaluatePolicy("upi_transfer", policy, {
      vpa: "supplier@okaxis",
      amount: "50000",
    });
    expect(r.decision).toBe("ALLOW");
  });

  // ── SP91: upi_transfer — VPA not in allowlist → BLOCK ─────────────────
  test("SP91: upi_transfer BLOCK — VPA not in allowlist", () => {
    const r = evaluatePolicy("upi_transfer", policy, {
      vpa: "attacker@ybl",
      amount: "50000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/VPA not in allowlist/);
  });

  // ── SP92: Amount float → STEP_UP ───────────────────────────────────────
  test("SP92: upi_payment STEP_UP — amount float", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "100.50",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  // ── SP93: Amount at exact ceiling boundary → no BLOCK ──────────────────
  test("SP93: upi_payment STEP_UP — amount at exact ceiling (not exceeded)", () => {
    const r = evaluatePolicy("upi_payment", policy, {
      vpa: "vendor@upi",
      amount: "1000000",
    });
    // gt_bigint: 1000000 is NOT > 1000000, so ceiling BLOCK does not fire.
    // But 1000000 > 100000 (step_up threshold) fires STEP_UP.
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount requires approval/);
  });
});

describe("upi/vpa-allowlist evaluation", () => {
  test("SP35: upi/vpa-allowlist resolves from SCHEMA_PACKS", () => {
    const pack = resolveSchemaPack("upi/vpa-allowlist");
    expect(pack.id).toBe("upi/vpa-allowlist");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP36: upi_payment BLOCK when vpa not in allowlist", () => {
    const rules = SCHEMA_PACKS["upi/vpa-allowlist"].rules.map((r) => ({
      ...r,
      params: {
        conditions: [
          { field: "vpa", op: "not_in" as const, value: ["vendor@okaxis"] },
        ],
      },
    }));
    const policy: PolicyConfig = { default: "ALLOW", rules };
    const r = evaluatePolicy("upi_payment", policy, { vpa: "attacker@ybl" });
    expect(r.decision).toBe("BLOCK");
  });

  test("SP37: upi_payment ALLOW when vpa in allowlist", () => {
    const rules = SCHEMA_PACKS["upi/vpa-allowlist"].rules.map((r) => ({
      ...r,
      params: {
        conditions: [
          { field: "vpa", op: "not_in" as const, value: ["vendor@okaxis"] },
        ],
      },
    }));
    const policy: PolicyConfig = { default: "ALLOW", rules };
    const r = evaluatePolicy("upi_payment", policy, { vpa: "vendor@okaxis" });
    expect(r.decision).toBe("ALLOW");
  });
});

// ── SP38–SP52, SP80–SP82: ach/enforce evaluation ─────────────────────────

describe("ach/enforce evaluation", () => {
  // Populate routing and account allowlists with test values
  const baseRules = SCHEMA_PACKS["ach/enforce"].rules.map((r) => {
    if (
      r.params?.conditions.length === 1 &&
      r.params.conditions[0].field === "routing_number" &&
      r.params.conditions[0].op === "not_in"
    ) {
      return {
        ...r,
        params: { conditions: [{ ...r.params.conditions[0], value: ["021000021"] }] },
      };
    }
    if (
      r.params?.conditions.length === 1 &&
      r.params.conditions[0].field === "account_id" &&
      r.params.conditions[0].op === "not_in"
    ) {
      return {
        ...r,
        params: { conditions: [{ ...r.params.conditions[0], value: ["acct_abc123"] }] },
      };
    }
    return r;
  });
  const policy: PolicyConfig = { default: "ALLOW", rules: baseRules };

  // Valid base params — passes all guards
  const validParams = {
    routing_number: "021000021",
    account_id: "acct_abc123",
    amount: "50000", // $500, under $1,000 step_up threshold
    sec_code: "CCD",
    direction: "debit",
  };

  test("SP38: ach/enforce resolves from SCHEMA_PACKS", () => {
    const pack = resolveSchemaPack("ach/enforce");
    expect(pack.id).toBe("ach/enforce");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP39: allowlisted routing + account, under threshold → ALLOW", () => {
    const r = evaluatePolicy("ach_transfer", policy, validParams);
    expect(r.decision).toBe("ALLOW");
  });

  test("SP40: non-allowlisted routing → BLOCK", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      routing_number: "999999999",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/routing number not in allowlist/);
  });

  test("SP41: missing routing field → BLOCK", () => {
    const { routing_number: _, ...noRouting } = validParams;
    const r = evaluatePolicy("ach_transfer", policy, noRouting);
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/routing number missing/);
  });

  test("SP80: routing field whitespace-only → BLOCK", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      routing_number: "   ",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/routing number missing/);
  });

  test("SP42: non-allowlisted account → BLOCK", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      account_id: "acct_unknown",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/account identifier not in allowlist/);
  });

  test("SP43: missing account field → BLOCK", () => {
    const { account_id: _, ...noAccount } = validParams;
    const r = evaluatePolicy("ach_transfer", policy, noAccount);
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/account identifier missing/);
  });

  test("SP44: amount exceeds matched account ceiling → BLOCK", () => {
    // Per-account ceiling is not expressible in static rules (AND-only logic
    // cannot correlate account with its ceiling). This test demonstrates the
    // operator custom rule pattern using merge_schema_params: true.
    const ceilingRule: PolicyRule = {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "amount exceeds account ceiling",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "account_id", op: "eq", value: "acct_abc123" },
          { field: "amount", op: "gt_bigint", value: "1000000" },
        ],
      },
    };
    const rulesWithCeiling = [
      ...baseRules.slice(0, 6),
      ceilingRule,
      ...baseRules.slice(6),
    ];
    const policyWithCeiling: PolicyConfig = { default: "ALLOW", rules: rulesWithCeiling };
    const r = evaluatePolicy("ach_transfer", policyWithCeiling, {
      ...validParams,
      amount: "1500000", // $15,000 > $10,000 ceiling
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/account ceiling/);
  });

  test("SP45: over global max_amount_cents → BLOCK", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      amount: "6000000", // $60,000 > $50,000 max
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/global ceiling/);
  });

  test("SP46: over step_up threshold → STEP_UP", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      amount: "200000", // $2,000 > $1,000 threshold
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount requires approval/);
  });

  test("SP47: missing amount → STEP_UP", () => {
    const { amount: _, ...noAmount } = validParams;
    const r = evaluatePolicy("ach_transfer", policy, noAmount);
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  test("SP81: amount whitespace-only → STEP_UP", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      amount: "  ",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  test("SP48: float amount → STEP_UP", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      amount: "99.5",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  test("SP49: negative amount → STEP_UP", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      amount: "-100",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount field missing or malformed/);
  });

  test("SP51: missing SEC code → BLOCK", () => {
    const { sec_code: _, ...noSecCode } = validParams;
    const r = evaluatePolicy("ach_transfer", policy, noSecCode);
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/SEC code missing/);
  });

  test("SP52: non-allowlisted SEC code → BLOCK", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      sec_code: "WEB",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/SEC code not in allowlist/);
  });

  test("SP50: credit without auto_approve_credits → STEP_UP", () => {
    const r = evaluatePolicy("ach_transfer", policy, {
      ...validParams,
      direction: "credit",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/credit transfer requires approval/);
  });

  test("SP82: Moov-style amount.value dot-path traversal", () => {
    // Moov exposes amount.value (cents) as a nested field. This test verifies
    // the evaluator's dot-path field resolution works for provider-specific
    // rules that operators add via merge_schema_params: true.
    const moovRule: PolicyRule = {
      tool: "ach_transfer",
      decision: "BLOCK",
      reason: "Moov transfer exceeds ceiling",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "amount.value", op: "gt_bigint", value: "5000000" }],
      },
    };
    const moovPolicy: PolicyConfig = { default: "ALLOW", rules: [moovRule] };
    const r = evaluatePolicy("ach_transfer", moovPolicy, {
      amount: { value: "6000000" },
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/Moov transfer exceeds ceiling/);
  });
});

// ── SP53–SP54: ach/account-allowlist evaluation ───────────────────────────

describe("ach/account-allowlist evaluation", () => {
  test("SP53: ach/account-allowlist resolves from SCHEMA_PACKS", () => {
    const pack = resolveSchemaPack("ach/account-allowlist");
    expect(pack.id).toBe("ach/account-allowlist");
    expect(pack.name).toBeTruthy();
    expect(Array.isArray(pack.rules)).toBe(true);
    expect(pack.rules.length).toBeGreaterThan(0);
  });

  test("SP54: ach_transfer BLOCK when account_id not in allowlist", () => {
    const rules = SCHEMA_PACKS["ach/account-allowlist"].rules.map((r) => ({
      ...r,
      params: {
        conditions: [
          { field: "account_id", op: "not_in" as const, value: ["acct_approved"] },
        ],
      },
    }));
    const policy: PolicyConfig = { default: "ALLOW", rules };
    const r = evaluatePolicy("ach_transfer", policy, { account_id: "acct_other" });
    expect(r.decision).toBe("BLOCK");
  });
});

// ── SP55–SP66: openclaw/enforce evaluation ──────────────────────────────────

describe("openclaw/enforce evaluation", () => {
  // Populate recipient allowlist with a real address (lowercase) for testing
  const rules = SCHEMA_PACKS["openclaw/enforce"].rules.map((r) => {
    if (
      r.tool === "openclaw.agent.transfer" &&
      r.params?.conditions[0]?.field === "recipient" &&
      r.params?.conditions[0]?.op === "not_in"
    ) {
      return {
        ...r,
        params: {
          conditions: [
            {
              field: "recipient",
              op: "not_in" as const,
              value: ["0x742d35cc6634c0532925a3b844bc454e4438f44e"],
            },
          ],
        },
      };
    }
    return r;
  });
  const policy: PolicyConfig = { default: "ALLOW", rules };

  test("SP55: allowlisted address under threshold → ALLOW", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "50000000000000000", // 0.05 ETH — under step_up threshold
      recipient: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    });
    expect(r.decision).toBe("ALLOW");
  });

  test("SP56: non-allowlisted address → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "50000000000000000",
      recipient: "0xdead000000000000000000000000000000000000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/allowlist/i);
  });

  test("SP57: missing recipient field → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "50000000000000000",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/recipient address missing/);
  });

  test("SP58: over max_amount_wei → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "6000000000000000000", // 6 ETH — over 5 ETH cap
      recipient: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/max_amount_wei/);
  });

  test("SP59: over step_up threshold, allowlisted → STEP_UP", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "200000000000000000", // 0.2 ETH — over 0.1 ETH threshold, under 5 ETH cap
      recipient: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    });
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP60: missing amount_wei → STEP_UP", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      recipient: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount_wei missing or malformed/);
  });

  test("SP61: non-BigInt-parseable amount_wei → STEP_UP", () => {
    const r = evaluatePolicy("openclaw.agent.transfer", policy, {
      amount_wei: "not_a_number",
      recipient: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
    });
    expect(r.decision).toBe("STEP_UP");
    expect(r.decision_reason).toMatch(/amount_wei missing or malformed/);
  });

  test("SP62: swap with excess slippage → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.swap", policy, {
      slippage_bps: 100,
      output_token: "ETH",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/slippage/i);
  });

  test("SP63: swap with missing slippage_bps → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.swap", policy, {
      output_token: "ETH",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/slippage_bps missing/);
  });

  test("SP64: swap with non-allowlisted output_token → BLOCK", () => {
    const r = evaluatePolicy("openclaw.agent.swap", policy, {
      slippage_bps: 10,
      output_token: "SHIB",
    });
    expect(r.decision).toBe("BLOCK");
    expect(r.decision_reason).toMatch(/token not in allowlist/i);
  });

  test("SP65: escrow release without auto_approve → STEP_UP", () => {
    const r = evaluatePolicy("openclaw.agent.checkout.escrow.release", policy, {});
    expect(r.decision).toBe("STEP_UP");
  });

  test("SP66: escrow refund → ALLOW", () => {
    const r = evaluatePolicy("openclaw.agent.checkout.escrow.refund", policy, {});
    expect(r.decision).toBe("ALLOW");
  });
});
