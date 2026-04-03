import { createReceipt, signReceipt, verifySignature } from "../index";
import type { AgentClassRegistration } from "../index";
import { ReceiptFields, SignedReceipt } from "../types";
import type { WorkflowManifestFields, ActionReceiptFields } from "../types";
import * as ed from "@noble/ed25519";

// Mandate continuity field overrides for testing
const MANDATE_FIELDS = {
  agent_class_id: "cls_abcdef1234567890abcdef1234567890",
  mandate_id: "mandate-payments-v1",
  mandate_version: "v1.0.0",
  chain_sequence: 0,
};

function makeActionFields(overrides: Partial<ReceiptFields> = {}): ReceiptFields {
  return {
    receipt_id: "01HXYZ000000000000000002",
    record_type: "action_receipt",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    workflow_id_source: "nonsudo_generated",
    agent_id: "agent-abc123",
    issued_at: "2026-02-28T10:00:01Z",
    prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    sequence_number: 1,
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    rfc3161_token: null,
    tsa_id: null,
    tool_name: "bash",
    params_canonical_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    decision: "ALLOW",
    decision_reason: "Policy allows this tool",
    decision_order: 1,
    queue_status: "COMPLETED",
    queue_timeout_ms: 5000,
    blast_radius: "LOW",
    reversible: true,
    state_version_before: 1,
    state_version_after: 2,
    response_hash: null,
    ...overrides,
  } as ReceiptFields;
}

function makeBudgetWarningFields(overrides: Record<string, unknown> = {}): ReceiptFields {
  return {
    budget_warning_id: "01HXYZ000000000000000010",
    record_type: "budget_warning",
    spec_version: "var/1.0",
    workflow_id: "01HXYZ000000000000000000",
    agent_id: "agent-abc123",
    sequence_number: 3,
    prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    tool_name: "stripe.createCharge",
    spent: 9000,
    reserved: 500,
    cap: 10000,
    threshold_pct: 90,
    issued_at: "2026-02-28T10:02:00Z",
    rfc3161_token: null,
    tsa_id: null,
    ...overrides,
  } as ReceiptFields;
}

describe("Mandate continuity fields — action_receipt (base type)", () => {
  test("action_receipt with mandate fields signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBe(MANDATE_FIELDS.agent_class_id);
    expect(signed.mandate_id).toBe(MANDATE_FIELDS.mandate_id);
    expect(signed.mandate_version).toBe(MANDATE_FIELDS.mandate_version);
    expect(signed.chain_sequence).toBe(MANDATE_FIELDS.chain_sequence);

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });

  test("tampering agent_class_id invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, agent_class_id: "cls_00000000000000000000000000000000" } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("tampering mandate_id invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, mandate_id: "mandate-evil" } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("action_receipt without mandate fields still signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeActionFields());
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBeUndefined();
    expect(signed.mandate_id).toBeUndefined();

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });
});

describe("Mandate continuity fields — budget_warning (non-base type)", () => {
  test("budget_warning with mandate fields signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBe(MANDATE_FIELDS.agent_class_id);
    expect(signed.mandate_id).toBe(MANDATE_FIELDS.mandate_id);
    expect(signed.mandate_version).toBe(MANDATE_FIELDS.mandate_version);
    expect(signed.chain_sequence).toBe(MANDATE_FIELDS.chain_sequence);

    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });

  test("tampering chain_sequence on budget_warning invalidates signature", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields(MANDATE_FIELDS));
    const signed = await signReceipt(unsigned, privKey);

    const tampered = { ...signed, chain_sequence: 999 } as SignedReceipt;
    const result = await verifySignature(tampered, pubKey);
    expect(result.valid).toBe(false);
  });

  test("budget_warning without mandate fields still signs and verifies", async () => {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = await ed.getPublicKeyAsync(privKey);

    const unsigned = createReceipt(makeBudgetWarningFields());
    const signed = await signReceipt(unsigned, privKey);

    expect(signed.agent_class_id).toBeUndefined();
    const result = await verifySignature(signed, pubKey);
    expect(result.valid).toBe(true);
  });
});

describe("Mandate continuity fields — type-level checks", () => {
  test("ActionReceiptFields with chain_sequence: 42 is valid", () => {
    const fields: ActionReceiptFields = {
      receipt_id: "01HXYZ000000000000000002",
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: "01HXYZ000000000000000000",
      workflow_id_source: "nonsudo_generated",
      agent_id: "agent-abc123",
      issued_at: "2026-02-28T10:00:01Z",
      prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      sequence_number: 1,
      policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      rfc3161_token: null,
      tsa_id: null,
      tool_name: "bash",
      params_canonical_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      decision: "ALLOW",
      decision_reason: "Policy allows",
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: "LOW",
      reversible: true,
      state_version_before: 1,
      state_version_after: 2,
      response_hash: null,
      chain_sequence: 42,
    };
    expect(fields.chain_sequence).toBe(42);
  });

  test("ActionReceiptFields without chain_sequence is valid (backward compat)", () => {
    const fields: ActionReceiptFields = {
      receipt_id: "01HXYZ000000000000000002",
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: "01HXYZ000000000000000000",
      workflow_id_source: "nonsudo_generated",
      agent_id: "agent-abc123",
      issued_at: "2026-02-28T10:00:01Z",
      prev_receipt_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      sequence_number: 1,
      policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      rfc3161_token: null,
      tsa_id: null,
      tool_name: "bash",
      params_canonical_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      decision: "ALLOW",
      decision_reason: "Policy allows",
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: "LOW",
      reversible: true,
      state_version_before: 1,
      state_version_after: 2,
      response_hash: null,
    };
    expect(fields.chain_sequence).toBeUndefined();
  });

  test("WorkflowManifestFields with agent_class_id, mandate_id, mandate_version is valid", () => {
    const fields: WorkflowManifestFields = {
      receipt_id: "01HXYZ000000000000000001",
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: "01HXYZ000000000000000000",
      workflow_id_source: "nonsudo_generated",
      agent_id: "agent-abc123",
      issued_at: "2026-02-28T10:00:00Z",
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: "user-1",
      workflow_owner: "org-1",
      session_budget: {},
      declared_tools: ["bash"],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
      agent_class_id: "cls_a3f8c2d1e4b7f9a2c1d3e5f7a9b2c4d6",
      mandate_id: "mandate-payments-v1",
      mandate_version: "v1.0.0",
    };
    expect(fields.agent_class_id).toBe("cls_a3f8c2d1e4b7f9a2c1d3e5f7a9b2c4d6");
    expect(fields.mandate_id).toBe("mandate-payments-v1");
    expect(fields.mandate_version).toBe("v1.0.0");
  });

  test("AgentClassRegistration can be constructed with all required fields", () => {
    const reg: AgentClassRegistration = {
      agent_class_id: "cls_a3f8c2d1e4b7f9a2c1d3e5f7a9b2c4d6",
      model_id: "claude-sonnet-4-6",
      system_prompt_hash: "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      tools_manifest_hash: "sha256:def456abc123def456abc123def456abc123def456abc123def456abc123def4",
      mandate_id: "mandate-payments-v1",
      mandate_version: "v1.0.0",
      genesis_receipt_id: "01HXYZ000000000000000001",
      registered_at: "2026-02-28T10:00:00Z",
      chain_sequence_head: 0,
    };
    expect(reg.agent_class_id).toBe("cls_a3f8c2d1e4b7f9a2c1d3e5f7a9b2c4d6");
    expect(reg.chain_sequence_head).toBe(0);
    expect(reg.genesis_receipt_id).toBe("01HXYZ000000000000000001");
  });

  test("AgentClassRegistration is importable from package root", () => {
    // This test validates the import at the top of this file:
    //   import type { AgentClassRegistration } from "../index";
    // If the type were not exported, this file would fail to compile.
    const reg: AgentClassRegistration = {
      agent_class_id: "cls_00000000000000000000000000000000",
      model_id: "test-model",
      system_prompt_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      tools_manifest_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      mandate_id: "test-mandate",
      mandate_version: "v0.0.1",
      genesis_receipt_id: "01TEST00000000000000000000",
      registered_at: "2026-01-01T00:00:00Z",
      chain_sequence_head: 100,
    };
    expect(reg).toBeDefined();
  });
});
