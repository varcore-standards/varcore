/**
 * WorkflowSession — manages the receipt chain for one NonSudo workflow.
 *
 * Created lazily by NonSudoCallbackHandler on the first tool call.
 * Writes a workflow_manifest on init, then chains action_receipt / dead_letter_receipt
 * for each subsequent tool invocation.
 *
 * Receipt write lifecycle (Phase 1):
 *   handleToolStart → pendActionReceipt (stores in _pendingActions, no disk write)
 *   handleToolEnd   → finalizeActionReceipt (computes response_hash, signs, writes)
 *   handleToolError → takePendingAction + emitDeadLetter (writes with response_hash: null)
 *
 * TODO(refactor): receipt-creation logic duplicates adapter-openai/src/receipt.ts.
 * Extract to a shared helper once a cross-adapter package is introduced.
 */

import * as fs from "fs";
import * as path from "path";
import { ulid } from "ulid";
import { canonicalHash, computeContentEntropyHash, varcoreLog } from "@varcore/core";
import { createReceipt, signReceipt, chainReceipt } from "@varcore/receipts";
import type {
  SignedReceipt,
  ReceiptFields,
  Decision,
  BlastRadius,
  FallbackPolicy,
} from "@varcore/receipts";
import type { LangChainAdapterConfig } from "./types";
import { SimpleReceiptWriter } from "./writer";

interface PendingAction {
  toolName: string;
  args: Record<string, unknown>;
  decision: Decision;
  decisionReason: string;
  blastRadius: BlastRadius;
  reversible: boolean;
}

function nowRfc3339(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

const PKG = "varcore/adapter-langchain";

/**
 * WorkflowSession manages receipt chain state for a
 * single LangChain agent session.
 *
 * Concurrency: emitActionReceipt and emitDeadLetter
 * share a single _emitQueue that serialises all chain
 * writes. Concurrent handleToolEnd calls (common in
 * parallel LangChain tool execution) are queued and
 * executed sequentially to preserve L2 chain integrity.
 * Without serialisation, parallel calls would read the
 * same prevReceipt and produce a forked chain that fails
 * L2 verification.
 */
export class WorkflowSession {
  private workflowId: string;
  private prevReceipt: SignedReceipt;
  private writer: SimpleReceiptWriter;
  private keypair: { privateKey: Uint8Array; keyId: string };
  private agentId: string;
  private policyBundleHash: string;
  private _pendingActions: Map<string, PendingAction> = new Map();
  private _emitQueue: Promise<void> = Promise.resolve();

  /** Structured log entry with workflow_id included for L2 correlation. */
  private log(level: Parameters<typeof varcoreLog>[0], msg: string, extra?: Record<string, unknown>): void {
    varcoreLog(level, PKG, msg, { workflow_id: this.workflowId, ...extra });
  }

  private constructor(
    workflowId: string,
    prevReceipt: SignedReceipt,
    writer: SimpleReceiptWriter,
    keypair: { privateKey: Uint8Array; keyId: string },
    agentId: string,
    policyBundleHash: string
  ) {
    this.workflowId = workflowId;
    this.prevReceipt = prevReceipt;
    this.writer = writer;
    this.keypair = keypair;
    this.agentId = agentId;
    this.policyBundleHash = policyBundleHash;
  }

  static async create(config: LangChainAdapterConfig): Promise<WorkflowSession> {
    // Load private key from key_path (hex-encoded, one line).
    // Validate format before use — Buffer.from(hex) silently skips non-hex
    // characters, producing a wrong-length key that generates garbage signatures.
    const privHex = fs.readFileSync(config.key_path, "utf8").trim();
    if (!/^[0-9a-fA-F]{64}$/.test(privHex)) {
      throw new Error(
        `Invalid Ed25519 private key in ${config.key_path}: ` +
        `expected 64 hex characters, got ${privHex.length}. ` +
        `Ensure the file contains a raw hex-encoded key, not a PEM-encoded key.`
      );
    }
    const privateKey = new Uint8Array(Buffer.from(privHex, "hex"));
    // Derive keyId from filename (e.g. "01ABC.key" → "01ABC")
    const keyId = path.basename(config.key_path, ".key");

    const workflowId = ulid();
    const policyBundleHash = config.policy_bundle_hash ?? "sha256:" + "0".repeat(64);
    const writer = new SimpleReceiptWriter(config.receipt_file);

    // Write workflow_manifest (sequence_number = 0, prev_receipt_hash = null)
    const manifestFields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "workflow_manifest",
      spec_version: "var/1.0",
      workflow_id: workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: config.agent_id,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      initiator_id: config.initiator_id,
      workflow_owner: config.workflow_owner,
      session_budget: config.session_budget ?? { api_calls: 1000 },
      declared_tools: [],
      capability_manifest_hash: null,
      parent_workflow_id: null,
      framework_ref: null,
    };

    const unsigned = createReceipt(manifestFields);
    const signed = await signReceipt(unsigned, privateKey, keyId);
    writer.append(signed);

    varcoreLog("debug", PKG, "WorkflowSession.create: workflow_manifest written", {
      workflow_id: workflowId,
      agent_id: config.agent_id,
    });

    return new WorkflowSession(
      workflowId,
      signed,
      writer,
      { privateKey, keyId },
      config.agent_id,
      policyBundleHash
    );
  }

  /** Stage a pending action receipt for this runId. No disk write occurs until finalizeActionReceipt(). */
  pendActionReceipt(
    runId: string,
    toolName: string,
    args: Record<string, unknown>,
    decision: Decision = "ALLOW",
    decisionReason: string = "langchain tool call",
    blastRadius: BlastRadius = "LOW",
    reversible: boolean = true
  ): void {
    this._pendingActions.set(runId, { toolName, args, decision, decisionReason, blastRadius, reversible });
  }

  /** Remove and return the pending action for runId, or undefined if none. */
  takePendingAction(runId: string): PendingAction | undefined {
    const pending = this._pendingActions.get(runId);
    this._pendingActions.delete(runId);
    return pending;
  }

  /**
   * Finalize a pending action receipt: compute response_hash from output (null if no response),
   * sign, and write. Returns null if no pending action exists for runId.
   */
  async finalizeActionReceipt(runId: string, output: string | null): Promise<SignedReceipt | null> {
    const pending = this.takePendingAction(runId);
    if (!pending) {
      this.log("warn", "finalizeActionReceipt: no pending action for run_id — receipt skipped", {
        run_id: runId,
      });
      return null;
    }
    const responseHash = output !== null ? computeContentEntropyHash(output) : null;
    const receipt = await this.emitActionReceipt(
      pending.toolName,
      pending.args,
      pending.decision,
      pending.decisionReason,
      pending.blastRadius,
      pending.reversible,
      responseHash
    );
    this.log("debug", "finalizeActionReceipt: action_receipt written", {
      run_id: runId,
      tool_name: pending.toolName,
      decision: pending.decision,
    });
    return receipt;
  }

  emitActionReceipt(
    ...args: Parameters<WorkflowSession["_doEmitActionReceipt"]>
  ): Promise<SignedReceipt> {
    const work = this._emitQueue.then(
      () => this._doEmitActionReceipt(...args),
      () => this._doEmitActionReceipt(...args)
    );
    this._emitQueue = work.then(() => {}, () => {});
    return work;
  }

  private async _doEmitActionReceipt(
    toolName: string,
    args: Record<string, unknown>,
    decision: Decision = "ALLOW",
    decisionReason: string = "langchain tool call",
    blastRadius: BlastRadius = "LOW",
    reversible: boolean = true,
    responseHash: string | null = null
  ): Promise<SignedReceipt> {
    const stateVersionBefore = this.prevReceipt.sequence_number;
    const stateVersionAfter =
      decision === "ALLOW" || decision === "FAIL_OPEN"
        ? stateVersionBefore + 1
        : stateVersionBefore;

    const fields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: this.workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: this.agentId,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: this.policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: toolName,
      params_canonical_hash: canonicalHash(args),
      decision,
      decision_reason: decisionReason,
      decision_order: 1,
      queue_status: "COMPLETED",
      queue_timeout_ms: 5000,
      blast_radius: blastRadius,
      reversible,
      state_version_before: stateVersionBefore,
      state_version_after: stateVersionAfter,
      response_hash: responseHash,
    };

    const unsigned = createReceipt(fields);
    const chained = chainReceipt(unsigned, this.prevReceipt);
    const signed = await signReceipt(chained, this.keypair.privateKey, this.keypair.keyId);
    this.writer.append(signed);
    this.prevReceipt = signed;
    return signed;
  }

  emitDeadLetter(
    ...args: Parameters<WorkflowSession["_doEmitDeadLetter"]>
  ): Promise<SignedReceipt> {
    const work = this._emitQueue.then(
      () => this._doEmitDeadLetter(...args),
      () => this._doEmitDeadLetter(...args)
    );
    this._emitQueue = work.then(() => {}, () => {});
    return work;
  }

  private async _doEmitDeadLetter(
    toolName: string,
    args: Record<string, unknown>,
    failureReason: string,
    fallbackPolicy: FallbackPolicy = "fail_closed"
  ): Promise<SignedReceipt> {
    const stateVersionBefore = this.prevReceipt.sequence_number;

    const fields: ReceiptFields = {
      receipt_id: ulid(),
      record_type: "action_receipt",
      spec_version: "var/1.0",
      workflow_id: this.workflowId,
      workflow_id_source: "nonsudo_generated",
      agent_id: this.agentId,
      issued_at: nowRfc3339(),
      prev_receipt_hash: null,
      sequence_number: 0,
      policy_bundle_hash: this.policyBundleHash,
      rfc3161_token: null,
      tsa_id: null,
      tool_name: toolName,
      params_canonical_hash: canonicalHash(args),
      decision: "FAIL_CLOSED",
      decision_reason: failureReason,
      decision_order: 1,
      queue_status: "DEAD_LETTER",
      queue_timeout_ms: 5000,
      blast_radius: "CRITICAL",
      reversible: false,
      state_version_before: stateVersionBefore,
      state_version_after: stateVersionBefore,
      response_hash: null,
      failure_reason: failureReason,
      fallback_policy: fallbackPolicy,
    };

    const unsigned = createReceipt(fields);
    const chained = chainReceipt(unsigned, this.prevReceipt);
    const signed = await signReceipt(chained, this.keypair.privateKey, this.keypair.keyId);
    this.writer.append(signed);
    this.prevReceipt = signed;
    this.log("debug", "emitDeadLetter: dead_letter receipt written", {
      tool_name: toolName,
      failure_reason: failureReason,
    });
    return signed;
  }

  async close(): Promise<void> {
    await this._emitQueue;
    this.writer.close();
  }
}
