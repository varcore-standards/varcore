import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { Serialized } from "@langchain/core/load/serializable";
import type { LangChainAdapterConfig } from "./types";
import { WorkflowSession } from "./session";
import { varcoreLog } from "@varcore/core";

const PKG = "varcore/adapter-langchain";

/**
 * NonSudoCallbackHandler — LangChain callback handler that emits VAR receipts
 * for every tool invocation.
 *
 * Usage:
 *   const handler = new NonSudoCallbackHandler(config);
 *   const llm = new ChatOpenAI({ callbacks: [handler] });
 *
 * Receipt file is written to config.receipt_file. The workflow manifest
 * is written lazily on the first tool call (async init via getSession()).
 *
 * Receipt write lifecycle:
 *   - handleToolStart → pendActionReceipt (no disk write; stores pending by runId)
 *     or dead_letter_receipt immediately if args cannot be parsed as JSON
 *   - handleToolEnd  → finalizeActionReceipt (computes response_hash, signs, writes)
 *   - handleToolError → dead_letter_receipt using pending tool name if available
 *
 * L2: All log entries include run_id wherever available so that log aggregators
 * can correlate all events for a single LangChain tool invocation.
 */
export class NonSudoCallbackHandler extends BaseCallbackHandler {
  name = "NonSudoCallbackHandler";

  private config: LangChainAdapterConfig;
  private _session: WorkflowSession | null = null;
  private _sessionInit: Promise<WorkflowSession> | null = null;

  constructor(config: LangChainAdapterConfig) {
    super();
    if (!config.agent_id) {
      throw new Error("LangChainAdapterConfig: agent_id is required");
    }
    this.config = config;
  }

  private getSession(): Promise<WorkflowSession> {
    if (this._session) return Promise.resolve(this._session);
    if (!this._sessionInit) {
      this._sessionInit = WorkflowSession.create(this.config)
        .then((s) => {
          this._session = s;
          return s;
        })
        .catch((err: unknown) => {
          // Reset so the next tool call re-attempts session creation rather
          // than re-throwing the same stale rejected promise forever.
          this._sessionInit = null;
          varcoreLog("error", PKG, "WorkflowSession.create failed", {
            error: String(err),
          });
          throw err;
        });
    }
    return this._sessionInit;
  }

  override async handleToolStart(
    tool: Serialized,
    input: string,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    name?: string
  ): Promise<void> {
    // Resolve tool name: prefer the explicit name param, then tool.id last element
    const toolName =
      name ??
      ((tool as { id?: string[] }).id?.at(-1)) ??
      "unknown";

    const session = await this.getSession();

    let args: Record<string, unknown>;
    try {
      args = JSON.parse(input) as Record<string, unknown>;
    } catch {
      // Malformed arguments → emit dead_letter_receipt instead of throwing
      varcoreLog("warn", PKG, "handleToolStart: failed to parse tool arguments — emitting dead_letter", {
        run_id: _runId,
        tool_name: toolName,
        input_preview: input.slice(0, 120),
      });
      await session.emitDeadLetter(
        toolName,
        {},
        "Failed to parse tool arguments: " + input,
        "fail_closed"
      );
      return;
    }

    varcoreLog("debug", PKG, "handleToolStart: pending action receipt", {
      run_id: _runId,
      tool_name: toolName,
    });

    session.pendActionReceipt(
      _runId,
      toolName,
      args,
      "ALLOW",
      "langchain tool call",
      "LOW",
      true
    );
  }

  override async handleToolEnd(
    _output: string,
    _runId: string
  ): Promise<void> {
    varcoreLog("debug", PKG, "handleToolEnd: finalizing action receipt", {
      run_id: _runId,
    });
    const session = await this.getSession();
    await session.finalizeActionReceipt(_runId, _output);
  }

  async close(): Promise<void> {
    if (this._session) {
      await this._session.close();
    }
  }

  override async handleToolError(
    err: Error | unknown,
    _runId: string
  ): Promise<void> {
    const session = await this.getSession();
    const message = err instanceof Error ? err.message : String(err);
    // Use pending tool name/args if available; fall back to unknown.
    const pending = session.takePendingAction(_runId);
    varcoreLog("warn", PKG, "handleToolError: emitting dead_letter receipt", {
      run_id: _runId,
      tool_name: pending?.toolName ?? "unknown",
      error: message,
    });
    await session.emitDeadLetter(
      pending?.toolName ?? "unknown",
      pending?.args ?? {},
      message,
      "fail_closed"
    );
  }
}
