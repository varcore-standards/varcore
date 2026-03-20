import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as ed from "@noble/ed25519";
import { LangChainAdapter } from "../adapter";
import type { LangChainToolCall, LangChainToolResult } from "../types";
import type { AgentActionResult } from "@varcore/core";
import { NonSudoCallbackHandler } from "../handler";
import { createNonSudoCallbacks } from "../index";

describe("LangChainAdapter", () => {
  let adapter: LangChainAdapter;

  beforeEach(() => {
    adapter = new LangChainAdapter();
  });

  // ── toAction ─────────────────────────────────────────────────────────────

  test("1. toAction maps name → tool_name", () => {
    const call: LangChainToolCall = { name: "search_web", args: { q: "hello" } };
    expect(adapter.toAction(call).tool_name).toBe("search_web");
  });

  test("2. toAction uses object args directly", () => {
    const args = { path: "/tmp/foo", encoding: "utf8" };
    const call: LangChainToolCall = { name: "read_file", args };
    expect(adapter.toAction(call).arguments).toEqual(args);
  });

  test("3. toAction parses JSON string args → object", () => {
    const call: LangChainToolCall = {
      name: "read_file",
      args: '{"path": "/tmp/foo"}',
    };
    expect(adapter.toAction(call).arguments).toEqual({ path: "/tmp/foo" });
  });

  test("4. toAction sets protocol: 'langchain'", () => {
    const call: LangChainToolCall = { name: "my_tool", args: {} };
    expect(adapter.toAction(call).protocol).toBe("langchain");
  });

  test("5. toAction throws SyntaxError on malformed JSON string args", () => {
    const call: LangChainToolCall = {
      name: "my_tool",
      args: "{bad: json}",
    };
    expect(() => adapter.toAction(call)).toThrow(SyntaxError);
  });

  // ── toResponse ───────────────────────────────────────────────────────────

  test("6. toResponse returns { content } on success", () => {
    const result: AgentActionResult = { success: true, content: "result text" };
    const response = adapter.toResponse(result) as LangChainToolResult;
    expect(response.content).toBe("result text");
    expect(response.isError).toBeUndefined();
  });

  test("7. toResponse returns { content: error, isError: true } on failure", () => {
    const result: AgentActionResult = { success: false, error: "BLOCKED" };
    const response = adapter.toResponse(result) as LangChainToolResult;
    expect(response.content).toBe("BLOCKED");
    expect(response.isError).toBe(true);
  });

  // ── NonSudoCallbackHandler ────────────────────────────────────────────────

  describe("NonSudoCallbackHandler", () => {
    let tmpDir: string;
    let keyFile: string;
    let receiptFile: string;

    beforeAll(async () => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonsudo-lc-test-"));
      keyFile = path.join(tmpDir, "test-key.key");
      receiptFile = path.join(tmpDir, "receipts.ndjson");

      // Generate a private key and write it as hex
      const privateKey = ed.utils.randomPrivateKey();
      fs.writeFileSync(keyFile, Buffer.from(privateKey).toString("hex") + "\n");
    });

    afterAll(() => {
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch {
        /* best-effort */
      }
    });

    test("8. NonSudoCallbackHandler has name 'NonSudoCallbackHandler'", () => {
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-lc-1",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: receiptFile,
        key_path: keyFile,
      });
      expect(handler.name).toBe("NonSudoCallbackHandler");
    });

    test("9. handleToolStart + handleToolEnd writes a receipt with response_hash populated", async () => {
      const testReceiptFile = path.join(tmpDir, "receipts-test9.ndjson");
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-lc-2",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: testReceiptFile,
        key_path: keyFile,
      });

      // Phase 1: handleToolStart stages the pending receipt (no disk write yet)
      await handler.handleToolStart(
        { id: ["tools", "my_tool"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"query": "hello world"}',
        "run-id-1",
        undefined,
        undefined,
        undefined,
        "my_tool"
      );

      // Only the workflow_manifest has been written so far
      expect(fs.existsSync(testReceiptFile)).toBe(true);
      const afterStart = fs
        .readFileSync(testReceiptFile, "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0);
      expect(afterStart.length).toBe(1);
      expect((JSON.parse(afterStart[0]) as { record_type: string }).record_type).toBe("workflow_manifest");

      // Phase 2: handleToolEnd finalizes — computes response_hash and writes the action_receipt
      await handler.handleToolEnd(JSON.stringify({ result: "search results" }), "run-id-1");

      const afterEnd = fs
        .readFileSync(testReceiptFile, "utf8")
        .split("\n")
        .filter((l) => l.trim().length > 0);
      expect(afterEnd.length).toBe(2);

      const manifest = JSON.parse(afterEnd[0]) as { record_type: string };
      const actionReceipt = JSON.parse(afterEnd[1]) as { record_type: string; response_hash: string | null };
      expect(manifest.record_type).toBe("workflow_manifest");
      expect(actionReceipt.record_type).toBe("action_receipt");
      expect(actionReceipt.response_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    test("10. createNonSudoCallbacks returns an array with a NonSudoCallbackHandler", () => {
      const callbacks = createNonSudoCallbacks({
        agent_id: "agent-lc-3",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: receiptFile,
        key_path: keyFile,
      });
      expect(Array.isArray(callbacks)).toBe(true);
      expect(callbacks.length).toBe(1);
      expect(callbacks[0]).toBeInstanceOf(NonSudoCallbackHandler);
    });

    // ── BUG-15 regression: _emitQueue serialisation ───────────────────────

    test("11. sequential emits produce a valid chain — distinct prev_receipt_hash values", async () => {
      const seqReceiptFile = path.join(tmpDir, "receipts-seq.ndjson");
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-seq",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: seqReceiptFile,
        key_path: keyFile,
      });

      // Two sequential tool calls
      await handler.handleToolStart(
        { id: ["tools", "tool_a"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"x":1}', "run-seq-1", undefined, undefined, undefined, "tool_a"
      );
      await handler.handleToolEnd('{"ok":true}', "run-seq-1");

      await handler.handleToolStart(
        { id: ["tools", "tool_b"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"x":2}', "run-seq-2", undefined, undefined, undefined, "tool_b"
      );
      await handler.handleToolEnd('{"ok":true}', "run-seq-2");

      await handler.close();

      const lines = fs.readFileSync(seqReceiptFile, "utf8").split("\n").filter((l) => l.trim().length > 0);
      // manifest + 2 action receipts
      expect(lines.length).toBe(3);

      const receipts = lines.map((l) => JSON.parse(l) as { prev_receipt_hash: string | null; sequence_number: number });
      // All prev_receipt_hash values are distinct (no fork)
      const hashes = receipts.map((r) => r.prev_receipt_hash);
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(hashes.length);
      // Sequence numbers are 0, 1, 2
      expect(receipts.map((r) => r.sequence_number)).toEqual([0, 1, 2]);
    });

    test("12. concurrent emits do not fork the chain — all prev_receipt_hash values are distinct", async () => {
      const concReceiptFile = path.join(tmpDir, "receipts-conc.ndjson");
      const handler = new NonSudoCallbackHandler({
        agent_id: "agent-conc",
        workflow_owner: "owner-1",
        initiator_id: "init-1",
        receipt_file: concReceiptFile,
        key_path: keyFile,
      });

      // Stage three pending actions
      await handler.handleToolStart(
        { id: ["tools", "t1"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"a":1}', "run-c1", undefined, undefined, undefined, "t1"
      );
      await handler.handleToolStart(
        { id: ["tools", "t2"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"a":2}', "run-c2", undefined, undefined, undefined, "t2"
      );
      await handler.handleToolStart(
        { id: ["tools", "t3"], lc: 1, type: "constructor" } as Parameters<typeof handler.handleToolStart>[0],
        '{"a":3}', "run-c3", undefined, undefined, undefined, "t3"
      );

      // Finalize all three concurrently — this is the BUG-15 scenario
      await Promise.all([
        handler.handleToolEnd('{"r":1}', "run-c1"),
        handler.handleToolEnd('{"r":2}', "run-c2"),
        handler.handleToolEnd('{"r":3}', "run-c3"),
      ]);

      await handler.close();

      const lines = fs.readFileSync(concReceiptFile, "utf8").split("\n").filter((l) => l.trim().length > 0);
      // manifest + 3 action receipts
      expect(lines.length).toBe(4);

      const receipts = lines.map((l) => JSON.parse(l) as { prev_receipt_hash: string | null; sequence_number: number });
      // All prev_receipt_hash values must be distinct — no two receipts share the same hash
      const hashes = receipts.map((r) => r.prev_receipt_hash);
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).toBe(hashes.length);
      // Sequence numbers must be 0, 1, 2, 3 (no gaps, no duplicates)
      expect(receipts.map((r) => r.sequence_number)).toEqual([0, 1, 2, 3]);
    });
  });
});
