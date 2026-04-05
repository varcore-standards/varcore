/**
 * nonsudo query [options]
 *
 * Queries an NDJSON receipt file with optional filters.
 * Output formats: table (default), json, csv.
 */

import * as fs from "fs";
import { readReceiptsFile } from "../receipts-reader";
import type { SignedReceipt } from "@varcore/receipts";

// ── Formatting ────────────────────────────────────────────────────────────────

function truncate(s: string, len: number): string {
  return s.length > len ? s.slice(0, len) : s;
}

function padRight(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function padLeft(s: string, n: number): string {
  return s.length >= n ? s : " ".repeat(n - s.length) + s;
}

function parseSince(since: string): number {
  const match = since.match(/^(\d+)([mhd])$/);
  if (!match) return NaN;
  const value = parseInt(match[1], 10);
  const unit = match[2];
  switch (unit) {
    case "m": return value * 60 * 1000;
    case "h": return value * 60 * 60 * 1000;
    case "d": return value * 24 * 60 * 60 * 1000;
    default: return NaN;
  }
}

function formatTable(receipts: SignedReceipt[]): string {
  const lines: string[] = [];
  lines.push(
    `  ${padLeft("SEQ", 5)}  ${padRight("TYPE", 22)}  ${padRight("TOOL", 22)}  ${padRight("DECISION", 12)}  ${padRight("ISSUED_AT", 20)}`
  );
  lines.push(
    `  ${padRight("─".repeat(5), 5)}  ${padRight("─".repeat(22), 22)}  ${padRight("─".repeat(22), 22)}  ${padRight("─".repeat(12), 12)}  ${padRight("─".repeat(20), 20)}`
  );
  for (const r of receipts) {
    const rr = r as unknown as Record<string, unknown>;
    const seq = padLeft(String(r.sequence_number), 5);
    const type = padRight(truncate(r.record_type, 22), 22);
    const tool = padRight(
      truncate(r.record_type === "action_receipt" ? ((rr.tool_name as string) ?? "—") : "—", 22),
      22
    );
    const decision = padRight(
      truncate(r.record_type === "action_receipt" ? ((rr.decision as string) ?? "—") : "—", 12),
      12
    );
    const issuedAt = padRight(r.issued_at.slice(0, 19), 20);
    lines.push(`  ${seq}  ${type}  ${tool}  ${decision}  ${issuedAt}`);
  }
  return lines.join("\n");
}

function formatCsv(receipts: SignedReceipt[]): string {
  if (receipts.length === 0) return "";
  const headers = Object.keys(receipts[0]);
  const csvLines = [
    headers.join(","),
    ...receipts.map((r) => {
      const rr = r as unknown as Record<string, unknown>;
      return headers
        .map((h) => {
          const val = rr[h];
          if (val === null || val === undefined) return "";
          const s = typeof val === "object" ? JSON.stringify(val) : String(val);
          return s.includes(",") || s.includes('"') || s.includes("\n")
            ? `"${s.replace(/"/g, '""')}"`
            : s;
        })
        .join(",");
    }),
  ];
  return csvLines.join("\n");
}

// ── Export ───────────────────────────────────────────────────────────────────

export interface QueryOptions {
  file: string;
  workflowId?: string;
  agent?: string;
  tool?: string;
  decision?: string;
  recordType?: string;
  since?: string;
  limit?: number;
  format?: "table" | "json" | "csv";
}

export async function runQuery(options: QueryOptions): Promise<number> {
  if (!options.file) {
    process.stderr.write(
      "Usage: nonsudo query --file <path> [--workflow-id <id>] [--tool <name>]\n" +
      "       [--agent <id>] [--decision <d>] [--record-type <t>]\n" +
      "       [--since <duration>] [--limit <n>] [--format table|json|csv]\n"
    );
    return 1;
  }

  if (!fs.existsSync(options.file)) {
    process.stderr.write(`nonsudo query: file not found: ${options.file}\n`);
    return 1;
  }

  let sinceMs: number | undefined;
  if (options.since) {
    sinceMs = parseSince(options.since);
    if (isNaN(sinceMs)) {
      process.stderr.write(
        `nonsudo query: invalid --since format "${options.since}". Use e.g. 30m, 1h, 24h, 7d\n`
      );
      return 1;
    }
  }

  let receipts: SignedReceipt[];
  try {
    receipts = readReceiptsFile(options.file);
  } catch (err) {
    process.stderr.write(
      `nonsudo query: failed to read file: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return 1;
  }

  const now = Date.now();
  const limit = options.limit ?? 50;
  const fmt = options.format ?? "table";

  let filtered = receipts.filter((r) => {
    const rr = r as unknown as Record<string, unknown>;
    if (options.workflowId && r.workflow_id !== options.workflowId) return false;
    if (options.agent && r.agent_id !== options.agent) return false;
    if (options.tool && (rr.tool_name as string) !== options.tool) return false;
    if (options.decision && (rr.decision as string) !== options.decision) return false;
    if (options.recordType && r.record_type !== options.recordType) return false;
    if (sinceMs !== undefined) {
      const issuedMs = new Date(r.issued_at).getTime();
      if (issuedMs < now - sinceMs) return false;
    }
    return true;
  });

  filtered = filtered.slice(0, limit);

  if (filtered.length === 0) {
    process.stdout.write("(no receipts match filters)\n");
    return 0;
  }

  if (fmt === "json") {
    process.stdout.write(JSON.stringify(filtered, null, 2) + "\n");
    return 0;
  }

  if (fmt === "csv") {
    process.stdout.write(formatCsv(filtered) + "\n");
    return 0;
  }

  process.stdout.write(formatTable(filtered) + "\n");
  return 0;
}
