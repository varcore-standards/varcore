import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

export type BlastRadiusLevel = "LOW" | "MED" | "HIGH" | "CRITICAL" | "UNKNOWN";

export interface ObserveLogEntry {
  type: "observe_log";
  spec_version: "nonsudo/observe-1";
  issued_at: string;
  workflow_id: string;
  sequence: number;
  agent_id: string;
  tool_name: string;
  params_canonical_hash: string;
  response_hash: string;
  latency_ms: number;
  blast_radius: BlastRadiusLevel;
}

export function sha256Hex(data: string): string {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

export class ObserveWriter {
  private readonly filePath: string;
  private sequence = 0;

  constructor(logDir: string, workflowId: string) {
    fs.mkdirSync(logDir, { recursive: true });
    this.filePath = path.join(logDir, `${workflowId}.observe.ndjson`);
  }

  write(entry: ObserveLogEntry): void {
    fs.appendFileSync(this.filePath, JSON.stringify(entry) + "\n");
  }

  nextSequence(): number {
    return ++this.sequence;
  }

  get logPath(): string {
    return this.filePath;
  }
}
