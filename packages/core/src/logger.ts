/**
 * varcoreLog — structured JSON logger for all @varcore/* packages.
 *
 * Emits one JSON line per call to process.stderr.
 * Never throws — logging failures are silently swallowed.
 *
 * Log entry shape:
 *   { ts, level, pkg, msg, ...extra }
 *
 * L2: callers should pass `run_id` and/or `workflow_id` in `extra` wherever
 * those values are available, so that all log entries for a single tool call
 * can be correlated by consumers.
 *
 * Usage:
 *   varcoreLog("warn", "varcore/receipts", "skipping malformed line", { file: path });
 *   varcoreLog("error", "varcore/adapter-langchain", "session init failed", { error: msg, run_id: runId });
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface VarcoreLogEntry {
  ts: string;
  level: LogLevel;
  pkg: string;
  msg: string;
  [key: string]: unknown;
}

export function varcoreLog(
  level: LogLevel,
  pkg: string,
  msg: string,
  extra?: Record<string, unknown>
): void {
  const entry: VarcoreLogEntry = {
    ts: new Date().toISOString(),
    level,
    pkg,
    msg,
    ...extra,
  };
  try {
    process.stderr.write(JSON.stringify(entry) + "\n");
  } catch {
    // Never throw from logging — swallow silently
  }
}
