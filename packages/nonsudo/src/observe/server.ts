import express, { Request, Response } from "express";
import { ObserveConfig } from "./config";
import { ObserveWriter, ObserveLogEntry, sha256Hex, BlastRadiusLevel } from "./writer";
import { DASHBOARD_HTML } from "./dashboard";

interface SSEClient {
  res: Response;
}

const BLAST_COLORS: Record<string, string> = {
  CRITICAL: "\x1b[31m",
  HIGH: "\x1b[33m",
  MED: "\x1b[34m",
  LOW: "\x1b[90m",
  UNKNOWN: "\x1b[90m",
};
const RESET = "\x1b[0m";

export function createObserveServer(
  config: ObserveConfig,
  writer: ObserveWriter,
  workflowId: string,
): express.Express {
  const app = express();
  const sseClients: SSEClient[] = [];
  const startTime = Date.now();
  let totalCalls = 0;

  app.use(express.json({ limit: "10mb" }));

  // CORS middleware
  if (config.cors) {
    app.use((_req: Request, res: Response, next) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      if (_req.method === "OPTIONS") {
        res.status(204).end();
        return;
      }
      next();
    });
  }

  // GET / — dashboard or info
  app.get("/", (_req: Request, res: Response) => {
    if (config.dashboard) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(DASHBOARD_HTML);
    } else {
      res.json({ message: "Dashboard disabled." });
    }
  });

  // GET /health
  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      mode: "observe",
      uptime_s: Math.floor((Date.now() - startTime) / 1000),
      calls: totalCalls,
      workflow_id: workflowId,
    });
  });

  // GET /events — SSE
  app.get("/events", (_req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const client: SSEClient = { res };
    sseClients.push(client);

    _req.on("close", () => {
      const idx = sseClients.indexOf(client);
      if (idx !== -1) sseClients.splice(idx, 1);
    });
  });

  function emitSSE(entry: ObserveLogEntry): void {
    const data = `data: ${JSON.stringify(entry)}\n\n`;
    for (const client of sseClients) {
      client.res.write(data);
    }
  }

  function printTerminalLine(entry: ObserveLogEntry): void {
    const t = new Date(entry.issued_at);
    const time = t.toLocaleTimeString("en-US", { hour12: false });
    const tool = entry.tool_name.padEnd(30);
    const blast = entry.blast_radius.padEnd(10);
    const color = BLAST_COLORS[entry.blast_radius] ?? RESET;
    process.stdout.write(`${time}  ${tool}  ${color}${blast}${RESET}  ${entry.latency_ms}ms\n`);
  }

  // POST / and POST /mcp — proxy handler
  async function handleProxy(req: Request, res: Response): Promise<void> {
    const body = req.body as Record<string, unknown>;

    // Extract tool name from JSON-RPC body
    const params = body.params as Record<string, unknown> | undefined;
    const toolName = (params?.name as string) ?? (body.method as string) ?? "unknown";

    // Compute params hash
    const paramsHash = "sha256:" + sha256Hex(JSON.stringify(params ?? {}));

    // Derive blast_radius — try policy evaluation, fall back to UNKNOWN
    let blastRadius: BlastRadiusLevel = "UNKNOWN";
    try {
      const { evaluatePolicy, loadPolicy } = await import("@varcore/policy");
      // Only attempt if we have a policy file
      const fs = await import("fs");
      const policyPath = "nonsudo.yaml";
      if (fs.existsSync(policyPath)) {
        const policy = loadPolicy(policyPath);
        const result = evaluatePolicy(toolName, policy);
        blastRadius = result.blast_radius as BlastRadiusLevel;
      }
    } catch {
      // Policy evaluation not available or failed — use UNKNOWN
    }

    const t0 = Date.now();

    try {
      const upstreamRes = await fetch(config.upstream_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const latencyMs = Date.now() - t0;
      const responseBody = await upstreamRes.text();

      // Compute response hash
      const responseHash = "sha256:" + sha256Hex(responseBody);

      totalCalls++;

      const entry: ObserveLogEntry = {
        type: "observe_log",
        spec_version: "nonsudo/observe-1",
        issued_at: new Date().toISOString(),
        workflow_id: workflowId,
        sequence: writer.nextSequence(),
        agent_id: config.agent_id,
        tool_name: toolName,
        params_canonical_hash: paramsHash,
        response_hash: responseHash,
        latency_ms: latencyMs,
        blast_radius: blastRadius,
      };

      writer.write(entry);
      emitSSE(entry);
      printTerminalLine(entry);

      // Forward upstream response
      res.status(upstreamRes.status);
      res.setHeader("Content-Type", upstreamRes.headers.get("content-type") ?? "application/json");
      res.send(responseBody);
    } catch (err) {
      const latencyMs = Date.now() - t0;
      totalCalls++;

      const errMsg = err instanceof Error ? err.message : String(err);

      const entry: ObserveLogEntry = {
        type: "observe_log",
        spec_version: "nonsudo/observe-1",
        issued_at: new Date().toISOString(),
        workflow_id: workflowId,
        sequence: writer.nextSequence(),
        agent_id: config.agent_id,
        tool_name: toolName,
        params_canonical_hash: paramsHash,
        response_hash: "sha256:" + sha256Hex(JSON.stringify({ error: errMsg })),
        latency_ms: latencyMs,
        blast_radius: blastRadius,
      };

      writer.write(entry);
      emitSSE(entry);
      printTerminalLine(entry);

      res.status(502).json({ error: `Upstream error: ${errMsg}` });
    }
  }

  app.post("/", handleProxy);
  app.post("/mcp", handleProxy);

  return app;
}
