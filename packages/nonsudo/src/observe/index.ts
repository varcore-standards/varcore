import { ulid } from "ulid";
import { ObserveConfig, loadObserveConfig } from "./config";
import { ensureKeypair } from "./keypair";
import { ObserveWriter } from "./writer";
import { createObserveServer } from "./server";
import type { Server } from "http";

export { loadObserveConfig } from "./config";
export type { ObserveConfig } from "./config";

export async function startObserveProxy(config: ObserveConfig): Promise<void> {
  const keypair = ensureKeypair(config.key_path);
  const workflowId = ulid();
  const writer = new ObserveWriter(config.log_dir, workflowId);
  const app = createObserveServer(config, writer, workflowId);

  // Read version from package.json
  let version = "0.0.0";
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const pkg = require("../../package.json") as { version: string };
    version = pkg.version;
  } catch {
    // fallback
  }

  const server: Server = app.listen(config.port, () => {
    console.log(`nonsudo v${version} \u2014 observe mode`);
    console.log(`Listening on  :${config.port}`);
    console.log(`Upstream      ${config.upstream_url}`);
    console.log(`Logs          ${writer.logPath}`);
    if (config.dashboard) {
      console.log(`Dashboard     http://localhost:${config.port}`);
    }
    console.log(`Key           ${keypair.keyId}`);
    console.log(`Workflow      ${workflowId}`);
    console.log("");
  });

  function shutdown(): void {
    console.log("\nShutting down...");
    server.close(() => {
      process.exit(0);
    });
    // Force exit after 5s if server doesn't close cleanly
    setTimeout(() => process.exit(0), 5000).unref();
  }

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
