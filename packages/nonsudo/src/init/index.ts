import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ensureKeypair } from "../observe/keypair";

interface InitResult {
  keyPath: string;
  publicKeyHex: string;
  configWritten: boolean;
  configPath: string;
  cursorPatched: boolean;
  claudePatched: boolean;
}

function resolveHome(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

function resolveBinPath(): string {
  // Resolve the nonsudo CLI entrypoint from the package's bin layout
  const pkgJsonPath = path.resolve(__dirname, "../../package.json");
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8")) as {
      bin?: Record<string, string>;
    };
    if (pkg.bin?.nonsudo) {
      return path.resolve(path.dirname(pkgJsonPath), pkg.bin.nonsudo);
    }
  } catch {
    // fallback
  }
  return path.resolve(__dirname, "../../bin/nonsudo.js");
}

function writeConfigIfAbsent(configPath: string): boolean {
  if (fs.existsSync(configPath)) {
    return false;
  }

  const initiatorId = process.env.USER ?? "developer";

  const yaml = [
    'version: "1.0"',
    "mode: observe",
    "",
    "proxy:",
    "  upstream_url: http://localhost:3001",
    "  port: 3100",
    "",
    "workflow:",
    "  agent_id: my-agent",
    `  initiator_id: ${initiatorId}`,
    "",
    "# To upgrade to enforce mode: https://nonsudo.com/pricing",
    "",
  ].join("\n");

  fs.writeFileSync(configPath, yaml);
  return true;
}

function patchIdeConfig(configFilePath: string, binPath: string): boolean {
  try {
    if (!fs.existsSync(configFilePath)) {
      return false;
    }

    const raw = fs.readFileSync(configFilePath, "utf8");
    const config = JSON.parse(raw) as Record<string, unknown>;

    if (!config.mcpServers) {
      config.mcpServers = {};
    }

    const servers = config.mcpServers as Record<string, unknown>;
    if (servers.nonsudo) {
      // Already present — do not modify
      return false;
    }

    servers.nonsudo = {
      command: "node",
      args: [binPath, "observe"],
    };

    fs.writeFileSync(configFilePath, JSON.stringify(config, null, 2) + "\n");
    return true;
  } catch {
    // File doesn't exist, can't be read, or can't be parsed — skip silently
    return false;
  }
}

export async function runInit(configPath: string): Promise<void> {
  const result = runInitInternal(configPath);
  printSummary(result);
}

export function runInitInternal(
  configPath: string,
  options?: {
    keyPath?: string;
    ideConfigPaths?: { cursor?: string; claude?: string };
  },
): InitResult {
  const keyPath = resolveHome(options?.keyPath ?? "~/.nonsudo/keys/default.key");
  const keypair = ensureKeypair(keyPath);

  const resolvedConfigPath = path.resolve(configPath);
  const configWritten = writeConfigIfAbsent(resolvedConfigPath);

  const binPath = resolveBinPath();

  const cursorPath =
    options?.ideConfigPaths?.cursor ??
    path.join(os.homedir(), ".cursor", "mcp.json");
  const claudePath =
    options?.ideConfigPaths?.claude ??
    path.join(
      os.homedir(),
      "Library",
      "Application Support",
      "Claude",
      "claude_desktop_config.json",
    );

  const cursorPatched = patchIdeConfig(cursorPath, binPath);
  const claudePatched = patchIdeConfig(claudePath, binPath);

  return {
    keyPath,
    publicKeyHex: keypair.publicKeyHex,
    configWritten,
    configPath: resolvedConfigPath,
    cursorPatched,
    claudePatched,
  };
}

function printSummary(result: InitResult): void {
  const pubKeyShort = result.publicKeyHex.slice(0, 16);

  console.log(`\u2713  Keypair ready:    ${result.keyPath}`);
  console.log(`   Public key: ${pubKeyShort}...`);

  if (result.configWritten) {
    console.log(`\u2713  Config written:   ${result.configPath}`);
  } else {
    console.log(`\u2713  Config written:   already exists \u2014 skipped`);
  }

  console.log(
    `\u2713  Cursor MCP:       ${result.cursorPatched ? "patched" : "not found"}`,
  );
  console.log(
    `\u2713  Claude Desktop:   ${result.claudePatched ? "patched" : "not found"}`,
  );

  console.log("");
  console.log("Next steps:");
  console.log("  nonsudo observe          start the observe proxy");
  console.log("  nonsudo verify <file>    verify a receipt chain");
  console.log("");
  console.log("Logs will be written under ~/.nonsudo/observe/");
}
