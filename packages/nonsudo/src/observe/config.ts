import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parse as parseYaml } from "yaml";

export interface ObserveConfig {
  upstream_url: string;
  port: number;
  agent_id: string;
  initiator_id: string;
  key_path: string;
  log_dir: string;
  cors: boolean;
  dashboard: boolean;
}

function resolveHome(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

const DEFAULTS: ObserveConfig = {
  upstream_url: "http://localhost:3001",
  port: 3100,
  agent_id: "agent_local",
  initiator_id: process.env.USER ?? "developer",
  key_path: "~/.nonsudo/keys/default.key",
  log_dir: "~/.nonsudo/observe/",
  cors: true,
  dashboard: true,
};

export function loadObserveConfig(yamlPath?: string): ObserveConfig {
  const config = { ...DEFAULTS };

  if (yamlPath && fs.existsSync(yamlPath)) {
    const raw = parseYaml(fs.readFileSync(yamlPath, "utf8")) as Record<string, unknown>;

    const proxy = raw["proxy"] as Record<string, unknown> | undefined;
    if (proxy) {
      if (typeof proxy["upstream_url"] === "string") config.upstream_url = proxy["upstream_url"];
      if (typeof proxy["port"] === "number") config.port = proxy["port"];
    }

    const workflow = raw["workflow"] as Record<string, unknown> | undefined;
    if (workflow) {
      if (typeof workflow["agent_id"] === "string") config.agent_id = workflow["agent_id"];
      if (typeof workflow["initiator_id"] === "string") config.initiator_id = workflow["initiator_id"];
    }

    const signing = raw["signing"] as Record<string, unknown> | undefined;
    if (signing) {
      if (typeof signing["key_path"] === "string") config.key_path = signing["key_path"];
    }

    const observe = raw["observe"] as Record<string, unknown> | undefined;
    if (observe) {
      if (typeof observe["log_dir"] === "string") config.log_dir = observe["log_dir"];
    }
  }

  config.key_path = resolveHome(config.key_path);
  config.log_dir = resolveHome(config.log_dir);

  return config;
}
