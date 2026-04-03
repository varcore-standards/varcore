import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { loadObserveConfig } from "../observe/config";
import { ensureKeypair } from "../observe/keypair";
import { ObserveWriter, sha256Hex } from "../observe/writer";
import type { ObserveLogEntry } from "../observe/writer";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonsudo-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ── loadObserveConfig ───────────────────────────────────────────────────────

describe("loadObserveConfig", () => {
  test("returns valid defaults with no args", () => {
    const cfg = loadObserveConfig();
    expect(cfg.port).toBe(3100);
    expect(cfg.upstream_url).toBe("http://localhost:3001");
    expect(cfg.key_path).toContain(".nonsudo");
    expect(cfg.log_dir).toContain(".nonsudo");
    // Tilde should be resolved to absolute path
    expect(cfg.key_path).not.toContain("~");
    expect(cfg.log_dir).not.toContain("~");
  });

  test("reads and merges from a YAML file", () => {
    const yamlPath = path.join(tmpDir, "observe.yaml");
    fs.writeFileSync(
      yamlPath,
      [
        "proxy:",
        "  upstream_url: http://api.example.com:4000",
        "  port: 9999",
        "workflow:",
        "  agent_id: test_agent",
        "observe:",
        "  log_dir: /tmp/test-logs",
        "",
      ].join("\n"),
    );

    const cfg = loadObserveConfig(yamlPath);
    expect(cfg.upstream_url).toBe("http://api.example.com:4000");
    expect(cfg.port).toBe(9999);
    expect(cfg.agent_id).toBe("test_agent");
    expect(cfg.log_dir).toBe("/tmp/test-logs");
    // Unset fields keep defaults
    expect(cfg.cors).toBe(true);
    expect(cfg.dashboard).toBe(true);
  });
});

// ── ensureKeypair ───────────────────────────────────────────────────────────

describe("ensureKeypair", () => {
  test("creates a key file that can be loaded back", () => {
    const keyPath = path.join(tmpDir, "keys", "test.key");

    const kp1 = ensureKeypair(keyPath);
    expect(kp1.keyId).toBeTruthy();
    expect(kp1.privateKeyHex).toHaveLength(64);
    expect(kp1.publicKeyHex).toHaveLength(64);
    expect(fs.existsSync(keyPath)).toBe(true);

    // Loading again returns the same keypair
    const kp2 = ensureKeypair(keyPath);
    expect(kp2.keyId).toBe(kp1.keyId);
    expect(kp2.privateKeyHex).toBe(kp1.privateKeyHex);
    expect(kp2.publicKeyHex).toBe(kp1.publicKeyHex);
  });
});

// ── ObserveWriter ───────────────────────────────────────────────────────────

describe("ObserveWriter", () => {
  test("write() appends a valid NDJSON line to the log file", () => {
    const writer = new ObserveWriter(tmpDir, "wf-test-001");

    const entry: ObserveLogEntry = {
      type: "observe_log",
      spec_version: "nonsudo/observe-1",
      issued_at: new Date().toISOString(),
      workflow_id: "wf-test-001",
      sequence: writer.nextSequence(),
      agent_id: "agent_local",
      tool_name: "stripe_charge",
      params_canonical_hash: sha256Hex('{"amount":100}'),
      response_hash: sha256Hex("ok"),
      latency_ms: 42,
      blast_radius: "MED",
    };

    writer.write(entry);

    const contents = fs.readFileSync(writer.logPath, "utf8").trim();
    const parsed = JSON.parse(contents) as ObserveLogEntry;
    expect(parsed.type).toBe("observe_log");
    expect(parsed.tool_name).toBe("stripe_charge");
    expect(parsed.sequence).toBe(1);
  });
});

// ── sha256Hex ───────────────────────────────────────────────────────────────

describe("sha256Hex", () => {
  test("returns a consistent 64-char hex string", () => {
    const hash = sha256Hex("hello");
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    // Deterministic
    expect(sha256Hex("hello")).toBe(hash);
    // Different input → different hash
    expect(sha256Hex("world")).not.toBe(hash);
  });
});
