import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { parse as parseYaml } from "yaml";
import { runInitInternal } from "../init/index";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nonsudo-init-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("runInit", () => {
  test("writes a valid YAML config file", () => {
    const configPath = path.join(tmpDir, "nonsudo.yaml");
    const keyPath = path.join(tmpDir, "keys", "test.key");

    runInitInternal(configPath, {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    });

    expect(fs.existsSync(configPath)).toBe(true);
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = parseYaml(raw) as Record<string, unknown>;
    expect(parsed).toBeTruthy();
  });

  test("running twice does not overwrite the config — byte-for-byte preserved", () => {
    const configPath = path.join(tmpDir, "nonsudo.yaml");
    const keyPath = path.join(tmpDir, "keys", "test.key");
    const opts = {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    };

    const r1 = runInitInternal(configPath, opts);
    expect(r1.configWritten).toBe(true);
    const contents1 = fs.readFileSync(configPath);

    const r2 = runInitInternal(configPath, opts);
    expect(r2.configWritten).toBe(false);
    const contents2 = fs.readFileSync(configPath);

    expect(contents1.equals(contents2)).toBe(true);
  });

  test("written YAML contains required fields", () => {
    const configPath = path.join(tmpDir, "nonsudo.yaml");
    const keyPath = path.join(tmpDir, "keys", "test.key");

    runInitInternal(configPath, {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    });

    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = parseYaml(raw) as Record<string, unknown>;

    expect(parsed.mode).toBe("observe");

    const proxy = parsed.proxy as Record<string, unknown>;
    expect(proxy.port).toBe(3100);
    expect(proxy.upstream_url).toBe("http://localhost:3001");

    const workflow = parsed.workflow as Record<string, unknown>;
    expect(workflow.agent_id).toBe("my-agent");
    expect(workflow.initiator_id).toBeTruthy();
  });

  test("generates a new keypair file when key path does not exist", () => {
    const configPath = path.join(tmpDir, "nonsudo.yaml");
    const keyPath = path.join(tmpDir, "keys", "new.key");

    expect(fs.existsSync(keyPath)).toBe(false);

    const result = runInitInternal(configPath, {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    });

    expect(fs.existsSync(keyPath)).toBe(true);
    expect(result.publicKeyHex).toHaveLength(64);
  });

  test("existing key file is not modified on rerun", () => {
    const configPath = path.join(tmpDir, "nonsudo.yaml");
    const keyPath = path.join(tmpDir, "keys", "existing.key");

    // First run — creates key
    runInitInternal(configPath, {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    });
    const keyContents1 = fs.readFileSync(keyPath);

    // Remove config so second run can write it (we only care about key here)
    fs.unlinkSync(path.join(tmpDir, "nonsudo.yaml"));

    // Second run — key must be byte-for-byte identical
    runInitInternal(configPath, {
      keyPath,
      ideConfigPaths: { cursor: "/nonexistent", claude: "/nonexistent" },
    });
    const keyContents2 = fs.readFileSync(keyPath);

    expect(keyContents1.equals(keyContents2)).toBe(true);
  });
});
