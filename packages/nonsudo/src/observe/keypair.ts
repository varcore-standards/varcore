import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

export interface ObserveKeypair {
  keyId: string;
  privateKeyHex: string;
  publicKeyHex: string;
}

export function ensureKeypair(keyPath: string): ObserveKeypair {
  if (fs.existsSync(keyPath)) {
    const raw = JSON.parse(fs.readFileSync(keyPath, "utf8")) as ObserveKeypair;
    return raw;
  }

  const keyDir = path.dirname(keyPath);
  fs.mkdirSync(keyDir, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });

  // Ed25519 raw key bytes: last 32 bytes of PKCS8 DER, last 32 bytes of SPKI DER
  const privateKeyHex = privDer.subarray(privDer.length - 32).toString("hex");
  const publicKeyHex = pubDer.subarray(pubDer.length - 32).toString("hex");

  const keyId = `ns-local-${Date.now().toString(36)}`;

  const keypair: ObserveKeypair = { keyId, privateKeyHex, publicKeyHex };

  fs.writeFileSync(keyPath, JSON.stringify(keypair, null, 2) + "\n", { mode: 0o600 });

  return keypair;
}
