import { createHash } from "crypto";
import canonicalize from "canonicalize";

/**
 * canonicalHash — canonical JSON hash used uniformly across @varcore/* packages.
 *
 * Applies JCS canonicalization (RFC 8785) via the `canonicalize` package, then
 * computes SHA-256, returning the result as "sha256:<hex>".
 *
 * Centralised here so that adapter-langchain, adapter-openai, and policy all
 * use identical canonicalization logic. A divergence in the `canonicalize`
 * package version across packages would otherwise produce silent hash mismatches.
 *
 * @param value - Any JSON-serialisable value (object, array, primitive).
 * @returns "sha256:<64 lowercase hex chars>"
 */
export function canonicalHash(value: unknown): string {
  const canonical = canonicalize(value as object) ?? "null";
  return "sha256:" + createHash("sha256")
    .update(Buffer.from(canonical, "utf8"))
    .digest("hex");
}
