export { OpenAIAdapter } from "./adapter";
export type { OpenAIFunctionCall, OpenAIToolResult, OpenAIAdapterConfig } from "./types";
export { createActionReceipt } from "./receipt";
export type { CreateActionReceiptParams } from "./receipt";

/**
 * wrapOpenAI — NOT YET IMPLEMENTED.
 *
 * Automatic interception of `client.chat.completions.create` is deferred to Phase 1.
 * This function currently throws so that callers are not silently left without receipt
 * coverage while believing the wrapper is active.
 *
 * **Use the manual API instead:**
 * ```ts
 * import { createActionReceipt } from "@varcore/adapter-openai";
 * const receipt = await createActionReceipt({ ... });
 * ```
 *
 * @throws {Error} Always — automatic interception not yet implemented.
 */
export function wrapOpenAI<T>(_client: T, _config: import("./types").OpenAIAdapterConfig): T {
  throw new Error(
    "wrapOpenAI: automatic interception is not yet implemented. " +
    "Use createActionReceipt() for manual receipt emission. " +
    "See @varcore/adapter-openai README for usage."
  );
}
