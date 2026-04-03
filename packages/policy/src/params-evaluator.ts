/**
 * params-evaluator — evaluates ParamsBlock conditions against action.arguments.
 *
 * D-22: sync, pure, no I/O, no LLM, no network.
 * Never throws — invalid conditions log a warning and return "no_match" or "type_error".
 * AND logic: all conditions must be satisfied for evaluateParams to return "match".
 *
 * ConditionResult three-state semantics:
 *   "match"      — condition satisfied; rule fires
 *   "no_match"   — condition not satisfied; skip rule (legitimate mismatch)
 *   "type_error" — field has wrong runtime type for this operator; caller must treat
 *                  as fail-closed BLOCK (params_type_error)
 */

import type { ParamsBlock, ParamsCondition } from "./types";
import { varcoreLog } from "@varcore/core";

const MAX_DEPTH = 5;
const PKG = "varcore/policy";

export type ConditionResult = "match" | "no_match" | "type_error";

/**
 * Traverse a dot-notation field path into an object.
 * Returns { found: true, value } on success.
 * Returns { found: false } if path is missing, intermediate key absent, or depth exceeded.
 * Returns { found: false, arrayDeadEnd: true } when traversal hits an array node —
 *   this is a type error: the policy tried to traverse through an array.
 */
function getField(
  obj: Record<string, unknown>,
  fieldPath: string
): { found: true; value: unknown } | { found: false; arrayDeadEnd?: boolean } {
  const parts = fieldPath.split(".");
  if (parts.length > MAX_DEPTH) {
    varcoreLog("warn", PKG, "params: field path exceeds max depth", {
      max_depth: MAX_DEPTH,
      field: fieldPath,
    });
    return { found: false };
  }

  let current: unknown = obj;
  for (const part of parts) {
    if (Array.isArray(current)) {
      // Traversing into an array with a non-index key is a dead-end that would
      // silently bypass the condition. Signal type_error to the caller.
      varcoreLog("warn", PKG, "params: array traversal dead-end — condition cannot be evaluated", {
        field: fieldPath,
      });
      return { found: false, arrayDeadEnd: true };
    }
    if (current === null || current === undefined || typeof current !== "object") {
      return { found: false };
    }
    current = (current as Record<string, unknown>)[part];
  }

  if (current === undefined || current === null) {
    return { found: false };
  }
  return { found: true, value: current };
}

function evaluateCondition(
  condition: ParamsCondition,
  actionArguments: Record<string, unknown>
): ConditionResult {
  const { field, op, value } = condition;
  const result = getField(actionArguments, field);

  // Array traversal dead-end — this is a type error, not a benign missing field
  if (!result.found && result.arrayDeadEnd) {
    return "type_error";
  }

  const found = result.found;
  const fieldValue = found ? result.value : undefined;

  // exists / not_exists don't need the field to be present
  if (op === "exists") {
    return found && fieldValue !== undefined && fieldValue !== null ? "match" : "no_match";
  }
  if (op === "not_exists") {
    return !found || fieldValue === undefined || fieldValue === null ? "match" : "no_match";
  }

  // All other ops: missing or null field → no_match
  if (!found) {
    return "no_match";
  }

  switch (op) {
    case "eq":
      return fieldValue === value ? "match" : "no_match";

    case "neq":
      return fieldValue !== value ? "match" : "no_match";

    case "gt":
      if (typeof fieldValue !== "number") {
        varcoreLog("warn", PKG, "params: gt requires a number field", {
          field,
          actual_type: typeof fieldValue,
        });
        return "type_error";
      }
      if (typeof value !== "number") {
        varcoreLog("warn", PKG, "params: gt requires a number value", { field });
        return "type_error";
      }
      return fieldValue > value ? "match" : "no_match";

    case "gte":
      if (typeof fieldValue !== "number" || typeof value !== "number") {
        varcoreLog("warn", PKG, "params: gte requires number operands", { field });
        return "type_error";
      }
      return fieldValue >= value ? "match" : "no_match";

    case "lt":
      if (typeof fieldValue !== "number" || typeof value !== "number") {
        varcoreLog("warn", PKG, "params: lt requires number operands", { field });
        return "type_error";
      }
      return fieldValue < value ? "match" : "no_match";

    case "lte":
      if (typeof fieldValue !== "number" || typeof value !== "number") {
        varcoreLog("warn", PKG, "params: lte requires number operands", { field });
        return "type_error";
      }
      return fieldValue <= value ? "match" : "no_match";

    case "match": {
      if (typeof fieldValue !== "string") {
        varcoreLog("warn", PKG, "params: match requires a string field", {
          field,
          actual_type: typeof fieldValue,
        });
        return "type_error";
      }
      let pattern: RegExp;
      try {
        pattern = new RegExp(String(value));
      } catch {
        varcoreLog("warn", PKG, "params: invalid regex for match operator", {
          field,
          regex: String(value),
        });
        return "no_match";
      }
      return pattern.test(fieldValue) ? "match" : "no_match";
    }

    case "not_match": {
      if (typeof fieldValue !== "string") {
        varcoreLog("warn", PKG, "params: not_match requires a string field", {
          field,
          actual_type: typeof fieldValue,
        });
        return "type_error";
      }
      let pattern: RegExp;
      try {
        pattern = new RegExp(String(value));
      } catch {
        varcoreLog("warn", PKG, "params: invalid regex for not_match operator", {
          field,
          regex: String(value),
        });
        return "no_match";
      }
      return !pattern.test(fieldValue) ? "match" : "no_match";
    }

    case "gt_bigint": {
      if (typeof fieldValue !== "string" || typeof value !== "string") {
        varcoreLog("warn", PKG, "params: gt_bigint requires string operands", {
          field,
          actual_type: typeof fieldValue,
        });
        return "type_error";
      }
      try {
        return BigInt(fieldValue) > BigInt(value) ? "match" : "no_match";
      } catch {
        varcoreLog("warn", PKG, "params: gt_bigint failed to parse BigInt", { field });
        return "type_error";
      }
    }

    case "in":
      if (!Array.isArray(value)) {
        varcoreLog("warn", PKG, "params: in operator requires an array value", { field });
        return "no_match";
      }
      return (value as unknown[]).includes(fieldValue) ? "match" : "no_match";

    case "not_in":
      if (!Array.isArray(value)) {
        varcoreLog("warn", PKG, "params: not_in operator requires an array value", { field });
        return "no_match";
      }
      return !(value as unknown[]).includes(fieldValue) ? "match" : "no_match";

    default: {
      const exhaustive: never = op;
      varcoreLog("warn", PKG, "params: unknown operator", { operator: String(exhaustive) });
      return "no_match";
    }
  }
}

/**
 * Evaluates all conditions against action.arguments.
 * Returns:
 *   "match"      — ALL conditions satisfied (AND logic)
 *   "no_match"   — at least one condition not satisfied
 *   "type_error" — at least one condition encountered a runtime type mismatch;
 *                  caller MUST treat as fail-closed BLOCK
 *
 * Sync, pure, no I/O — D-22.
 * Never throws — unexpected errors in evaluateCondition are caught and returned as "type_error".
 */
export function evaluateParams(
  params: ParamsBlock,
  actionArguments: Record<string, unknown>
): ConditionResult {
  for (const condition of params.conditions) {
    try {
      const result = evaluateCondition(condition, actionArguments);
      if (result === "type_error") {
        return "type_error";
      }
      if (result === "no_match") {
        return "no_match";
      }
      // result === "match" — continue to next condition (AND logic)
    } catch {
      // Safety net — evaluateCondition should not throw but if it does, log and fail closed
      varcoreLog("error", PKG, "params: unexpected error evaluating condition", {
        condition: JSON.stringify(condition),
      });
      return "type_error";
    }
  }
  return "match";
}
