// ── Receipt lifecycle ──────────────────────────────────────────────────────
export {
  createReceipt,
  signReceipt,
  chainReceipt,
  verifySignature,
} from "@varcore/receipts";

// ── Verification layers ────────────────────────────────────────────────────
export {
  verifyChain,
  verifyL3,
  verifyL4,
  loadTsaSidecar,
  parseMessageImprintHex,
  isValidKeyId,
} from "@varcore/receipts";

// ── Core utilities ─────────────────────────────────────────────────────────
export { canonicalHash, computeContentEntropyHash, computeAgentClassId } from "@varcore/core";

// ── Types ──────────────────────────────────────────────────────────────────
export type {
  // Core union types
  ReceiptFields,
  SignedReceipt,
  UnsignedReceipt,
  SignatureBlock,
  // Discriminant enums
  RecordType,
  Decision,
  BlastRadius,
  QueueStatus,
  ApprovalOutcome,
  TerminalOutcome,
  BillableReason,
  DeploymentMode,
  // Named signed subtypes — for record_type discriminant narrowing
  SignedWorkflowManifest,
  SignedActionReceipt,
  SignedDeadLetterReceipt,
  SignedWorkflowClosed,
  SignedPostReceipt,
  SignedRecoveryEvent,
  SignedBudgetWarning,
  SignedReservationExpired,
  SignedApprovalReceipt,
  // Field shapes that are publicly exported
  ApprovalReceiptFields,
  PostReceiptFields,
  RecoveryEventFields,
  BudgetWarningFields,
  ReservationExpiredFields,
  // Verification result types
  ChainVerificationResult,
  ChainError,
  ChainErrorCode,
  ChainWarning,
  ChainWarningCode,
  TsaRecord,
  L3Result,
  L3Status,
  L4Result,
  L4Status,
  L4Violation,
  L4ViolationCode,
} from "@varcore/receipts";

export type { SigningProvider, PublicKeyJwk, AgentClassInput } from "@varcore/core";

// ── Observe proxy ─────────────────────────────────────────────────────────
export { startObserveProxy, loadObserveConfig } from "./observe/index";
export type { ObserveConfig } from "./observe/index";

// ── Init ──────────────────────────────────────────────────────────────────
export { runInit } from "./init/index";
