import type { SchemaPackDefinition } from "../types";

export const euAiActEnforce: SchemaPackDefinition = {
  id: "eu-ai-act/enforce",
  name: "EU AI Act Article 12",
  description:
    "Enforces logging and human oversight requirements for high-risk AI system actions under EU AI Act Article 12",
  rules: [
    {
      tool: "llm_inference",
      decision: "STEP_UP",
      reason:
        "EU AI Act Article 9: high-risk AI systems require human oversight before execution",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "risk_classification", op: "in", value: ["high_risk", "unacceptable_risk"] },
        ],
      },
    },
    {
      tool: "llm_inference",
      decision: "ALLOW",
      reason:
        "EU AI Act: limited risk systems may proceed with transparency obligations met",
      blast_radius: "LOW",
      reversible: true,
      params: {
        conditions: [
          { field: "risk_classification", op: "eq", value: "limited_risk" },
        ],
      },
    },
    {
      tool: "automated_decision",
      decision: "STEP_UP",
      reason:
        "EU AI Act Article 14: human oversight required for automated decisions affecting individuals",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "affects_individual", op: "eq", value: true }],
      },
    },
    {
      tool: "automated_decision",
      decision: "ALLOW",
      reason:
        "EU AI Act: automated decision without individual impact may proceed",
      blast_radius: "MED",
      reversible: true,
    },
    {
      tool: "training_data_access",
      decision: "STEP_UP",
      reason:
        "EU AI Act Article 10: personal data in training sets requires human review",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "contains_personal_data", op: "eq", value: true }],
      },
    },
    {
      tool: "model_deployment",
      decision: "STEP_UP",
      reason:
        "EU AI Act Article 9: production deployment of AI systems requires human authorization",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "environment", op: "in", value: ["production", "prod"] },
        ],
      },
    },
    {
      tool: "model_deployment",
      decision: "ALLOW",
      reason:
        "EU AI Act: non-production deployment may proceed with full audit trail",
      blast_radius: "MED",
      reversible: true,
    },
  ],
};
