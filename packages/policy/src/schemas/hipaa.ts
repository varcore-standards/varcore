import type { SchemaPackDefinition } from "../types";

export const hipaaEnforce: SchemaPackDefinition = {
  id: "hipaa/enforce",
  name: "HIPAA Agent Controls",
  description:
    "Enforces HIPAA Privacy and Security Rule requirements for AI agents accessing protected health information",
  rules: [
    {
      tool: "ehr_read",
      decision: "BLOCK",
      reason:
        "HIPAA Privacy Rule: PHI access requires patient authorization or covered exception",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "patient_consent", op: "eq", value: false }],
      },
    },
    {
      tool: "ehr_write",
      decision: "STEP_UP",
      reason:
        "HIPAA Security Rule: PHI modification requires human authorization",
      blast_radius: "CRITICAL",
      reversible: false,
    },
    {
      tool: "ehr_delete",
      decision: "BLOCK",
      reason:
        "HIPAA requires PHI retention for minimum 6 years — deletion is prohibited",
      blast_radius: "CRITICAL",
      reversible: false,
    },
    {
      tool: "phi_export",
      decision: "BLOCK",
      reason:
        "HIPAA Business Associate Agreement required before PHI export to third party",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [{ field: "destination_hipaa_compliant", op: "eq", value: false }],
      },
    },
    {
      tool: "phi_export",
      decision: "STEP_UP",
      reason:
        "HIPAA: PHI export to compliant destination requires human authorization",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "patient_message",
      decision: "STEP_UP",
      reason:
        "HIPAA: patient communications containing PHI require human review",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "contains_phi", op: "eq", value: true }],
      },
    },
    {
      tool: "audit_log_access",
      decision: "BLOCK",
      reason:
        "HIPAA: audit log access restricted to compliance and security purposes",
      blast_radius: "MED",
      reversible: false,
      params: {
        conditions: [
          { field: "purpose", op: "not_in", value: ["compliance", "security_review", "breach_investigation"] },
        ],
      },
    },
  ],
};
