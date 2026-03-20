import type { SchemaPackDefinition } from "../types";

export const gdprEnforce: SchemaPackDefinition = {
  id: "gdpr/enforce",
  name: "GDPR Agent Controls",
  description:
    "Enforces GDPR data subject rights and lawful basis requirements for AI agents processing personal data",
  rules: [
    {
      tool: "personal_data_collect",
      decision: "BLOCK",
      reason:
        "GDPR Article 6: personal data processing requires a documented lawful basis",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "lawful_basis", op: "not_exists" }],
      },
    },
    {
      tool: "personal_data_collect",
      decision: "ALLOW",
      reason:
        "GDPR Article 6: valid lawful basis documented — processing may proceed",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          {
            field: "lawful_basis",
            op: "in",
            value: [
              "consent",
              "contract",
              "legal_obligation",
              "vital_interests",
              "public_task",
              "legitimate_interests",
            ],
          },
        ],
      },
    },
    {
      tool: "personal_data_transfer",
      decision: "BLOCK",
      reason:
        "GDPR Chapter V: transfer to country without adequacy decision requires additional safeguards not configured",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          {
            field: "destination_country",
            op: "not_in",
            value: [
              "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
              "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU",
              "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
              "IS", "LI", "NO", "GB", "CH", "US", "CA", "JP", "NZ",
              "KR", "IL", "UY", "AR",
            ],
          },
        ],
      },
    },
    {
      tool: "personal_data_transfer",
      decision: "STEP_UP",
      reason:
        "GDPR Chapter V: cross-border personal data transfer requires human authorization",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "data_subject_delete",
      decision: "STEP_UP",
      reason:
        "GDPR Article 17: right to erasure requests require human verification before execution",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "data_subject_export",
      decision: "STEP_UP",
      reason:
        "GDPR Article 20: data portability requests require human verification before export",
      blast_radius: "MED",
      reversible: false,
    },
    {
      tool: "profiling_decision",
      decision: "BLOCK",
      reason:
        "GDPR Article 22: solely automated decisions with legal effect require human involvement",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "solely_automated", op: "eq", value: true }],
      },
    },
  ],
};
