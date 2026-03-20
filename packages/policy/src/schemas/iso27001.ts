import type { SchemaPackDefinition } from "../types";

export const iso27001Enforce: SchemaPackDefinition = {
  id: "iso27001/enforce",
  name: "ISO 27001 Agent Controls",
  description:
    "Enforces ISO 27001 information security controls for AI agents operating on organizational assets and systems",
  rules: [
    {
      tool: "asset_delete",
      decision: "BLOCK",
      reason:
        "ISO 27001 A.8.1: classified information assets require human authorization to delete",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "asset_classification", op: "in", value: ["confidential", "restricted"] },
        ],
      },
    },
    {
      tool: "asset_delete",
      decision: "STEP_UP",
      reason:
        "ISO 27001 A.8.1: asset deletion requires human authorization",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "network_access_change",
      decision: "STEP_UP",
      reason:
        "ISO 27001 A.9.1: network access control changes require human authorization",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "vulnerability_scan",
      decision: "STEP_UP",
      reason:
        "ISO 27001 A.12.6: production or external vulnerability scans require authorization",
      blast_radius: "MED",
      reversible: true,
      params: {
        conditions: [
          { field: "scope", op: "in", value: ["production", "prod", "external"] },
        ],
      },
    },
    {
      tool: "incident_response_action",
      decision: "STEP_UP",
      reason:
        "ISO 27001 A.16.1: incident response actions with operational impact require human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "action", op: "in", value: ["isolate", "shutdown", "block_ip", "revoke_access"] },
        ],
      },
    },
    {
      tool: "cryptographic_key_create",
      decision: "STEP_UP",
      reason:
        "ISO 27001 A.10.1: cryptographic key creation for sensitive purposes requires authorization",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [
          { field: "key_usage", op: "in", value: ["signing", "encryption", "authentication"] },
        ],
      },
    },
    {
      tool: "log_delete",
      decision: "BLOCK",
      reason:
        "ISO 27001 A.12.4: security log deletion is prohibited — tampers with audit trail",
      blast_radius: "CRITICAL",
      reversible: false,
    },
  ],
};
