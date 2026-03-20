import type { SchemaPackDefinition } from "../types";

export const soc2Enforce: SchemaPackDefinition = {
  id: "soc2/enforce",
  name: "SOC 2 Agent Controls",
  description:
    "Enforces SOC 2 Trust Service Criteria for AI agents operating on customer data and production systems",
  rules: [
    {
      tool: "user_data_export",
      decision: "BLOCK",
      reason:
        "SOC 2 CC6.1: logical access to customer data restricted to authorized personnel",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "requestor_authorized", op: "eq", value: false }],
      },
    },
    {
      tool: "user_data_export",
      decision: "STEP_UP",
      reason:
        "SOC 2 CC6.1: authorized customer data export requires human confirmation",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "production_config_change",
      decision: "STEP_UP",
      reason:
        "SOC 2 CC8.1: production configuration changes require change management approval",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "access_grant",
      decision: "STEP_UP",
      reason:
        "SOC 2 CC6.3: privileged access grants require human authorization",
      blast_radius: "CRITICAL",
      reversible: false,
      params: {
        conditions: [
          { field: "role", op: "in", value: ["admin", "superuser", "root"] },
        ],
      },
    },
    {
      tool: "access_revoke",
      decision: "ALLOW",
      reason:
        "SOC 2 CC6.3: access revocation is a security-reducing action and may proceed",
      blast_radius: "LOW",
      reversible: false,
    },
    {
      tool: "encryption_key_rotate",
      decision: "STEP_UP",
      reason:
        "SOC 2 CC6.7: cryptographic key operations require human authorization",
      blast_radius: "CRITICAL",
      reversible: false,
    },
    {
      tool: "backup_delete",
      decision: "BLOCK",
      reason:
        "SOC 2 A1.2: backup deletion prohibited — availability commitments require retention",
      blast_radius: "CRITICAL",
      reversible: false,
    },
  ],
};
