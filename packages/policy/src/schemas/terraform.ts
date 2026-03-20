import type { SchemaPackDefinition } from "../types";

export const terraformEnforce: SchemaPackDefinition = {
  id: "terraform/enforce",
  name: "Terraform Enforce",
  description:
    "Infrastructure safety — blocks destroy operations, requires step-up approval for production apply and state changes",
  rules: [
    {
      tool: "terraform_destroy",
      decision: "BLOCK",
      reason:
        "destroy is irreversible — requires explicit human approval outside the agent workflow",
      blast_radius: "CRITICAL",
      reversible: false,
    },
    {
      tool: "terraform_apply",
      decision: "STEP_UP",
      reason: "production apply requires human approval",
      blast_radius: "HIGH",
      reversible: false,
      params: {
        conditions: [{ field: "workspace", op: "match", value: "prod" }],
      },
    },
    {
      tool: "terraform_apply",
      decision: "ALLOW",
      reason: "non-production apply is permitted",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "terraform_state_rm",
      decision: "STEP_UP",
      reason: "state removal is difficult to reverse",
      blast_radius: "HIGH",
      reversible: false,
    },
    {
      tool: "terraform_workspace_delete",
      decision: "STEP_UP",
      reason: "workspace deletion requires approval",
      blast_radius: "MED",
      reversible: false,
    },
    {
      tool: "terraform_plan",
      decision: "ALLOW",
      reason: "plan is read-only",
      blast_radius: "LOW",
      reversible: true,
    },
    {
      tool: "terraform_init",
      decision: "ALLOW",
      reason: "init is safe and idempotent",
      blast_radius: "LOW",
      reversible: true,
    },
  ],
};
