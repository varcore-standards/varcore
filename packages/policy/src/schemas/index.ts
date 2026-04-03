import { stripeEnforce, stripeBeneficiary } from "./stripe";
import { githubEnforce } from "./github";
import { awsS3Enforce } from "./aws-s3";
import { pciDssStripe } from "./pci-dss";
import { terraformEnforce } from "./terraform";
import { euAiActEnforce } from "./eu-ai-act";
import { hipaaEnforce } from "./hipaa";
import { soc2Enforce } from "./soc2";
import { gdprEnforce } from "./gdpr";
import { iso27001Enforce } from "./iso27001";
import { upiEnforce, upiVpaAllowlist } from "./upi";
import { achEnforce, achAccountAllowlist } from "./ach";
import { openclawEnforce } from "./openclaw";
import type { SchemaPackDefinition } from "../types";
import { PolicyLoadError } from "../types";

export const SCHEMA_PACKS: Record<string, SchemaPackDefinition> = {
  "stripe/enforce": stripeEnforce,
  "stripe/beneficiary": stripeBeneficiary,
  "github/enforce": githubEnforce,
  "aws-s3/enforce": awsS3Enforce,
  "pci-dss/stripe": pciDssStripe,
  "terraform/enforce": terraformEnforce,
  "eu-ai-act/enforce": euAiActEnforce,
  "hipaa/enforce": hipaaEnforce,
  "soc2/enforce": soc2Enforce,
  "gdpr/enforce": gdprEnforce,
  "iso27001/enforce": iso27001Enforce,
  "upi/enforce": upiEnforce,
  "upi/vpa-allowlist": upiVpaAllowlist,
  "ach/enforce": achEnforce,
  "ach/account-allowlist": achAccountAllowlist,
  "openclaw/enforce": openclawEnforce,
};

export function resolveSchemaPack(id: string): SchemaPackDefinition {
  const pack = SCHEMA_PACKS[id];
  if (!pack) {
    throw new PolicyLoadError(
      `Unknown schema pack: "${id}". Run: nonsudo schemas list`
    );
  }
  return pack;
}
