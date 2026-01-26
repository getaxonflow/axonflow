/**
 * Compliance Policy Examples - TypeScript
 *
 * Demonstrates using allowed_providers in dynamic policies for:
 *   - GDPR: EU data sovereignty
 *   - HIPAA: Healthcare data protection
 *   - RBI: India financial data sovereignty
 *
 * SDK Methods demonstrated:
 *   - createDynamicPolicy() with actions containing allowed_providers config
 *   - listDynamicPolicies()
 *   - deleteDynamicPolicy()
 *
 * Usage:
 *   npx ts-node index.ts
 *
 * Environment:
 *   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID     - Client ID for authentication
 *   AXONFLOW_CLIENT_SECRET - Client secret (required for dynamic policies)
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";
import type { DynamicPolicyAction } from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

// Helper to extract allowed_providers from action config
function getAllowedProviders(actions?: DynamicPolicyAction[]): string[] | undefined {
  if (!actions) return undefined;
  for (const action of actions) {
    if (action.config && action.config.allowed_providers) {
      return action.config.allowed_providers as string[];
    }
  }
  return undefined;
}

async function main(): Promise<void> {
  // Initialize client
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const clientId = process.env.AXONFLOW_CLIENT_ID || "";
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET || "";
  const tenant = process.env.AXONFLOW_CLIENT_ID || "demo-tenant";

  const client = new AxonFlow({
    endpoint,
    clientId,
    clientSecret,
    tenant,
  });

  console.log("=== Compliance Policy Examples ===\n");

  const createdPolicies: string[] = [];

  // 1. GDPR - EU Data Sovereignty
  console.log("1. Creating GDPR policy for EU data sovereignty...");
  let gdprPolicyId: string | null = null;
  try {
    const gdprPolicy = await client.createDynamicPolicy({
      name: "gdpr-eu-data-sovereignty",
      description: "Route EU users to EU-hosted LLMs only (GDPR Article 44)",
      type: "content",
      category: "dynamic-compliance",
      conditions: [
        { field: "user_region", operator: "equals", value: "EU" },
      ],
      actions: [
        {
          type: "route",
          config: { allowed_providers: ["ollama", "azure-eu"] },
        },
      ],
      enabled: true,
    });
    console.log(`   Created: ${gdprPolicy.name} (ID: ${gdprPolicy.id})`);
    const providers = getAllowedProviders(gdprPolicy.actions);
    if (providers) {
      console.log(`   Allowed providers: ${providers.join(", ")}`);
    }
    gdprPolicyId = gdprPolicy.id;
    createdPolicies.push(gdprPolicy.id);
    assertCheck(gdprPolicy.id !== undefined && gdprPolicy.id !== "", "GDPR policy created with valid ID");
    assertCheck(gdprPolicy.name === "gdpr-eu-data-sovereignty", "GDPR policy name is correct");
    assertCheck(providers !== undefined && providers.length === 2, "GDPR policy has 2 allowed providers");
    assertCheck(providers?.includes("ollama") === true, "GDPR policy includes ollama provider");
    assertCheck(providers?.includes("azure-eu") === true, "GDPR policy includes azure-eu provider");
  } catch (error) {
    console.log(`   Failed to create GDPR policy: ${error}`);
    failures.push("GDPR policy creation failed");
  }

  // 2. HIPAA - Healthcare Data Protection
  console.log("\n2. Creating HIPAA policy for PHI protection...");
  try {
    const hipaaPolicy = await client.createDynamicPolicy({
      name: "hipaa-phi-protection",
      description: "Route PHI queries to local LLM only (HIPAA Safe Harbor)",
      type: "content",
      category: "dynamic-compliance",
      conditions: [
        { field: "request_type", operator: "equals", value: "healthcare" },
        { field: "contains_phi", operator: "equals", value: true },
      ],
      actions: [
        {
          type: "route",
          config: { allowed_providers: ["ollama"] },
        },
      ],
      enabled: true,
    });
    console.log(`   Created: ${hipaaPolicy.name} (ID: ${hipaaPolicy.id})`);
    const providers = getAllowedProviders(hipaaPolicy.actions);
    if (providers) {
      console.log(`   Allowed providers: ${providers.join(", ")}`);
    }
    createdPolicies.push(hipaaPolicy.id);
    assertCheck(hipaaPolicy.id !== undefined && hipaaPolicy.id !== "", "HIPAA policy created with valid ID");
    assertCheck(hipaaPolicy.name === "hipaa-phi-protection", "HIPAA policy name is correct");
    assertCheck(providers !== undefined && providers.length === 1, "HIPAA policy has 1 allowed provider");
    assertCheck(providers?.includes("ollama") === true, "HIPAA policy restricts to local ollama only");
    assertCheck((hipaaPolicy.conditions?.length || 0) === 2, "HIPAA policy has 2 conditions");
  } catch (error) {
    console.log(`   Failed to create HIPAA policy: ${error}`);
    failures.push("HIPAA policy creation failed");
  }

  // 3. RBI - India Financial Data Sovereignty
  console.log("\n3. Creating RBI policy for financial data sovereignty...");
  try {
    const rbiPolicy = await client.createDynamicPolicy({
      name: "rbi-financial-data-sovereignty",
      description:
        "Route banking queries to India-hosted providers (RBI Data Localization)",
      type: "content",
      category: "dynamic-compliance",
      conditions: [
        { field: "request_type", operator: "equals", value: "banking" },
        { field: "user_region", operator: "equals", value: "IN" },
      ],
      actions: [
        {
          type: "route",
          config: { allowed_providers: ["azure-india", "ollama"] },
        },
      ],
      enabled: true,
    });
    console.log(`   Created: ${rbiPolicy.name} (ID: ${rbiPolicy.id})`);
    const providers = getAllowedProviders(rbiPolicy.actions);
    if (providers) {
      console.log(`   Allowed providers: ${providers.join(", ")}`);
    }
    createdPolicies.push(rbiPolicy.id);
    assertCheck(rbiPolicy.id !== undefined && rbiPolicy.id !== "", "RBI policy created with valid ID");
    assertCheck(rbiPolicy.name === "rbi-financial-data-sovereignty", "RBI policy name is correct");
    assertCheck(providers !== undefined && providers.length === 2, "RBI policy has 2 allowed providers");
    assertCheck(providers?.includes("azure-india") === true, "RBI policy includes azure-india provider");
    assertCheck(providers?.includes("ollama") === true, "RBI policy includes ollama provider");
  } catch (error) {
    console.log(`   Failed to create RBI policy: ${error}`);
    failures.push("RBI policy creation failed");
  }

  // 4. List all compliance policies
  console.log("\n4. Listing all compliance policies...");
  try {
    const policies = await client.listDynamicPolicies();
    let complianceCount = 0;
    for (const p of policies) {
      const providers = getAllowedProviders(p.actions);
      if (providers && providers.length > 0) {
        complianceCount++;
        console.log(`   - ${p.name}: providers=${providers.join(", ")}`);
      }
    }
    console.log(`   Found ${complianceCount} policies with provider restrictions`);
    assertCheck(Array.isArray(policies), "listDynamicPolicies returns an array");
    assertCheck(complianceCount >= 3, "At least 3 compliance policies with provider restrictions exist");
  } catch (error) {
    console.log(`   Failed to list policies: ${error}`);
    failures.push("listDynamicPolicies failed");
  }

  // 5. Cleanup
  console.log("\n5. Cleaning up test policies...");
  let deletedCount = 0;
  for (const policyId of createdPolicies) {
    try {
      await client.deleteDynamicPolicy(policyId);
      deletedCount++;
    } catch (error) {
      console.log(`   Failed to delete ${policyId}: ${error}`);
    }
  }
  console.log(`   Deleted ${deletedCount} test policies`);
  assertCheck(deletedCount === createdPolicies.length, `All ${createdPolicies.length} test policies deleted successfully`);

  console.log("\n=== Compliance Policy Examples Complete ===");

  // Final assertion summary
  if (failures.length > 0) {
    console.log(`\n=== ASSERTION FAILURES: ${failures.length} ===`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
  } else {
    console.log("\n=== ALL ASSERTIONS PASSED ===");
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
