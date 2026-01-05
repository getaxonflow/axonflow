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
 *   AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_LICENSE_KEY - Required for dynamic policies
 */

import { AxonFlow } from "@axonflow/sdk";
import type { DynamicPolicyAction } from "@axonflow/sdk";

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
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY || "";
  const tenant = process.env.AXONFLOW_CLIENT_ID || "demo-tenant";

  const client = new AxonFlow({
    endpoint,
    licenseKey,
    tenant,
  });

  console.log("=== Compliance Policy Examples ===\n");

  const createdPolicies: string[] = [];

  // 1. GDPR - EU Data Sovereignty
  console.log("1. Creating GDPR policy for EU data sovereignty...");
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
    createdPolicies.push(gdprPolicy.id);
  } catch (error) {
    console.log(`   Failed to create GDPR policy: ${error}`);
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
  } catch (error) {
    console.log(`   Failed to create HIPAA policy: ${error}`);
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
  } catch (error) {
    console.log(`   Failed to create RBI policy: ${error}`);
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
  } catch (error) {
    console.log(`   Failed to list policies: ${error}`);
  }

  // 5. Cleanup
  console.log("\n5. Cleaning up test policies...");
  for (const policyId of createdPolicies) {
    try {
      await client.deleteDynamicPolicy(policyId);
    } catch (error) {
      console.log(`   Failed to delete ${policyId}: ${error}`);
    }
  }
  console.log(`   Deleted ${createdPolicies.length} test policies`);

  console.log("\n=== Compliance Policy Examples Complete ===");
}

main().catch(console.error);
