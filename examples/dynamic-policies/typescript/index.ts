/**
 * Dynamic Policy Management Example - TypeScript
 *
 * Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
 * Dynamic policies use an LLM to evaluate complex, context-aware rules that
 * can't be expressed with simple regex patterns.
 *
 * SDK Methods demonstrated:
 *   - listDynamicPolicies()
 *   - createDynamicPolicy()
 *   - getDynamicPolicy()
 *   - updateDynamicPolicy()
 *   - deleteDynamicPolicy()
 *   - toggleDynamicPolicy()
 *   - getEffectiveDynamicPolicies()
 *
 * Usage:
 *   npx ts-node index.ts
 *
 * Environment:
 *   AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_LICENSE_KEY - Required for dynamic policies
 */

import { AxonFlow } from "@axonflow/sdk";

async function main() {
  // Initialize client
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY;

  const client = new AxonFlow({
    endpoint,
    licenseKey: licenseKey || undefined,
  });

  console.log("=== Dynamic Policy Management Example ===\n");

  let createdPolicy: any = null;

  try {
    // 1. List existing dynamic policies
    console.log("1. Listing existing dynamic policies...");
    const policies = await client.listDynamicPolicies();
    console.log(`   Found ${policies.length} dynamic policies`);
    for (const p of policies) {
      console.log(`   - ${p.id}: ${p.name} (enabled: ${p.enabled})`);
    }

    // 2. Create a new dynamic policy
    console.log("\n2. Creating a new dynamic policy...");
    createdPolicy = await client.createDynamicPolicy({
      name: "financial-advice-guard",
      description: "Block requests that ask for specific financial advice",
      prompt:
        "Evaluate if this request is asking for specific financial advice like stock picks, investment amounts, or trading strategies. If so, block it.",
      action: "block",
      enabled: true,
      tenantId: "demo-tenant",
    });
    console.log(
      `   Created policy: ${createdPolicy.name} (ID: ${createdPolicy.id})`
    );

    // 3. Get the policy by ID
    console.log("\n3. Getting policy by ID...");
    const policy = await client.getDynamicPolicy(createdPolicy.id);
    console.log(`   Policy: ${policy.name}`);
    console.log(`   Description: ${policy.description}`);
    console.log(`   Prompt: ${policy.prompt}`);
    console.log(`   Action: ${policy.action}`);

    // 4. Update the policy
    console.log("\n4. Updating policy description...");
    const updated = await client.updateDynamicPolicy(createdPolicy.id, {
      description:
        "Block requests asking for specific financial or investment advice",
    });
    console.log(`   Updated description: ${updated.description}`);

    // 5. Toggle policy (disable it)
    console.log("\n5. Toggling policy (disabling)...");
    const toggled = await client.toggleDynamicPolicy(createdPolicy.id);
    console.log(`   Policy enabled: ${toggled.enabled}`);

    // 6. Get effective dynamic policies
    console.log("\n6. Getting effective dynamic policies...");
    const effective = await client.getEffectiveDynamicPolicies();
    console.log(`   Found ${effective.length} effective dynamic policies`);
  } finally {
    // 7. Delete the test policy (cleanup)
    if (createdPolicy) {
      console.log("\n7. Cleaning up - deleting test policy...");
      try {
        await client.deleteDynamicPolicy(createdPolicy.id);
        console.log("   Policy deleted successfully");
      } catch (error) {
        console.log(`   Failed to delete policy: ${error}`);
      }
    }
  }

  console.log("\n=== Dynamic Policy Example Complete ===");
}

main().catch(console.error);
