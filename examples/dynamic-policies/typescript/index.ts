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
 *   AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET - Required for dynamic policies
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  // Initialize client
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  const client = new AxonFlow({
    endpoint,
    clientId: clientId || "demo-tenant",  // Required for OAuth2 client credentials
    clientSecret: clientSecret || "",
  });

  console.log("=== Dynamic Policy Management Example ===\n");

  let createdPolicy: any = null;

  try {
    // 1. List existing dynamic policies
    console.log("1. Listing existing dynamic policies...");
    const policies = await client.listDynamicPolicies();
    console.log(`   Found ${(policies || []).length} dynamic policies`);
    for (const p of (policies || [])) {
      console.log(`   - ${p.id}: ${p.name} (enabled: ${p.enabled})`);
    }
    assertCheck(Array.isArray(policies), "listDynamicPolicies returns an array");

    // 2. Create a new dynamic policy
    console.log("\n2. Creating a new dynamic policy...");
    createdPolicy = await client.createDynamicPolicy({
      name: "high-risk-block",
      description: "Block requests with high risk scores",
      type: "risk",
      category: "dynamic-risk",
      conditions: [
        {
          field: "risk_score",
          operator: "greater_than",
          value: 0.8,
        },
      ],
      actions: [
        {
          type: "block",
          config: { reason: "High risk detected" },
        },
      ],
      priority: 100,
      enabled: true,
      tenantId: "demo-tenant",
    } as any);
    console.log(
      `   Created policy: ${createdPolicy.name} (ID: ${createdPolicy.id})`
    );
    assertCheck(createdPolicy.id !== undefined && createdPolicy.id !== "", "createDynamicPolicy returns policy with valid ID");
    assertCheck(createdPolicy.name === "high-risk-block", "createDynamicPolicy returns correct name");
    assertCheck(createdPolicy.enabled === true, "createDynamicPolicy returns policy as enabled");

    // 3. Get the policy by ID
    console.log("\n3. Getting policy by ID...");
    const policy = await client.getDynamicPolicy(createdPolicy.id);
    console.log(`   Policy: ${policy.name}`);
    console.log(`   Description: ${policy.description}`);
    console.log(`   Type: ${policy.type}`);
    console.log(`   Priority: ${policy.priority}`);
    console.log(`   Conditions: ${policy.conditions?.length || 0}`);
    console.log(`   Actions: ${policy.actions?.length || 0}`);
    assertCheck(policy.id === createdPolicy.id, "getDynamicPolicy returns matching policy ID");
    assertCheck(policy.name === "high-risk-block", "getDynamicPolicy returns correct name");
    assertCheck(policy.priority === 100, "getDynamicPolicy returns correct priority");
    assertCheck((policy.conditions?.length || 0) > 0, "getDynamicPolicy returns policy with conditions");
    assertCheck((policy.actions?.length || 0) > 0, "getDynamicPolicy returns policy with actions");

    // 4. Update the policy
    console.log("\n4. Updating policy description...");
    const updated = await client.updateDynamicPolicy(createdPolicy.id, {
      description:
        "Block requests with risk scores above threshold (0.8)",
    });
    console.log(`   Updated description: ${updated.description}`);
    assertCheck(updated.description === "Block requests with risk scores above threshold (0.8)", "updateDynamicPolicy updates description correctly");
    assertCheck(updated.id === createdPolicy.id, "updateDynamicPolicy returns same policy ID");

    // 5. Toggle policy (disable it)
    console.log("\n5. Toggling policy (disabling)...");
    const toggled = await client.toggleDynamicPolicy(createdPolicy.id, false);
    console.log(`   Policy enabled: ${toggled.enabled}`);
    assertCheck(toggled.enabled === false, "toggleDynamicPolicy disables policy correctly");
    assertCheck(toggled.id === createdPolicy.id, "toggleDynamicPolicy returns same policy ID");

    // 6. Get effective dynamic policies
    console.log("\n6. Getting effective dynamic policies...");
    const effective = await client.getEffectiveDynamicPolicies();
    console.log(`   Found ${(effective || []).length} effective dynamic policies`);
    assertCheck(Array.isArray(effective), "getEffectiveDynamicPolicies returns an array");
    // Disabled policy should NOT be in effective list
    const foundDisabled = (effective || []).find((p: any) => p.id === createdPolicy.id);
    assertCheck(foundDisabled === undefined, "Disabled policy is not in effective policies list");
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
