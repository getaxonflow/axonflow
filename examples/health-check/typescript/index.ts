/**
 * Health Check Example - TypeScript
 *
 * Demonstrates how to check the health of AxonFlow Agent and Orchestrator services.
 * This is essential for monitoring and ensuring your governance infrastructure is running.
 *
 * Usage:
 *   npx ts-node index.ts
 *
 * Environment:
 *   AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
 *   AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET - Optional for community mode
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import { AxonFlow } from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

async function main() {
  // Initialize client (credentials optional for community mode)
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const clientId = process.env.AXONFLOW_CLIENT_ID;
  const clientSecret = process.env.AXONFLOW_CLIENT_SECRET;

  const client = new AxonFlow({
    endpoint,
    clientId: clientId || undefined,
    clientSecret: clientSecret || undefined,
  });

  console.log("=== AxonFlow Health Check Example ===\n");

  // 1. Check Agent health
  console.log("1. Checking Agent health...");
  let agentHealth;
  try {
    agentHealth = await client.healthCheck();
    console.log(`   Agent Status: ${agentHealth.status.toUpperCase()}`);
    if (agentHealth.version) {
      console.log(`   Version: ${agentHealth.version}`);
    }
    assertCheck(agentHealth.status === "healthy", "Agent returns healthy status");
    assertCheck(typeof agentHealth.status === "string", "Agent health response has status field");
  } catch (error) {
    console.log(`   Agent health check failed: ${error}`);
    failures.push("Agent health check threw an exception");
  }

  // 2. Check Orchestrator health
  console.log("\n2. Checking Orchestrator health...");
  let orchHealth;
  try {
    orchHealth = await client.orchestratorHealthCheck();
    console.log(`   Orchestrator Status: ${orchHealth.status.toUpperCase()}`);
    if (orchHealth.version) {
      console.log(`   Version: ${orchHealth.version}`);
    }
    assertCheck(orchHealth.status === "healthy", "Orchestrator returns healthy status");
    assertCheck(typeof orchHealth.status === "string", "Orchestrator health response has status field");
  } catch (error) {
    console.log(`   Orchestrator health check failed: ${error}`);
    failures.push("Orchestrator health check threw an exception");
  }

  // 3. Summary
  console.log("\n=== Health Check Summary ===");
  console.log(`   Agent: ${agentHealth?.status === "healthy" ? "HEALTHY" : "UNHEALTHY"}`);
  console.log(`   Orchestrator: ${orchHealth?.status === "healthy" ? "HEALTHY" : "UNHEALTHY"}`);

  // Verify both services are healthy
  assertCheck(
    agentHealth?.status === "healthy" && orchHealth?.status === "healthy",
    "Both Agent and Orchestrator are healthy"
  );

  // Final assertion summary
  console.log("\n=== Assertion Summary ===");
  if (failures.length === 0) {
    console.log("All assertions passed!");
  } else {
    console.log(`${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch(console.error);
