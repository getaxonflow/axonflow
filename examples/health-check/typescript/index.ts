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
 *   AXONFLOW_LICENSE_KEY - Optional for community mode
 */

import { AxonFlow } from "@axonflow/sdk";

async function main() {
  // Initialize client (credentials optional for community mode)
  const endpoint = process.env.AXONFLOW_ENDPOINT || "http://localhost:8080";
  const licenseKey = process.env.AXONFLOW_LICENSE_KEY;

  const client = new AxonFlow({
    endpoint,
    licenseKey: licenseKey || undefined,
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
  } catch (error) {
    console.log(`   Agent health check failed: ${error}`);
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
  } catch (error) {
    console.log(`   Orchestrator health check failed: ${error}`);
  }

  // 3. Summary
  console.log("\n=== Health Check Summary ===");
  console.log(`   Agent: ${agentHealth?.status === "healthy" ? "HEALTHY" : "UNHEALTHY"}`);
  console.log(`   Orchestrator: ${orchHealth?.status === "healthy" ? "HEALTHY" : "UNHEALTHY"}`);

  // Exit with error if either service is unhealthy
  if (agentHealth?.status !== "healthy" || orchHealth?.status !== "healthy") {
    process.exit(1);
  }
}

main().catch(console.error);
