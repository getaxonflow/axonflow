/**
 * LLM Provider Routing Example
 *
 * This example demonstrates how AxonFlow routes requests to LLM providers.
 * Provider selection is controlled SERVER-SIDE via environment variables,
 * not per-request. This ensures consistent routing policies across your org.
 *
 * Server-side configuration (environment variables):
 *   LLM_ROUTING_STRATEGY=weighted|round_robin|failover|cost_optimized*
 *   PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20
 *   DEFAULT_LLM_PROVIDER=openai
 *
 * * cost_optimized is Enterprise only
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
  // Initialize client
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID,
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET,
  });

  // AXONFLOW_USER_TOKEN: Set to JWT for enterprise mode
  // In community mode, SDK defaults to "anonymous" if not set
  const userToken = process.env.AXONFLOW_USER_TOKEN || "";

  console.log("=== LLM Provider Routing Examples ===\n");
  console.log("Provider selection is server-side. Configure via environment variables:");
  console.log("  LLM_ROUTING_STRATEGY=weighted");
  console.log("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20\n");

  // Example 1: Send a request (server decides which provider to use)
  console.log("1. Send request (server routes based on configured strategy):");
  try {
    const response = await client.proxyLLMCall({
      userToken,
      query: "What is 2 + 2?",
      requestType: "chat",
      context: { provider: "openai" },
    });
    const data = typeof response.data === 'object'
      ? JSON.stringify(response.data).substring(0, 100)
      : String(response.data).substring(0, 100);
    console.log(`   Response: ${data}...`);
    console.log(`   Success: ${response.success}`);
    assertCheck(response.success === true, "Response success is true");
    assertCheck(response.data !== undefined && response.data !== null, "Response data is present");
    assertCheck(!response.blocked, "Response is not blocked");
    console.log();
  } catch (error) {
    console.log(`   Error: ${error}`);
    failures.push("Example 1: Request failed with error");
    console.log();
  }

  // Example 2: Multiple requests show distribution based on weights
  console.log("2. Multiple requests (observe provider distribution):");
  let successCount = 0;
  for (let i = 1; i <= 3; i++) {
    try {
      const response = await client.proxyLLMCall({
        userToken,
        query: `Question ${i}: What is the capital of France?`,
        requestType: "chat",
        context: { provider: "openai" },
      });
      if (response.success) {
        successCount++;
      }
      console.log(`   Request ${i}: Success=${response.success} (provider selected by server)`);
    } catch (error) {
      console.log(`   Request ${i} Error: ${error}`);
    }
  }
  assertCheck(successCount >= 1, `At least 1 of 3 requests succeeded (got ${successCount})`);
  console.log();

  // Example 3: Health check
  console.log("3. Check agent health:");
  try {
    const health = await client.healthCheck();
    console.log(`   Status: ${health.status}`);
    assertCheck(health.status === "healthy" || health.status === "ok", `Health status is healthy (got: ${health.status})`);
  } catch (error) {
    console.log(`   Error: ${error}`);
    failures.push("Health check failed");
  }

  console.log("\n=== Examples Complete ===");
  console.log("\nTo change provider routing, update server environment variables:");
  console.log("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover");
  console.log("  - PROVIDER_WEIGHTS: distribution percentages");
  console.log("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy");

  // Final summary
  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  } else {
    console.log("All assertions passed!");
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
