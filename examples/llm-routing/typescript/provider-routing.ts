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
 */

import { AxonFlow } from "@axonflow/sdk";

async function main() {
  // Initialize client
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    licenseKey: process.env.AXONFLOW_LICENSE_KEY,
  });

  console.log("=== LLM Provider Routing Examples ===\n");
  console.log("Provider selection is server-side. Configure via environment variables:");
  console.log("  LLM_ROUTING_STRATEGY=weighted");
  console.log("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20\n");

  // Example 1: Send a request (server decides which provider to use)
  console.log("1. Send request (server routes based on configured strategy):");
  try {
    const response = await client.executeQuery({
      userToken: "demo-user",
      query: "What is 2 + 2?",
      requestType: "chat",
    });
    const data = typeof response.data === 'object'
      ? JSON.stringify(response.data).substring(0, 100)
      : String(response.data).substring(0, 100);
    console.log(`   Response: ${data}...`);
    console.log(`   Success: ${response.success}\n`);
  } catch (error) {
    console.log(`   Error: ${error}\n`);
  }

  // Example 2: Multiple requests show distribution based on weights
  console.log("2. Multiple requests (observe provider distribution):");
  for (let i = 1; i <= 3; i++) {
    try {
      const response = await client.executeQuery({
        userToken: "demo-user",
        query: `Question ${i}: What is the capital of France?`,
        requestType: "chat",
      });
      console.log(`   Request ${i}: Success (provider selected by server)`);
    } catch (error) {
      console.log(`   Request ${i} Error: ${error}`);
    }
  }
  console.log();

  // Example 3: Health check
  console.log("3. Check agent health:");
  try {
    const health = await client.healthCheck();
    console.log(`   Status: ${health.status}`);
  } catch (error) {
    console.log(`   Error: ${error}`);
  }

  console.log("\n=== Examples Complete ===");
  console.log("\nTo change provider routing, update server environment variables:");
  console.log("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover");
  console.log("  - PROVIDER_WEIGHTS: distribution percentages");
  console.log("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy");
}

main().catch(console.error);
