/**
 * LLM Provider Routing Example
 *
 * This example demonstrates how to:
 * 1. Use default routing (server-side configuration)
 * 2. Specify a preferred provider in requests
 * 3. Query provider status
 *
 * Server-side configuration (environment variables):
 *   LLM_ROUTING_STRATEGY=weighted|round_robin|failover
 *   PROVIDER_WEIGHTS=openai:50,anthropic:30,bedrock:20
 *   DEFAULT_LLM_PROVIDER=bedrock
 */

import { AxonFlowClient } from "@axonflow/sdk";

async function main() {
  // Initialize client
  const client = new AxonFlowClient({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    licenseKey: process.env.AXONFLOW_LICENSE_KEY,
    tenant: process.env.AXONFLOW_TENANT || "demo",
  });

  console.log("=== LLM Provider Routing Examples ===\n");

  // Example 1: Default routing (uses server-side strategy)
  console.log("1. Default routing (server decides provider):");
  const defaultResponse = await client.proxy({
    query: "What is 2 + 2?",
    requestType: "chat",
  });
  console.log(`   Response: ${defaultResponse.response?.substring(0, 50)}...`);
  console.log(`   Provider used: ${defaultResponse.metadata?.provider || "unknown"}\n`);

  // Example 2: Request a specific provider
  console.log("2. Request specific provider (OpenAI):");
  const openaiResponse = await client.proxy({
    query: "What is the capital of France?",
    requestType: "chat",
    context: {
      provider: "openai", // Request specific provider
    },
  });
  console.log(`   Response: ${openaiResponse.response?.substring(0, 50)}...`);
  console.log(`   Provider used: ${openaiResponse.metadata?.provider || "unknown"}\n`);

  // Example 3: Request Anthropic
  console.log("3. Request specific provider (Anthropic):");
  const anthropicResponse = await client.proxy({
    query: "Explain quantum computing in one sentence.",
    requestType: "chat",
    context: {
      provider: "anthropic",
    },
  });
  console.log(`   Response: ${anthropicResponse.response?.substring(0, 50)}...`);
  console.log(`   Provider used: ${anthropicResponse.metadata?.provider || "unknown"}\n`);

  // Example 4: Request with model override
  console.log("4. Request with specific model:");
  const modelResponse = await client.proxy({
    query: "What is machine learning?",
    requestType: "chat",
    context: {
      provider: "openai",
      model: "gpt-4o-mini", // Specify exact model
    },
  });
  console.log(`   Response: ${modelResponse.response?.substring(0, 50)}...`);
  console.log(`   Model used: ${modelResponse.metadata?.model || "unknown"}\n`);

  // Example 5: Health check to see available providers
  console.log("5. Check provider health status:");
  const health = await client.health();
  console.log(`   Status: ${health.status}`);
  if (health.providers) {
    for (const [name, status] of Object.entries(health.providers)) {
      console.log(`   - ${name}: ${(status as any).healthy ? "✓ healthy" : "✗ unhealthy"}`);
    }
  }

  console.log("\n=== Examples Complete ===");
}

main().catch(console.error);
