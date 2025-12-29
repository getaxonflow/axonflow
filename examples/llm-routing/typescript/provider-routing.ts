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

import { AxonFlow } from "@axonflow/sdk";

async function main() {
  // Initialize client
  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_ENDPOINT || "http://localhost:8080",
    licenseKey: process.env.AXONFLOW_LICENSE_KEY,
  });

  console.log("=== LLM Provider Routing Examples ===\n");

  // Example 1: Default routing (uses server-side strategy)
  console.log("1. Default routing (server decides provider):");
  try {
    const defaultResponse = await client.executeQuery({
      userToken: "demo-user",
      query: "What is 2 + 2?",
      requestType: "chat",
    });
    const data = typeof defaultResponse.data === 'object'
      ? JSON.stringify(defaultResponse.data).substring(0, 100)
      : String(defaultResponse.data).substring(0, 100);
    console.log(`   Response: ${data}...`);
    console.log(`   Success: ${defaultResponse.success}\n`);
  } catch (error) {
    console.log(`   Error: ${error}\n`);
  }

  // Example 2: Request specific provider (Ollama - local)
  console.log("2. Request specific provider (Ollama):");
  try {
    const ollamaResponse = await client.executeQuery({
      userToken: "demo-user",
      query: "What is the capital of France?",
      requestType: "chat",
      context: {
        provider: "ollama", // Request specific provider
      },
    });
    const data = typeof ollamaResponse.data === 'object'
      ? JSON.stringify(ollamaResponse.data).substring(0, 100)
      : String(ollamaResponse.data).substring(0, 100);
    console.log(`   Response: ${data}...`);
    console.log(`   Success: ${ollamaResponse.success}\n`);
  } catch (error) {
    console.log(`   Error: ${error}\n`);
  }

  // Example 3: Request with model override
  console.log("3. Request with specific model:");
  try {
    const modelResponse = await client.executeQuery({
      userToken: "demo-user",
      query: "What is machine learning in one sentence?",
      requestType: "chat",
      context: {
        provider: "ollama",
        model: "tinyllama", // Specify exact model
      },
    });
    const data = typeof modelResponse.data === 'object'
      ? JSON.stringify(modelResponse.data).substring(0, 100)
      : String(modelResponse.data).substring(0, 100);
    console.log(`   Response: ${data}...`);
    console.log(`   Success: ${modelResponse.success}\n`);
  } catch (error) {
    console.log(`   Error: ${error}\n`);
  }

  // Example 4: Health check
  console.log("4. Check agent health:");
  try {
    const health = await client.healthCheck();
    console.log(`   Status: ${health.status}`);
    console.log(`   Version: ${health.version || "N/A"}\n`);
  } catch (error) {
    console.log(`   Error: ${error}\n`);
  }

  console.log("=== Examples Complete ===");
}

main().catch(console.error);
