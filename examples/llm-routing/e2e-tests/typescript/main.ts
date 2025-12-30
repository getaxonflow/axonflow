// Community LLM Provider E2E Tests using TypeScript SDK
import { AxonFlowClient } from "@axonflow/sdk";

async function main() {
  // Create client
  const endpoint = process.env.ORCHESTRATOR_URL || "http://localhost:8081";
  const client = new AxonFlowClient({ endpoint });

  console.log("=== Community LLM Provider Tests (TypeScript SDK) ===");
  console.log(`Target: ${endpoint}\n`);

  // Test 1: List providers
  console.log("Test 1: List providers");
  try {
    const providers = await client.listProviders();
    for (const p of providers) {
      console.log(`  - ${p.name} (${p.type}): ${p.health.status}`);
    }
  } catch (e) {
    console.log(`  Failed: ${e}`);
  }
  console.log();

  // Test 2: Per-request OpenAI
  console.log("Test 2: Per-request selection - OpenAI");
  try {
    const resp = await client.process({
      query: "Say hello in 3 words",
      requestType: "chat",
      context: { provider: "openai" },
      user: { email: "test@example.com", role: "user" },
    });
    console.log(`  Provider: ${resp.providerInfo.provider}`);
    console.log(`  Response: ${truncate(resp.data.data, 50)}`);
  } catch (e) {
    console.log(`  Failed: ${e}`);
  }
  console.log();

  // Test 3: Per-request Anthropic
  console.log("Test 3: Per-request selection - Anthropic");
  try {
    const resp = await client.process({
      query: "Say hello in 3 words",
      requestType: "chat",
      context: { provider: "anthropic" },
      user: { email: "test@example.com", role: "user" },
    });
    console.log(`  Provider: ${resp.providerInfo.provider}`);
    console.log(`  Response: ${truncate(resp.data.data, 50)}`);
  } catch (e) {
    console.log(`  Failed: ${e}`);
  }
  console.log();

  // Test 4: Per-request Gemini
  console.log("Test 4: Per-request selection - Gemini");
  try {
    const resp = await client.process({
      query: "Say hello in 3 words",
      requestType: "chat",
      context: { provider: "gemini" },
      user: { email: "test@example.com", role: "user" },
    });
    console.log(`  Provider: ${resp.providerInfo.provider}`);
    console.log(`  Response: ${truncate(resp.data.data, 50)}`);
  } catch (e) {
    console.log(`  Failed: ${e}`);
  }
  console.log();

  // Test 5: Weighted routing distribution
  console.log("Test 5: Weighted routing distribution (5 requests)");
  const providersUsed: Record<string, number> = {};
  for (let i = 0; i < 5; i++) {
    try {
      const resp = await client.process({
        query: "Hello",
        requestType: "chat",
        user: { email: "test@example.com", role: "user" },
      });
      const provider = resp.providerInfo.provider;
      providersUsed[provider] = (providersUsed[provider] || 0) + 1;
      console.log(`  Request ${i + 1}: ${provider}`);
    } catch (e) {
      console.log(`  Request ${i + 1}: failed (${e})`);
    }
  }
  console.log();

  console.log("=== Tests Complete ===");
}

function truncate(s: string, maxLen: number): string {
  return s.length <= maxLen ? s : s.substring(0, maxLen) + "...";
}

main().catch(console.error);
