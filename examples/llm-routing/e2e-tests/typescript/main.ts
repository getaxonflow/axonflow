/**
 * Community LLM Provider E2E Tests using TypeScript SDK
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */
import { AxonFlowClient } from "@axonflow/sdk";

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
  // Create client
  const endpoint = process.env.AXONFLOW_AGENT_URL || "http://localhost:8080";
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
    assertCheck(Array.isArray(providers), "Providers response is an array");
    assertCheck(providers.length > 0, `At least one provider returned (got ${providers.length})`);
  } catch (e) {
    console.log(`  Failed: ${e}`);
    failures.push("Test 1: listProviders failed");
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
    assertCheck(resp.providerInfo !== undefined, "ProviderInfo is present in response");
    assertCheck(resp.providerInfo.provider === "openai", `Provider is openai (got: ${resp.providerInfo.provider})`);
    assertCheck(resp.data !== undefined && resp.data.data !== undefined, "Response data is present");
  } catch (e) {
    console.log(`  Failed: ${e}`);
    failures.push("Test 2: OpenAI request failed");
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
    assertCheck(resp.providerInfo !== undefined, "ProviderInfo is present in response");
    assertCheck(resp.providerInfo.provider === "anthropic", `Provider is anthropic (got: ${resp.providerInfo.provider})`);
    assertCheck(resp.data !== undefined && resp.data.data !== undefined, "Response data is present");
  } catch (e) {
    console.log(`  Failed: ${e}`);
    failures.push("Test 3: Anthropic request failed");
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
    assertCheck(resp.providerInfo !== undefined, "ProviderInfo is present in response");
    assertCheck(resp.providerInfo.provider === "gemini", `Provider is gemini (got: ${resp.providerInfo.provider})`);
    assertCheck(resp.data !== undefined && resp.data.data !== undefined, "Response data is present");
  } catch (e) {
    console.log(`  Failed: ${e}`);
    failures.push("Test 4: Gemini request failed");
  }
  console.log();

  // Test 5: Weighted routing distribution
  console.log("Test 5: Weighted routing distribution (5 requests)");
  const providersUsed: Record<string, number> = {};
  let test5SuccessCount = 0;
  for (let i = 0; i < 5; i++) {
    try {
      const resp = await client.process({
        query: "Hello",
        requestType: "chat",
        user: { email: "test@example.com", role: "user" },
      });
      const provider = resp.providerInfo.provider;
      providersUsed[provider] = (providersUsed[provider] || 0) + 1;
      test5SuccessCount++;
      console.log(`  Request ${i + 1}: ${provider}`);
    } catch (e) {
      console.log(`  Request ${i + 1}: failed (${e})`);
    }
  }
  assertCheck(test5SuccessCount >= 3, `At least 3/5 weighted requests succeeded (got ${test5SuccessCount})`);
  assertCheck(Object.keys(providersUsed).length >= 1, `At least 1 provider was used (got ${Object.keys(providersUsed).length})`);
  console.log();

  console.log("=== Tests Complete ===");
  console.log();
  if (failures.length > 0) {
    console.log(`FAILED: ${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  } else {
    console.log("All assertions passed!");
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

function truncate(s: string, maxLen: number): string {
  return s.length <= maxLen ? s : s.substring(0, maxLen) + "...";
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
