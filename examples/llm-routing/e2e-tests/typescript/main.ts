/**
 * Community LLM Provider E2E Tests using TypeScript SDK
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
  const endpoint = process.env.AXONFLOW_AGENT_URL || "http://localhost:8080";
  const client = new AxonFlow({
    endpoint,
    clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo-secret",
  });

  console.log("=== Community LLM Provider Tests (TypeScript SDK) ===");
  console.log(`Target: ${endpoint}\n`);

  // Test 1: List providers
  console.log("Test 1: List providers");
  try {
    const providers = await client.listProviders();
    for (const p of providers) {
      console.log(`  - ${p.name} (${p.type}): ${p.health?.status ?? "unknown"}`);
    }
    assertCheck(Array.isArray(providers), "Providers response is an array");
    assertCheck(providers.length > 0, `At least one provider returned (got ${providers.length})`);
  } catch (e) {
    console.log(`  Failed: ${e}`);
    failures.push("Test 1: listProviders failed");
  }
  console.log();

  // Test 2-4: Per-request provider selection.
  // Note: ExecuteQueryResponse currently returns policyInfo + budgetInfo
  // but does not surface providerInfo on the response. We assert the call
  // succeeded and a non-empty response was produced; per-provider tracking
  // is verified at the platform/Prometheus layer.
  const providersToTest = ["openai", "anthropic", "gemini"];
  for (let idx = 0; idx < providersToTest.length; idx++) {
    const provider = providersToTest[idx];
    console.log(`Test ${idx + 2}: Per-request selection - ${provider}`);
    try {
      const resp = await client.proxyLLMCall({
        userToken: "test-user",
        query: "Say hello in 3 words",
        requestType: "chat",
        context: { provider },
      });
      const text =
        resp.data && typeof resp.data === "object"
          ? (resp.data as { data?: string }).data
          : undefined;
      console.log(`  Response: ${truncate(text ?? "", 50)}`);
      assertCheck(resp.success === true, `${provider} request reports success`);
      assertCheck(
        typeof text === "string" && text.length > 0,
        `${provider} response data is non-empty`
      );
    } catch (e) {
      console.log(`  Failed: ${e}`);
      failures.push(`${provider} request failed`);
    }
    console.log();
  }

  // Test 5: Repeated default-routing requests succeed
  console.log("Test 5: Default-route distribution (5 requests)");
  let successCount = 0;
  for (let i = 0; i < 5; i++) {
    try {
      const resp = await client.proxyLLMCall({
        userToken: "test-user",
        query: "Hello",
        requestType: "chat",
      });
      if (resp.success) {
        successCount++;
        console.log(`  Request ${i + 1}: success`);
      } else {
        console.log(`  Request ${i + 1}: not-success`);
      }
    } catch (e) {
      console.log(`  Request ${i + 1}: failed (${e})`);
    }
  }
  assertCheck(
    successCount >= 3,
    `At least 3/5 default-route requests succeeded (got ${successCount})`
  );
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
