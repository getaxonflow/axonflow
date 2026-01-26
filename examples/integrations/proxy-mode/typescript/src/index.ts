/**
 * AxonFlow Proxy Mode - TypeScript Example
 *
 * Proxy Mode sends requests directly to AxonFlow which handles:
 * - Policy validation (SQL injection, PII detection, etc.)
 * - LLM routing to configured providers
 * - Audit logging
 *
 * This is the simplest integration - no direct LLM SDK calls needed.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

// =============================================================================
// Assertion Infrastructure
// =============================================================================

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

const config = {
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  tenant: process.env.AXONFLOW_TENANT || "demo",
};

async function main() {
  console.log("AxonFlow Proxy Mode - TypeScript Example");
  console.log("=".repeat(60));
  console.log();

  const axonflow = new AxonFlow({
    endpoint: config.endpoint,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    tenant: config.tenant,
    debug: true,
  });

  // Example queries to demonstrate Proxy Mode
  const queries = [
    {
      query: "What are the key benefits of AI governance in enterprise?",
      description: "Safe query - should pass through to LLM",
      requestType: "chat" as const,
    },
    {
      query: "Summarize the principles of responsible AI in 3 bullet points.",
      description: "Safe query - should pass through to LLM",
      requestType: "chat" as const,
    },
    {
      query: "SELECT * FROM users; DROP TABLE secrets;",
      description: "SQL injection - should be BLOCKED",
      requestType: "chat" as const,
    },
    {
      query: "Process this payment for SSN 123-45-6789",
      description: "PII (SSN) - should be BLOCKED or redacted",
      requestType: "chat" as const,
    },
  ];

  // Track results for assertions
  const results: Array<{
    index: number;
    description: string;
    shouldBlock: boolean;
    wasBlocked: boolean;
    hasResponse: boolean;
    latencyMs: number;
    error?: string;
  }> = [];

  for (let i = 0; i < queries.length; i++) {
    const { query, description, requestType } = queries[i];
    const shouldBlock = description.includes("BLOCKED");

    console.log(`\n${"-".repeat(60)}`);
    console.log(`Query ${i + 1}: ${description}`);
    console.log(`${"-".repeat(60)}`);
    console.log(`Query: "${query.substring(0, 60)}${query.length > 60 ? "..." : ""}"`);

    const startTime = Date.now();

    try {
      // Use proxyLLMCall for Proxy Mode - AxonFlow handles everything
      const response = await axonflow.proxyLLMCall({
        userToken: "demo-user-123",
        query,
        requestType,
        context: {
          provider: "openai",
          model: "gpt-3.5-turbo",
        },
      });

      const latencyMs = Date.now() - startTime;

      if (response.blocked) {
        console.log(`\n  Status: BLOCKED`);
        console.log(`  Reason: ${response.blockReason || "Policy violation"}`);
        if (response.policyInfo?.policiesEvaluated) {
          console.log(`  Policies Evaluated: ${response.policyInfo.policiesEvaluated.join(", ")}`);
        }
        results.push({
          index: i + 1,
          description,
          shouldBlock,
          wasBlocked: true,
          hasResponse: false,
          latencyMs,
        });
      } else if (response.success) {
        console.log(`\n  Status: SUCCESS`);
        const data = typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);
        console.log(`  Response: ${data.substring(0, 200)}${data.length > 200 ? "..." : ""}`);

        // Check if the response data actually contains an error (LLM routing failed)
        const responseError = typeof response.data === "object" && response.data?.error
          ? response.data.error
          : (data.includes("LLM routing failed") || data.includes("LLM router not initialized"))
            ? data
            : undefined;

        results.push({
          index: i + 1,
          description,
          shouldBlock,
          wasBlocked: false,
          hasResponse: data !== "" && data !== "null" && data !== "undefined" && !responseError,
          latencyMs,
          error: responseError,
        });
      } else {
        console.log(`\n  Status: FAILED`);
        console.log(`  Error: ${response.error || "Unknown error"}`);
        results.push({
          index: i + 1,
          description,
          shouldBlock,
          wasBlocked: false,
          hasResponse: false,
          latencyMs,
          error: response.error || "Unknown error",
        });
      }

      console.log(`  Latency: ${latencyMs}ms`);

    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      console.log(`\n  Status: ERROR`);
      console.log(`  Error: ${errorMessage}`);
      console.log(`  Latency: ${latencyMs}ms`);

      // Check if error indicates blocking (some implementations throw on block)
      const isBlockError = errorMessage.toLowerCase().includes("blocked") ||
        errorMessage.toLowerCase().includes("sql injection") ||
        errorMessage.toLowerCase().includes("pii") ||
        errorMessage.toLowerCase().includes("ssn");

      results.push({
        index: i + 1,
        description,
        shouldBlock,
        wasBlocked: isBlockError,
        hasResponse: false,
        latencyMs,
        error: errorMessage,
      });
    }
  }

  // Run assertions based on results
  console.log("\n" + "=".repeat(60));
  console.log("Assertions");
  console.log("=".repeat(60));

  // Check if LLM router is configured
  const llmNotConfigured = results.some(r => r.error?.includes("LLM router not initialized") || r.error?.includes("LLM routing failed"));
  if (llmNotConfigured) {
    console.log("   Note: LLM router not configured - testing policy enforcement only");
    console.log();
  }

  // Safe queries (first two) should succeed OR fail gracefully without blocking
  const safeResults = results.filter(r => !r.shouldBlock);
  for (const result of safeResults) {
    assertCheck(!result.wasBlocked, `Query ${result.index} (safe) is not blocked`);
    // If LLM not configured, we only check it's not blocked (can't verify response)
    if (!llmNotConfigured) {
      assertCheck(result.hasResponse || result.error === undefined, `Query ${result.index} (safe) returns a response`);
    }
  }

  // Blocked queries - SQLi should always be blocked, PII may require LLM to be configured
  const blockedResults = results.filter(r => r.shouldBlock);
  for (const result of blockedResults) {
    // SQLi detection happens before LLM routing, so it should always work
    const isSqlInjection = result.description.toLowerCase().includes("sql injection");
    if (isSqlInjection) {
      assertCheck(result.wasBlocked, `Query ${result.index} (${result.description}) is blocked`);
    } else if (llmNotConfigured) {
      // PII detection may depend on LLM configuration
      console.log(`   SKIP: Query ${result.index} (${result.description}) - requires LLM configuration`);
    } else {
      assertCheck(result.wasBlocked, `Query ${result.index} (${result.description}) is blocked`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Test Summary");
  console.log("=".repeat(60));
  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    failures.forEach((f) => console.log(`   - ${f}`));
  }
  console.log("=".repeat(60));
  console.log();
  console.log("Key Takeaways:");
  console.log("  - Proxy Mode sends queries directly to AxonFlow");
  console.log("  - AxonFlow handles policy checking AND LLM routing");
  console.log("  - No direct LLM SDK calls needed in your code");
  console.log("  - Simplest integration for AI governance");
}

main()
  .then(() => {
    process.exit(failures.length > 0 ? 1 : 0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
