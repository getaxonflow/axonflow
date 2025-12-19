/**
 * AxonFlow Proxy Mode - TypeScript Example
 *
 * Proxy Mode sends requests directly to AxonFlow which handles:
 * - Policy validation (SQL injection, PII detection, etc.)
 * - LLM routing to configured providers
 * - Audit logging
 *
 * This is the simplest integration - no direct LLM SDK calls needed.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";

const config = {
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "demo",
};

async function main() {
  console.log("AxonFlow Proxy Mode - TypeScript Example");
  console.log("=".repeat(60));
  console.log();

  const axonflow = new AxonFlow({
    endpoint: config.endpoint,
    licenseKey: config.licenseKey,
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

  for (let i = 0; i < queries.length; i++) {
    const { query, description, requestType } = queries[i];

    console.log(`\n${"-".repeat(60)}`);
    console.log(`Query ${i + 1}: ${description}`);
    console.log(`${"-".repeat(60)}`);
    console.log(`Query: "${query.substring(0, 60)}${query.length > 60 ? "..." : ""}"`);

    const startTime = Date.now();

    try {
      // Use executeQuery for Proxy Mode - AxonFlow handles everything
      const response = await axonflow.executeQuery({
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
      } else if (response.success) {
        console.log(`\n  Status: SUCCESS`);
        const data = typeof response.data === "string"
          ? response.data
          : JSON.stringify(response.data);
        console.log(`  Response: ${data.substring(0, 200)}${data.length > 200 ? "..." : ""}`);
      } else {
        console.log(`\n  Status: FAILED`);
        console.log(`  Error: ${response.error || "Unknown error"}`);
      }

      console.log(`  Latency: ${latencyMs}ms`);

    } catch (error) {
      const latencyMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      console.log(`\n  Status: ERROR`);
      console.log(`  Error: ${errorMessage}`);
      console.log(`  Latency: ${latencyMs}ms`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Proxy Mode Demo Complete");
  console.log("=".repeat(60));
  console.log();
  console.log("Key Takeaways:");
  console.log("  - Proxy Mode sends queries directly to AxonFlow");
  console.log("  - AxonFlow handles policy checking AND LLM routing");
  console.log("  - No direct LLM SDK calls needed in your code");
  console.log("  - Simplest integration for AI governance");
}

main().catch(console.error);
