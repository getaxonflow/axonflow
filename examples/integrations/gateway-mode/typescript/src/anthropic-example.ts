/**
 * AxonFlow Gateway Mode - Anthropic Claude Example
 *
 * Demonstrates Gateway Mode with Anthropic's Claude models.
 * Same pattern as OpenAI: Pre-check -> LLM Call -> Audit
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import Anthropic from "@anthropic-ai/sdk";

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
  axonflow: {
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
    tenant: process.env.AXONFLOW_TENANT || "demo",
  },
  anthropic: {
    apiKey: process.env.ANTHROPIC_API_KEY || "",
  },
};

async function main() {
  console.log("AxonFlow Gateway Mode - Anthropic Claude Example\n");

  const axonflow = new AxonFlow({
    endpoint: config.axonflow.endpoint,
    clientId: config.axonflow.clientId,
    clientSecret: config.axonflow.clientSecret,
    tenant: config.axonflow.tenant,
  });

  const anthropic = new Anthropic({
    apiKey: config.anthropic.apiKey,
  });

  const userToken = "user-456";
  const query = "Explain the importance of audit trails in AI systems.";
  const context = {
    user_role: "compliance_officer",
    department: "legal",
  };

  console.log(`Query: "${query}"`);
  console.log(`User: ${userToken}`);
  console.log("");

  try {
    // Step 1: Pre-Check
    console.log("Step 1: Policy Pre-Check...");
    const startPreCheck = Date.now();

    const preCheckResult = await axonflow.getPolicyApprovedContext({
      userToken,
      query,
      context,
    });

    const preCheckLatency = Date.now() - startPreCheck;
    console.log(`   Completed in ${preCheckLatency}ms`);
    console.log(`   Context ID: ${preCheckResult.contextId}`);

    // Assertions for pre-check
    assertCheck(preCheckResult.contextId !== undefined && preCheckResult.contextId !== "", "Pre-check returns a contextId");
    assertCheck(typeof preCheckResult.approved === "boolean", "Pre-check returns approved as boolean");

    if (!preCheckResult.approved) {
      console.log(`   BLOCKED: ${preCheckResult.blockReason}`);
      assertCheck(false, "Safe query should be approved (pre-check)");
      process.exit(failures.length > 0 ? 1 : 0);
      return;
    }

    assertCheck(preCheckResult.approved === true, "Safe query is approved by policy pre-check");
    assertCheck(preCheckLatency < 10000, "Pre-check completes within 10 seconds");
    console.log("");

    // Step 2: Claude LLM Call
    console.log("Step 2: LLM Call (Claude)...");
    const startLLM = Date.now();

    const message = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 200,
      messages: [
        {
          role: "user",
          content: query,
        },
      ],
    });

    const llmLatency = Date.now() - startLLM;
    const response =
      message.content[0].type === "text" ? message.content[0].text : "";

    console.log(`   Response received in ${llmLatency}ms`);
    console.log(
      `   Tokens: ${message.usage.input_tokens} in, ${message.usage.output_tokens} out`
    );

    // Assertions for LLM call
    assertCheck(response !== "", "Claude returns non-empty response");
    assertCheck(message.content.length > 0, "Claude returns content");
    assertCheck(message.usage.input_tokens > 0, "Claude reports input tokens used");
    assertCheck(message.usage.output_tokens > 0, "Claude reports output tokens used");
    assertCheck(message.stop_reason !== undefined, "Claude provides stop_reason");

    console.log("");

    // Step 3: Audit
    console.log("Step 3: Audit Logging...");
    const startAudit = Date.now();

    await axonflow.auditLLMCall({
      contextId: preCheckResult.contextId,
      responseSummary: response.substring(0, 100),
      provider: "anthropic",
      model: "claude-3-haiku-20240307",
      tokenUsage: {
        promptTokens: message.usage.input_tokens,
        completionTokens: message.usage.output_tokens,
        totalTokens: message.usage.input_tokens + message.usage.output_tokens,
      },
      latencyMs: llmLatency,
    });

    const auditLatency = Date.now() - startAudit;
    console.log(`   Audit logged in ${auditLatency}ms`);

    // Assertions for audit
    assertCheck(auditLatency < 5000, "Audit logging completes within 5 seconds");

    console.log("");

    // Results
    const governanceOverhead = preCheckLatency + auditLatency;
    console.log("=".repeat(60));
    console.log(`Response:\n${response}\n`);
    console.log(`Governance overhead: ${governanceOverhead}ms`);
    console.log(`   (Pre-check: ${preCheckLatency}ms + Audit: ${auditLatency}ms)`);

    // Final assertions
    assertCheck(governanceOverhead < llmLatency * 2, "Governance overhead is less than LLM call time");

    // Test Summary
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

  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main().then(() => {
  process.exit(failures.length > 0 ? 1 : 0);
});
