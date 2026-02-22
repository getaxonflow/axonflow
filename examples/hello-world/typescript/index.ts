/**
 * AxonFlow Hello World - TypeScript
 *
 * The simplest example of using AxonFlow SDK with Gateway Mode.
 * Gateway Mode: Pre-check policies, make your own LLM call, then audit.
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   ✓ PASS: ${message}`);
  } else {
    console.log(`   ❌ FAIL: ${message}`);
    failures.push(message);
  }
}

// Initialize AxonFlow client with OAuth2-style credentials
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "demo",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "demo-secret",
  debug: true,
});

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || "",
});

async function main() {
  const query = "What is the capital of France?";

  console.log("AxonFlow Hello World - Gateway Mode\n");
  console.log(`Query: "${query}"\n`);

  try {
    // Step 1: Pre-check with AxonFlow policies
    console.log("Step 1: Policy pre-check...");
    const preCheck = await axonflow.getPolicyApprovedContext({
      userToken: process.env.AXONFLOW_USER_TOKEN || "demo-user",
      query,
      context: { example: "hello-world" },
    });

    assertCheck(preCheck.contextId !== "", "contextId is not empty");

    if (!preCheck.approved) {
      console.log(`BLOCKED: ${preCheck.blockReason}`);
      assertCheck(preCheck.blockReason !== "", "blockReason provided for blocked request");
      console.log(`Policies: ${preCheck.policies?.join(", ")}`);
    } else {
      console.log(`   Approved! Context ID: ${preCheck.contextId}\n`);
      assertCheck(preCheck.approved === true, "Pre-check approved for safe query");

      // Step 2: Make your own LLM call
      console.log("Step 2: Calling OpenAI...");
      const startTime = Date.now();
      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: query }],
        max_tokens: 100,
      });
      const latencyMs = Date.now() - startTime;

      const response = completion.choices[0]?.message?.content || "";
      assertCheck(response !== "", "OpenAI response is not empty");
      console.log(`   Response received in ${latencyMs}ms\n`);

      // Step 3: Audit the call
      console.log("Step 3: Auditing...");
      await axonflow.auditLLMCall({
        contextId: preCheck.contextId,
        responseSummary: response.substring(0, 100),
        provider: "openai",
        model: "gpt-4o-mini",
        tokenUsage: {
          promptTokens: completion.usage?.prompt_tokens || 0,
          completionTokens: completion.usage?.completion_tokens || 0,
          totalTokens: completion.usage?.total_tokens || 0,
        },
        latencyMs,
      });
      console.log("   Audit logged!\n");
      assertCheck(true, "Audit call completed successfully");

      // Display result
      console.log("=".repeat(50));
      console.log("Result:");
      console.log("=".repeat(50));
      console.log(response);
    }

    // Summary
    console.log("\n" + "=".repeat(50));
    if (failures.length === 0) {
      console.log("✓ ALL ASSERTIONS PASSED");
    } else {
      console.log(`❌ ${failures.length} ASSERTION(S) FAILED:`);
      failures.forEach((f) => console.log(`   - ${f}`));
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    if (errorMessage.includes("blocked") || errorMessage.includes("Policy")) {
      console.log("Request blocked by policy:", errorMessage);
    } else {
      console.error("Error:", errorMessage);
      failures.push(`Unexpected error: ${errorMessage}`);
    }
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
