/**
 * AxonFlow Hello World - TypeScript
 *
 * The simplest example of using AxonFlow SDK with Gateway Mode.
 * Gateway Mode: Pre-check policies, make your own LLM call, then audit.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

// Initialize AxonFlow client
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "demo",
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
      userToken: "demo-user",
      query,
      context: { example: "hello-world" },
    });

    if (!preCheck.approved) {
      console.log(`BLOCKED: ${preCheck.blockReason}`);
      console.log(`Policies: ${preCheck.policies?.join(", ")}`);
      return;
    }
    console.log(`   Approved! Context ID: ${preCheck.contextId}\n`);

    // Step 2: Make your own LLM call
    console.log("Step 2: Calling OpenAI...");
    const startTime = Date.now();
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [{ role: "user", content: query }],
      max_tokens: 100,
    });
    const latencyMs = Date.now() - startTime;

    const response = completion.choices[0]?.message?.content || "";
    console.log(`   Response received in ${latencyMs}ms\n`);

    // Step 3: Audit the call
    console.log("Step 3: Auditing...");
    await axonflow.auditLLMCall({
      contextId: preCheck.contextId,
      responseSummary: response.substring(0, 100),
      provider: "openai",
      model: "gpt-3.5-turbo",
      tokenUsage: {
        promptTokens: completion.usage?.prompt_tokens || 0,
        completionTokens: completion.usage?.completion_tokens || 0,
        totalTokens: completion.usage?.total_tokens || 0,
      },
      latencyMs,
    });
    console.log("   Audit logged!\n");

    // Display result
    console.log("=".repeat(50));
    console.log("Result:");
    console.log("=".repeat(50));
    console.log(response);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    if (errorMessage.includes("blocked") || errorMessage.includes("Policy")) {
      console.log("Request blocked by policy:", errorMessage);
    } else {
      console.error("Error:", errorMessage);
      process.exit(1);
    }
  }
}

main();
