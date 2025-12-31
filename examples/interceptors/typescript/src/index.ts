/**
 * AxonFlow LLM Interceptor Example - TypeScript
 *
 * Demonstrates how to wrap LLM provider clients with AxonFlow governance.
 * This provides transparent policy enforcement without changing your existing
 * LLM call patterns.
 *
 * This example shows the recommended Gateway Mode approach:
 * - Pre-check queries against policies before LLM calls
 * - Block requests that violate policies
 * - Audit LLM responses for compliance tracking
 *
 * Usage:
 *   export AXONFLOW_AGENT_URL=http://localhost:8080
 *   export OPENAI_API_KEY=your-openai-key
 *   npx ts-node src/index.ts
 */

import "dotenv/config";
import { AxonFlow, PolicyViolationError } from "@axonflow/sdk";
import OpenAI from "openai";

// Initialize AxonFlow client (Community Mode - no auth required)
const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  tenant: process.env.AXONFLOW_TENANT || "interceptor-demo",
  debug: true,
});

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || "",
});

/**
 * GovernedOpenAI wraps OpenAI client with AxonFlow governance.
 * All calls are automatically policy-checked and audited.
 */
class GovernedOpenAI {
  private axonflow: AxonFlow;
  private openai: OpenAI;
  private userToken: string;

  constructor(axonflow: AxonFlow, openai: OpenAI, userToken: string) {
    this.axonflow = axonflow;
    this.openai = openai;
    this.userToken = userToken;
  }

  /**
   * Create a chat completion with AxonFlow governance
   */
  async createChatCompletion(
    messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[],
    options?: Partial<OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming>
  ): Promise<OpenAI.Chat.Completions.ChatCompletion> {
    // Extract query from messages
    const query = messages
      .filter((m) => m.role === "user")
      .map((m) => (typeof m.content === "string" ? m.content : ""))
      .join(" ");

    // Step 1: Pre-check with AxonFlow policies
    const preCheck = await this.axonflow.getPolicyApprovedContext({
      userToken: this.userToken,
      query,
      context: { provider: "openai", model: options?.model || "gpt-3.5-turbo" },
    });

    if (!preCheck.approved) {
      throw new PolicyViolationError(
        preCheck.blockReason || "Policy violation",
        preCheck.policies || ["unknown"]
      );
    }

    // Step 2: Make the LLM call
    const startTime = Date.now();
    const completion = await this.openai.chat.completions.create({
      model: options?.model || "gpt-3.5-turbo",
      messages,
      max_tokens: options?.max_tokens || 100,
      ...options,
    });
    const latencyMs = Date.now() - startTime;

    // Step 3: Audit the call
    const response = completion.choices[0]?.message?.content || "";
    await this.axonflow.auditLLMCall({
      contextId: preCheck.contextId,
      responseSummary: response.substring(0, 100),
      provider: "openai",
      model: options?.model || "gpt-3.5-turbo",
      tokenUsage: {
        promptTokens: completion.usage?.prompt_tokens || 0,
        completionTokens: completion.usage?.completion_tokens || 0,
        totalTokens: completion.usage?.total_tokens || 0,
      },
      latencyMs,
    });

    return completion;
  }
}

async function runTest(
  governedClient: GovernedOpenAI,
  query: string,
  description: string
): Promise<void> {
  console.log(`${description}`);
  console.log("-".repeat(40));
  console.log(`Query: ${query}`);

  try {
    const response = await governedClient.createChatCompletion([
      { role: "user", content: query },
    ]);

    console.log("Status: APPROVED");
    console.log(`Response: ${response.choices[0]?.message?.content}`);
  } catch (error) {
    if (error instanceof PolicyViolationError) {
      console.log("Status: BLOCKED");
      console.log(`Reason: ${error.message}`);
    } else {
      console.log(`Error: ${error instanceof Error ? error.message : error}`);
    }
  }
  console.log();
}

async function main() {
  console.log("AxonFlow LLM Interceptor Example - TypeScript");
  console.log("=".repeat(60));
  console.log();

  // Create governed OpenAI client
  const governedClient = new GovernedOpenAI(axonflow, openai, "user-123");

  console.log("Testing LLM Interceptor with OpenAI (Gateway Mode)");
  console.log("-".repeat(60));
  console.log();

  // Example 1: Safe query (should pass)
  await runTest(
    governedClient,
    "What is the capital of France?",
    "Example 1: Safe Query"
  );

  // Example 2: Query with PII (should be blocked)
  await runTest(
    governedClient,
    "Process refund for SSN 123-45-6789",
    "Example 2: Query with PII (Expected: Blocked)"
  );

  // Example 3: SQL injection attempt (should be blocked)
  await runTest(
    governedClient,
    "SELECT * FROM users WHERE 1=1; DROP TABLE users;--",
    "Example 3: SQL Injection (Expected: Blocked)"
  );

  console.log("=".repeat(60));
  console.log("TypeScript LLM Interceptor Test: COMPLETE");
  console.log();
  console.log("Note: This example uses Gateway Mode (recommended).");
  console.log("The wrapOpenAIClient interceptor is deprecated in v2.0.0.");
  console.log("See: https://docs.getaxonflow.com/sdk/gateway-mode");
}

main().catch(console.error);
