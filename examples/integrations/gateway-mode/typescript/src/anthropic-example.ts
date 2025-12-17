/**
 * AxonFlow Gateway Mode - Anthropic Claude Example
 *
 * Demonstrates Gateway Mode with Anthropic's Claude models.
 * Same pattern as OpenAI: Pre-check -> LLM Call -> Audit
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import Anthropic from "@anthropic-ai/sdk";

const config = {
  axonflow: {
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
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
    licenseKey: config.axonflow.licenseKey,
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

    if (!preCheckResult.approved) {
      console.log(`   BLOCKED: ${preCheckResult.blockReason}`);
      return;
    }
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
    console.log("");

    // Results
    const governanceOverhead = preCheckLatency + auditLatency;
    console.log("=".repeat(60));
    console.log(`Response:\n${response}\n`);
    console.log(`Governance overhead: ${governanceOverhead}ms`);
    console.log(`   (Pre-check: ${preCheckLatency}ms + Audit: ${auditLatency}ms)`);
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
