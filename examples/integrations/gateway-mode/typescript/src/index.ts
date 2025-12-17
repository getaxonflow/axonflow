/**
 * AxonFlow Gateway Mode - TypeScript Example
 *
 * This example demonstrates the Gateway Mode pattern:
 * 1. Pre-check: Validate request against policies BEFORE calling LLM
 * 2. LLM Call: Make your own LLM call directly (you control the provider)
 * 3. Audit: Log the interaction for compliance and monitoring
 *
 * Benefits:
 * - Lowest latency (~3-5ms overhead)
 * - Full control over LLM provider and parameters
 * - Complete audit trail for compliance
 * - Works with any LLM provider
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

// Configuration from environment
const config = {
  axonflow: {
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
    tenant: process.env.AXONFLOW_TENANT || "demo",
  },
  openai: {
    apiKey: process.env.OPENAI_API_KEY || "",
  },
};

async function main() {
  console.log("AxonFlow Gateway Mode - TypeScript Example\n");

  // Initialize clients
  const axonflow = new AxonFlow({
    endpoint: config.axonflow.endpoint,
    licenseKey: config.axonflow.licenseKey,
    tenant: config.axonflow.tenant,
  });

  const openai = new OpenAI({
    apiKey: config.openai.apiKey,
  });

  // Example user and query
  const userToken = "user-123";
  const query = "What are the benefits of AI governance in enterprise?";
  const context = {
    user_role: "developer",
    department: "engineering",
  };

  console.log(`Query: "${query}"`);
  console.log(`User: ${userToken}`);
  console.log(`Context:`, context);
  console.log("");

  try {
    // =========================================================================
    // STEP 1: Pre-Check - Validate against policies before LLM call
    // =========================================================================
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
    console.log(`   Approved: ${preCheckResult.approved}`);

    if (!preCheckResult.approved) {
      console.log(`   BLOCKED: ${preCheckResult.blockReason}`);
      console.log(`   Policies triggered: ${preCheckResult.policies?.join(", ")}`);
      return;
    }

    console.log("");

    // =========================================================================
    // STEP 2: LLM Call - Make your own call to your preferred provider
    // =========================================================================
    console.log("Step 2: LLM Call (OpenAI)...");
    const startLLM = Date.now();

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: "You are a helpful AI governance expert. Be concise.",
        },
        {
          role: "user",
          content: query,
        },
      ],
      max_tokens: 200,
    });

    const llmLatency = Date.now() - startLLM;
    const response = completion.choices[0]?.message?.content || "";
    const tokenUsage = completion.usage;

    console.log(`   Response received in ${llmLatency}ms`);
    console.log(`   Tokens: ${tokenUsage?.prompt_tokens} prompt, ${tokenUsage?.completion_tokens} completion`);
    console.log("");

    // =========================================================================
    // STEP 3: Audit - Log the interaction for compliance
    // =========================================================================
    console.log("Step 3: Audit Logging...");
    const startAudit = Date.now();

    await axonflow.auditLLMCall({
      contextId: preCheckResult.contextId,
      responseSummary: response.substring(0, 100),
      provider: "openai",
      model: "gpt-3.5-turbo",
      tokenUsage: {
        promptTokens: tokenUsage?.prompt_tokens || 0,
        completionTokens: tokenUsage?.completion_tokens || 0,
        totalTokens: tokenUsage?.total_tokens || 0,
      },
      latencyMs: llmLatency,
    });

    const auditLatency = Date.now() - startAudit;
    console.log(`   Audit logged in ${auditLatency}ms`);
    console.log("");

    // =========================================================================
    // Results
    // =========================================================================
    const totalLatency = preCheckLatency + auditLatency;
    console.log("=".repeat(60));
    console.log("Results");
    console.log("=".repeat(60));
    console.log(`\nResponse:\n${response}\n`);
    console.log("Latency Breakdown:");
    console.log(`   Pre-check:  ${preCheckLatency}ms`);
    console.log(`   LLM call:   ${llmLatency}ms`);
    console.log(`   Audit:      ${auditLatency}ms`);
    console.log("   -----------------");
    console.log(`   Governance: ${totalLatency}ms (overhead)`);
    console.log(`   Total:      ${preCheckLatency + llmLatency + auditLatency}ms`);
    console.log("");
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
