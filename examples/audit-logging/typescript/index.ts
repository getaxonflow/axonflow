/**
 * AxonFlow Audit Logging - TypeScript
 *
 * Demonstrates the complete Gateway Mode workflow with audit logging:
 * 1. Pre-check - Validate request against policies
 * 2. LLM Call - Make your own call to OpenAI
 * 3. Audit - Log the interaction for compliance
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  licenseKey: process.env.AXONFLOW_LICENSE_KEY || "",
  tenant: process.env.AXONFLOW_TENANT || "audit-logging-demo",
});

const openaiKey = process.env.OPENAI_API_KEY || "";
const openai = openaiKey ? new OpenAI({ apiKey: openaiKey }) : null;

interface QueryTest {
  name: string;
  query: string;
}

async function main() {
  console.log("AxonFlow Audit Logging - TypeScript");
  console.log("=".repeat(40));
  console.log();

  if (!openai) {
    console.log("Note: Using mock LLM responses (set OPENAI_API_KEY for real calls)");
    console.log();
  }

  const queries: QueryTest[] = [
    { name: "Simple Question", query: "What is the capital of France?" },
    { name: "Technical Query", query: "Explain the CAP theorem in distributed systems." },
    { name: "Analysis Request", query: "What are the key benefits of containerization?" },
  ];

  for (const q of queries) {
    console.log(`Query: ${q.name}`);
    console.log(`  "${q.query}"`);
    console.log();

    // Step 1: Pre-check
    console.log("Step 1: Policy Pre-Check...");
    const precheckStart = Date.now();

    let precheck;
    try {
      precheck = await axonflow.getPolicyApprovedContext({
        userToken: "audit-user",
        query: q.query,
        context: { example: "audit-logging" },
      });
    } catch (error) {
      console.log(`   Error: ${error instanceof Error ? error.message : error}`);
      continue;
    }

    const precheckLatency = Date.now() - precheckStart;
    console.log(`   Latency: ${precheckLatency}ms`);
    console.log(`   Context ID: ${precheck.contextId}`);

    if (!precheck.approved) {
      console.log(`   BLOCKED: ${precheck.blockReason}`);
      console.log();
      continue;
    }
    console.log("   Status: APPROVED");
    console.log();

    // Step 2: LLM Call
    console.log("Step 2: LLM Call (OpenAI)...");
    const llmStart = Date.now();

    let response: string;
    let promptTokens: number;
    let completionTokens: number;
    let totalTokens: number;

    if (openai) {
      const completion = await openai.chat.completions.create({
        model: "gpt-3.5-turbo",
        messages: [{ role: "user", content: q.query }],
        max_tokens: 150,
      });
      response = completion.choices[0]?.message?.content || "";
      promptTokens = completion.usage?.prompt_tokens || 0;
      completionTokens = completion.usage?.completion_tokens || 0;
      totalTokens = completion.usage?.total_tokens || 0;
    } else {
      // Mock response
      await new Promise((resolve) => setTimeout(resolve, 100));
      response = `Mock response for: ${q.query}`;
      promptTokens = 20;
      completionTokens = 30;
      totalTokens = 50;
    }

    const llmLatency = Date.now() - llmStart;
    console.log(`   Latency: ${llmLatency}ms`);
    console.log(`   Tokens: ${promptTokens} prompt, ${completionTokens} completion`);
    console.log();

    // Step 3: Audit
    console.log("Step 3: Audit Logging...");
    const auditStart = Date.now();

    const responseSummary = response.length > 100 ? response.substring(0, 100) + "..." : response;

    try {
      await axonflow.auditLLMCall({
        contextId: precheck.contextId,
        responseSummary,
        provider: "openai",
        model: "gpt-3.5-turbo",
        tokenUsage: {
          promptTokens,
          completionTokens,
          totalTokens,
        },
        latencyMs: llmLatency,
      });
      const auditLatency = Date.now() - auditStart;
      console.log(`   Latency: ${auditLatency}ms`);
      console.log("   Audit logged successfully");

      // Summary
      const governance = precheckLatency + auditLatency;
      const total = precheckLatency + llmLatency + auditLatency;

      console.log();
      console.log("   Latency Breakdown:");
      console.log(`     Pre-check:  ${precheckLatency}ms`);
      console.log(`     LLM call:   ${llmLatency}ms`);
      console.log(`     Audit:      ${auditLatency}ms`);
      console.log(`     Governance: ${governance}ms (${((governance / total) * 100).toFixed(1)}% overhead)`);
      console.log(`     Total:      ${total}ms`);
    } catch (error) {
      console.log(`   Warning: Audit failed: ${error instanceof Error ? error.message : error}`);
    }

    console.log();
    console.log("=".repeat(40));
    console.log();
  }

  console.log("Audit Logging Complete!");
  console.log();
  console.log("Query audit logs via Orchestrator API:");
  console.log("  curl http://localhost:8081/api/v1/audit/tenant/audit-logging-demo");
}

main();
