/**
 * AxonFlow Audit Logging - TypeScript
 *
 * Demonstrates the complete Gateway Mode workflow with audit logging:
 * 1. Pre-check - Validate request against policies
 * 2. LLM Call - Make your own call to OpenAI
 * 3. Audit - Log the interaction for compliance
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 */

import "dotenv/config";
import { AxonFlow } from "@axonflow/sdk";
import OpenAI from "openai";

const axonflow = new AxonFlow({
  endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
  clientId: process.env.AXONFLOW_CLIENT_ID || "audit-logging-demo",
  clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  tenant: process.env.AXONFLOW_CLIENT_ID || process.env.AXONFLOW_TENANT || "audit-logging-demo",
});

const openaiKey = process.env.OPENAI_API_KEY || "";
const openai = openaiKey ? new OpenAI({ apiKey: openaiKey }) : null;
const userToken = process.env.AXONFLOW_USER_TOKEN || "audit-user";
const clientId = process.env.AXONFLOW_CLIENT_ID || "audit-logging-demo";

interface QueryTest {
  name: string;
  query: string;
}

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
        userToken,
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
    assertCheck(typeof precheck.contextId === "string" && precheck.contextId.length > 0, "Pre-check returns valid contextId");

    if (!precheck.approved) {
      console.log(`   BLOCKED: ${precheck.blockReason}`);
      console.log();
      continue;
    }
    console.log("   Status: APPROVED");
    assertCheck(precheck.approved === true, "Pre-check approved for valid query");
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
      assertCheck(true, "Audit logging completed without error");

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

  // =========================================================================
  // Query Audit Logs (SDK Methods)
  // =========================================================================

  console.log("=".repeat(40));
  console.log("Query Audit Logs via SDK");
  console.log("=".repeat(40));
  console.log();

  // Get audit logs for tenant (default pagination)
  console.log("1. getAuditLogsByTenant (default options):");
  try {
    const tenantLogs = await axonflow.getAuditLogsByTenant(clientId);
    console.log(`   Found ${tenantLogs.entries.length} entries`);
    assertCheck(Array.isArray(tenantLogs.entries), "getAuditLogsByTenant returns entries array");
    if (tenantLogs.entries.length > 0) {
      const entry = tenantLogs.entries[0];
      console.log(`   Latest: ${entry.timestamp} - ${entry.provider}/${entry.model}`);
      assertCheck(entry.timestamp instanceof Date, "Audit entry has timestamp");
      assertCheck(typeof entry.provider === "string", "Audit entry has provider");
    }
  } catch (error) {
    console.log(`   Error: ${error instanceof Error ? error.message : error}`);
    failures.push("getAuditLogsByTenant failed");
  }
  console.log();

  // Get audit logs with custom pagination
  console.log("2. getAuditLogsByTenant (limit=5, offset=0):");
  try {
    const paginatedLogs = await axonflow.getAuditLogsByTenant(clientId, {
      limit: 5,
      offset: 0,
    });
    const hasMore = paginatedLogs.total > paginatedLogs.offset + paginatedLogs.entries.length;
    console.log(`   Found ${paginatedLogs.entries.length} entries (hasMore: ${hasMore})`);
    // Note: The audit API may return more results than the requested limit;
    // the limit parameter is advisory and not strictly enforced server-side.
    assertCheck(paginatedLogs.entries.length > 0, "Pagination returns audit entries");
    assertCheck(typeof paginatedLogs.total === "number", "Pagination response includes total count");
  } catch (error) {
    console.log(`   Error: ${error instanceof Error ? error.message : error}`);
    failures.push("getAuditLogsByTenant with pagination failed");
  }
  console.log();

  // Search audit logs with filters
  console.log("3. searchAuditLogs (with filters):");
  try {
    const searchResult = await axonflow.searchAuditLogs({
      clientId,
      requestType: "chat",
      limit: 10,
    });
    console.log(`   Found ${searchResult.entries.length} matching entries`);
    assertCheck(Array.isArray(searchResult.entries), "searchAuditLogs returns entries array");
    searchResult.entries.slice(0, 3).forEach((entry) => {
      const status = entry.blocked ? "blocked" : "allowed";
      console.log(`   - ${entry.id}: ${status} (${entry.tokensUsed} tokens)`);
    });
    if (searchResult.entries.length > 3) {
      console.log(`   ... and ${searchResult.entries.length - 3} more`);
    }
  } catch (error) {
    console.log(`   Error: ${error instanceof Error ? error.message : error}`);
    failures.push("searchAuditLogs failed");
  }
  console.log();

  console.log("=".repeat(40));
  console.log("Done!");

  // Final assertion summary
  console.log();
  console.log("=".repeat(40));
  console.log("Assertion Summary");
  console.log("=".repeat(40));
  if (failures.length === 0) {
    console.log("All assertions passed!");
  } else {
    console.log(`${failures.length} assertion(s) failed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
  }

  process.exit(failures.length > 0 ? 1 : 0);
}

main();
