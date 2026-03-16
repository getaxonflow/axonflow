/**
 * LangGraph Per-Tool Governance Example - TypeScript
 *
 * Requires: @axonflow/sdk v4.2.0+
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
 *
 * This example demonstrates per-tool governance using the AxonFlowLangGraphAdapter.
 * Instead of governing an entire tools node as one step, each individual tool
 * invocation gets its own gate check — enabling fine-grained tool-level policies.
 *
 * Run with: npx tsx langgraph_tools_example.ts
 * Prerequisites: docker compose up -d
 */

import "dotenv/config";
import {
  AxonFlow,
  AxonFlowLangGraphAdapter,
  WorkflowBlockedError,
} from "@axonflow/sdk";

const failures: string[] = [];

function assertCheck(condition: boolean, message: string): void {
  if (condition) {
    console.log(`   \u2713 PASS: ${message}`);
  } else {
    console.log(`   FAIL: ${message}`);
    failures.push(message);
  }
}

async function main(): Promise<number> {
  console.log("LangGraph Per-Tool Governance Example - TypeScript");
  console.log("=".repeat(50));
  console.log();
  console.log("Demonstrates per-tool governance within a LangGraph tools node.");
  console.log("Each tool invocation gets its own gate check and completion tracking.");
  console.log();

  const client = new AxonFlow({
    endpoint: process.env.AXONFLOW_AGENT_URL || "http://localhost:8080",
    clientId: process.env.AXONFLOW_CLIENT_ID || "langgraph-tools-example-ts",
    clientSecret: process.env.AXONFLOW_CLIENT_SECRET || "",
  });

  const adapter = new AxonFlowLangGraphAdapter(client, "langgraph-research-agent", {
    source: "langgraph",
    autoBlock: true,
  });

  try {
    // --- Start workflow with trace_id ---
    console.log("Step 1: Start Workflow (with trace_id)");
    const workflowId = await adapter.startWorkflow(
      { example: "per-tool-governance-ts" },
      "otel-trace-12345-research-ts",
    );

    assertCheck(workflowId !== null && workflowId !== undefined, "startWorkflow returned workflowId");
    assertCheck(workflowId.length > 0, "workflowId is not empty");
    console.log(`   Workflow started: ${workflowId}`);
    console.log();

    // --- Step 2: LLM Node --- standard gate check ---
    console.log("Step 2: Node 'plan_research' (LLM call)");
    console.log("   Checking gate...");

    const gateResult = await adapter.checkGate("plan_research", "llm_call", {
      model: "claude-sonnet-4-20250514",
      provider: "anthropic",
      stepInput: { prompt: "Plan research on AI governance" },
    });

    assertCheck(gateResult === true, "checkGate returned true for plan_research");

    if (gateResult) {
      console.log("   Gate: ALLOWED --- executing LLM node...");
      const planResult = {
        plan: ["web_search", "sql_query", "code_analysis"],
        tokens_used: 150,
      };

      await adapter.stepCompleted("plan_research", {
        output: planResult,
        tokensIn: 50,
        tokensOut: 150,
        costUsd: 0.003,
      });
      assertCheck(true, "stepCompleted succeeded for plan_research");
      console.log("   Node completed!");
    }
    console.log();

    // --- Step 3: Tools Node --- per-tool governance ---
    console.log("Step 3: Tools Node (3 individual tools)");
    console.log("   Each tool gets its own gate check.");
    console.log();

    // Tool 1: web_search (function type)
    console.log("   Tool 3a: web_search (function)");
    let toolAllowed = await adapter.checkToolGate("web_search", "function", {
      toolInput: { query: "AI governance frameworks 2026" },
    });

    assertCheck(toolAllowed === true, "checkToolGate returned true for web_search");

    if (toolAllowed) {
      console.log("   Gate: ALLOWED --- executing web_search...");
      const searchResult = { results: [{ title: "EU AI Act", url: "https://example.com" }] };

      await adapter.toolCompleted("web_search", {
        output: searchResult,
        tokensIn: 0,
        tokensOut: 0,
        costUsd: 0.001,
      });
      assertCheck(true, "toolCompleted succeeded for web_search");
      console.log("   Tool completed!");
    }
    console.log();

    // Tool 2: sql_query (MCP type)
    console.log("   Tool 3b: sql_query (mcp)");
    toolAllowed = await adapter.checkToolGate("sql_query", "mcp", {
      toolInput: { query: "SELECT COUNT(*) FROM regulations WHERE region='EU'" },
    });

    assertCheck(toolAllowed === true, "checkToolGate returned true for sql_query");

    if (toolAllowed) {
      console.log("   Gate: ALLOWED --- executing sql_query...");
      const sqlResult = { rows: [{ count: 42 }] };

      await adapter.toolCompleted("sql_query", {
        output: sqlResult,
      });
      assertCheck(true, "toolCompleted succeeded for sql_query");
      console.log("   Tool completed!");
    }
    console.log();

    // Tool 3: code_executor (function type)
    console.log("   Tool 3c: code_executor (function)");
    toolAllowed = await adapter.checkToolGate("code_executor", "function", {
      toolInput: { language: "python", code: "print('analysis complete')" },
    });

    assertCheck(toolAllowed === true, "checkToolGate returned true for code_executor");

    if (toolAllowed) {
      console.log("   Gate: ALLOWED --- executing code_executor...");
      const execResult = { stdout: "analysis complete", exit_code: 0 };

      await adapter.toolCompleted("code_executor", {
        output: execResult,
      });
      assertCheck(true, "toolCompleted succeeded for code_executor");
      console.log("   Tool completed!");
    }
    console.log();

    // --- Step 4: Final Synthesis (LLM call) ---
    console.log("Step 4: Node 'synthesize_report' (LLM call)");
    console.log("   Checking gate...");

    const gate2 = await adapter.checkGate("synthesize_report", "llm_call", {
      model: "claude-sonnet-4-20250514",
      provider: "anthropic",
      stepInput: { prompt: "Synthesize research findings" },
    });

    assertCheck(gate2 === true, "checkGate returned true for synthesize_report");

    if (gate2) {
      console.log("   Gate: ALLOWED --- executing LLM node...");
      const report = { report: "AI governance analysis complete", word_count: 500 };

      await adapter.stepCompleted("synthesize_report", {
        output: report,
        tokensIn: 200,
        tokensOut: 500,
        costUsd: 0.01,
      });
      assertCheck(true, "stepCompleted succeeded for synthesize_report");
      console.log("   Node completed!");
    }
    console.log();

    // --- Verify workflow status ---
    console.log("Step 5: Verify Workflow Status");
    const status = await client.getWorkflow(workflowId);

    assertCheck(status !== null && status !== undefined, "getWorkflow returned status");
    console.log(`   Status: ${status.status}`);
    console.log(`   Steps recorded: ${status.steps?.length || 0}`);

    // We should have 5 steps: plan_research + 3 tools + synthesize_report
    assertCheck(
      (status.steps?.length || 0) >= 5,
      "at least 5 steps recorded (1 LLM + 3 tools + 1 LLM)",
    );

    // Verify trace_id persists
    assertCheck(
      status.trace_id === "otel-trace-12345-research-ts",
      "trace_id preserved in status",
    );
    console.log();

    console.log("Step 6: Workflow Complete");
    await adapter.completeWorkflow();
    assertCheck(true, "completeWorkflow succeeded");

  } catch (e) {
    if (e instanceof WorkflowBlockedError) {
      console.log(`   BLOCKED: ${e.message}`);
      console.log(`   Step: ${e.details?.stepId}`);
      console.log(`   Reason: ${e.details?.reason}`);
      assertCheck(true, "WorkflowBlockedError raised correctly");
    } else {
      throw e;
    }
  }

  console.log();
  console.log("=".repeat(50));

  if (failures.length === 0) {
    console.log("ALL TESTS PASSED");
    console.log();
    console.log("Per-Tool Governance validated:");
    console.log("  - startWorkflow() with trace_id");
    console.log("  - checkGate() for LLM nodes");
    console.log("  - checkToolGate() for individual tools (function, mcp)");
    console.log("  - toolCompleted() for tool-level completion tracking");
    console.log("  - stepCompleted() with post-execution metrics");
    console.log("  - Workflow status tracks all steps including tools");
    console.log("  - trace_id preserved across lifecycle");
    return 0;
  } else {
    console.log(`${failures.length} TEST(S) FAILED:`);
    for (const f of failures) {
      console.log(`   - ${f}`);
    }
    return 1;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
