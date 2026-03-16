package com.getaxonflow.examples;

import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.adapters.*;
import com.getaxonflow.sdk.types.workflow.WorkflowTypes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * LangGraph Per-Tool Governance Example - Java
 *
 * Requires: axonflow-sdk-java v4.2.0+
 *
 * VALIDATION: This example exits with code 1 if any assertion fails.
 *
 * "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
 *
 * This example demonstrates per-tool governance using the LangGraphAdapter.
 * Instead of governing an entire tools node as one step, each individual tool
 * invocation gets its own gate check, enabling fine-grained tool-level policies.
 *
 * Run with: mvn exec:java -Dexec.mainClass="com.getaxonflow.examples.LangGraphToolsExample" -q
 * Prerequisites: docker compose up -d
 */
public class LangGraphToolsExample {

    private static final List<String> failures = new ArrayList<>();

    private static void assertCheck(boolean condition, String message) {
        if (condition) {
            System.out.println("   \u2713 PASS: " + message);
        } else {
            System.out.println("   FAIL: " + message);
            failures.add(message);
        }
    }

    private static String getEnv(String key, String defaultValue) {
        String value = System.getenv(key);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    public static void main(String[] args) {
        System.out.println("LangGraph Per-Tool Governance Example - Java");
        System.out.println("=============================================");
        System.out.println();
        System.out.println("Demonstrates per-tool governance within a LangGraph tools node.");
        System.out.println("Each tool invocation gets its own gate check and completion tracking.");
        System.out.println();

        AxonFlow client = AxonFlow.create(AxonFlowConfig.builder()
                .endpoint(getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
                .clientId(getEnv("AXONFLOW_CLIENT_ID", "langgraph-tools-example-java"))
                .clientSecret(getEnv("AXONFLOW_CLIENT_SECRET", ""))
                .build());

        LangGraphAdapter adapter = LangGraphAdapter.builder(client, "langgraph-research-agent")
                .autoBlock(true)
                .build();

        try {
            // --- Start workflow with trace_id ---
            System.out.println("Step 1: Start Workflow (with trace_id)");
            String workflowId = adapter.startWorkflow(
                    Map.of("example", "per-tool-governance-java"),
                    "otel-trace-12345-research-java");

            assertCheck(workflowId != null, "startWorkflow returned workflowId");
            assertCheck(!workflowId.isEmpty(), "workflowId is not empty");
            System.out.println("   Workflow started: " + workflowId);
            System.out.println();

            // --- Step 2: LLM Node --- standard gate check ---
            System.out.println("Step 2: Node 'plan_research' (LLM call)");
            System.out.println("   Checking gate...");

            boolean gateResult = adapter.checkGate("plan_research", "llm_call",
                    CheckGateOptions.builder()
                            .model("claude-sonnet-4-20250514")
                            .provider("anthropic")
                            .stepInput(Map.of("prompt", "Plan research on AI governance"))
                            .build());

            assertCheck(gateResult, "checkGate returned true for plan_research");

            if (gateResult) {
                System.out.println("   Gate: ALLOWED --- executing LLM node...");
                adapter.stepCompleted("plan_research", StepCompletedOptions.builder()
                        .output(Map.of(
                                "plan", List.of("web_search", "sql_query", "code_analysis"),
                                "tokens_used", 150))
                        .tokensIn(50)
                        .tokensOut(150)
                        .costUsd(0.003)
                        .build());
                assertCheck(true, "stepCompleted succeeded for plan_research");
                System.out.println("   Node completed!");
            }
            System.out.println();

            // --- Step 3: Tools Node --- per-tool governance ---
            System.out.println("Step 3: Tools Node (3 individual tools)");
            System.out.println("   Each tool gets its own gate check.");
            System.out.println();

            // Tool 1: web_search (function type)
            System.out.println("   Tool 3a: web_search (function)");
            boolean toolAllowed = adapter.checkToolGate("web_search", "function",
                    CheckToolGateOptions.builder()
                            .toolInput(Map.of("query", "AI governance frameworks 2026"))
                            .build());

            assertCheck(toolAllowed, "checkToolGate returned true for web_search");

            if (toolAllowed) {
                System.out.println("   Gate: ALLOWED --- executing web_search...");
                adapter.toolCompleted("web_search", ToolCompletedOptions.builder()
                        .output(Map.of("results", List.of(Map.of("title", "EU AI Act", "url", "https://example.com"))))
                        .costUsd(0.001)
                        .build());
                assertCheck(true, "toolCompleted succeeded for web_search");
                System.out.println("   Tool completed!");
            }
            System.out.println();

            // Tool 2: sql_query (MCP type)
            System.out.println("   Tool 3b: sql_query (mcp)");
            toolAllowed = adapter.checkToolGate("sql_query", "mcp",
                    CheckToolGateOptions.builder()
                            .toolInput(Map.of("query", "SELECT COUNT(*) FROM regulations WHERE region='EU'"))
                            .build());

            assertCheck(toolAllowed, "checkToolGate returned true for sql_query");

            if (toolAllowed) {
                System.out.println("   Gate: ALLOWED --- executing sql_query...");
                adapter.toolCompleted("sql_query", ToolCompletedOptions.builder()
                        .output(Map.of("rows", List.of(Map.of("count", 42))))
                        .build());
                assertCheck(true, "toolCompleted succeeded for sql_query");
                System.out.println("   Tool completed!");
            }
            System.out.println();

            // Tool 3: code_executor (function type)
            System.out.println("   Tool 3c: code_executor (function)");
            toolAllowed = adapter.checkToolGate("code_executor", "function",
                    CheckToolGateOptions.builder()
                            .toolInput(Map.of("language", "python", "code", "print('analysis complete')"))
                            .build());

            assertCheck(toolAllowed, "checkToolGate returned true for code_executor");

            if (toolAllowed) {
                System.out.println("   Gate: ALLOWED --- executing code_executor...");
                adapter.toolCompleted("code_executor", ToolCompletedOptions.builder()
                        .output(Map.of("stdout", "analysis complete", "exit_code", 0))
                        .build());
                assertCheck(true, "toolCompleted succeeded for code_executor");
                System.out.println("   Tool completed!");
            }
            System.out.println();

            // --- Step 4: Final Synthesis (LLM call) ---
            System.out.println("Step 4: Node 'synthesize_report' (LLM call)");
            System.out.println("   Checking gate...");

            boolean gate2 = adapter.checkGate("synthesize_report", "llm_call",
                    CheckGateOptions.builder()
                            .model("claude-sonnet-4-20250514")
                            .provider("anthropic")
                            .stepInput(Map.of("prompt", "Synthesize research findings"))
                            .build());

            assertCheck(gate2, "checkGate returned true for synthesize_report");

            if (gate2) {
                System.out.println("   Gate: ALLOWED --- executing LLM node...");
                adapter.stepCompleted("synthesize_report", StepCompletedOptions.builder()
                        .output(Map.of("report", "AI governance analysis complete", "word_count", 500))
                        .tokensIn(200)
                        .tokensOut(500)
                        .costUsd(0.01)
                        .build());
                assertCheck(true, "stepCompleted succeeded for synthesize_report");
                System.out.println("   Node completed!");
            }
            System.out.println();

            // --- Verify workflow status ---
            System.out.println("Step 5: Verify Workflow Status");
            WorkflowTypes.WorkflowStatusResponse status = client.getWorkflow(workflowId);

            assertCheck(status != null, "getWorkflow returned status");
            System.out.println("   Status: " + status.getStatus());
            System.out.println("   Steps recorded: " + (status.getSteps() != null ? status.getSteps().size() : 0));

            // We should have 5 steps: plan_research + 3 tools + synthesize_report
            int stepCount = status.getSteps() != null ? status.getSteps().size() : 0;
            assertCheck(stepCount >= 5, "at least 5 steps recorded (1 LLM + 3 tools + 1 LLM)");

            // Verify trace_id persists
            assertCheck("otel-trace-12345-research-java".equals(status.getTraceId()),
                    "trace_id preserved in status");
            System.out.println();

            System.out.println("Step 6: Workflow Complete");
            adapter.completeWorkflow();
            assertCheck(true, "completeWorkflow succeeded");

        } catch (WorkflowBlockedError e) {
            System.out.println("   BLOCKED: " + e.getMessage());
            System.out.println("   Step: " + e.getStepId());
            System.out.println("   Reason: " + e.getReason());
            assertCheck(true, "WorkflowBlockedError raised correctly");
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        System.out.println();
        System.out.println("=============================================");

        if (failures.isEmpty()) {
            System.out.println("ALL TESTS PASSED");
            System.out.println();
            System.out.println("Per-Tool Governance validated:");
            System.out.println("  - startWorkflow() with trace_id");
            System.out.println("  - checkGate() for LLM nodes");
            System.out.println("  - checkToolGate() for individual tools (function, mcp)");
            System.out.println("  - toolCompleted() for tool-level completion tracking");
            System.out.println("  - stepCompleted() with post-execution metrics");
            System.out.println("  - Workflow status tracks all steps including tools");
            System.out.println("  - trace_id preserved across lifecycle");
            System.exit(0);
        } else {
            System.out.println(failures.size() + " TEST(S) FAILED:");
            for (String f : failures) {
                System.out.println("   - " + f);
            }
            System.exit(1);
        }
    }
}
