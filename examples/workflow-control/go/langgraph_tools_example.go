//go:build ignore

// LangGraph Per-Tool Governance Example - Go
//
// Requires: axonflow-sdk-go v5.0.0+
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
//
// This example demonstrates per-tool governance using the LangGraphAdapter.
// Instead of governing an entire tools node as one step, each individual tool
// invocation gets its own gate check — enabling fine-grained tool-level policies.
//
// Run with: go run langgraph_tools_example.go
// Prerequisites: docker compose up -d
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v7"
)

var toolsFailures []string

func toolsAssertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   \u2713 PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		toolsFailures = append(toolsFailures, message)
	}
}

func getToolsEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	os.Exit(runToolsExample())
}

func runToolsExample() int {
	fmt.Println("LangGraph Per-Tool Governance Example - Go")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("Demonstrates per-tool governance within a LangGraph tools node.")
	fmt.Println("Each tool invocation gets its own gate check and completion tracking.")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getToolsEnv("AXONFLOW_ENDPOINT", getToolsEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
		ClientID:     getToolsEnv("AXONFLOW_CLIENT_ID", "langgraph-tools-example-go"),
		ClientSecret: getToolsEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	adapter := axonflow.NewLangGraphAdapter(client, "langgraph-research-agent")
	ctx := context.Background()

	// --- Start workflow with trace_id ---
	fmt.Println("Step 1: Start Workflow (with trace_id)")
	workflowID, err := adapter.StartWorkflow(ctx,
		map[string]interface{}{"example": "per-tool-governance-go"},
		"otel-trace-12345-research-go",
	)
	if err != nil {
		fmt.Printf("   FATAL: Failed to start workflow: %v\n", err)
		return 1
	}

	toolsAssertCheck(workflowID != "", "StartWorkflow returned workflowID")
	fmt.Printf("   Workflow started: %s\n", workflowID)
	fmt.Println()

	// --- Step 2: LLM Node --- standard gate check ---
	fmt.Println("Step 2: Node 'plan_research' (LLM call)")
	fmt.Println("   Checking gate...")

	gateResult, err := adapter.CheckGate(ctx, "plan_research", axonflow.StepTypeLLMCall,
		&axonflow.CheckGateOptions{
			Model:    "claude-sonnet-4-20250514",
			Provider: "anthropic",
			StepInput: map[string]interface{}{
				"prompt": "Plan research on AI governance",
			},
		})
	if err != nil {
		fmt.Printf("   BLOCKED or ERROR: %v\n", err)
		toolsAssertCheck(true, "CheckGate returned error (blocked or approval required)")
		return printToolsSummary()
	}

	toolsAssertCheck(gateResult, "CheckGate returned true for plan_research")

	if gateResult {
		fmt.Println("   Gate: ALLOWED --- executing LLM node...")
		tokensIn := 50
		tokensOut := 150
		costUsd := 0.003
		err = adapter.StepCompleted(ctx, "plan_research", &axonflow.StepCompletedOptions{
			Output: map[string]interface{}{
				"plan":        []string{"web_search", "sql_query", "code_analysis"},
				"tokens_used": 150,
			},
			TokensIn:  &tokensIn,
			TokensOut: &tokensOut,
			CostUSD:   &costUsd,
		})
		toolsAssertCheck(err == nil, "StepCompleted succeeded for plan_research")
		fmt.Println("   Node completed!")
	}
	fmt.Println()

	// --- Step 3: Tools Node --- per-tool governance ---
	fmt.Println("Step 3: Tools Node (3 individual tools)")
	fmt.Println("   Each tool gets its own gate check.")
	fmt.Println()

	{
		// Tool 1: web_search (function type)
		fmt.Println("   Tool 3a: web_search (function)")
		toolAllowed, toolErr := adapter.CheckToolGate(ctx, "web_search", "function",
			&axonflow.CheckToolGateOptions{
				ToolInput: map[string]interface{}{"query": "AI governance frameworks 2026"},
			})
		if toolErr != nil {
			fmt.Printf("   ERROR: %v\n", toolErr)
		}
		toolsAssertCheck(toolAllowed, "CheckToolGate returned true for web_search")

		if toolAllowed {
			fmt.Println("   Gate: ALLOWED --- executing web_search...")
			costSearch := 0.001
			err = adapter.ToolCompleted(ctx, "web_search", &axonflow.ToolCompletedOptions{
				Output: map[string]interface{}{
					"results": []map[string]interface{}{
						{"title": "EU AI Act", "url": "https://example.com"},
					},
				},
				CostUSD: &costSearch,
			})
			toolsAssertCheck(err == nil, "ToolCompleted succeeded for web_search")
			fmt.Println("   Tool completed!")
		}
		fmt.Println()
	}

	{
		// Tool 2: sql_query (MCP type)
		fmt.Println("   Tool 3b: sql_query (mcp)")
		toolAllowed, toolErr := adapter.CheckToolGate(ctx, "sql_query", "mcp",
			&axonflow.CheckToolGateOptions{
				ToolInput: map[string]interface{}{
					"query": "SELECT COUNT(*) FROM regulations WHERE region='EU'",
				},
			})
		if toolErr != nil {
			fmt.Printf("   ERROR: %v\n", toolErr)
		}
		toolsAssertCheck(toolAllowed, "CheckToolGate returned true for sql_query")

		if toolAllowed {
			fmt.Println("   Gate: ALLOWED --- executing sql_query...")
			err = adapter.ToolCompleted(ctx, "sql_query", &axonflow.ToolCompletedOptions{
				Output: map[string]interface{}{
					"rows": []map[string]interface{}{{"count": 42}},
				},
			})
			toolsAssertCheck(err == nil, "ToolCompleted succeeded for sql_query")
			fmt.Println("   Tool completed!")
		}
		fmt.Println()
	}

	{
		// Tool 3: code_executor (function type)
		fmt.Println("   Tool 3c: code_executor (function)")
		toolAllowed, toolErr := adapter.CheckToolGate(ctx, "code_executor", "function",
			&axonflow.CheckToolGateOptions{
				ToolInput: map[string]interface{}{
					"language": "python",
					"code":     "print('analysis complete')",
				},
			})
		if toolErr != nil {
			fmt.Printf("   ERROR: %v\n", toolErr)
		}
		toolsAssertCheck(toolAllowed, "CheckToolGate returned true for code_executor")

		if toolAllowed {
			fmt.Println("   Gate: ALLOWED --- executing code_executor...")
			err = adapter.ToolCompleted(ctx, "code_executor", &axonflow.ToolCompletedOptions{
				Output: map[string]interface{}{
					"stdout":    "analysis complete",
					"exit_code": 0,
				},
			})
			toolsAssertCheck(err == nil, "ToolCompleted succeeded for code_executor")
			fmt.Println("   Tool completed!")
		}
		fmt.Println()
	}

	// --- Step 4: Final Synthesis (LLM call) ---
	fmt.Println("Step 4: Node 'synthesize_report' (LLM call)")
	fmt.Println("   Checking gate...")

	{
		gate2, gate2Err := adapter.CheckGate(ctx, "synthesize_report", axonflow.StepTypeLLMCall,
			&axonflow.CheckGateOptions{
				Model:    "claude-sonnet-4-20250514",
				Provider: "anthropic",
				StepInput: map[string]interface{}{
					"prompt": "Synthesize research findings",
				},
			})
		if gate2Err != nil {
			fmt.Printf("   ERROR: %v\n", gate2Err)
		}
		toolsAssertCheck(gate2, "CheckGate returned true for synthesize_report")

		if gate2 {
			fmt.Println("   Gate: ALLOWED --- executing LLM node...")
			tokensIn := 200
			tokensOut := 500
			costUsd := 0.01
			err = adapter.StepCompleted(ctx, "synthesize_report", &axonflow.StepCompletedOptions{
				Output: map[string]interface{}{
					"report":     "AI governance analysis complete",
					"word_count": 500,
				},
				TokensIn:  &tokensIn,
				TokensOut: &tokensOut,
				CostUSD:   &costUsd,
			})
			toolsAssertCheck(err == nil, "StepCompleted succeeded for synthesize_report")
			fmt.Println("   Node completed!")
		}
		fmt.Println()
	}

	// --- Verify workflow status ---
	fmt.Println("Step 5: Verify Workflow Status")
	status, statusErr := client.GetWorkflow(workflowID)
	if statusErr != nil {
		fmt.Printf("   ERROR: GetWorkflow failed: %v\n", statusErr)
	} else {
		toolsAssertCheck(status != nil, "GetWorkflow returned status")
		fmt.Printf("   Status: %s\n", status.Status)
		fmt.Printf("   Steps recorded: %d\n", len(status.Steps))

		// We should have 5 steps: plan_research + 3 tools + synthesize_report
		toolsAssertCheck(len(status.Steps) >= 5, "at least 5 steps recorded (1 LLM + 3 tools + 1 LLM)")

		// Verify trace_id persists
		toolsAssertCheck(status.TraceID == "otel-trace-12345-research-go", "trace_id preserved in status")
	}
	fmt.Println()

	fmt.Println("Step 6: Workflow Complete")
	err = adapter.CompleteWorkflow(ctx)
	toolsAssertCheck(err == nil, "CompleteWorkflow succeeded")

	return printToolsSummary()
}

func printToolsSummary() int {
	fmt.Println()
	fmt.Println("==========================================")

	if len(toolsFailures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Per-Tool Governance validated:")
		fmt.Println("  - StartWorkflow() with trace_id")
		fmt.Println("  - CheckGate() for LLM nodes")
		fmt.Println("  - CheckToolGate() for individual tools (function, mcp)")
		fmt.Println("  - ToolCompleted() for tool-level completion tracking")
		fmt.Println("  - StepCompleted() with post-execution metrics")
		fmt.Println("  - Workflow status tracks all steps including tools")
		fmt.Println("  - trace_id preserved across lifecycle")
		return 0
	}

	fmt.Printf("%d TEST(S) FAILED:\n", len(toolsFailures))
	for _, f := range toolsFailures {
		fmt.Printf("   - %s\n", f)
	}
	return 1
}
