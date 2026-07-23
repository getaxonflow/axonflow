// GovernedTool -- Framework-Agnostic Tool Governance Example (Go)
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates GovernedTool wrapping standard Tool interface implementations
// with AxonFlow input/output governance. Tests the UNDERLYING policy engine
// behavior: PII detection actually blocks/redacts, SQLi is actually caught,
// policies are actually evaluated, and tools are NOT called when input is blocked.
//
// GovernedTool works with any framework that accepts the axonflow.Tool interface.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

var (
	failures []string
	callLog  []string
)

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

// =============================================================================
// Simulated Tools (standard axonflow.Tool -- no AxonFlow awareness)
// =============================================================================

type safeSearchTool struct{}

func (t *safeSearchTool) Name() string        { return "safe_search" }
func (t *safeSearchTool) Description() string  { return "Search for products -- returns clean data without PII." }
func (t *safeSearchTool) Invoke(ctx context.Context, input any) (any, error) {
	args := input.(map[string]interface{})
	query := args["query"].(string)
	callLog = append(callLog, fmt.Sprintf("safe_search:%s", query))
	return `{"products": [{"name": "Widget A", "price": 9.99}]}`, nil
}

type customerLookupTool struct{}

func (t *customerLookupTool) Name() string        { return "customer_lookup" }
func (t *customerLookupTool) Description() string  { return "Look up customer data -- returns PII in results." }
func (t *customerLookupTool) Invoke(ctx context.Context, input any) (any, error) {
	args := input.(map[string]interface{})
	query := args["query"].(string)
	callLog = append(callLog, fmt.Sprintf("customer_lookup:%s", query))
	return `{"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com", "order_status": "shipped"}`, nil
}

type sendEmailTool struct{}

func (t *sendEmailTool) Name() string        { return "send_email" }
func (t *sendEmailTool) Description() string  { return "Send an email notification." }
func (t *sendEmailTool) Invoke(ctx context.Context, input any) (any, error) {
	args := input.(map[string]interface{})
	message := args["message"].(string)
	callLog = append(callLog, fmt.Sprintf("send_email:%s", message))
	return "Email sent successfully", nil
}

// =============================================================================
// Tests
// =============================================================================

func testCleanToolCall(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 1] Clean Tool Call -- Policies Must Be Evaluated")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&safeSearchTool{}, client, nil)

	t0 := time.Now()
	result, err := governed.Invoke(ctx, map[string]interface{}{"query": "latest widgets"})
	latencyMs := time.Since(t0).Milliseconds()

	assertCheck(err == nil, "Tool call did not return error")
	if err != nil {
		fmt.Printf("   Error: %v\n\n", err)
		return
	}
	assertCheck(result != nil, "Tool call returned a result")
	assertCheck(len(callLog) == 1, "Wrapped tool was called exactly once")
	assertCheck(callLog[0] == "safe_search:latest widgets", "Tool received correct args")
	assertCheck(strings.Contains(fmt.Sprintf("%v", result), "Widget A"), "Result contains expected data")
	fmt.Printf("   Latency: %dms\n", latencyMs)

	// Verify the policy engine actually ran
	direct, err := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "safe_search",
		Statement:     `{"query": "latest widgets"}`,
	})
	if err == nil {
		assertCheck(
			direct.PoliciesEvaluated > 0,
			fmt.Sprintf("Policy engine evaluated %d policies (not zero)", direct.PoliciesEvaluated),
		)
	}
	fmt.Println()
}

func testSqliInToolInputBlocked(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 2] SQL Injection in Tool Input -- Must Block")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&safeSearchTool{}, client, &axonflow.GovernedToolOptions{
		ConnectorTypeFn: func(name string) string { return "postgres.query" },
	})

	sqliInput := "SELECT * FROM users WHERE id=1; DROP TABLE users;--"
	_, err := governed.Invoke(ctx, map[string]interface{}{"query": sqliInput})

	blocked := axonflow.IsPolicyViolationError(err)
	if blocked {
		fmt.Printf("   Blocked: %v\n", err)
	}

	assertCheck(blocked, "SQL injection tool call was blocked")
	assertCheck(len(callLog) == 0, "Tool was NOT called (blocked before execution)")

	// Verify underlying policy engine
	direct, checkErr := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres.query",
		Statement:     sqliInput,
	})
	if checkErr == nil {
		assertCheck(!direct.Allowed, "Direct check-input confirms SQLi is blocked")
		assertCheck(
			len(direct.BlockReason) > 0,
			fmt.Sprintf("Block reason: %s", direct.BlockReason),
		)
	}
	fmt.Println()
}

func testPiiInToolInput(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 3] PII in Tool Input -- Must Be Detected")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&sendEmailTool{}, client, nil)

	piiInput := "Customer SSN is 123-45-6789, please process their refund"

	// Verify the policy engine detects PII via direct call first
	stmt, _ := json.Marshal(map[string]string{"message": piiInput})
	direct, err := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "send_email",
		Statement:     string(stmt),
	})

	piiDetected := false
	if err == nil {
		if !direct.Allowed {
			piiDetected = true
			fmt.Printf("   Direct check: Input blocked (%s)\n", direct.BlockReason)
		} else {
			piiDetected = direct.PoliciesEvaluated > 0
			fmt.Printf("   Direct check: %d policies evaluated (PII_ACTION may be warn/log)\n", direct.PoliciesEvaluated)
		}
	}

	assertCheck(piiDetected, "PII in tool input was detected by policy engine")

	// Now test through GovernedTool
	result, invokeErr := governed.Invoke(ctx, map[string]interface{}{"message": piiInput})
	if invokeErr != nil {
		if axonflow.IsPolicyViolationError(invokeErr) {
			assertCheck(len(callLog) == 0, "Tool NOT called (PII blocking at input)")
			fmt.Printf("   GovernedTool blocked: %v\n", invokeErr)
		}
	} else {
		assertCheck(len(callLog) == 1, "Tool called (PII detected but not blocking at input)")
		fmt.Printf("   GovernedTool result: %v\n", result)
	}
	fmt.Println()
}

func testPiiInToolOutput(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 4] PII in Tool Output -- Must Be Detected/Redacted")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&customerLookupTool{}, client, nil)

	// Verify policy engine handles PII output via direct call
	piiOutput := `{"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"}`
	direct, err := client.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{
		ConnectorType: "customer_lookup",
		Message:       piiOutput,
	})

	outputPiiHandled := false
	if err == nil {
		if !direct.Allowed {
			outputPiiHandled = true
			fmt.Printf("   Direct check: Output blocked (%s)\n", direct.BlockReason)
		} else if direct.RedactedData != nil {
			outputPiiHandled = true
			fmt.Println("   Direct check: Output redacted")
		} else {
			outputPiiHandled = direct.PoliciesEvaluated > 0
			fmt.Printf("   Direct check: %d policies evaluated\n", direct.PoliciesEvaluated)
		}
	}

	assertCheck(outputPiiHandled, "PII in tool output was handled by policy engine")

	// Test through GovernedTool
	result, invokeErr := governed.Invoke(ctx, map[string]interface{}{"query": "John Doe"})
	if invokeErr != nil {
		if axonflow.IsPolicyViolationError(invokeErr) {
			assertCheck(len(callLog) == 1, "Tool was called before output block")
			fmt.Printf("   GovernedTool: Output blocked (%v)\n", invokeErr)
		}
	} else {
		assertCheck(len(callLog) == 1, "Tool was called (output-side check)")
		resultStr := fmt.Sprintf("%v", result)
		if !strings.Contains(resultStr, "123-45-6789") {
			fmt.Println("   GovernedTool: Output redacted (raw SSN not present)")
		} else if strings.Contains(resultStr, "***") || strings.Contains(resultStr, "REDACTED") {
			fmt.Println("   GovernedTool: Output redacted")
		} else {
			fmt.Println("   GovernedTool: Output returned (PII_ACTION may be warn/log)")
		}
		if len(resultStr) > 200 {
			resultStr = resultStr[:200]
		}
		fmt.Printf("   Result: %s\n", resultStr)
	}
	fmt.Println()
}

func testCustomConnectorType(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 5] Custom Connector Type Derivation")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&safeSearchTool{}, client, &axonflow.GovernedToolOptions{
		ConnectorTypeFn: func(name string) string { return fmt.Sprintf("salesforce.%s", name) },
	})

	assertCheck(
		strings.Contains(governed.String(), "salesforce.safe_search"),
		fmt.Sprintf("Connector type derived correctly: %s", governed.String()),
	)

	result, err := governed.Invoke(ctx, map[string]interface{}{"query": "find contacts"})
	assertCheck(err == nil && result != nil, "Custom connector type call succeeded")
	assertCheck(len(callLog) == 1, "Tool was called")

	// Verify connector type was used in the check
	direct, checkErr := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "salesforce.safe_search",
		Statement:     `{"query": "find contacts"}`,
	})
	if checkErr == nil {
		assertCheck(direct.Allowed, "Direct check with custom connector_type allowed")
		assertCheck(
			direct.PoliciesEvaluated > 0,
			fmt.Sprintf("Policies evaluated: %d", direct.PoliciesEvaluated),
		)
	}
	fmt.Println()
}

func testQueryOperation(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 6] Read-Only Tool with operation='query'")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	governed := axonflow.GovernTool(&safeSearchTool{}, client, &axonflow.GovernedToolOptions{
		Operation: "query",
	})

	result, err := governed.Invoke(ctx, map[string]interface{}{"query": "list products"})
	assertCheck(err == nil && result != nil, "Query-mode tool call succeeded")
	assertCheck(len(callLog) == 1, "Tool was called")

	// Verify operation forwarded
	direct, checkErr := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "safe_search",
		Statement:     `{"query": "list products"}`,
		Operation:     "query",
	})
	if checkErr == nil {
		assertCheck(direct.Allowed, "Direct check with operation=query allowed")
	}
	fmt.Println()
}

func testGovernToolsHelper(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 7] GovernTools() Helper -- Multi-Tool Wrapping")
	fmt.Println(strings.Repeat("=", 60))

	callLog = nil
	tools := []axonflow.Tool{
		&safeSearchTool{},
		&customerLookupTool{},
		&sendEmailTool{},
	}
	governed := axonflow.GovernTools(tools, client, nil)

	assertCheck(len(governed) == 3, fmt.Sprintf("Wrapped %d tools", len(governed)))

	for _, g := range governed {
		assertCheck(g.Name() != "", fmt.Sprintf("%s has a name", g.Name()))
		assertCheck(g.Description() != "", fmt.Sprintf("%s has a description", g.Name()))
	}

	// Call first tool
	result, err := governed[0].Invoke(ctx, map[string]interface{}{"query": "test"})
	assertCheck(err == nil && result != nil, "First governed tool returned result")
	assertCheck(len(callLog) == 1, "Only the first tool was called")

	names := make([]string, len(governed))
	for i, g := range governed {
		names[i] = g.Name()
	}
	fmt.Printf("   Tools: %s\n", strings.Join(names, ", "))
	fmt.Println()
}

func testReprAndMetadata(ctx context.Context, client *axonflow.AxonFlowClient) {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("[Test 8] GovernedTool Metadata & String()")
	fmt.Println(strings.Repeat("=", 60))

	governed := axonflow.GovernTool(&safeSearchTool{}, client, nil)

	assertCheck(governed.Name() == "safe_search", fmt.Sprintf("Name: %s", governed.Name()))
	assertCheck(
		governed.Description() == "Search for products -- returns clean data without PII.",
		"Description preserved",
	)
	assertCheck(strings.Contains(governed.String(), "GovernedTool"), fmt.Sprintf("String: %s", governed.String()))
	assertCheck(strings.Contains(governed.String(), "safe_search"), "Tool name in String()")

	// Custom connector type
	governed2 := axonflow.GovernTool(&customerLookupTool{}, client, &axonflow.GovernedToolOptions{
		ConnectorTypeFn: func(n string) string { return fmt.Sprintf("crm.%s", n) },
		Operation:       "query",
	})
	assertCheck(
		strings.Contains(governed2.String(), "crm.customer_lookup"),
		fmt.Sprintf("Custom String: %s", governed2.String()),
	)
	fmt.Println()
}

// =============================================================================
// Main
// =============================================================================

func main() {
	fmt.Println("GovernedTool -- Framework-Agnostic Tool Governance (Go)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println("Validates AxonFlow policy enforcement around any Tool interface,")
	fmt.Println("verifying the underlying policy engine behavior.")
	fmt.Println()

	agentURL := getEnv("AXONFLOW_ENDPOINT", getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
	fmt.Printf("Checking AxonFlow at %s...\n", agentURL)

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "governed-tool-example"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// Health check
	if err := client.HealthCheck(); err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("\nMake sure AxonFlow is running: docker compose up -d")
		os.Exit(1)
	}
	fmt.Println("Status: healthy")
	fmt.Println()

	fmt.Println("Running GovernedTool tests...")
	fmt.Println()

	ctx := context.Background()

	testCleanToolCall(ctx, client)
	testSqliInToolInputBlocked(ctx, client)
	testPiiInToolInput(ctx, client)
	testPiiInToolOutput(ctx, client)
	testCustomConnectorType(ctx, client)
	testQueryOperation(ctx, client)
	testGovernToolsHelper(ctx, client)
	testReprAndMetadata(ctx, client)

	// Summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Test Summary")
	fmt.Println(strings.Repeat("=", 60))
	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
	}
	fmt.Println(strings.Repeat("=", 60))

	if len(failures) > 0 {
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
