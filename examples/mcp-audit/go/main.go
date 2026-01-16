// MCP Audit Logging Example - Go SDK
//
// This example demonstrates how MCP query operations are automatically
// audited by AxonFlow. Every MCP query/execute operation is logged to
// the mcp_query_audits table with policy evaluation results.
//
// What gets audited:
//   - Request phase: SQLi detection, PII blocking
//   - Response phase: PII redaction
//   - Exfiltration checks: Row/volume limits
//   - Final result: success/failure, duration
//
// Usage:
//   docker compose up -d  # Start AxonFlow
//   cd examples/mcp-audit/go
//   go run main.go

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	// Get configuration from environment
	agentURL := os.Getenv("AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	clientID := os.Getenv("CLIENT_ID")
	if clientID == "" {
		clientID = "demo-client"
	}

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "demo-secret"
	}

	fmt.Println("==============================================")
	fmt.Println("MCP Audit Logging Example - Go SDK")
	fmt.Println("==============================================")
	fmt.Printf("Agent URL: %s\n", agentURL)
	fmt.Printf("Client ID: %s\n\n", clientID)

	// Create AxonFlow client
	client, err := axonflow.NewClient(axonflow.Config{
		AgentURL:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		fmt.Printf("FAILED: Could not create client: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: Simple query (creates audit entry)
	fmt.Println("Test 1: Execute simple MCP query...")
	fmt.Println("----------------------------------------------")

	result, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT 1 as test_value, 'hello' as test_message",
	})

	if err != nil {
		fmt.Printf("Query error (expected if postgres not configured): %v\n", err)
	} else {
		fmt.Printf("SUCCESS: Query executed\n")
		fmt.Printf("  Row count: %d\n", result.RowCount)
		fmt.Printf("  Duration: %dms\n", result.DurationMs)
		if result.PolicyInfo != nil {
			fmt.Printf("  Policies evaluated: %d\n", result.PolicyInfo.PoliciesEvaluated)
			fmt.Printf("  Blocked: %v\n", result.PolicyInfo.Blocked)
			fmt.Printf("  Redacted fields: %v\n", result.PolicyInfo.RedactedFields)
		}
	}
	fmt.Println()

	// Test 2: Query that may trigger PII detection
	fmt.Println("Test 2: Execute query with potential PII fields...")
	fmt.Println("----------------------------------------------")

	result, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT email, phone, name FROM users LIMIT 5",
	})

	if err != nil {
		fmt.Printf("Query error: %v\n", err)
	} else {
		fmt.Printf("SUCCESS: Query executed\n")
		fmt.Printf("  Row count: %d\n", result.RowCount)
		if result.PolicyInfo != nil {
			fmt.Printf("  Policies evaluated: %d\n", result.PolicyInfo.PoliciesEvaluated)
			if len(result.PolicyInfo.RedactedFields) > 0 {
				fmt.Printf("  PII REDACTED! Fields: %v\n", result.PolicyInfo.RedactedFields)
			}
		}
	}
	fmt.Println()

	// Test 3: Query with SQLi pattern (should be blocked)
	fmt.Println("Test 3: Execute query with SQLi pattern (should be blocked)...")
	fmt.Println("----------------------------------------------")

	result, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM users; DROP TABLE users;--",
	})

	if err != nil {
		fmt.Printf("Query blocked as expected: %v\n", err)
		fmt.Println("SUCCESS: SQLi attempt was blocked and audit logged")
	} else {
		fmt.Println("Note: SQLi detection may not be enabled")
	}
	fmt.Println()

	// Test 4: Execute (INSERT) operation
	fmt.Println("Test 4: Execute INSERT operation...")
	fmt.Println("----------------------------------------------")

	execResult, err := client.MCPExecute(ctx, axonflow.MCPExecuteRequest{
		Connector: "postgres",
		Action:    "INSERT",
		Statement: "INSERT INTO audit_test (name) VALUES ('test')",
	})

	if err != nil {
		fmt.Printf("Execute error (expected if table doesn't exist): %v\n", err)
	} else {
		fmt.Printf("SUCCESS: Execute completed\n")
		fmt.Printf("  Rows affected: %d\n", execResult.RowsAffected)
		fmt.Printf("  Duration: %dms\n", execResult.DurationMs)
	}
	fmt.Println()

	fmt.Println("==============================================")
	fmt.Println("MCP Audit Logging Tests Complete!")
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("All MCP operations above have been logged to the")
	fmt.Println("mcp_query_audits table. Each entry includes:")
	fmt.Println("  - audit_id: Unique identifier")
	fmt.Println("  - tenant_id, client_id, user_id: Who made the request")
	fmt.Println("  - connector_name, operation: What was requested")
	fmt.Println("  - request_blocked, request_block_reason: If request was blocked")
	fmt.Println("  - response_redacted, response_redacted_fields: If PII was redacted")
	fmt.Println("  - exfil_exceeded, exfil_limit_type: If exfiltration limit hit")
	fmt.Println("  - success, error_message: Final result")
	fmt.Println("  - duration_ms: How long it took")
}
