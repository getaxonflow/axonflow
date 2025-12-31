// MCP Connector Example - Tests Orchestrator-to-Agent Routing
//
// This example tests the FULL MCP connector flow:
//   SDK -> Orchestrator (port 8081) -> Agent (port 8080) -> Connector
//
// This is different from direct agent calls and exercises the
// internal service authentication between orchestrator and agent.
//
// Usage:
//   docker compose up -d  # Start AxonFlow
//   cd examples/mcp-connectors/go
//   go run main.go

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// OrchestratorRequest matches the orchestrator's expected request format
type OrchestratorRequest struct {
	RequestID   string                 `json:"request_id"`
	Query       string                 `json:"query"`
	RequestType string                 `json:"request_type"`
	User        UserContext            `json:"user"`
	Client      ClientContext          `json:"client"`
	Context     map[string]interface{} `json:"context"`
}

type UserContext struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	TenantID string `json:"tenant_id"`
}

type ClientContext struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}

type OrchestratorResponse struct {
	RequestID      string                 `json:"request_id"`
	Success        bool                   `json:"success"`
	Data           map[string]interface{} `json:"data"`
	Error          string                 `json:"error"`
	ProcessingTime string                 `json:"processing_time"`
}

func main() {
	orchestratorURL := os.Getenv("ORCHESTRATOR_URL")
	if orchestratorURL == "" {
		orchestratorURL = "http://localhost:8081"
	}

	fmt.Println("==============================================")
	fmt.Println("MCP Connector Example - Orchestrator Routing")
	fmt.Println("==============================================")
	fmt.Printf("Orchestrator URL: %s\n\n", orchestratorURL)

	// Test 1: Query axonflow_rds connector through orchestrator
	// Note: "axonflow_rds" is the default postgres connector registered when DATABASE_URL is set
	fmt.Println("Test 1: Query axonflow_rds connector via orchestrator...")

	req := OrchestratorRequest{
		RequestID:   fmt.Sprintf("mcp-test-%d", time.Now().UnixNano()),
		Query:       "SELECT 1 as test_value, 'hello' as test_message",
		RequestType: "mcp-query",
		User: UserContext{
			Email:    "test@example.com",
			Role:     "user",
			TenantID: "default",
		},
		Client: ClientContext{
			ID:       "test-client",
			TenantID: "default",
		},
		Context: map[string]interface{}{
			"connector": "axonflow_rds",
			"params":    map[string]interface{}{},
		},
	}

	result, err := sendRequest(orchestratorURL+"/api/v1/process", req)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}

	if result.Success {
		fmt.Println("SUCCESS: MCP query through orchestrator worked!")
		fmt.Printf("  Request ID: %s\n", result.RequestID)
		fmt.Printf("  Processing Time: %s\n", result.ProcessingTime)
		if result.Data != nil {
			if rows, ok := result.Data["rows"].([]interface{}); ok {
				fmt.Printf("  Rows returned: %d\n", len(rows))
			}
			if connector, ok := result.Data["connector"].(string); ok {
				fmt.Printf("  Connector: %s\n", connector)
			}
		}
	} else {
		fmt.Printf("FAILED: %s\n", result.Error)
		os.Exit(1)
	}

	// Test 2: Query with a different statement
	fmt.Println("\nTest 2: Query current timestamp...")

	req.RequestID = fmt.Sprintf("mcp-test-%d", time.Now().UnixNano())
	req.Query = "SELECT NOW() as current_time, 'AxonFlow MCP' as source"

	result, err = sendRequest(orchestratorURL+"/api/v1/process", req)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		os.Exit(1)
	}

	if result.Success {
		fmt.Println("SUCCESS: Timestamp query worked!")
		if result.Data != nil {
			if rows, ok := result.Data["rows"].([]interface{}); ok && len(rows) > 0 {
				fmt.Printf("  Result: %v\n", rows[0])
			}
		}
	} else {
		fmt.Printf("FAILED: %s\n", result.Error)
		os.Exit(1)
	}

	fmt.Println("\n==============================================")
	fmt.Println("All MCP connector tests PASSED!")
	fmt.Println("==============================================")
}

func sendRequest(url string, req OrchestratorRequest) (*OrchestratorResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result OrchestratorResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(respBody))
	}

	return &result, nil
}
