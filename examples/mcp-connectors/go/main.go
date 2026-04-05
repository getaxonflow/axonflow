// MCP Connector Example - Tests Agent Routing
//
// This example tests the FULL MCP connector flow:
//   SDK -> Agent (port 8080) -> Connector
//
// VALIDATION: This example exits with code 1 if any assertion fails.
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

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

// AgentRequest matches the agent's expected request format
type AgentRequest struct {
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

type AgentResponse struct {
	RequestID      string                 `json:"request_id"`
	Success        bool                   `json:"success"`
	Data           map[string]interface{} `json:"data"`
	Error          string                 `json:"error"`
	ProcessingTime string                 `json:"processing_time"`
}

func main() {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	fmt.Println("==============================================")
	fmt.Println("MCP Connector Example - Agent Routing")
	fmt.Println("==============================================")
	fmt.Printf("Agent URL: %s\n\n", agentURL)

	// Test 1: Query postgres connector through agent
	// Note: "postgres" is the default postgres connector registered when DATABASE_URL is set
	fmt.Println("Test 1: Query postgres connector via agent...")

	req := AgentRequest{
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
			"connector": "postgres",
			"params":    map[string]interface{}{},
		},
	}

	result, err := sendRequest(agentURL+"/api/v1/process", req)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		assertCheck(false, "Test 1: MCP query request succeeded")
	} else if result.Success {
		fmt.Println("SUCCESS: MCP query through agent worked!")
		fmt.Printf("  Request ID: %s\n", result.RequestID)
		fmt.Printf("  Processing Time: %s\n", result.ProcessingTime)
		assertCheck(true, "Test 1: MCP query request succeeded")
		assertCheck(result.RequestID != "", "Test 1: Request ID returned")
		if result.Data != nil {
			if rows, ok := result.Data["rows"].([]interface{}); ok {
				fmt.Printf("  Rows returned: %d\n", len(rows))
				assertCheck(len(rows) > 0, "Test 1: Query returned rows")
			}
			if connector, ok := result.Data["connector"].(string); ok {
				fmt.Printf("  Connector: %s\n", connector)
			}
		}
	} else {
		fmt.Printf("FAILED: %s\n", result.Error)
		assertCheck(false, "Test 1: MCP query returned success")
	}

	// Test 2: Query with a different statement
	fmt.Println("\nTest 2: Query current timestamp...")

	req.RequestID = fmt.Sprintf("mcp-test-%d", time.Now().UnixNano())
	req.Query = "SELECT NOW() as current_time, 'AxonFlow MCP' as source"

	result, err = sendRequest(agentURL+"/api/v1/process", req)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		assertCheck(false, "Test 2: Timestamp query request succeeded")
	} else if result.Success {
		fmt.Println("SUCCESS: Timestamp query worked!")
		assertCheck(true, "Test 2: Timestamp query request succeeded")
		if result.Data != nil {
			if rows, ok := result.Data["rows"].([]interface{}); ok && len(rows) > 0 {
				fmt.Printf("  Result: %v\n", rows[0])
				assertCheck(true, "Test 2: Timestamp query returned data")
			}
		}
	} else {
		fmt.Printf("FAILED: %s\n", result.Error)
		assertCheck(false, "Test 2: Timestamp query returned success")
	}

	fmt.Println("\n==============================================")
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL ASSERTIONS PASSED - MCP connector tests verified!")
	fmt.Println("==============================================")
}

func sendRequest(url string, req AgentRequest) (*AgentResponse, error) {
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

	var result AgentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(respBody))
	}

	return &result, nil
}
