// Parameterized Query Example - Tests Deterministic Parameter Ordering
//
// This example verifies that parameterized queries with multiple parameters
// produce deterministic results. The Postgres connector sorts parameter keys
// alphabetically before building positional arguments ($1, $2, $3...).
//
// This is critical because Go map iteration is non-deterministic, which could
// cause parameter mismatch bugs without proper key sorting.
//
// Usage:
//   docker compose up -d  # Start AxonFlow
//   cd examples/mcp-connectors/parameterized-queries/go
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

// MCPQueryRequest matches the agent's expected request format
type MCPQueryRequest struct {
	Connector  string                 `json:"connector"`
	Statement  string                 `json:"statement"`
	Parameters map[string]interface{} `json:"parameters"`
}

type MCPQueryResponse struct {
	Success   bool                     `json:"success"`
	Connector string                   `json:"connector"`
	Data      []map[string]interface{} `json:"data"`
	RowCount  int                      `json:"row_count"`
}

func main() {
	agentURL := os.Getenv("AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	fmt.Println("============================================================")
	fmt.Println("Parameterized Query Example - Deterministic Parameter Ordering")
	fmt.Println("============================================================")
	fmt.Printf("Agent URL: %s\n\n", agentURL)
	fmt.Println("This example verifies fix for issue #281:")
	fmt.Println("  - Go map iteration is non-deterministic")
	fmt.Println("  - buildArgs() now sorts keys alphabetically")
	fmt.Println("  - Parameters are assigned to $1, $2, $3... in sorted order")
	fmt.Println()

	allPassed := true

	// Test 1: Parameterized query with multiple parameters
	if !testParameterizedQuery(agentURL) {
		allPassed = false
	}

	// Test 2: Determinism test (multiple iterations)
	if !testDeterminism(agentURL, 10) {
		allPassed = false
	}

	// Test 3: Single parameter
	if !testSingleParam(agentURL) {
		allPassed = false
	}

	// Test 4: Empty parameters
	if !testEmptyParams(agentURL) {
		allPassed = false
	}

	fmt.Println()
	fmt.Println("============================================================")
	if allPassed {
		fmt.Println("All parameterized query tests PASSED!")
		fmt.Println("============================================================")
	} else {
		fmt.Println("Some tests FAILED!")
		fmt.Println("============================================================")
		os.Exit(1)
	}
}

// testParameterizedQuery tests that parameters are ordered alphabetically by key
func testParameterizedQuery(agentURL string) bool {
	fmt.Println("Test 1: Parameterized query with multiple parameters...")
	fmt.Println("  Keys provided: zebra, alpha, middle (non-alphabetical)")
	fmt.Println("  Expected order after sorting: alpha, middle, zebra")

	req := MCPQueryRequest{
		Connector: "axonflow_rds",
		Statement: "SELECT $1::text as first_param, $2::text as second_param, $3::text as third_param",
		Parameters: map[string]interface{}{
			"zebra":  "Z",
			"alpha":  "A",
			"middle": "M",
		},
	}

	result, err := sendRequest(agentURL+"/mcp/resources/query", req)
	if err != nil {
		fmt.Printf("  FAILED: %v\n", err)
		return false
	}

	if !result.Success {
		fmt.Println("  FAILED: Request unsuccessful")
		return false
	}

	if len(result.Data) == 0 {
		fmt.Println("  FAILED: No data returned")
		return false
	}

	row := result.Data[0]
	first := fmt.Sprintf("%v", row["first_param"])
	second := fmt.Sprintf("%v", row["second_param"])
	third := fmt.Sprintf("%v", row["third_param"])

	fmt.Printf("  Result: first_param=%s, second_param=%s, third_param=%s\n", first, second, third)

	if first == "A" && second == "M" && third == "Z" {
		fmt.Println("  SUCCESS: Parameters in correct alphabetical key order!")
		return true
	}

	fmt.Printf("  FAILED: Expected first=A, second=M, third=Z\n")
	fmt.Printf("          Got first=%s, second=%s, third=%s\n", first, second, third)
	return false
}

// testDeterminism runs multiple iterations to verify consistent ordering
func testDeterminism(agentURL string, iterations int) bool {
	fmt.Printf("\nTest 2: Determinism test (%d iterations)...\n", iterations)

	// Expected order after alphabetical sort: alpha, bravo, charlie, delta, echo
	expected := map[string]string{
		"p1": "A",
		"p2": "B",
		"p3": "C",
		"p4": "D",
		"p5": "E",
	}

	for i := 0; i < iterations; i++ {
		req := MCPQueryRequest{
			Connector: "axonflow_rds",
			Statement: "SELECT $1::text as p1, $2::text as p2, $3::text as p3, $4::text as p4, $5::text as p5",
			Parameters: map[string]interface{}{
				"echo":    "E",
				"alpha":   "A",
				"delta":   "D",
				"bravo":   "B",
				"charlie": "C",
			},
		}

		result, err := sendRequest(agentURL+"/mcp/resources/query", req)
		if err != nil {
			fmt.Printf("  Iteration %d: FAILED - %v\n", i+1, err)
			return false
		}

		if !result.Success {
			fmt.Printf("  Iteration %d: FAILED - Request unsuccessful\n", i+1)
			return false
		}

		if len(result.Data) == 0 {
			fmt.Printf("  Iteration %d: FAILED - No data returned\n", i+1)
			return false
		}

		row := result.Data[0]
		for key, expectedVal := range expected {
			actualVal := fmt.Sprintf("%v", row[key])
			if actualVal != expectedVal {
				fmt.Printf("  Iteration %d: FAILED - %s expected %s, got %s\n", i+1, key, expectedVal, actualVal)
				return false
			}
		}
	}

	fmt.Printf("  SUCCESS: All %d iterations produced consistent results!\n", iterations)
	return true
}

// testSingleParam tests single parameter edge case
func testSingleParam(agentURL string) bool {
	fmt.Println("\nTest 3: Single parameter query...")

	req := MCPQueryRequest{
		Connector: "axonflow_rds",
		Statement: "SELECT $1::text as value",
		Parameters: map[string]interface{}{
			"only_param": "SINGLE",
		},
	}

	result, err := sendRequest(agentURL+"/mcp/resources/query", req)
	if err != nil {
		fmt.Printf("  FAILED: %v\n", err)
		return false
	}

	if !result.Success {
		fmt.Println("  FAILED: Request unsuccessful")
		return false
	}

	if len(result.Data) == 0 {
		fmt.Println("  FAILED: No data returned")
		return false
	}

	value := fmt.Sprintf("%v", result.Data[0]["value"])
	if value == "SINGLE" {
		fmt.Printf("  SUCCESS: Single parameter worked! value=%s\n", value)
		return true
	}

	fmt.Printf("  FAILED: Expected 'SINGLE', got '%s'\n", value)
	return false
}

// testEmptyParams tests query with no parameters
func testEmptyParams(agentURL string) bool {
	fmt.Println("\nTest 4: Query with no parameters...")

	req := MCPQueryRequest{
		Connector:  "axonflow_rds",
		Statement:  "SELECT 'no params' as result",
		Parameters: map[string]interface{}{},
	}

	result, err := sendRequest(agentURL+"/mcp/resources/query", req)
	if err != nil {
		fmt.Printf("  FAILED: %v\n", err)
		return false
	}

	if !result.Success {
		fmt.Println("  FAILED: Request unsuccessful")
		return false
	}

	if len(result.Data) == 0 {
		fmt.Println("  FAILED: No data returned")
		return false
	}

	value := fmt.Sprintf("%v", result.Data[0]["result"])
	if value == "no params" {
		fmt.Printf("  SUCCESS: Empty params query worked! result=%s\n", value)
		return true
	}

	fmt.Printf("  FAILED: Expected 'no params', got '%s'\n", value)
	return false
}

func sendRequest(url string, req MCPQueryRequest) (*MCPQueryResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Tenant-ID", "default")

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

	var result MCPQueryResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(respBody))
	}

	return &result, nil
}
