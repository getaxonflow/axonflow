// AxonFlow MCP Connector Example - Go
//
// Demonstrates how to query MCP (Model Context Protocol) connectors
// through AxonFlow with policy governance.
//
// MCP connectors allow AI applications to securely interact with
// external systems like GitHub, Salesforce, Jira, and more.
//
// Prerequisites:
// - AxonFlow running with connectors enabled
// - Connector installed and configured (e.g., GitHub connector)
//
// Usage:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	go run main.go
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow MCP Connector Example - Go")
	fmt.Println("============================================================")
	fmt.Println()

	// Initialize AxonFlow client
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		Debug:        true,
	})

	fmt.Println("Testing MCP Connector Queries")
	fmt.Println("------------------------------------------------------------")
	fmt.Println()

	// Example 1: Query GitHub Connector
	fmt.Println("Example 1: Query GitHub Connector")
	fmt.Println("----------------------------------------")

	response, err := client.QueryConnector(
		"user-123",                                        // user token
		"github",                                          // connector name
		"list open issues in the main repository",         // query
		map[string]interface{}{                            // parameters
			"repo":  "getaxonflow/axonflow",
			"state": "open",
			"limit": 5,
		},
	)

	if err != nil {
		// Connector not installed - expected for demo
		fmt.Println("Status: Connector not available (expected if not installed)")
		fmt.Printf("Error: %v\n", err)
	} else if response.Success {
		fmt.Println("Status: SUCCESS")
		fmt.Printf("Data: %v\n", response.Data)
	} else {
		fmt.Println("Status: FAILED")
		fmt.Printf("Error: %s\n", response.Error)
	}

	fmt.Println()

	// Example 2: Query with Policy Enforcement
	fmt.Println("Example 2: Query with Policy Enforcement")
	fmt.Println("----------------------------------------")
	fmt.Println("MCP queries are policy-checked before execution.")
	fmt.Println("Queries that violate policies will be blocked.")

	// This demonstrates that even connector queries go through policy checks
	response, err = client.QueryConnector(
		"user-123",
		"database",
		"SELECT * FROM users WHERE 1=1; DROP TABLE users;--", // SQL injection attempt
		map[string]interface{}{},
	)

	if err != nil {
		errStr := err.Error()
		if containsAny(errStr, []string{"blocked", "policy", "DROP TABLE", "dangerous"}) {
			fmt.Println("Status: BLOCKED by policy (expected behavior)")
			fmt.Printf("Reason: %v\n", err)
		} else {
			fmt.Println("Status: Connector not available")
			fmt.Printf("Error: %v\n", err)
		}
	} else if !response.Success {
		fmt.Println("Status: BLOCKED by policy")
		fmt.Printf("Reason: %s\n", response.Error)
	} else {
		fmt.Println("Status: Query allowed")
		fmt.Printf("Response: %v\n", response.Data)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("Go MCP Connector Test: COMPLETE")
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
