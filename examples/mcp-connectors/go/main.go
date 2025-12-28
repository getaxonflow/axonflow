// AxonFlow MCP Connector Example - Go
//
// Demonstrates how to query MCP (Model Context Protocol) connectors
// through AxonFlow with policy governance.
//
// MCP connectors allow AI applications to securely interact with
// external systems like databases, APIs, and more.
//
// Prerequisites:
// - AxonFlow running with connectors enabled (docker-compose up -d)
// - PostgreSQL connector configured in config/axonflow.yaml
//
// Usage:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	go run main.go
package main

import (
	"fmt"
	"os"
	"strings"

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

	// Use default client ID for self-hosted mode if not set
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo" // Default for self-hosted/community mode
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     agentURL,
		ClientID:     clientID,
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		Debug:        true,
	})

	fmt.Println("Testing MCP Connector Queries")
	fmt.Println("------------------------------------------------------------")
	fmt.Println()

	// Example 1: Query PostgreSQL Connector (configured in axonflow.yaml)
	fmt.Println("Example 1: Query PostgreSQL Connector")
	fmt.Println("----------------------------------------")

	response, err := client.QueryConnector(
		"user-123",  // user token
		"postgres",  // connector name (configured in config/axonflow.yaml)
		"SELECT 1 as health_check, current_timestamp as server_time", // safe query
		map[string]interface{}{},
	)

	if err != nil {
		fmt.Println("Status: FAILED")
		fmt.Printf("Error: %v\n", err)
	} else if response.Success {
		fmt.Println("Status: SUCCESS")
		fmt.Printf("Data: %v\n", response.Data)
	} else {
		fmt.Println("Status: FAILED")
		fmt.Printf("Error: %s\n", response.Error)
	}

	fmt.Println()

	// Example 2: Query with Policy Enforcement (SQL Injection)
	fmt.Println("Example 2: Query with Policy Enforcement")
	fmt.Println("----------------------------------------")
	fmt.Println("MCP queries are policy-checked before execution.")
	fmt.Println("Queries that violate policies will be blocked.")
	fmt.Println()

	// This demonstrates that even connector queries go through policy checks
	response, err = client.QueryConnector(
		"user-123",
		"postgres",
		"SELECT * FROM users WHERE 1=1; DROP TABLE users;--", // SQL injection attempt
		map[string]interface{}{},
	)

	if err != nil {
		errStr := err.Error()
		if containsAny(errStr, []string{"blocked", "policy", "DROP TABLE", "dangerous", "SQL injection"}) {
			fmt.Println("Status: BLOCKED by policy (expected behavior)")
			fmt.Printf("Reason: %v\n", err)
		} else {
			fmt.Println("Status: Error")
			fmt.Printf("Error: %v\n", err)
		}
	} else if !response.Success {
		if strings.Contains(response.Error, "blocked") || strings.Contains(response.Error, "policy") {
			fmt.Println("Status: BLOCKED by policy (expected behavior)")
		} else {
			fmt.Println("Status: FAILED")
		}
		fmt.Printf("Reason: %s\n", response.Error)
	} else {
		fmt.Println("Status: Query allowed (UNEXPECTED - should have been blocked!)")
		fmt.Printf("Response: %v\n", response.Data)
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("Go MCP Connector Test: COMPLETE")
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
