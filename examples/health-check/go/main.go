// Health Check Example - Go
//
// Demonstrates how to check the health of AxonFlow Agent and Orchestrator services.
// This is essential for monitoring and ensuring your governance infrastructure is running.
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_AGENT_URL     - Agent URL (default: http://localhost:8080)
//   AXONFLOW_CLIENT_ID     - OAuth2 client ID (optional for community mode)
//   AXONFLOW_CLIENT_SECRET - OAuth2 client secret (optional for community mode)
//
// VALIDATION: This example exits with code 1 if any assertion fails.

package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   ✓ PASS: %s\n", message)
	} else {
		fmt.Printf("   ❌ FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	// Initialize client (credentials optional for community mode)
	agentURL := os.Getenv("AXONFLOW_ENDPOINT")
	if agentURL == "" {
		agentURL = os.Getenv("AXONFLOW_AGENT_URL")
	}
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	config := axonflow.AxonFlowConfig{
		Endpoint:   agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"), // Optional for community
	}

	client := axonflow.NewClient(config)

	fmt.Println("=== AxonFlow Health Check Example ===")
	fmt.Println()

	// 1. Check Agent health
	fmt.Println("1. Checking Agent health...")
	agentHealthy := true
	if err := client.HealthCheck(); err != nil {
		log.Printf("   Agent health check failed: %v", err)
		agentHealthy = false
	} else {
		fmt.Println("   Agent Status: HEALTHY")
	}
	assertCheck(agentHealthy, "Agent is healthy")

	// 2. Check Orchestrator health
	fmt.Println()
	fmt.Println("2. Checking Orchestrator health...")
	orchHealthy := true
	if err := client.OrchestratorHealthCheck(); err != nil {
		log.Printf("   Orchestrator health check failed: %v", err)
		orchHealthy = false
	} else {
		fmt.Println("   Orchestrator Status: HEALTHY")
	}
	assertCheck(orchHealthy, "Orchestrator is healthy")

	// 3. Summary
	fmt.Println()
	fmt.Println("=== Health Check Summary ===")
	if agentHealthy {
		fmt.Println("   Agent: HEALTHY")
	} else {
		fmt.Println("   Agent: UNHEALTHY")
	}
	if orchHealthy {
		fmt.Println("   Orchestrator: HEALTHY")
	} else {
		fmt.Println("   Orchestrator: UNHEALTHY")
	}

	if len(failures) > 0 {
		fmt.Printf("\n❌ %d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
