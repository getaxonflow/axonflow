// Health Check Example - Go
//
// Demonstrates how to check the health of AxonFlow Agent and Orchestrator services.
// This is essential for monitoring and ensuring your governance infrastructure is running.
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_AGENT_URL   - Agent URL (default: http://localhost:8080)
//   AXONFLOW_LICENSE_KEY - Optional for community mode

package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	// Initialize client (credentials optional for community mode)
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	config := axonflow.AxonFlowConfig{
		Endpoint:   agentURL,
		LicenseKey: os.Getenv("AXONFLOW_LICENSE_KEY"), // Optional for community
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

	// Exit with error if either service is unhealthy
	if !agentHealthy || !orchHealthy {
		os.Exit(1)
	}
}
