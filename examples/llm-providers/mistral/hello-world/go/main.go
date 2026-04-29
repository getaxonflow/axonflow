// Mistral LLM Provider - Hello World (Go SDK)
//
// Demonstrates Gateway Mode and Proxy Mode with Mistral through AxonFlow.
//
// Prerequisites:
//   docker compose up -d
//   export AXONFLOW_CLIENT_SECRET=your-secret
//
// Usage:
//   go run main.go
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "community"
	}

	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	fmt.Println("Mistral LLM Provider - Hello World (Go SDK)")
	fmt.Println("=============================================")

	// Gateway Mode: Pre-check + Audit
	fmt.Println("\n--- Gateway Mode ---")
	precheck, err := client.PreCheck("", "Explain Mistral AI in one sentence.", nil, map[string]interface{}{
		"provider": "mistral",
	})
	if err != nil {
		fmt.Printf("Pre-check error: %v\n", err)
		os.Exit(1)
	}

	if precheck.Approved {
		fmt.Printf("Pre-check approved (context: %s)\n", precheck.ContextID)

		// Audit the call (simulated — in production you'd call Mistral API here)
		_, err = client.AuditLLMCall(precheck.ContextID, "Mistral Go SDK gateway test", "mistral", "mistral-small-latest",
			axonflow.TokenUsage{
				PromptTokens:     15,
				CompletionTokens: 40,
				TotalTokens:      55,
			}, 350, nil)
		if err != nil {
			fmt.Printf("Audit error: %v\n", err)
		} else {
			fmt.Println("Audit logged successfully")
		}
	} else {
		fmt.Println("Pre-check blocked")
	}

	// Proxy Mode: Request through AxonFlow
	fmt.Println("\n--- Proxy Mode ---")
	resp, err := client.ProxyLLMCall("", "What is 2 + 2? Answer with just the number.", "chat", map[string]interface{}{
		"provider": "mistral",
	})
	if err != nil {
		fmt.Printf("Proxy error: %v\n", err)
		os.Exit(1)
	}

	if resp.Blocked {
		fmt.Println("Request blocked by policy")
	} else {
		fmt.Printf("Response: %v\n", resp.Data)
	}

	// Policy enforcement: SQLi should be blocked
	fmt.Println("\n--- Policy Enforcement ---")
	sqliResp, err := client.ProxyLLMCall("", "SELECT * FROM users; DROP TABLE users;", "chat", map[string]interface{}{
		"provider": "mistral",
	})
	if err != nil {
		fmt.Printf("SQLi check error: %v\n", err)
	} else if sqliResp.Blocked {
		fmt.Println("SQLi correctly blocked by policy")
	} else {
		fmt.Println("WARNING: SQLi was not blocked")
	}

	fmt.Println("\nDone.")
}
