package main

import (
	"fmt"
	"log"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
		Debug:        true,
	})

	fmt.Println("🔌 Connecting to AxonFlow...")

	// Send query with simple policy
	response, err := client.ExecuteQuery(
		"demo-user",                       // userToken
		"What is the capital of France?",  // query
		"chat",                            // requestType
		map[string]interface{}{            // context
			"user_role": "agent",
		},
	)
	if err != nil {
		log.Fatal("❌ Error:", err)
	}

	// Display results
	fmt.Println("✅ Query successful!")
	fmt.Printf("Result: %v\n", response.Result)
	fmt.Printf("Blocked: %v\n", response.Blocked)
	if response.Blocked {
		fmt.Printf("Block Reason: %s\n", response.BlockReason)
	}
	if response.PolicyInfo != nil {
		fmt.Printf("Policies Evaluated: %v\n", response.PolicyInfo.PoliciesEvaluated)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
