// Package main demonstrates code governance features in Go.
//
// This example shows automatic code detection in LLM responses:
// 1. Send a code generation query to AxonFlow
// 2. AxonFlow automatically detects code in the response
// 3. Code metadata is included in policy_info for audit
//
// The code_artifact field in the response contains:
// - language: Detected programming language
// - code_type: Category (function, class, script, config, snippet)
// - size_bytes: Size of detected code
// - line_count: Number of lines
// - secrets_detected: Count of potential secrets
// - unsafe_patterns: Count of unsafe code patterns
//
// Prerequisites:
// - AxonFlow Agent running on localhost:8080
// - OpenAI or Anthropic API key configured in AxonFlow
//
// Usage:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	go run main.go
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Code Governance - Go")
	fmt.Println("============================================================")
	fmt.Println()
	fmt.Println("This demo shows automatic code detection in LLM responses.")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-client"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
	})

	// Example 1: Generate a Go function
	fmt.Println("------------------------------------------------------------")
	fmt.Println("Example 1: Generate a Go function")
	fmt.Println("------------------------------------------------------------")

	response, err := client.ExecuteQuery(
		"developer-123",
		"Write a Go function to validate email addresses using regex",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else if response.Blocked {
		fmt.Printf("Status: BLOCKED - %s\n", response.BlockReason)
	} else {
		fmt.Println("Status: ALLOWED")
		fmt.Println()

		// Display response preview
		dataStr := fmt.Sprintf("%v", response.Data)
		if len(dataStr) > 300 {
			dataStr = dataStr[:300] + "..."
		}
		fmt.Printf("Response preview:\n  %s\n\n", dataStr)

		// Display audit trail
		fmt.Println("Audit Trail:")
		if response.PolicyInfo != nil {
			fmt.Printf("  Processing Time: %s\n", response.PolicyInfo.ProcessingTime)
			fmt.Printf("  Policies Evaluated: %v\n", response.PolicyInfo.PoliciesEvaluated)

			// Code Governance: Check for code artifact metadata
			if response.PolicyInfo.CodeArtifact != nil {
				artifact := response.PolicyInfo.CodeArtifact
				fmt.Println()
				fmt.Println("Code Artifact Detected:")
				fmt.Printf("  Language: %s\n", artifact.Language)
				fmt.Printf("  Type: %s\n", artifact.CodeType)
				fmt.Printf("  Size: %d bytes\n", artifact.SizeBytes)
				fmt.Printf("  Lines: %d\n", artifact.LineCount)
				fmt.Printf("  Secrets Detected: %d\n", artifact.SecretsDetected)
				fmt.Printf("  Unsafe Patterns: %d\n", artifact.UnsafePatterns)
			}
		}
	}

	fmt.Println()

	// Example 2: Check for unsafe patterns
	fmt.Println("------------------------------------------------------------")
	fmt.Println("Example 2: Check for unsafe patterns in generated code")
	fmt.Println("------------------------------------------------------------")

	response, err = client.ExecuteQuery(
		"developer-123",
		"Write a Go function that uses os/exec to run shell commands from user input",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else if response.Blocked {
		fmt.Printf("Status: BLOCKED - %s\n", response.BlockReason)
	} else {
		fmt.Println("Status: ALLOWED")
		fmt.Println()

		if response.PolicyInfo != nil {
			fmt.Printf("Processing Time: %s\n", response.PolicyInfo.ProcessingTime)

			if response.PolicyInfo.CodeArtifact != nil {
				artifact := response.PolicyInfo.CodeArtifact
				fmt.Println()
				fmt.Println("Code Artifact Analysis:")
				fmt.Printf("  Language: %s\n", artifact.Language)
				fmt.Printf("  Unsafe Patterns: %d\n", artifact.UnsafePatterns)
				if artifact.UnsafePatterns > 0 {
					fmt.Println()
					fmt.Printf("  WARNING: %d unsafe code pattern(s) detected!\n", artifact.UnsafePatterns)
					fmt.Println("  Review carefully before using in production.")
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("Summary")
	fmt.Println("============================================================")
	fmt.Println()
	fmt.Println("Code Governance automatically:")
	fmt.Println("  1. Detects code blocks in LLM responses")
	fmt.Println("  2. Identifies the programming language")
	fmt.Println("  3. Counts potential secrets and unsafe patterns")
	fmt.Println("  4. Includes metadata in policy_info for audit")
	fmt.Println()
	fmt.Println("Use this metadata to:")
	fmt.Println("  - Alert on unsafe patterns before deployment")
	fmt.Println("  - Track code generation for compliance")
	fmt.Println("  - Build dashboards for AI code generation metrics")
	fmt.Println()
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
