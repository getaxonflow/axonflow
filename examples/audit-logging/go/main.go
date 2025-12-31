// Package main demonstrates AxonFlow's audit logging capabilities.
//
// This example shows the complete Gateway Mode workflow:
// 1. Pre-check - Validate request against policies
// 2. LLM Call - Make your own call to OpenAI
// 3. Audit - Log the interaction for compliance
//
// The audit entry links back to the pre-check via context_id, providing
// a complete audit trail from request to response.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
	openai "github.com/sashabaranov/go-openai"
)

func main() {
	fmt.Println("AxonFlow Audit Logging - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize clients
	axClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "audit-logging-demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	openaiKey := getEnv("OPENAI_API_KEY", "")
	if openaiKey == "" {
		fmt.Println("OPENAI_API_KEY not set. Using mock LLM response.")
	}
	openaiClient := openai.NewClient(openaiKey)

	// Test queries
	queries := []struct {
		name  string
		query string
	}{
		{"Simple Question", "What is the capital of France?"},
		{"Technical Query", "Explain the CAP theorem in distributed systems."},
		{"Analysis Request", "What are the key benefits of containerization?"},
	}

	ctx := context.Background()

	for _, q := range queries {
		fmt.Printf("Query: %s\n", q.name)
		fmt.Printf("  \"%s\"\n\n", q.query)

		// Step 1: Pre-check
		fmt.Println("Step 1: Policy Pre-Check...")
		preCheckStart := time.Now()

		preCheck, err := axClient.GetPolicyApprovedContext(
			"audit-user",
			q.query,
			nil,
			map[string]interface{}{"example": "audit-logging"},
		)
		if err != nil {
			log.Printf("Pre-check failed: %v", err)
			continue
		}

		preCheckLatency := time.Since(preCheckStart)
		fmt.Printf("   Latency: %v\n", preCheckLatency)
		fmt.Printf("   Context ID: %s\n", preCheck.ContextID)

		if !preCheck.Approved {
			fmt.Printf("   BLOCKED: %s\n\n", preCheck.BlockReason)
			continue
		}
		fmt.Printf("   Status: APPROVED\n\n")

		// Step 2: LLM Call
		fmt.Println("Step 2: LLM Call (OpenAI)...")
		llmStart := time.Now()

		var response string
		var promptTokens, completionTokens, totalTokens int

		if openaiKey != "" {
			completion, err := openaiClient.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
				Model: openai.GPT3Dot5Turbo,
				Messages: []openai.ChatCompletionMessage{
					{Role: openai.ChatMessageRoleUser, Content: q.query},
				},
				MaxTokens: 150,
			})
			if err != nil {
				log.Printf("OpenAI call failed: %v", err)
				continue
			}
			response = completion.Choices[0].Message.Content
			promptTokens = completion.Usage.PromptTokens
			completionTokens = completion.Usage.CompletionTokens
			totalTokens = completion.Usage.TotalTokens
		} else {
			// Mock response for testing without API key
			time.Sleep(100 * time.Millisecond) // Simulate latency
			response = fmt.Sprintf("Mock response for: %s", q.query)
			promptTokens = 20
			completionTokens = 30
			totalTokens = 50
		}

		llmLatency := time.Since(llmStart)
		fmt.Printf("   Latency: %v\n", llmLatency)
		fmt.Printf("   Tokens: %d prompt, %d completion\n\n", promptTokens, completionTokens)

		// Step 3: Audit
		fmt.Println("Step 3: Audit Logging...")
		auditStart := time.Now()

		responseSummary := response
		if len(responseSummary) > 100 {
			responseSummary = responseSummary[:100] + "..."
		}

		auditResult, err := axClient.AuditLLMCall(
			preCheck.ContextID,
			responseSummary,
			"openai",
			"gpt-3.5-turbo",
			axonflow.TokenUsage{
				PromptTokens:     promptTokens,
				CompletionTokens: completionTokens,
				TotalTokens:      totalTokens,
			},
			llmLatency.Milliseconds(),
			nil,
		)

		auditLatency := time.Since(auditStart)
		if err != nil {
			fmt.Printf("   Warning: Audit failed: %v\n", err)
		} else {
			fmt.Printf("   Latency: %v\n", auditLatency)
			if auditResult != nil {
				fmt.Printf("   Audit ID: %s\n", auditResult.AuditID)
			}
		}

		// Summary
		governance := preCheckLatency + auditLatency
		total := preCheckLatency + llmLatency + auditLatency

		fmt.Println()
		fmt.Println("   Latency Breakdown:")
		fmt.Printf("     Pre-check:  %v\n", preCheckLatency)
		fmt.Printf("     LLM call:   %v\n", llmLatency)
		fmt.Printf("     Audit:      %v\n", auditLatency)
		fmt.Printf("     Governance: %v (%.1f%% overhead)\n", governance, float64(governance)/float64(total)*100)
		fmt.Printf("     Total:      %v\n", total)
		fmt.Println()
		fmt.Println("========================================")
		fmt.Println()
	}

	fmt.Println("Audit Logging Complete!")
	fmt.Println()
	fmt.Println("Query audit logs via Orchestrator API:")
	fmt.Println("  curl http://localhost:8081/api/v1/audit/tenant/audit-logging-demo")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
