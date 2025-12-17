// Package main demonstrates AxonFlow Gateway Mode in Go.
//
// Gateway Mode provides the lowest latency AI governance by separating
// policy enforcement from LLM calls. The workflow is:
//
//  1. Pre-check: Validate request against policies BEFORE calling LLM
//  2. LLM Call: Make your own call to your preferred provider
//  3. Audit: Log the interaction for compliance and monitoring
//
// This gives you full control over LLM parameters while maintaining
// complete audit trails with ~3-5ms governance overhead.
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
	fmt.Println("AxonFlow Gateway Mode - Go Example")
	fmt.Println()

	// Initialize AxonFlow client
	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// Initialize OpenAI client
	openaiClient := openai.NewClient(getEnv("OPENAI_API_KEY", ""))

	// Example request
	userToken := "user-789"
	query := "What are best practices for AI model deployment?"
	requestContext := map[string]interface{}{
		"user_role":  "engineer",
		"department": "platform",
	}

	fmt.Printf("Query: %q\n", query)
	fmt.Printf("User: %s\n", userToken)
	fmt.Printf("Context: %v\n\n", requestContext)

	ctx := context.Background()

	// =========================================================================
	// STEP 1: Pre-Check - Validate against policies before LLM call
	// =========================================================================
	fmt.Println("Step 1: Policy Pre-Check...")
	preCheckStart := time.Now()

	preCheckResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		query,
		nil, // dataSources (optional)
		requestContext,
	)
	if err != nil {
		log.Fatalf("Pre-check failed: %v", err)
	}

	preCheckLatency := time.Since(preCheckStart)
	fmt.Printf("   Completed in %v\n", preCheckLatency)
	fmt.Printf("   Context ID: %s\n", preCheckResult.ContextID)
	fmt.Printf("   Approved: %v\n", preCheckResult.Approved)

	if !preCheckResult.Approved {
		fmt.Printf("   BLOCKED: %s\n", preCheckResult.BlockReason)
		fmt.Printf("   Policies: %v\n", preCheckResult.Policies)
		return
	}
	fmt.Println()

	// =========================================================================
	// STEP 2: LLM Call - Make your own call to OpenAI
	// =========================================================================
	fmt.Println("Step 2: LLM Call (OpenAI)...")
	llmStart := time.Now()

	chatReq := openai.ChatCompletionRequest{
		Model: openai.GPT3Dot5Turbo,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a helpful AI expert. Be concise.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: query,
			},
		},
		MaxTokens: 200,
	}

	completion, err := openaiClient.CreateChatCompletion(ctx, chatReq)
	if err != nil {
		log.Fatalf("OpenAI call failed: %v", err)
	}

	llmLatency := time.Since(llmStart)
	response := completion.Choices[0].Message.Content
	usage := completion.Usage

	fmt.Printf("   Response received in %v\n", llmLatency)
	fmt.Printf("   Tokens: %d prompt, %d completion\n",
		usage.PromptTokens, usage.CompletionTokens)
	fmt.Println()

	// =========================================================================
	// STEP 3: Audit - Log the interaction for compliance
	// =========================================================================
	fmt.Println("Step 3: Audit Logging...")
	auditStart := time.Now()

	// Truncate response for summary
	responseSummary := response
	if len(responseSummary) > 100 {
		responseSummary = responseSummary[:100]
	}

	auditResult, err := axonflowClient.AuditLLMCall(
		preCheckResult.ContextID,
		responseSummary,
		"openai",       // provider
		"gpt-3.5-turbo", // model
		axonflow.TokenUsage{
			PromptTokens:     usage.PromptTokens,
			CompletionTokens: usage.CompletionTokens,
			TotalTokens:      usage.TotalTokens,
		},
		llmLatency.Milliseconds(),
		nil, // metadata (optional)
	)
	if err != nil {
		log.Printf("Warning: Audit failed (non-fatal): %v", err)
	}

	auditLatency := time.Since(auditStart)
	fmt.Printf("   Audit logged in %v\n", auditLatency)
	if auditResult != nil {
		fmt.Printf("   Audit ID: %s\n", auditResult.AuditID)
	}
	fmt.Println()

	// =========================================================================
	// Results
	// =========================================================================
	governanceOverhead := preCheckLatency + auditLatency
	totalLatency := preCheckLatency + llmLatency + auditLatency

	fmt.Println("============================================================")
	fmt.Println("Results")
	fmt.Println("============================================================")
	fmt.Printf("\nResponse:\n%s\n\n", response)
	fmt.Println("Latency Breakdown:")
	fmt.Printf("   Pre-check:  %v\n", preCheckLatency)
	fmt.Printf("   LLM call:   %v\n", llmLatency)
	fmt.Printf("   Audit:      %v\n", auditLatency)
	fmt.Println("   -----------------")
	fmt.Printf("   Governance: %v (overhead)\n", governanceOverhead)
	fmt.Printf("   Total:      %v\n", totalLatency)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
