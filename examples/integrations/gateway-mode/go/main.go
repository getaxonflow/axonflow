// Package main demonstrates and VALIDATES AxonFlow Gateway Mode in Go.
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
//
// Issue #1082: Examples should test actual behavior, not just API availability
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v2"
	openai "github.com/sashabaranov/go-openai"
)

var (
	passCount int
	failCount int
)

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
		passCount++
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failCount++
	}
}

func main() {
	fmt.Println("AxonFlow Gateway Mode - Go Example")
	fmt.Println()

	// Initialize AxonFlow client
	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "gateway-mode-example"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""), // Optional for community mode
	})

	// Initialize OpenAI client
	openaiKey := getEnv("OPENAI_API_KEY", "")
	if openaiKey == "" {
		fmt.Println("OPENAI_API_KEY not set. Will use mock LLM response.")
		fmt.Println()
	}
	openaiClient := openai.NewClient(openaiKey)

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
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		failCount++
		printSummary()
		os.Exit(1)
	}

	preCheckLatency := time.Since(preCheckStart)
	fmt.Printf("   Completed in %v\n", preCheckLatency)
	assert(preCheckResult.ContextID != "", "Pre-check returns context ID")
	assert(preCheckResult.Approved, "Request is approved (no policy violations)")
	fmt.Printf("   Context ID: %s\n", preCheckResult.ContextID)
	fmt.Printf("   Approved: %v\n", preCheckResult.Approved)

	if !preCheckResult.Approved {
		fmt.Printf("   BLOCKED: %s\n", preCheckResult.BlockReason)
		fmt.Printf("   Policies: %v\n", preCheckResult.Policies)
		// Continue to show assertions status even if blocked
	}
	fmt.Println()

	// =========================================================================
	// STEP 2: LLM Call - Make your own call to OpenAI
	// =========================================================================
	fmt.Println("Step 2: LLM Call (OpenAI)...")
	llmStart := time.Now()

	var response string
	var usage openai.Usage

	if openaiKey != "" {
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
			fmt.Printf("   ERROR: OpenAI call failed: %v\n", err)
			failCount++
			// Continue with mock response
			response = "Mock response due to LLM error"
			usage = openai.Usage{PromptTokens: 25, CompletionTokens: 20, TotalTokens: 45}
		} else {
			response = completion.Choices[0].Message.Content
			usage = completion.Usage
		}
	} else {
		// Mock response for testing without API key
		time.Sleep(100 * time.Millisecond) // Simulate latency
		response = "Mock response: Best practices include thorough testing, gradual rollouts, monitoring, and having rollback procedures."
		usage = openai.Usage{
			PromptTokens:     25,
			CompletionTokens: 40,
			TotalTokens:      65,
		}
	}

	llmLatency := time.Since(llmStart)
	fmt.Printf("   Response received in %v\n", llmLatency)
	fmt.Printf("   Tokens: %d prompt, %d completion\n",
		usage.PromptTokens, usage.CompletionTokens)
	assert(response != "", "LLM returns a response")
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
	auditLatency := time.Since(auditStart)
	if err != nil {
		fmt.Printf("   Warning: Audit failed (non-fatal): %v\n", err)
		// Audit is non-fatal - continue
	} else {
		assert(auditResult != nil, "Audit returns result")
		if auditResult != nil {
			assert(auditResult.AuditID != "", "Audit returns audit ID")
			fmt.Printf("   Audit ID: %s\n", auditResult.AuditID)
		}
	}
	fmt.Printf("   Audit logged in %v\n", auditLatency)
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
	fmt.Println()

	printSummary()
}

func printSummary() {
	fmt.Println("============================================================")
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)
	fmt.Println("============================================================")

	if failCount > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	} else {
		fmt.Println("ALL TESTS PASSED - Gateway Mode verified!")
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
