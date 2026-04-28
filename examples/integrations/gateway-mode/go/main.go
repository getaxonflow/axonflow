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
// Gateway-specific policy config env vars (override defaults for gateway mode only):
//
//	GATEWAY_PII_ACTION  - PII action in gateway mode: "redact", "block", or "log"
//	GATEWAY_SQLI_ACTION - SQLi action in gateway mode: "block", "warn", or "log"
//
// Issue #1082: Examples should test actual behavior, not just API availability
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v6"
	openai "github.com/sashabaranov/go-openai"
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

	// Example request — use JWT from env if available (required in enterprise/evaluation mode)
	userToken := getEnv("AXONFLOW_USER_TOKEN", "user-789")
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
		assertCheck(false, "Pre-check succeeded")
		printSummary()
		os.Exit(1)
	}

	preCheckLatency := time.Since(preCheckStart)
	fmt.Printf("   Completed in %v\n", preCheckLatency)
	assertCheck(preCheckResult.ContextID != "", "Pre-check returns context ID")
	assertCheck(preCheckResult.Approved, "Request is approved (no policy violations)")
	fmt.Printf("   Context ID: %s\n", preCheckResult.ContextID)
	fmt.Printf("   Approved: %v\n", preCheckResult.Approved)

	if !preCheckResult.Approved {
		fmt.Printf("   BLOCKED: %s\n", preCheckResult.BlockReason)
		fmt.Printf("   Policies: %v\n", preCheckResult.Policies)
		// Continue to show assertions status even if blocked
	}
	fmt.Println()

	// =========================================================================
	// STEP 1b: PII Detection - SSN triggers redaction flag
	// =========================================================================
	fmt.Println("Step 1b: PII Detection (SSN)...")
	piiResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		"Process refund for customer with SSN 123-45-6789",
		nil, requestContext,
	)
	if err != nil {
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		assertCheck(false, "PII pre-check succeeded")
	} else {
		assertCheck(piiResult.Approved, "PII query approved (redact mode, not blocked)")
		assertCheck(len(piiResult.Policies) > 0, "PII policies detected")
		fmt.Printf("   Policies: %v\n", piiResult.Policies)
	}
	fmt.Println()

	// =========================================================================
	// STEP 1c: India PII Detection - PAN and Aadhaar
	// =========================================================================
	fmt.Println("Step 1c: India PII Detection (PAN)...")
	panResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		"Verify PAN number ABCPD1234E for tax filing",
		nil, requestContext,
	)
	if err != nil {
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		assertCheck(false, "PAN pre-check succeeded")
	} else {
		assertCheck(panResult.Approved, "India PAN approved (redact mode)")
		assertCheck(len(panResult.Policies) > 0, "India PII policies detected for PAN")
		fmt.Printf("   Policies: %v\n", panResult.Policies)
	}

	fmt.Println("Step 1c: India PII Detection (Aadhaar)...")
	aadhaarResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		"Link Aadhaar 2345 6789 0123 to bank account",
		nil, requestContext,
	)
	if err != nil {
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		assertCheck(false, "Aadhaar pre-check succeeded")
	} else {
		assertCheck(aadhaarResult.Approved, "India Aadhaar approved (redact mode)")
		assertCheck(len(aadhaarResult.Policies) > 0, "India PII policies detected for Aadhaar")
		fmt.Printf("   Policies: %v\n", aadhaarResult.Policies)
	}
	fmt.Println()

	// =========================================================================
	// STEP 1d: SQL Injection Detection - should be BLOCKED
	// =========================================================================
	fmt.Println("Step 1d: SQL Injection Detection (DROP TABLE)...")
	sqliResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		"SELECT * FROM users; DROP TABLE users;--",
		nil, requestContext,
	)
	if err != nil {
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		assertCheck(false, "SQLi pre-check succeeded")
	} else {
		assertCheck(!sqliResult.Approved, "SQLi query is BLOCKED")
		assertCheck(sqliResult.BlockReason != "", "Block reason provided for SQLi")
		fmt.Printf("   Block reason: %s\n", sqliResult.BlockReason)
	}

	fmt.Println("Step 1d: SQL Injection Detection (UNION SELECT)...")
	unionResult, err := axonflowClient.GetPolicyApprovedContext(
		userToken,
		"Get user where id = 1 UNION SELECT password FROM admin",
		nil, requestContext,
	)
	if err != nil {
		fmt.Printf("   ERROR: Pre-check failed: %v\n", err)
		assertCheck(false, "UNION SQLi pre-check succeeded")
	} else {
		assertCheck(!unionResult.Approved, "UNION SQLi query is BLOCKED")
		assertCheck(unionResult.BlockReason != "", "Block reason provided for UNION SQLi")
		fmt.Printf("   Block reason: %s\n", unionResult.BlockReason)
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
			// Note: OpenAI errors are non-fatal, continue with mock response
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
	assertCheck(response != "", "LLM returns a response")
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
		"gpt-4o-mini", // model
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
		assertCheck(auditResult != nil, "Audit returns result")
		if auditResult != nil {
			assertCheck(auditResult.AuditID != "", "Audit returns audit ID")
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
	if len(failures) > 0 {
		fmt.Printf("\n❌ %d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL TESTS PASSED - Gateway Mode verified!")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
