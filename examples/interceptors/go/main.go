// AxonFlow LLM Interceptor Example - Go
//
// Demonstrates how to wrap LLM provider clients with AxonFlow governance
// using interceptors. This provides transparent policy enforcement without
// changing your existing LLM call patterns.
//
// Interceptors automatically:
// - Pre-check queries against policies before LLM calls
// - Block requests that violate policies
// - Audit LLM responses for compliance tracking
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Usage:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	export OPENAI_API_KEY=your-openai-key
//	go run main.go
package main

import (
	"context"
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v5"
	"github.com/getaxonflow/axonflow-sdk-go/v5/interceptors"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	fmt.Println("AxonFlow LLM Interceptor Example - Go")
	fmt.Println("============================================================")
	fmt.Println()

	// Initialize AxonFlow client
	agentURL := os.Getenv("AXONFLOW_ENDPOINT")
	if agentURL == "" {
		agentURL = os.Getenv("AXONFLOW_AGENT_URL")
	}
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	if userToken == "" {
		userToken = "user-123"
	}

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		Debug:        true,
	})

	// Create a wrapped OpenAI function using the interceptor
	// In a real app, this would wrap your actual OpenAI client
	wrappedCall := interceptors.WrapOpenAIFunc(
		mockOpenAICall, // Replace with your actual OpenAI call
		axonflowClient,
		userToken,
	)

	fmt.Println("Testing LLM Interceptor with OpenAI")
	fmt.Println("------------------------------------------------------------")
	fmt.Println()

	ctx := context.Background()

	// Example 1: Safe query (should pass)
	fmt.Println("Example 1: Safe Query")
	fmt.Println("----------------------------------------")
	runTest(ctx, wrappedCall, "What is the capital of France?", false, "Safe query")
	fmt.Println()

	// Example 2: Query with PII (may be blocked OR approved with redaction)
	// Default policies use PII_ACTION=redact, so the query may be approved
	// with PII redacted rather than blocked outright
	fmt.Println("Example 2: Query with PII (Expected: Blocked or Approved with Redaction)")
	fmt.Println("----------------------------------------")
	runPIITest(ctx, wrappedCall, "Process refund for SSN 123-45-6789")
	fmt.Println()

	// Example 3: SQL injection attempt (should be blocked)
	fmt.Println("Example 3: SQL Injection (Expected: Blocked)")
	fmt.Println("----------------------------------------")
	runTest(ctx, wrappedCall, "SELECT * FROM users WHERE 1=1; DROP TABLE users;--", true, "SQL injection")
	fmt.Println()

	fmt.Println("============================================================")

	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}

	fmt.Println("ALL ASSERTIONS PASSED - Interceptor example verified!")
}

func runTest(ctx context.Context, wrappedCall interceptors.OpenAICreateFunc, query string, expectBlocked bool, testName string) {
	fmt.Printf("Query: %s\n", query)

	req := interceptors.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []interceptors.ChatMessage{
			{Role: "user", Content: query},
		},
		MaxTokens: 100,
	}

	response, err := wrappedCall(ctx, req)
	if err != nil {
		if interceptors.IsPolicyViolationError(err) {
			pve, _ := interceptors.GetPolicyViolation(err)
			fmt.Printf("Status: BLOCKED\n")
			fmt.Printf("Reason: %s\n", pve.BlockReason)
			assertCheck(expectBlocked, testName+": query was blocked as expected")
			assertCheck(pve.BlockReason != "", testName+": block reason is provided")
		} else {
			fmt.Printf("Error: %v\n", err)
			if !expectBlocked {
				assertCheck(false, testName+": unexpected error: "+err.Error())
			}
		}
		return
	}

	fmt.Printf("Status: APPROVED\n")
	if len(response.Choices) > 0 {
		fmt.Printf("Response: %s\n", response.Choices[0].Message.Content)
	}
	assertCheck(!expectBlocked, testName+": query was approved as expected")
	assertCheck(len(response.Choices) > 0, testName+": response has content")
}

func runPIITest(ctx context.Context, wrappedCall interceptors.OpenAICreateFunc, query string) {
	fmt.Printf("Query: %s\n", query)

	req := interceptors.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []interceptors.ChatMessage{
			{Role: "user", Content: query},
		},
		MaxTokens: 100,
	}

	response, err := wrappedCall(ctx, req)
	if err != nil {
		if interceptors.IsPolicyViolationError(err) {
			pve, _ := interceptors.GetPolicyViolation(err)
			fmt.Printf("Status: BLOCKED\n")
			fmt.Printf("Reason: %s\n", pve.BlockReason)
			assertCheck(true, "PII query was processed (blocked)")
		} else {
			fmt.Printf("Error: %v\n", err)
			assertCheck(false, "PII query: unexpected error: "+err.Error())
		}
		return
	}

	fmt.Printf("Status: APPROVED\n")
	if len(response.Choices) > 0 {
		fmt.Printf("Response: %s\n", response.Choices[0].Message.Content)
	}
	assertCheck(true, "PII query was processed (approved with redaction)")
}

// mockOpenAICall simulates an OpenAI API call for demonstration
// Replace this with your actual OpenAI client call in production
func mockOpenAICall(ctx context.Context, req interceptors.ChatCompletionRequest) (interceptors.ChatCompletionResponse, error) {
	// In production, you would use the actual OpenAI SDK here:
	//
	// import "github.com/sashabaranov/go-openai"
	//
	// client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
	// resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
	//     Model:    req.Model,
	//     Messages: convertMessages(req.Messages),
	// })

	// For demo purposes, return a mock response
	return interceptors.ChatCompletionResponse{
		ID:      "mock-response-id",
		Model:   req.Model,
		Created: 1234567890,
		Choices: []interceptors.ChatCompletionChoice{
			{
				Index: 0,
				Message: interceptors.ChatMessage{
					Role:    "assistant",
					Content: "Paris is the capital of France.",
				},
				FinishReason: "stop",
			},
		},
		Usage: interceptors.Usage{
			PromptTokens:     10,
			CompletionTokens: 8,
			TotalTokens:      18,
		},
	}, nil
}
