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

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
	"github.com/getaxonflow/axonflow-sdk-go/interceptors"
)

func main() {
	fmt.Println("AxonFlow LLM Interceptor Example - Go")
	fmt.Println("============================================================")
	fmt.Println()

	// Initialize AxonFlow client
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	axonflowClient := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		Debug:        true,
	})

	// Create a wrapped OpenAI function using the interceptor
	// In a real app, this would wrap your actual OpenAI client
	wrappedCall := interceptors.WrapOpenAIFunc(
		mockOpenAICall, // Replace with your actual OpenAI call
		axonflowClient,
		"user-123",
	)

	fmt.Println("Testing LLM Interceptor with OpenAI")
	fmt.Println("------------------------------------------------------------")
	fmt.Println()

	ctx := context.Background()

	// Example 1: Safe query (should pass)
	fmt.Println("Example 1: Safe Query")
	fmt.Println("----------------------------------------")
	runTest(ctx, wrappedCall, "What is the capital of France?")
	fmt.Println()

	// Example 2: Query with PII (should be blocked by default policies)
	fmt.Println("Example 2: Query with PII (Expected: Blocked)")
	fmt.Println("----------------------------------------")
	runTest(ctx, wrappedCall, "Process refund for SSN 123-45-6789")
	fmt.Println()

	// Example 3: SQL injection attempt (should be blocked)
	fmt.Println("Example 3: SQL Injection (Expected: Blocked)")
	fmt.Println("----------------------------------------")
	runTest(ctx, wrappedCall, "SELECT * FROM users WHERE 1=1; DROP TABLE users;--")
	fmt.Println()

	fmt.Println("============================================================")
	fmt.Println("Go LLM Interceptor Test: COMPLETE")
}

func runTest(ctx context.Context, wrappedCall interceptors.OpenAICreateFunc, query string) {
	fmt.Printf("Query: %s\n", query)

	req := interceptors.ChatCompletionRequest{
		Model: "gpt-3.5-turbo",
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
		} else {
			fmt.Printf("Error: %v\n", err)
		}
		return
	}

	fmt.Printf("Status: APPROVED\n")
	if len(response.Choices) > 0 {
		fmt.Printf("Response: %s\n", response.Choices[0].Message.Content)
	}
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
