//go:build enterprise

// Copyright 2025 AxonFlow
// Licensed under the Elastic License 2.0 (ELv2)
// Enterprise features - not available in Community distribution

package llmadapters

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"

	"axonflow/platform/orchestrator/llm"
)

// mockBedrockClient implements BedrockClient for testing.
type mockBedrockClient struct {
	response *bedrockruntime.InvokeModelOutput
	err      error
}

func (m *mockBedrockClient) InvokeModel(ctx context.Context, params *bedrockruntime.InvokeModelInput, optFns ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.response, nil
}

// createMockAnthropicResponse creates a mock Anthropic Claude response.
func createMockAnthropicResponse(content string, inputTokens, outputTokens int) *bedrockruntime.InvokeModelOutput {
	resp := map[string]interface{}{
		"content": []map[string]string{
			{"text": content},
		},
		"usage": map[string]int{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	}
	body, _ := json.Marshal(resp)
	return &bedrockruntime.InvokeModelOutput{
		Body: body,
	}
}

func TestBedrockAdapter_Name(t *testing.T) {
	tests := []struct {
		name     string
		adpName  string
		expected string
	}{
		{"default name", "", "bedrock"},
		{"custom name", "bedrock-primary", "bedrock-primary"},
		{"another name", "aws-claude", "aws-claude"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter := NewBedrockAdapterWithClient(tt.adpName, &mockBedrockClient{}, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

			if got := adapter.Name(); got != tt.expected {
				t.Errorf("Name() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBedrockAdapter_Type(t *testing.T) {
	adapter := NewBedrockAdapterWithClient("test", &mockBedrockClient{}, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

	if got := adapter.Type(); got != llm.ProviderTypeBedrock {
		t.Errorf("Type() = %v, want %v", got, llm.ProviderTypeBedrock)
	}
}

func TestBedrockAdapter_Capabilities(t *testing.T) {
	adapter := NewBedrockAdapterWithClient("test", &mockBedrockClient{}, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

	capabilities := adapter.Capabilities()

	expectedCaps := map[llm.Capability]bool{
		llm.CapabilityChat:        true,
		llm.CapabilityCompletion:  true,
		llm.CapabilityStreaming:   true,
		llm.CapabilityLongContext: true,
	}

	if len(capabilities) != len(expectedCaps) {
		t.Errorf("Capabilities() returned %d capabilities, want %d", len(capabilities), len(expectedCaps))
	}

	for _, cap := range capabilities {
		if !expectedCaps[cap] {
			t.Errorf("Unexpected capability: %v", cap)
		}
	}
}

func TestBedrockAdapter_SupportsStreaming(t *testing.T) {
	adapter := NewBedrockAdapterWithClient("test", &mockBedrockClient{}, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

	if !adapter.SupportsStreaming() {
		t.Error("SupportsStreaming() = false, want true")
	}
}

func TestBedrockAdapter_Complete(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			response: createMockAnthropicResponse("Hello! How can I help?", 10, 5),
		}

		adapter := NewBedrockAdapterWithClient("bedrock-test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		req := llm.CompletionRequest{
			Prompt:      "Hello",
			MaxTokens:   100,
			Temperature: 0.7,
		}

		resp, err := adapter.Complete(context.Background(), req)

		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		if resp.Content != "Hello! How can I help?" {
			t.Errorf("Content = %v, want 'Hello! How can I help?'", resp.Content)
		}

		if resp.Usage.PromptTokens != 10 {
			t.Errorf("PromptTokens = %v, want 10", resp.Usage.PromptTokens)
		}

		if resp.Usage.CompletionTokens != 5 {
			t.Errorf("CompletionTokens = %v, want 5", resp.Usage.CompletionTokens)
		}

		if resp.Usage.TotalTokens != 15 {
			t.Errorf("TotalTokens = %v, want 15", resp.Usage.TotalTokens)
		}
	})

	t.Run("uses default model when not specified", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			response: createMockAnthropicResponse("test", 1, 1),
		}

		adapter := NewBedrockAdapterWithClient("test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		req := llm.CompletionRequest{
			Prompt: "Hello",
		}

		resp, err := adapter.Complete(context.Background(), req)

		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		if resp.Model != "anthropic.claude-sonnet-4-20250514-v1:0" {
			t.Errorf("Model = %v, want 'anthropic.claude-sonnet-4-20250514-v1:0'", resp.Model)
		}
	})

	t.Run("uses specified model when provided", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			response: createMockAnthropicResponse("test", 1, 1),
		}

		adapter := NewBedrockAdapterWithClient("test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		req := llm.CompletionRequest{
			Prompt: "Hello",
			Model:  "anthropic.claude-opus-4-20250514-v1:0",
		}

		resp, err := adapter.Complete(context.Background(), req)

		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		if resp.Model != "anthropic.claude-opus-4-20250514-v1:0" {
			t.Errorf("Model = %v, want 'anthropic.claude-opus-4-20250514-v1:0'", resp.Model)
		}
	})

	t.Run("error handling", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			err: errors.New("connection timeout"),
		}

		adapter := NewBedrockAdapterWithClient("bedrock-test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		req := llm.CompletionRequest{
			Prompt:    "Hello",
			MaxTokens: 100,
		}

		_, err := adapter.Complete(context.Background(), req)

		if err == nil {
			t.Fatal("Complete() expected error, got nil")
		}

		providerErr, ok := err.(*llm.ProviderError)
		if !ok {
			t.Fatalf("expected *llm.ProviderError, got %T", err)
		}

		if providerErr.Provider != "bedrock-test" {
			t.Errorf("Provider = %v, want 'bedrock-test'", providerErr.Provider)
		}

		if providerErr.Code != llm.ErrCodeServerError {
			t.Errorf("Code = %v, want %v", providerErr.Code, llm.ErrCodeServerError)
		}

		if !providerErr.Retryable {
			t.Error("Retryable = false, want true")
		}
	})
}

func TestBedrockAdapter_HealthCheck(t *testing.T) {
	t.Run("healthy provider", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			response: createMockAnthropicResponse("Hi", 1, 1),
		}

		adapter := NewBedrockAdapterWithClient("bedrock-test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		result, err := adapter.HealthCheck(context.Background())

		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}

		if result.Status != llm.HealthStatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusHealthy)
		}

		if result.Latency <= 0 {
			t.Error("Latency should be > 0")
		}

		if result.LastChecked.IsZero() {
			t.Error("LastChecked should be set")
		}
	})

	t.Run("unhealthy provider", func(t *testing.T) {
		mockClient := &mockBedrockClient{
			err: errors.New("service unavailable"),
		}

		adapter := NewBedrockAdapterWithClient("bedrock-test", mockClient, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

		result, err := adapter.HealthCheck(context.Background())

		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}

		if result.Status != llm.HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, llm.HealthStatusUnhealthy)
		}

		if result.Message == "" {
			t.Error("Message should contain error details")
		}
	})
}

func TestBedrockAdapter_EstimateCost(t *testing.T) {
	adapter := NewBedrockAdapterWithClient("bedrock-test", &mockBedrockClient{}, "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic")

	tests := []struct {
		name       string
		prompt     string
		maxTokens  int
		wantInput  int
		wantOutput int
	}{
		{
			name:       "short prompt default tokens",
			prompt:     "Hello",
			maxTokens:  0,
			wantInput:  1,
			wantOutput: 1000,
		},
		{
			name:       "longer prompt with max tokens",
			prompt:     "This is a longer prompt with more characters",
			maxTokens:  500,
			wantInput:  11, // 44 chars / 4
			wantOutput: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := llm.CompletionRequest{
				Prompt:    tt.prompt,
				MaxTokens: tt.maxTokens,
			}

			estimate := adapter.EstimateCost(req)

			if estimate == nil {
				t.Fatal("EstimateCost() returned nil")
			}

			if estimate.EstimatedInputTokens != tt.wantInput {
				t.Errorf("EstimatedInputTokens = %v, want %v", estimate.EstimatedInputTokens, tt.wantInput)
			}

			if estimate.EstimatedOutputTokens != tt.wantOutput {
				t.Errorf("EstimatedOutputTokens = %v, want %v", estimate.EstimatedOutputTokens, tt.wantOutput)
			}

			if estimate.Currency != "USD" {
				t.Errorf("Currency = %v, want USD", estimate.Currency)
			}

			// Bedrock has non-zero costs
			if estimate.InputCostPer1K <= 0 {
				t.Error("InputCostPer1K should be > 0 for Bedrock")
			}

			if estimate.OutputCostPer1K <= 0 {
				t.Error("OutputCostPer1K should be > 0 for Bedrock")
			}

			if estimate.TotalEstimate <= 0 {
				t.Error("TotalEstimate should be > 0 for Bedrock")
			}
		})
	}
}

func TestDetectModelFamily(t *testing.T) {
	tests := []struct {
		name     string
		modelID  string
		expected string
	}{
		{"anthropic standard", "anthropic.claude-sonnet-4-20250514-v1:0", "anthropic"},
		{"amazon titan", "amazon.titan-text-express-v1", "amazon"},
		{"meta llama", "meta.llama3-70b-instruct-v1:0", "meta"},
		{"mistral", "mistral.mistral-large-2402-v1:0", "mistral"},
		{"eu inference profile", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0", "anthropic"},
		{"us inference profile", "us.anthropic.claude-sonnet-4-20250514-v1:0", "anthropic"},
		{"global inference profile", "global.anthropic.claude-opus-4-20250514-v1:0", "anthropic"},
		{"apac inference profile", "apac.meta.llama3-70b-instruct-v1:0", "meta"},
		{"unknown family", "unknown.model-v1", ""},
		{"empty", "", ""},
		{"single segment", "anthropic", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectModelFamily(tt.modelID)
			if result != tt.expected {
				t.Errorf("detectModelFamily(%q) = %q, want %q", tt.modelID, result, tt.expected)
			}
		})
	}
}

func TestBedrockAdapterInterfaceCompliance(t *testing.T) {
	var _ llm.Provider = (*BedrockAdapter)(nil)
}
