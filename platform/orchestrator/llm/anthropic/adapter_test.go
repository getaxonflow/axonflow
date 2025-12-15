// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anthropic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewLLMProviderAdapter tests adapter creation
func TestNewLLMProviderAdapter(t *testing.T) {
	provider := &Provider{
		apiKey: "test-key",
	}

	adapter := NewLLMProviderAdapter(provider)
	if adapter == nil {
		t.Fatal("NewLLMProviderAdapter returned nil")
	}

	if adapter.provider != provider {
		t.Error("Adapter provider doesn't match")
	}
}

// TestNewLLMProvider tests provider adapter creation from API key
func TestNewLLMProvider(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		expectNil bool
	}{
		{
			name:      "empty key returns nil",
			apiKey:    "",
			expectNil: true,
		},
		{
			name:      "valid key returns adapter",
			apiKey:    "test-api-key",
			expectNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewLLMProvider(tt.apiKey)
			if err != nil {
				t.Errorf("NewLLMProvider returned error: %v", err)
			}

			if tt.expectNil && adapter != nil {
				t.Error("Expected nil adapter for empty key")
			}
			if !tt.expectNil && adapter == nil {
				t.Error("Expected non-nil adapter for valid key")
			}
		})
	}
}

// TestLLMProviderAdapter_Name tests the Name method
func TestLLMProviderAdapter_Name(t *testing.T) {
	provider := &Provider{
		apiKey: "test-key",
	}

	adapter := NewLLMProviderAdapter(provider)
	name := adapter.Name()

	if name != "anthropic" {
		t.Errorf("Name() = %q, want %q", name, "anthropic")
	}
}

// TestLLMProviderAdapter_IsHealthy tests the IsHealthy method
func TestLLMProviderAdapter_IsHealthy(t *testing.T) {
	provider := &Provider{
		apiKey:  "test-key",
		healthy: true,
	}

	adapter := NewLLMProviderAdapter(provider)
	healthy := adapter.IsHealthy()

	if !healthy {
		t.Error("IsHealthy() should return true for healthy provider")
	}
}

// TestLLMProviderAdapter_IsHealthy_Unhealthy tests unhealthy state
func TestLLMProviderAdapter_IsHealthy_Unhealthy(t *testing.T) {
	provider := &Provider{
		apiKey:  "test-key",
		healthy: false,
	}

	adapter := NewLLMProviderAdapter(provider)
	healthy := adapter.IsHealthy()

	if healthy {
		t.Error("IsHealthy() should return false for unhealthy provider")
	}
}

// TestLLMProviderAdapter_GetCapabilities tests the GetCapabilities method
func TestLLMProviderAdapter_GetCapabilities(t *testing.T) {
	provider := &Provider{
		apiKey: "test-key",
	}

	adapter := NewLLMProviderAdapter(provider)
	caps := adapter.GetCapabilities()

	if len(caps) == 0 {
		t.Error("GetCapabilities() should return capabilities")
	}

	// Check for expected capabilities
	hasStreaming := false
	for _, cap := range caps {
		if cap == "streaming" {
			hasStreaming = true
			break
		}
	}
	if !hasStreaming {
		t.Error("Expected streaming capability")
	}
}

// TestLLMProviderAdapter_EstimateCost tests the EstimateCost method
func TestLLMProviderAdapter_EstimateCost(t *testing.T) {
	provider := &Provider{
		apiKey: "test-key",
	}

	adapter := NewLLMProviderAdapter(provider)

	tests := []struct {
		tokens   int
		minCost  float64
		maxCost  float64
	}{
		{tokens: 0, minCost: 0, maxCost: 0.0001},
		{tokens: 1000, minCost: 0.0001, maxCost: 1.0},
		{tokens: 10000, minCost: 0.001, maxCost: 10.0},
	}

	for _, tt := range tests {
		cost := adapter.EstimateCost(tt.tokens)
		if cost < tt.minCost || cost > tt.maxCost {
			t.Errorf("EstimateCost(%d) = %f, expected between %f and %f",
				tt.tokens, cost, tt.minCost, tt.maxCost)
		}
	}
}

// TestLLMProviderAdapter_GetProvider tests the GetProvider method
func TestLLMProviderAdapter_GetProvider(t *testing.T) {
	provider := &Provider{
		apiKey: "test-key",
	}

	adapter := NewLLMProviderAdapter(provider)
	got := adapter.GetProvider()

	if got != provider {
		t.Error("GetProvider() should return the original provider")
	}
}

// TestLLMProviderAdapter_Query tests the Query method with mock server
func TestLLMProviderAdapter_Query(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"id": "msg_test",
			"type": "message",
			"role": "assistant",
			"content": [{"type": "text", "text": "Hello from test!"}],
			"model": "claude-3-opus-20240229",
			"stop_reason": "end_turn",
			"usage": {
				"input_tokens": 10,
				"output_tokens": 5
			}
		}`))
	}))
	defer server.Close()

	provider := &Provider{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 10 * time.Second},
		healthy: true,
	}

	adapter := NewLLMProviderAdapter(provider)

	ctx := context.Background()
	options := QueryOptions{
		MaxTokens:   100,
		Temperature: 0.7,
		Model:       "claude-3-opus-20240229",
	}

	resp, err := adapter.Query(ctx, "Hello", options)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}

	if resp == nil {
		t.Fatal("Query returned nil response")
	}

	if resp.Content != "Hello from test!" {
		t.Errorf("Unexpected content: %q", resp.Content)
	}

	if resp.Model != "claude-3-opus-20240229" {
		t.Errorf("Unexpected model: %q", resp.Model)
	}

	if resp.TokensUsed != 15 {
		t.Errorf("Unexpected tokens: %d", resp.TokensUsed)
	}

	if resp.Metadata["provider"] != "anthropic" {
		t.Error("Expected metadata to include provider")
	}
}

// TestLLMProviderAdapter_Query_Error tests Query error handling
func TestLLMProviderAdapter_Query_Error(t *testing.T) {
	// Create mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{
			"type": "error",
			"error": {"type": "authentication_error", "message": "Invalid API Key"}
		}`))
	}))
	defer server.Close()

	provider := &Provider{
		apiKey:  "invalid-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 10 * time.Second},
		healthy: true,
	}

	adapter := NewLLMProviderAdapter(provider)

	ctx := context.Background()
	options := QueryOptions{
		MaxTokens: 100,
	}

	_, err := adapter.Query(ctx, "Hello", options)
	if err == nil {
		t.Error("Expected error for invalid API key")
	}
}

// TestLLMProviderAdapter_QueryStream tests the QueryStream method
func TestLLMProviderAdapter_QueryStream(t *testing.T) {
	// Create mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Send SSE events
		w.Write([]byte(`event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hello "}}

event: content_block_delta
data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "World"}}

event: message_delta
data: {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 2}}

event: message_stop
data: {"type": "message_stop"}

`))
	}))
	defer server.Close()

	provider := &Provider{
		apiKey:  "test-key",
		baseURL: server.URL,
		client:  &http.Client{Timeout: 10 * time.Second},
		healthy: true,
	}

	adapter := NewLLMProviderAdapter(provider)

	ctx := context.Background()
	options := QueryOptions{
		MaxTokens:   100,
		Temperature: 0.7,
	}

	var chunks []string
	resp, err := adapter.QueryStream(ctx, "Hello", options, func(chunk string) error {
		chunks = append(chunks, chunk)
		return nil
	})

	if err != nil {
		t.Fatalf("QueryStream returned error: %v", err)
	}

	if resp == nil {
		t.Fatal("QueryStream returned nil response")
	}

	if len(chunks) == 0 {
		t.Error("Expected to receive chunks")
	}

	if resp.Metadata["streamed"] != true {
		t.Error("Expected streamed metadata to be true")
	}
}

// TestQueryOptions tests QueryOptions struct
func TestQueryOptions(t *testing.T) {
	opts := QueryOptions{
		MaxTokens:    1000,
		Temperature:  0.8,
		Model:        "claude-3-opus-20240229",
		SystemPrompt: "You are a helpful assistant",
	}

	if opts.MaxTokens != 1000 {
		t.Errorf("MaxTokens = %d, want 1000", opts.MaxTokens)
	}

	if opts.Temperature != 0.8 {
		t.Errorf("Temperature = %f, want 0.8", opts.Temperature)
	}

	if opts.Model != "claude-3-opus-20240229" {
		t.Errorf("Model = %q, want claude-3-opus-20240229", opts.Model)
	}

	if opts.SystemPrompt != "You are a helpful assistant" {
		t.Errorf("SystemPrompt incorrect")
	}
}

// TestLLMResponse tests LLMResponse struct
func TestLLMResponse(t *testing.T) {
	resp := LLMResponse{
		Content:      "Test content",
		Model:        "claude-3-opus-20240229",
		TokensUsed:   100,
		ResponseTime: 500 * time.Millisecond,
		Metadata: map[string]interface{}{
			"provider": "anthropic",
		},
	}

	if resp.Content != "Test content" {
		t.Error("Content mismatch")
	}

	if resp.TokensUsed != 100 {
		t.Errorf("TokensUsed = %d, want 100", resp.TokensUsed)
	}

	if resp.ResponseTime != 500*time.Millisecond {
		t.Error("ResponseTime mismatch")
	}

	if resp.Metadata["provider"] != "anthropic" {
		t.Error("Metadata provider mismatch")
	}
}
