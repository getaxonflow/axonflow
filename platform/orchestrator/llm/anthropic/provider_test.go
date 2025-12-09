// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockHTTPClient is a mock implementation of HTTPClient
type MockHTTPClient struct {
	mock.Mock
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

// =============================================================================
// Provider Creation Tests
// =============================================================================

func TestNewProvider_Success(t *testing.T) {
	provider, err := NewProvider(Config{
		APIKey: "test-api-key",
	})

	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "anthropic", provider.Name())
	assert.Equal(t, DefaultBaseURL, provider.baseURL)
	assert.Equal(t, DefaultAPIVersion, provider.apiVersion)
	assert.Equal(t, DefaultModel, provider.model)
	assert.Equal(t, DefaultTimeout, provider.timeout)
	assert.True(t, provider.IsHealthy())
}

func TestNewProvider_CustomConfig(t *testing.T) {
	provider, err := NewProvider(Config{
		APIKey:     "test-api-key",
		BaseURL:    "https://custom.anthropic.com",
		APIVersion: "2024-01-01",
		Model:      ModelClaude3Opus,
		Timeout:    60 * time.Second,
	})

	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, "https://custom.anthropic.com", provider.baseURL)
	assert.Equal(t, "2024-01-01", provider.apiVersion)
	assert.Equal(t, ModelClaude3Opus, provider.model)
	assert.Equal(t, 60*time.Second, provider.timeout)
}

func TestNewProvider_MissingAPIKey(t *testing.T) {
	provider, err := NewProvider(Config{})

	assert.Error(t, err)
	assert.Nil(t, provider)
	assert.Contains(t, err.Error(), "API key is required")
}

// =============================================================================
// Provider Methods Tests
// =============================================================================

func TestProvider_Name(t *testing.T) {
	provider := &Provider{}
	assert.Equal(t, "anthropic", provider.Name())
}

func TestProvider_SupportsStreaming(t *testing.T) {
	provider := &Provider{}
	assert.True(t, provider.SupportsStreaming())
}

func TestProvider_GetCapabilities(t *testing.T) {
	provider := &Provider{}
	capabilities := provider.GetCapabilities()

	assert.Contains(t, capabilities, "reasoning")
	assert.Contains(t, capabilities, "analysis")
	assert.Contains(t, capabilities, "writing")
	assert.Contains(t, capabilities, "code_generation")
	assert.Contains(t, capabilities, "long_context")
	assert.Contains(t, capabilities, "vision")
	assert.Contains(t, capabilities, "streaming")
}

func TestProvider_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		healthy  bool
		expected bool
	}{
		{
			name:     "healthy with API key",
			apiKey:   "test-key",
			healthy:  true,
			expected: true,
		},
		{
			name:     "unhealthy state",
			apiKey:   "test-key",
			healthy:  false,
			expected: false,
		},
		{
			name:     "missing API key",
			apiKey:   "",
			healthy:  true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{
				apiKey:  tt.apiKey,
				healthy: tt.healthy,
			}
			assert.Equal(t, tt.expected, provider.IsHealthy())
		})
	}
}

func TestProvider_EstimateCost(t *testing.T) {
	provider := &Provider{}

	tests := []struct {
		name     string
		tokens   int
		expected float64
	}{
		{"zero tokens", 0, 0.0},
		{"1000 tokens", 1000, 0.009},
		{"10000 tokens", 10000, 0.09},
		{"100000 tokens", 100000, 0.9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := provider.EstimateCost(tt.tokens)
			assert.InDelta(t, tt.expected, cost, 0.0001)
		})
	}
}

// =============================================================================
// Complete Tests
// =============================================================================

func TestProvider_Complete_Success(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	// Create mock response
	apiResp := anthropicResponse{
		ID:         "msg_123",
		Type:       "message",
		Role:       "assistant",
		Model:      ModelClaude35Sonnet,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Paris is the capital of France."},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  10,
			OutputTokens: 8,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		return req.URL.String() == DefaultBaseURL+"/v1/messages" &&
			req.Header.Get("x-api-key") == "test-api-key" &&
			req.Header.Get("anthropic-version") == DefaultAPIVersion
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	// Execute
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:      "What is the capital of France?",
		MaxTokens:   100,
		Temperature: 0.7,
	})

	// Verify
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Paris is the capital of France.", resp.Content)
	assert.Equal(t, ModelClaude35Sonnet, resp.Model)
	assert.Equal(t, "end_turn", resp.StopReason)
	assert.Equal(t, 10, resp.Usage.InputTokens)
	assert.Equal(t, 8, resp.Usage.OutputTokens)
	assert.Equal(t, 18, resp.Usage.TotalTokens)
	assert.Greater(t, resp.Latency, time.Duration(0))

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_ModelOverride(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	// Create mock response
	apiResp := anthropicResponse{
		ID:         "msg_456",
		Type:       "message",
		Model:      ModelClaude3Opus,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response from Opus"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		return strings.Contains(string(body), ModelClaude3Opus)
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	// Execute with model override
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:      "Test prompt",
		MaxTokens:   50,
		Temperature: 0.5,
		Model:       ModelClaude3Opus,
	})

	// Verify
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, ModelClaude3Opus, resp.Model)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_WithSystemPrompt(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_789",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response with system prompt"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  20,
			OutputTokens: 10,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		return strings.Contains(string(body), "You are a helpful assistant")
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	// Execute with system prompt
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:       "Hello",
		SystemPrompt: "You are a helpful assistant",
		MaxTokens:    100,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Response with system prompt", resp.Content)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_HTTPError(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	// Mock 500 error response
	errorResp := `{"type":"error","error":{"type":"server_error","message":"Internal server error"}}`
	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(bytes.NewReader([]byte(errorResp))),
	}, nil)

	// Execute
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	// Verify
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, provider.IsHealthy()) // Should mark as unhealthy on 5xx

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Equal(t, "server_error", apiErr.Type)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_RateLimitError(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	errorResp := `{"type":"error","error":{"type":"rate_limit_error","message":"Rate limit exceeded"}}`
	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusTooManyRequests,
		Body:       io.NopCloser(bytes.NewReader([]byte(errorResp))),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.True(t, apiErr.IsRateLimitError())

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_AuthError(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "invalid-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	errorResp := `{"type":"error","error":{"type":"authentication_error","message":"Invalid API key"}}`
	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusUnauthorized,
		Body:       io.NopCloser(bytes.NewReader([]byte(errorResp))),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.True(t, apiErr.IsAuthError())

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_NetworkError(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	mockClient.On("Do", mock.Anything).Return(nil, errors.New("connection refused"))

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "anthropic API error")
	assert.False(t, provider.IsHealthy())

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_InvalidJSON(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("invalid json"))),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to decode response")

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_ContextCancellation(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockClient.On("Do", mock.Anything).Return(nil, context.Canceled)

	resp, err := provider.Complete(ctx, CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	assert.Error(t, err)
	assert.Nil(t, resp)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_MultipleContentBlocks(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_multi",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "First part. "},
			{Type: "text", Text: "Second part."},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 10,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	require.NoError(t, err)
	assert.Equal(t, "First part. Second part.", resp.Content)

	mockClient.AssertExpectations(t)
}

// =============================================================================
// Streaming Tests
// =============================================================================

func TestProvider_CompleteStream_Success(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	// Create SSE stream response
	streamData := `event: message_start
data: {"type":"message_start","message":{"id":"msg_stream","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":10}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}

event: message_stop
data: {"type":"message_stop"}

`

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(streamData))),
	}, nil)

	// Collect chunks
	var chunks []string
	handler := func(chunk StreamChunk) error {
		if chunk.Content != "" {
			chunks = append(chunks, chunk.Content)
		}
		return nil
	}

	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt:    "Say hello",
		MaxTokens: 50,
	}, handler)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Hello world!", resp.Content)
	assert.Equal(t, []string{"Hello", " world", "!"}, chunks)
	assert.Equal(t, 10, resp.Usage.InputTokens)
	assert.Equal(t, 3, resp.Usage.OutputTokens)
	assert.Equal(t, 13, resp.Usage.TotalTokens)

	mockClient.AssertExpectations(t)
}

func TestProvider_CompleteStream_NilHandler(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	streamData := `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Test"}}

event: message_stop
data: {"type":"message_stop"}

`

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(streamData))),
	}, nil)

	// Should work with nil handler
	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 50,
	}, nil)

	require.NoError(t, err)
	assert.Equal(t, "Test", resp.Content)

	mockClient.AssertExpectations(t)
}

func TestProvider_CompleteStream_HandlerError(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	streamData := `event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Test"}}

`

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(streamData))),
	}, nil)

	handlerErr := errors.New("handler error")
	handler := func(chunk StreamChunk) error {
		return handlerErr
	}

	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 50,
	}, handler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "handler error")

	mockClient.AssertExpectations(t)
}

// =============================================================================
// Model Validation Tests
// =============================================================================

func TestGetSupportedModels(t *testing.T) {
	models := GetSupportedModels()

	assert.Contains(t, models, ModelClaude4Opus)
	assert.Contains(t, models, ModelClaude4Sonnet)
	assert.Contains(t, models, ModelClaude35Sonnet)
	assert.Contains(t, models, ModelClaude35Haiku)
	assert.Contains(t, models, ModelClaude3Opus)
	assert.Contains(t, models, ModelClaude3Sonnet)
	assert.Contains(t, models, ModelClaude3Haiku)
}

func TestIsValidModel(t *testing.T) {
	tests := []struct {
		name     string
		model    string
		expected bool
	}{
		{"Claude 4 Opus", ModelClaude4Opus, true},
		{"Claude 4 Sonnet", ModelClaude4Sonnet, true},
		{"Claude 3.5 Sonnet", ModelClaude35Sonnet, true},
		{"Claude 3 Opus", ModelClaude3Opus, true},
		{"Custom Claude model", "claude-custom-model", true},
		{"Invalid model", "gpt-4", false},
		{"Empty model", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidModel(tt.model)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// API Error Tests
// =============================================================================

func TestAPIError_Error(t *testing.T) {
	err := &APIError{
		StatusCode: 429,
		Type:       "rate_limit_error",
		Message:    "Too many requests",
	}

	assert.Contains(t, err.Error(), "429")
	assert.Contains(t, err.Error(), "rate_limit_error")
	assert.Contains(t, err.Error(), "Too many requests")
}

func TestAPIError_IsRateLimitError(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected bool
	}{
		{
			name:     "rate limit by status code",
			err:      &APIError{StatusCode: http.StatusTooManyRequests, Type: "error"},
			expected: true,
		},
		{
			name:     "rate limit by type",
			err:      &APIError{StatusCode: 400, Type: "rate_limit_error"},
			expected: true,
		},
		{
			name:     "not rate limit",
			err:      &APIError{StatusCode: 500, Type: "server_error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.IsRateLimitError())
		})
	}
}

func TestAPIError_IsAuthError(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected bool
	}{
		{
			name:     "auth error by status code",
			err:      &APIError{StatusCode: http.StatusUnauthorized, Type: "error"},
			expected: true,
		},
		{
			name:     "auth error by type",
			err:      &APIError{StatusCode: 400, Type: "authentication_error"},
			expected: true,
		},
		{
			name:     "not auth error",
			err:      &APIError{StatusCode: 500, Type: "server_error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.IsAuthError())
		})
	}
}

func TestAPIError_IsOverloadedError(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected bool
	}{
		{
			name:     "overloaded by status code",
			err:      &APIError{StatusCode: http.StatusServiceUnavailable, Type: "error"},
			expected: true,
		},
		{
			name:     "overloaded by type",
			err:      &APIError{StatusCode: 400, Type: "overloaded_error"},
			expected: true,
		},
		{
			name:     "not overloaded",
			err:      &APIError{StatusCode: 500, Type: "server_error"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.IsOverloadedError())
		})
	}
}

// =============================================================================
// Default Values Tests
// =============================================================================

func TestProvider_Complete_DefaultValues(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_default",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))

		var apiReq anthropicRequest
		if err := json.Unmarshal(body, &apiReq); err != nil {
			return false
		}

		// Verify defaults are used
		return apiReq.MaxTokens == DefaultMaxTokens &&
			apiReq.Model == DefaultModel
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	// Execute with minimal request (rely on defaults)
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Test",
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)

	mockClient.AssertExpectations(t)
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestProvider_Complete_EmptyResponse(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_empty",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content:    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{}, // Empty content
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 0,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "", resp.Content)
	assert.Equal(t, 5, resp.Usage.InputTokens)
	assert.Equal(t, 0, resp.Usage.OutputTokens)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_WithStopSequences(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_stop",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "stop_sequence",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response before stop"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		return strings.Contains(string(body), `"stop_sequences":["STOP","END"]`)
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:        "Test",
		MaxTokens:     100,
		StopSequences: []string{"STOP", "END"},
	})

	require.NoError(t, err)
	assert.Equal(t, "stop_sequence", resp.StopReason)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_WithTemperatureZero(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_temp_zero",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Deterministic response"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	// Verify that temperature=0 is actually sent to the API (not replaced with default)
	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		// Temperature 0 should be in the request as "temperature":0
		return strings.Contains(string(body), `"temperature":0`)
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	// Execute with temperature=0 (deterministic output)
	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:      "Test",
		MaxTokens:   100,
		Temperature: 0.0, // Explicitly set to 0 for deterministic outputs
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "Deterministic response", resp.Content)

	mockClient.AssertExpectations(t)
}

func TestProvider_Complete_WithTopPAndTopK(t *testing.T) {
	mockClient := new(MockHTTPClient)

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	apiResp := anthropicResponse{
		ID:         "msg_sampling",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient.On("Do", mock.MatchedBy(func(req *http.Request) bool {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		return strings.Contains(string(body), `"top_p":0.9`) &&
			strings.Contains(string(body), `"top_k":40`)
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}, nil)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:    "Test",
		MaxTokens: 100,
		TopP:      0.9,
		TopK:      40,
	})

	require.NoError(t, err)
	assert.NotNil(t, resp)

	mockClient.AssertExpectations(t)
}

// =============================================================================
// Concurrency Tests
// =============================================================================

// ConcurrentMockHTTPClient is a mock that can handle concurrent calls
type ConcurrentMockHTTPClient struct {
	respBody []byte
}

func (c *ConcurrentMockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(c.respBody)),
	}, nil
}

func TestProvider_ConcurrentRequests(t *testing.T) {
	apiResp := anthropicResponse{
		ID:         "msg_concurrent",
		Type:       "message",
		Model:      DefaultModel,
		StopReason: "end_turn",
		Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{
			{Type: "text", Text: "Response"},
		},
		Usage: struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		}{
			InputTokens:  5,
			OutputTokens: 5,
		},
	}
	respBody, _ := json.Marshal(apiResp)

	mockClient := &ConcurrentMockHTTPClient{respBody: respBody}

	provider := &Provider{
		apiKey:     "test-api-key",
		baseURL:    DefaultBaseURL,
		apiVersion: DefaultAPIVersion,
		model:      DefaultModel,
		timeout:    DefaultTimeout,
		client:     mockClient,
		healthy:    true,
	}

	// Run concurrent requests
	const numRequests = 10
	done := make(chan bool, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			_, err := provider.Complete(context.Background(), CompletionRequest{
				Prompt:    "Test",
				MaxTokens: 100,
			})
			done <- err == nil
		}()
	}

	// All requests should succeed
	for i := 0; i < numRequests; i++ {
		assert.True(t, <-done)
	}
}

func TestProvider_HealthStatusConcurrency(t *testing.T) {
	provider := &Provider{
		apiKey:  "test-key",
		healthy: true,
	}

	// Concurrent health status updates
	const numGoroutines = 100
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			if i%2 == 0 {
				provider.setHealthy(true)
			} else {
				provider.setHealthy(false)
			}
			_ = provider.IsHealthy()
			done <- true
		}(i)
	}

	// All goroutines should complete without race conditions
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
