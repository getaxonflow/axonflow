// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockHTTPClient is a mock HTTP client for testing.
type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

// Helper to create a successful response.
func successResponse(content string, promptTokens, completionTokens int) *http.Response {
	resp := map[string]any{
		"id":      "chatcmpl-test123",
		"object":  "chat.completion",
		"created": 1234567890,
		"model":   "gpt-4o-mini-2024-07-18",
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     promptTokens,
			"completion_tokens": completionTokens,
			"total_tokens":      promptTokens + completionTokens,
		},
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

// Helper to create an error response.
func errorResponse(statusCode int, code, message string) *http.Response {
	resp := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
			"type":    "invalid_request_error",
		},
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

// Helper to create a streaming response.
func streamingResponse(chunks []string) *http.Response {
	var builder strings.Builder
	for i, chunk := range chunks {
		data := map[string]any{
			"id":      "chatcmpl-stream123",
			"object":  "chat.completion.chunk",
			"created": 1234567890,
			"model":   "gpt-4o-mini-2024-07-18",
			"choices": []map[string]any{
				{
					"index": 0,
					"delta": map[string]string{
						"content": chunk,
					},
				},
			},
		}
		// Add finish reason to last chunk
		if i == len(chunks)-1 {
			data["choices"].([]map[string]any)[0]["finish_reason"] = "stop"
		}
		jsonData, _ := json.Marshal(data)
		builder.WriteString("data: ")
		builder.Write(jsonData)
		builder.WriteString("\n\n")
	}
	builder.WriteString("data: [DONE]\n\n")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(builder.String())),
		Header:     make(http.Header),
	}
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: Config{
				Endpoint:       "https://test.openai.azure.com",
				APIKey:         "test-key",
				DeploymentName: "gpt-4o-mini",
			},
			wantErr: false,
		},
		{
			name: "missing endpoint",
			config: Config{
				APIKey:         "test-key",
				DeploymentName: "gpt-4o-mini",
			},
			wantErr: true,
			errMsg:  "endpoint is required",
		},
		{
			name: "missing API key",
			config: Config{
				Endpoint:       "https://test.openai.azure.com",
				DeploymentName: "gpt-4o-mini",
			},
			wantErr: true,
			errMsg:  "API key is required",
		},
		{
			name: "missing deployment name",
			config: Config{
				Endpoint: "https://test.openai.azure.com",
				APIKey:   "test-key",
			},
			wantErr: true,
			errMsg:  "deployment name is required",
		},
		{
			name: "trailing slash normalized",
			config: Config{
				Endpoint:       "https://test.openai.azure.com/",
				APIKey:         "test-key",
				DeploymentName: "gpt-4o-mini",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewProvider() expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("NewProvider() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Errorf("NewProvider() unexpected error = %v", err)
				return
			}
			if provider == nil {
				t.Error("NewProvider() returned nil provider")
			}
		})
	}
}

func TestAuthTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		expected AuthType
	}{
		{
			name:     "Classic Azure OpenAI",
			endpoint: "https://myresource.openai.azure.com",
			expected: AuthTypeAPIKey,
		},
		{
			name:     "Azure AI Foundry",
			endpoint: "https://myresource-eastus.cognitiveservices.azure.com",
			expected: AuthTypeBearer,
		},
		{
			name:     "Foundry with different region",
			endpoint: "https://saura-mjw3kb7m-eastus2.cognitiveservices.azure.com",
			expected: AuthTypeBearer,
		},
		{
			name:     "Classic case insensitive",
			endpoint: "https://MyResource.OpenAI.Azure.COM",
			expected: AuthTypeAPIKey,
		},
		{
			name:     "Foundry case insensitive",
			endpoint: "https://MyResource.CognitiveServices.Azure.COM",
			expected: AuthTypeBearer,
		},
		{
			name:     "Unknown endpoint defaults to api-key",
			endpoint: "https://custom-endpoint.example.com",
			expected: AuthTypeAPIKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(Config{
				Endpoint:       tt.endpoint,
				APIKey:         "test-key",
				DeploymentName: "gpt-4o-mini",
			})
			if err != nil {
				t.Fatalf("NewProvider() unexpected error = %v", err)
			}
			if provider.GetAuthType() != tt.expected {
				t.Errorf("GetAuthType() = %v, want %v", provider.GetAuthType(), tt.expected)
			}
		})
	}
}

func TestAuthTypeOverride(t *testing.T) {
	// Test that explicit auth type overrides auto-detection
	provider, err := NewProvider(Config{
		Endpoint:       "https://test.cognitiveservices.azure.com", // Would auto-detect Bearer
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
		AuthType:       AuthTypeAPIKey, // But we override to api-key
	})
	if err != nil {
		t.Fatalf("NewProvider() unexpected error = %v", err)
	}
	if provider.GetAuthType() != AuthTypeAPIKey {
		t.Errorf("GetAuthType() = %v, want %v (override)", provider.GetAuthType(), AuthTypeAPIKey)
	}
}

func TestComplete(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request
			if req.Method != "POST" {
				t.Errorf("Expected POST request, got %s", req.Method)
			}
			if !strings.Contains(req.URL.Path, "/openai/deployments/gpt-4o-mini/chat/completions") {
				t.Errorf("Unexpected URL path: %s", req.URL.Path)
			}
			if req.Header.Get("api-key") != "test-key" {
				t.Errorf("Expected api-key header, got: %s", req.Header.Get("api-key"))
			}
			if req.Header.Get("Content-Type") != "application/json" {
				t.Errorf("Expected Content-Type application/json, got: %s", req.Header.Get("Content-Type"))
			}

			return successResponse("Hello! How can I help you?", 10, 8), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx := context.Background()
	resp, err := provider.Complete(ctx, CompletionRequest{
		Prompt:      "Hello",
		MaxTokens:   100,
		Temperature: 0.7,
	})

	if err != nil {
		t.Fatalf("Complete() unexpected error = %v", err)
	}
	if resp.Content != "Hello! How can I help you?" {
		t.Errorf("Complete() content = %q, want %q", resp.Content, "Hello! How can I help you?")
	}
	if resp.Usage.InputTokens != 10 {
		t.Errorf("Complete() input tokens = %d, want %d", resp.Usage.InputTokens, 10)
	}
	if resp.Usage.OutputTokens != 8 {
		t.Errorf("Complete() output tokens = %d, want %d", resp.Usage.OutputTokens, 8)
	}
}

func TestCompleteBearerAuth(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.cognitiveservices.azure.com", // Foundry endpoint
		APIKey:         "bearer-token-123",
		DeploymentName: "gpt-4o-mini",
	})

	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify Bearer auth header
			authHeader := req.Header.Get("Authorization")
			if authHeader != "Bearer bearer-token-123" {
				t.Errorf("Expected Bearer auth header, got: %s", authHeader)
			}
			// api-key header should NOT be set
			if req.Header.Get("api-key") != "" {
				t.Errorf("api-key header should not be set for Bearer auth")
			}

			return successResponse("Hello from Foundry!", 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx := context.Background()
	resp, err := provider.Complete(ctx, CompletionRequest{
		Prompt: "Hello",
	})

	if err != nil {
		t.Fatalf("Complete() unexpected error = %v", err)
	}
	if resp.Content != "Hello from Foundry!" {
		t.Errorf("Complete() content = %q, want %q", resp.Content, "Hello from Foundry!")
	}
}

func TestCompleteWithSystemPrompt(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	var capturedBody map[string]any
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Capture request body
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("I am a helpful assistant!", 20, 6), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx := context.Background()
	_, err := provider.Complete(ctx, CompletionRequest{
		Prompt:       "Who are you?",
		SystemPrompt: "You are a helpful assistant.",
	})

	if err != nil {
		t.Fatalf("Complete() unexpected error = %v", err)
	}

	messages := capturedBody["messages"].([]any)
	if len(messages) != 2 {
		t.Errorf("Expected 2 messages (system + user), got %d", len(messages))
	}
	systemMsg := messages[0].(map[string]any)
	if systemMsg["role"] != "system" {
		t.Errorf("First message should be system role, got %s", systemMsg["role"])
	}
	if systemMsg["content"] != "You are a helpful assistant." {
		t.Errorf("System message content mismatch")
	}
}

func TestCompleteError(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "invalid-key",
		DeploymentName: "gpt-4o-mini",
	})

	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return errorResponse(401, "invalid_api_key", "Invalid API key"), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx := context.Background()
	_, err := provider.Complete(ctx, CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("Complete() expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("Expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("APIError.StatusCode = %d, want 401", apiErr.StatusCode)
	}
	if !apiErr.IsAuthError() {
		t.Error("Expected IsAuthError() to return true")
	}
}

func TestCompleteStream(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	chunks := []string{"Hello", " there", "!"}
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return streamingResponse(chunks), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	var receivedChunks []string
	handler := func(chunk StreamChunk) error {
		if chunk.Content != "" {
			receivedChunks = append(receivedChunks, chunk.Content)
		}
		return nil
	}

	ctx := context.Background()
	resp, err := provider.CompleteStream(ctx, CompletionRequest{
		Prompt: "Hello",
	}, handler)

	if err != nil {
		t.Fatalf("CompleteStream() unexpected error = %v", err)
	}
	if resp.Content != "Hello there!" {
		t.Errorf("CompleteStream() content = %q, want %q", resp.Content, "Hello there!")
	}
	if len(receivedChunks) != 3 {
		t.Errorf("Expected 3 chunks, got %d", len(receivedChunks))
	}
}

func TestProviderName(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	if provider.Name() != "azure-openai" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "azure-openai")
	}
}

func TestProviderCapabilities(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	capabilities := provider.GetCapabilities()
	expectedCaps := []string{"reasoning", "analysis", "writing", "code_generation", "vision", "streaming", "function_calling"}

	if len(capabilities) != len(expectedCaps) {
		t.Errorf("GetCapabilities() returned %d capabilities, want %d", len(capabilities), len(expectedCaps))
	}

	for _, expected := range expectedCaps {
		found := false
		for _, cap := range capabilities {
			if cap == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("GetCapabilities() missing expected capability: %s", expected)
		}
	}
}

func TestSupportsStreaming(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	if !provider.SupportsStreaming() {
		t.Error("SupportsStreaming() should return true")
	}
}

func TestIsHealthy(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	if !provider.IsHealthy() {
		t.Error("IsHealthy() should return true for new provider")
	}

	// Simulate failure
	provider.setHealthy(false)
	if provider.IsHealthy() {
		t.Error("IsHealthy() should return false after setHealthy(false)")
	}

	// Recover
	provider.setHealthy(true)
	if !provider.IsHealthy() {
		t.Error("IsHealthy() should return true after setHealthy(true)")
	}
}

func TestEstimateCost(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	cost := provider.EstimateCost(1000)
	if cost <= 0 {
		t.Errorf("EstimateCost(1000) = %f, want > 0", cost)
	}
}

func TestDefaultValues(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	// Check default API version is set
	if provider.apiVersion != DefaultAPIVersion {
		t.Errorf("Default apiVersion = %q, want %q", provider.apiVersion, DefaultAPIVersion)
	}

	// Check default timeout
	if provider.timeout != DefaultTimeout {
		t.Errorf("Default timeout = %v, want %v", provider.timeout, DefaultTimeout)
	}
}

func TestContextCancellation(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
	})

	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Check if context is cancelled
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			default:
				return successResponse("Hello", 10, 5), nil
			}
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := provider.Complete(ctx, CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestBuildURL(t *testing.T) {
	provider, _ := NewProvider(Config{
		Endpoint:       "https://test.openai.azure.com",
		APIKey:         "test-key",
		DeploymentName: "gpt-4o-mini",
		APIVersion:     "2024-08-01-preview",
	})

	url := provider.buildURL("gpt-4o-mini", false)
	expected := "https://test.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-08-01-preview"
	if url != expected {
		t.Errorf("buildURL() = %q, want %q", url, expected)
	}
}

func TestAPIErrorMethods(t *testing.T) {
	tests := []struct {
		name          string
		err           *APIError
		isRateLimit   bool
		isAuth        bool
		isQuota       bool
	}{
		{
			name:        "rate limit error",
			err:         &APIError{StatusCode: 429, Code: "rate_limit_exceeded"},
			isRateLimit: true,
			isAuth:      false,
			isQuota:     false,
		},
		{
			name:        "auth error - 401",
			err:         &APIError{StatusCode: 401, Code: "invalid_api_key"},
			isRateLimit: false,
			isAuth:      true,
			isQuota:     false,
		},
		{
			name:        "auth error - 403",
			err:         &APIError{StatusCode: 403, Code: "access_denied"},
			isRateLimit: false,
			isAuth:      true,
			isQuota:     false,
		},
		{
			name:        "quota exceeded",
			err:         &APIError{StatusCode: 402, Code: "quota_exceeded"},
			isRateLimit: false,
			isAuth:      false,
			isQuota:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.IsRateLimitError() != tt.isRateLimit {
				t.Errorf("IsRateLimitError() = %v, want %v", tt.err.IsRateLimitError(), tt.isRateLimit)
			}
			if tt.err.IsAuthError() != tt.isAuth {
				t.Errorf("IsAuthError() = %v, want %v", tt.err.IsAuthError(), tt.isAuth)
			}
			if tt.err.IsQuotaExceededError() != tt.isQuota {
				t.Errorf("IsQuotaExceededError() = %v, want %v", tt.err.IsQuotaExceededError(), tt.isQuota)
			}
		})
	}
}
