// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gemini

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
)

// mockHTTPClient is a mock HTTP client for testing.
type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

// Helper to create a successful response.
func successResponse(content string, inputTokens, outputTokens int) *http.Response {
	resp := geminiResponse{
		Candidates: []geminiCandidate{
			{
				Content: geminiContent{
					Parts: []geminiPart{{Text: content}},
					Role:  "model",
				},
				FinishReason: "STOP",
				Index:        0,
			},
		},
		UsageMetadata: &geminiUsageMetadata{
			PromptTokenCount:     inputTokens,
			CandidatesTokenCount: outputTokens,
			TotalTokenCount:      inputTokens + outputTokens,
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
func errorResponse(statusCode int, message, status string) *http.Response {
	resp := map[string]any{
		"error": map[string]any{
			"code":    statusCode,
			"message": message,
			"status":  status,
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
		resp := geminiResponse{
			Candidates: []geminiCandidate{
				{
					Content: geminiContent{
						Parts: []geminiPart{{Text: chunk}},
						Role:  "model",
					},
					Index: 0,
				},
			},
		}
		// Add finish reason to last chunk
		if i == len(chunks)-1 {
			resp.Candidates[0].FinishReason = "STOP"
			resp.UsageMetadata = &geminiUsageMetadata{
				PromptTokenCount:     10,
				CandidatesTokenCount: 20,
				TotalTokenCount:      30,
			}
		}
		data, _ := json.Marshal(resp)
		builder.WriteString("data: ")
		builder.Write(data)
		builder.WriteString("\n\n")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(builder.String())),
		Header:     make(http.Header),
	}
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config with all fields",
			cfg: Config{
				APIKey:     "test-api-key",
				BaseURL:    "https://custom.api.com",
				APIVersion: "v1",
				Model:      ModelGemini15Flash,
				Timeout:    60 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid config with minimal fields",
			cfg: Config{
				APIKey: "test-api-key",
			},
			wantErr: false,
		},
		{
			name:    "missing API key",
			cfg:     Config{},
			wantErr: true,
			errMsg:  "gemini API key is required",
		},
		{
			name: "empty API key",
			cfg: Config{
				APIKey: "",
			},
			wantErr: true,
			errMsg:  "gemini API key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error message should contain %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if provider == nil {
				t.Error("provider should not be nil")
				return
			}

			// Verify defaults
			if tt.cfg.BaseURL == "" && provider.baseURL != DefaultBaseURL {
				t.Errorf("expected default base URL %q, got %q", DefaultBaseURL, provider.baseURL)
			}
			if tt.cfg.APIVersion == "" && provider.apiVersion != DefaultAPIVersion {
				t.Errorf("expected default API version %q, got %q", DefaultAPIVersion, provider.apiVersion)
			}
			if tt.cfg.Model == "" && provider.model != DefaultModel {
				t.Errorf("expected default model %q, got %q", DefaultModel, provider.model)
			}
			if tt.cfg.Timeout == 0 && provider.timeout != DefaultTimeout {
				t.Errorf("expected default timeout %v, got %v", DefaultTimeout, provider.timeout)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	if name := provider.Name(); name != "gemini" {
		t.Errorf("expected name %q, got %q", "gemini", name)
	}
}

func TestProviderSupportsStreaming(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	if !provider.SupportsStreaming() {
		t.Error("provider should support streaming")
	}
}

func TestProviderGetCapabilities(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	capabilities := provider.GetCapabilities()

	expectedCapabilities := []string{
		"reasoning",
		"analysis",
		"writing",
		"code_generation",
		"long_context",
		"vision",
		"streaming",
		"function_calling",
	}

	if len(capabilities) != len(expectedCapabilities) {
		t.Errorf("expected %d capabilities, got %d", len(expectedCapabilities), len(capabilities))
	}

	for _, expected := range expectedCapabilities {
		found := false
		for _, cap := range capabilities {
			if cap == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing capability: %s", expected)
		}
	}
}

func TestProviderIsHealthy(t *testing.T) {
	t.Run("healthy provider", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		if !provider.IsHealthy() {
			t.Error("new provider should be healthy")
		}
	})

	t.Run("unhealthy after setHealthy(false)", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		provider.setHealthy(false)
		if provider.IsHealthy() {
			t.Error("provider should be unhealthy after setHealthy(false)")
		}
	})

	t.Run("healthy after recovery", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		provider.setHealthy(false)
		provider.setHealthy(true)
		if !provider.IsHealthy() {
			t.Error("provider should be healthy after setHealthy(true)")
		}
	})
}

func TestProviderEstimateCost(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})

	tests := []struct {
		tokens   int
		expected float64
	}{
		{1000, 0.003125},
		{0, 0},
		{1, 0.000003125},
	}

	for _, tt := range tests {
		cost := provider.EstimateCost(tt.tokens)
		if cost != tt.expected {
			t.Errorf("EstimateCost(%d) = %v, want %v", tt.tokens, cost, tt.expected)
		}
	}
}

func TestProviderComplete(t *testing.T) {
	t.Run("successful completion", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				// Verify request
				if req.Method != "POST" {
					t.Errorf("expected POST, got %s", req.Method)
				}
				if !strings.Contains(req.URL.String(), "generateContent") {
					t.Error("URL should contain generateContent")
				}
				if !strings.Contains(req.URL.String(), "key=test-key") {
					t.Error("URL should contain API key")
				}
				return successResponse("Hello, world!", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		resp, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt:    "Say hello",
			MaxTokens: 100,
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Content != "Hello, world!" {
			t.Errorf("expected content %q, got %q", "Hello, world!", resp.Content)
		}
		if resp.Usage.InputTokens != 10 {
			t.Errorf("expected input tokens 10, got %d", resp.Usage.InputTokens)
		}
		if resp.Usage.OutputTokens != 5 {
			t.Errorf("expected output tokens 5, got %d", resp.Usage.OutputTokens)
		}
		if resp.StopReason != "stop" {
			t.Errorf("expected stop reason %q, got %q", "stop", resp.StopReason)
		}
	})

	t.Run("with system prompt", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		var capturedBody map[string]any
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				json.Unmarshal(body, &capturedBody)
				return successResponse("Response", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt:       "Hello",
			SystemPrompt: "You are helpful",
			MaxTokens:    100,
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedBody["systemInstruction"] == nil {
			t.Error("request should contain systemInstruction")
		}
	})

	t.Run("with custom model", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.String(), ModelGemini15Flash) {
					t.Errorf("URL should contain model %s", ModelGemini15Flash)
				}
				return successResponse("Response", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt: "Hello",
			Model:  ModelGemini15Flash,
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("with generation config options", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		var capturedBody map[string]any
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				json.Unmarshal(body, &capturedBody)
				return successResponse("Response", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt:        "Hello",
			MaxTokens:     500,
			Temperature:   0.5,
			TopP:          0.9,
			TopK:          40,
			StopSequences: []string{"END"},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		genConfig := capturedBody["generationConfig"].(map[string]any)
		if genConfig["maxOutputTokens"] != float64(500) {
			t.Errorf("expected maxOutputTokens 500, got %v", genConfig["maxOutputTokens"])
		}
		if genConfig["temperature"] != 0.5 {
			t.Errorf("expected temperature 0.5, got %v", genConfig["temperature"])
		}
		if genConfig["topP"] != 0.9 {
			t.Errorf("expected topP 0.9, got %v", genConfig["topP"])
		}
		if genConfig["topK"] != float64(40) {
			t.Errorf("expected topK 40, got %v", genConfig["topK"])
		}
	})

	t.Run("network error", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt: "Hello",
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "gemini API error") {
			t.Errorf("error should mention gemini API error: %v", err)
		}
		if provider.IsHealthy() {
			t.Error("provider should be unhealthy after network error")
		}
	})

	t.Run("API error response", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return errorResponse(401, "Invalid API key", "UNAUTHENTICATED"), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt: "Hello",
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if !apiErr.IsAuthError() {
			t.Error("error should be an auth error")
		}
	})

	t.Run("rate limit error", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return errorResponse(429, "Rate limit exceeded", "RESOURCE_EXHAUSTED"), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt: "Hello",
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if !apiErr.IsRateLimitError() {
			t.Error("error should be a rate limit error")
		}
		if !apiErr.IsQuotaExceededError() {
			t.Error("error should be a quota exceeded error")
		}
	})

	t.Run("server error sets unhealthy", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return errorResponse(500, "Internal error", "INTERNAL"), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.Complete(context.Background(), CompletionRequest{
			Prompt: "Hello",
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if provider.IsHealthy() {
			t.Error("provider should be unhealthy after 500 error")
		}
	})

	t.Run("default temperature when negative", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		var capturedBody map[string]any
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				json.Unmarshal(body, &capturedBody)
				return successResponse("Response", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, _ = provider.Complete(context.Background(), CompletionRequest{
			Prompt:      "Hello",
			Temperature: -1, // Invalid, should use default
		})

		genConfig := capturedBody["generationConfig"].(map[string]any)
		if genConfig["temperature"] != DefaultTemperature {
			t.Errorf("expected default temperature %v, got %v", DefaultTemperature, genConfig["temperature"])
		}
	})

	t.Run("zero temperature is valid", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		var capturedBody map[string]any
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				json.Unmarshal(body, &capturedBody)
				return successResponse("Response", 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, _ = provider.Complete(context.Background(), CompletionRequest{
			Prompt:      "Hello",
			Temperature: 0, // Valid for deterministic output
		})

		genConfig := capturedBody["generationConfig"].(map[string]any)
		if genConfig["temperature"] != float64(0) {
			t.Errorf("expected temperature 0, got %v", genConfig["temperature"])
		}
	})
}

func TestProviderCompleteStream(t *testing.T) {
	t.Run("successful streaming", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				if !strings.Contains(req.URL.String(), "streamGenerateContent") {
					t.Error("URL should contain streamGenerateContent")
				}
				if !strings.Contains(req.URL.String(), "alt=sse") {
					t.Error("URL should contain alt=sse")
				}
				return streamingResponse([]string{"Hello", ", ", "world", "!"}), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		var chunks []string
		resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
			Prompt:    "Say hello",
			MaxTokens: 100,
		}, func(chunk StreamChunk) error {
			if chunk.Content != "" {
				chunks = append(chunks, chunk.Content)
			}
			return nil
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Content != "Hello, world!" {
			t.Errorf("expected content %q, got %q", "Hello, world!", resp.Content)
		}
		if len(chunks) != 4 {
			t.Errorf("expected 4 chunks, got %d", len(chunks))
		}
	})

	t.Run("handler error stops stream", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return streamingResponse([]string{"Hello", ", ", "world", "!"}), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		handlerErr := errors.New("handler error")
		_, err := provider.CompleteStream(context.Background(), CompletionRequest{
			Prompt: "Say hello",
		}, func(chunk StreamChunk) error {
			return handlerErr
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "handler error") {
			t.Errorf("error should mention handler error: %v", err)
		}
	})

	t.Run("network error", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.CompleteStream(context.Background(), CompletionRequest{
			Prompt: "Hello",
		}, func(chunk StreamChunk) error {
			return nil
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if provider.IsHealthy() {
			t.Error("provider should be unhealthy after network error")
		}
	})

	t.Run("API error response", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return errorResponse(401, "Invalid API key", "UNAUTHENTICATED"), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		_, err := provider.CompleteStream(context.Background(), CompletionRequest{
			Prompt: "Hello",
		}, func(chunk StreamChunk) error {
			return nil
		})

		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("nil handler", func(t *testing.T) {
		provider, _ := NewProvider(Config{APIKey: "test-key"})
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return streamingResponse([]string{"Hello"}), nil
			},
		}
		provider.SetHTTPClient(mockClient)

		resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
			Prompt: "Hello",
		}, nil)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Content != "Hello" {
			t.Errorf("expected content %q, got %q", "Hello", resp.Content)
		}
	})
}

func TestAPIError(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		err := &APIError{
			StatusCode: 401,
			Code:       401,
			Status:     "UNAUTHENTICATED",
			Message:    "Invalid API key",
		}
		expected := "gemini API error (status 401, code 401, UNAUTHENTICATED): Invalid API key"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("IsRateLimitError", func(t *testing.T) {
		tests := []struct {
			statusCode int
			status     string
			expected   bool
		}{
			{429, "", true},
			{429, "RESOURCE_EXHAUSTED", true},
			{200, "RESOURCE_EXHAUSTED", true},
			{401, "UNAUTHENTICATED", false},
			{500, "INTERNAL", false},
		}

		for _, tt := range tests {
			err := &APIError{StatusCode: tt.statusCode, Status: tt.status}
			if err.IsRateLimitError() != tt.expected {
				t.Errorf("IsRateLimitError(%d, %s) = %v, want %v",
					tt.statusCode, tt.status, err.IsRateLimitError(), tt.expected)
			}
		}
	})

	t.Run("IsAuthError", func(t *testing.T) {
		tests := []struct {
			statusCode int
			status     string
			expected   bool
		}{
			{401, "", true},
			{403, "", true},
			{200, "UNAUTHENTICATED", true},
			{200, "PERMISSION_DENIED", true},
			{429, "RESOURCE_EXHAUSTED", false},
			{500, "INTERNAL", false},
		}

		for _, tt := range tests {
			err := &APIError{StatusCode: tt.statusCode, Status: tt.status}
			if err.IsAuthError() != tt.expected {
				t.Errorf("IsAuthError(%d, %s) = %v, want %v",
					tt.statusCode, tt.status, err.IsAuthError(), tt.expected)
			}
		}
	})

	t.Run("IsQuotaExceededError", func(t *testing.T) {
		tests := []struct {
			status   string
			expected bool
		}{
			{"RESOURCE_EXHAUSTED", true},
			{"UNAUTHENTICATED", false},
			{"", false},
		}

		for _, tt := range tests {
			err := &APIError{Status: tt.status}
			if err.IsQuotaExceededError() != tt.expected {
				t.Errorf("IsQuotaExceededError(%s) = %v, want %v",
					tt.status, err.IsQuotaExceededError(), tt.expected)
			}
		}
	})
}

func TestGetSupportedModels(t *testing.T) {
	models := GetSupportedModels()
	if len(models) == 0 {
		t.Error("should return at least one model")
	}

	expectedModels := []string{
		ModelGemini2Flash,
		ModelGemini15Pro,
		ModelGemini15Flash,
	}

	for _, expected := range expectedModels {
		found := false
		for _, m := range models {
			if m == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing model: %s", expected)
		}
	}
}

func TestIsValidModel(t *testing.T) {
	tests := []struct {
		model    string
		expected bool
	}{
		{ModelGemini15Pro, true},
		{ModelGemini15Flash, true},
		{ModelGemini2Flash, true},
		{"gemini-custom-model", true}, // Custom models starting with gemini-
		{"gpt-4", false},
		{"claude-3", false},
		{"", false},
	}

	for _, tt := range tests {
		if IsValidModel(tt.model) != tt.expected {
			t.Errorf("IsValidModel(%q) = %v, want %v", tt.model, IsValidModel(tt.model), tt.expected)
		}
	}
}

func TestMapFinishReason(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"STOP", "stop"},
		{"MAX_TOKENS", "max_tokens"},
		{"SAFETY", "content_filter"},
		{"RECITATION", "content_filter"},
		{"OTHER", "other"},
		{"UNKNOWN", "UNKNOWN"},
		{"", ""},
	}

	for _, tt := range tests {
		if result := mapFinishReason(tt.input); result != tt.expected {
			t.Errorf("mapFinishReason(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestProviderConcurrency(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			time.Sleep(10 * time.Millisecond) // Simulate latency
			return successResponse("Response", 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	// Run multiple concurrent requests
	const numRequests = 10
	done := make(chan bool, numRequests)
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func() {
			_, err := provider.Complete(context.Background(), CompletionRequest{
				Prompt: "Hello",
			})
			if err != nil {
				errs <- err
			}
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < numRequests; i++ {
		<-done
	}

	// Check for errors
	close(errs)
	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}

	// Provider should still be healthy
	if !provider.IsHealthy() {
		t.Error("provider should be healthy after concurrent requests")
	}
}

func TestProviderHealthConcurrency(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})

	// Concurrent health status updates
	const numUpdates = 100
	done := make(chan bool, numUpdates*2)

	// Writers
	for i := 0; i < numUpdates; i++ {
		go func(healthy bool) {
			provider.setHealthy(healthy)
			done <- true
		}(i%2 == 0)
	}

	// Readers
	for i := 0; i < numUpdates; i++ {
		go func() {
			_ = provider.IsHealthy()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numUpdates*2; i++ {
		<-done
	}
}

func TestEmptyResponse(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Response with no candidates
			resp := geminiResponse{
				Candidates: []geminiCandidate{},
			}
			body, _ := json.Marshal(resp)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		},
	}
	provider.SetHTTPClient(mockClient)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "" {
		t.Errorf("expected empty content, got %q", resp.Content)
	}
}

func TestMalformedResponse(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("invalid json")),
				Header:     make(http.Header),
			}, nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Error("expected error for malformed response")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("error should mention decode failure: %v", err)
	}
}

func TestMalformedErrorResponse(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader("plain text error")),
				Header:     make(http.Header),
			}, nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Error("expected error")
	}
	if !strings.Contains(err.Error(), "plain text error") {
		t.Errorf("error should contain raw error text: %v", err)
	}
}

func BenchmarkProviderComplete(b *testing.B) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return successResponse("Response", 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx := context.Background()
	req := CompletionRequest{
		Prompt:    "Hello",
		MaxTokens: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Complete(ctx, req)
	}
}
