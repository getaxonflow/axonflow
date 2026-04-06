// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package mistral

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// Helper to create a successful chat completion response.
func successResponse(content, model string, inputTokens, outputTokens int) *http.Response {
	resp := chatCompletionResponse{
		ID:      "chatcmpl-test-123",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []struct {
			Index        int         `json:"index"`
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{
			{
				Index:        0,
				Message:      chatMessage{Role: "assistant", Content: content},
				FinishReason: "stop",
			},
		},
		Usage: struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		}{
			PromptTokens:     inputTokens,
			CompletionTokens: outputTokens,
			TotalTokens:      inputTokens + outputTokens,
		},
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

// Helper to create an API error response.
func errorResponse(statusCode int, errType, code, message string) *http.Response {
	resp := struct {
		Object  string `json:"object"`
		Message string `json:"message"`
		Type    string `json:"type"`
		Param   string `json:"param"`
		Code    string `json:"code"`
	}{
		Object:  "error",
		Message: message,
		Type:    errType,
		Code:    code,
	}
	body, _ := json.Marshal(resp)
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

// Helper to create a streaming SSE response with multiple chunks and a [DONE] signal.
func streamingResponse(chunks []string, model string, inputTokens, outputTokens int) *http.Response {
	var builder strings.Builder
	for i, chunk := range chunks {
		event := chatCompletionStreamResponse{
			ID:      "chatcmpl-stream-123",
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   model,
			Choices: []struct {
				Index int `json:"index"`
				Delta struct {
					Role    string `json:"role,omitempty"`
					Content string `json:"content,omitempty"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason,omitempty"`
			}{
				{
					Index: 0,
					Delta: struct {
						Role    string `json:"role,omitempty"`
						Content string `json:"content,omitempty"`
					}{Content: chunk},
				},
			},
		}
		// Last chunk gets finish reason and usage
		if i == len(chunks)-1 {
			event.Choices[0].FinishReason = "stop"
			event.Usage = &struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				TotalTokens      int `json:"total_tokens"`
			}{
				PromptTokens:     inputTokens,
				CompletionTokens: outputTokens,
				TotalTokens:      inputTokens + outputTokens,
			}
		}
		data, _ := json.Marshal(event)
		builder.WriteString("data: ")
		builder.Write(data)
		builder.WriteString("\n\n")
	}
	builder.WriteString("data: [DONE]\n\n")
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(builder.String())),
		Header:     make(http.Header),
	}
}

// ---------------------------------------------------------------------------
// Construction & Config
// ---------------------------------------------------------------------------

func TestNewProvider_Success(t *testing.T) {
	provider, err := NewProvider(Config{
		APIKey:  "test-api-key",
		BaseURL: "https://custom.mistral.ai",
		Model:   ModelMistralLargeLatest,
		Timeout: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider == nil {
		t.Fatal("provider should not be nil")
	}
	if provider.apiKey != "test-api-key" {
		t.Errorf("expected apiKey %q, got %q", "test-api-key", provider.apiKey)
	}
	if provider.baseURL != "https://custom.mistral.ai" {
		t.Errorf("expected baseURL %q, got %q", "https://custom.mistral.ai", provider.baseURL)
	}
	if provider.model != ModelMistralLargeLatest {
		t.Errorf("expected model %q, got %q", ModelMistralLargeLatest, provider.model)
	}
	if provider.timeout != 60*time.Second {
		t.Errorf("expected timeout %v, got %v", 60*time.Second, provider.timeout)
	}
	if !provider.healthy {
		t.Error("new provider should be healthy")
	}
}

func TestNewProvider_MissingAPIKey(t *testing.T) {
	_, err := NewProvider(Config{})
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
	if !strings.Contains(err.Error(), "API key is required") {
		t.Errorf("error should mention API key requirement, got: %v", err)
	}
}

func TestNewProvider_DefaultModel(t *testing.T) {
	provider, err := NewProvider(Config{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.model != ModelMistralSmallLatest {
		t.Errorf("expected default model %q, got %q", ModelMistralSmallLatest, provider.model)
	}
}

func TestNewProvider_CustomEndpoint(t *testing.T) {
	provider, err := NewProvider(Config{
		APIKey:  "test-key",
		BaseURL: "https://my-proxy.example.com/",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Trailing slash should be trimmed
	if provider.baseURL != "https://my-proxy.example.com" {
		t.Errorf("expected baseURL without trailing slash, got %q", provider.baseURL)
	}
}

func TestNewProvider_CustomTimeout(t *testing.T) {
	provider, err := NewProvider(Config{
		APIKey:  "test-key",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", provider.timeout)
	}
}

func TestNewProvider_Defaults(t *testing.T) {
	provider, err := NewProvider(Config{APIKey: "test-key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if provider.baseURL != DefaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", DefaultBaseURL, provider.baseURL)
	}
	if provider.model != DefaultModel {
		t.Errorf("expected default model %q, got %q", DefaultModel, provider.model)
	}
	if provider.timeout != DefaultTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultTimeout, provider.timeout)
	}
}

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

func TestProvider_Complete_Success(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify request method and URL
			if req.Method != "POST" {
				t.Errorf("expected POST, got %s", req.Method)
			}
			if !strings.Contains(req.URL.String(), "/v1/chat/completions") {
				t.Errorf("URL should contain /v1/chat/completions, got %s", req.URL.String())
			}
			// Verify auth header
			auth := req.Header.Get("Authorization")
			if auth != "Bearer test-key" {
				t.Errorf("expected Authorization 'Bearer test-key', got %q", auth)
			}
			// Verify content type
			if req.Header.Get("Content-Type") != "application/json" {
				t.Errorf("expected Content-Type application/json, got %q", req.Header.Get("Content-Type"))
			}
			// Verify request body
			var body chatCompletionRequest
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode request body: %v", err)
			}
			if body.Model != ModelMistralSmallLatest {
				t.Errorf("expected model %q, got %q", ModelMistralSmallLatest, body.Model)
			}
			if body.Stream {
				t.Error("stream should be false for non-streaming request")
			}
			return successResponse("Hello from Mistral!", ModelMistralSmallLatest, 12, 8), nil
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
	if resp.Content != "Hello from Mistral!" {
		t.Errorf("expected content %q, got %q", "Hello from Mistral!", resp.Content)
	}
	if resp.Model != ModelMistralSmallLatest {
		t.Errorf("expected model %q, got %q", ModelMistralSmallLatest, resp.Model)
	}
	if resp.Usage.InputTokens != 12 {
		t.Errorf("expected input tokens 12, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 8 {
		t.Errorf("expected output tokens 8, got %d", resp.Usage.OutputTokens)
	}
	if resp.Usage.TotalTokens != 20 {
		t.Errorf("expected total tokens 20, got %d", resp.Usage.TotalTokens)
	}
	if resp.StopReason != "stop" {
		t.Errorf("expected stop reason %q, got %q", "stop", resp.StopReason)
	}
	if resp.Latency <= 0 {
		t.Error("latency should be positive")
	}
}

func TestProvider_Complete_WithSystemPrompt(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:       "Hello",
		SystemPrompt: "You are a helpful assistant",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(capturedBody.Messages) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(capturedBody.Messages))
	}
	if capturedBody.Messages[0].Role != "system" {
		t.Errorf("first message role should be 'system', got %q", capturedBody.Messages[0].Role)
	}
	if capturedBody.Messages[0].Content != "You are a helpful assistant" {
		t.Errorf("system message content mismatch")
	}
	if capturedBody.Messages[1].Role != "user" {
		t.Errorf("second message role should be 'user', got %q", capturedBody.Messages[1].Role)
	}
}

func TestProvider_Complete_WithModelOverride(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralLargeLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
		Model:  ModelMistralLargeLatest,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedBody.Model != ModelMistralLargeLatest {
		t.Errorf("expected model %q, got %q", ModelMistralLargeLatest, capturedBody.Model)
	}
}

func TestProvider_Complete_WithGenerationOptions(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt:        "Hello",
		MaxTokens:     500,
		Temperature:   0.5,
		TopP:          0.9,
		StopSequences: []string{"END", "STOP"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedBody.MaxTokens != 500 {
		t.Errorf("expected max_tokens 500, got %d", capturedBody.MaxTokens)
	}
	if capturedBody.Temperature != 0.5 {
		t.Errorf("expected temperature 0.5, got %v", capturedBody.Temperature)
	}
	if capturedBody.TopP == nil || *capturedBody.TopP != 0.9 {
		t.Errorf("expected top_p 0.9, got %v", capturedBody.TopP)
	}
	if len(capturedBody.Stop) != 2 || capturedBody.Stop[0] != "END" {
		t.Errorf("expected stop sequences [END, STOP], got %v", capturedBody.Stop)
	}
}

func TestProvider_Complete_EmptyMessages(t *testing.T) {
	// An empty prompt still sends to the API — the provider builds the message list.
	// With an empty string prompt, it still creates a user message with empty content.
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("", ModelMistralSmallLatest, 0, 0), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	resp, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The API still sends a user message, even if empty
	if len(capturedBody.Messages) != 1 {
		t.Errorf("expected 1 message, got %d", len(capturedBody.Messages))
	}
	if resp.Content != "" {
		t.Errorf("expected empty content, got %q", resp.Content)
	}
}

func TestProvider_Complete_APIError(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return errorResponse(500, "server_error", "internal_error", "Internal server error"), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected status code 500, got %d", apiErr.StatusCode)
	}
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after 500 error")
	}
}

func TestProvider_Complete_MalformedJSON(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("this is not json")),
				Header:     make(http.Header),
			}, nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for malformed JSON response")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("error should mention decode failure, got: %v", err)
	}
}

func TestProvider_Complete_MalformedErrorResponse(t *testing.T) {
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
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "plain text error") {
		t.Errorf("error should contain raw error text, got: %v", err)
	}
}

func TestProvider_Complete_Timeout(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
	}
	provider.SetHTTPClient(mockClient)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	_, err := provider.Complete(ctx, CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for timed out request")
	}
	if !strings.Contains(err.Error(), "mistral API error") {
		t.Errorf("error should mention mistral API error, got: %v", err)
	}
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after timeout")
	}
}

func TestProvider_Complete_RateLimited(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return errorResponse(429, "rate_limit", "rate_limit_exceeded", "Too many requests"), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for rate limit")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if !apiErr.IsRateLimitError() {
		t.Error("error should be a rate limit error")
	}
	// 429 is < 500 so health should NOT be set to unhealthy
	if !provider.IsHealthy() {
		t.Error("provider should remain healthy after rate limit (not a server error)")
	}
}

func TestProvider_Complete_NetworkError(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection refused")
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if !strings.Contains(err.Error(), "mistral API error") {
		t.Errorf("error should mention mistral API error, got: %v", err)
	}
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after network error")
	}
}

func TestProvider_Complete_SuccessRestoresHealth(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	provider.setHealthy(false) // Simulate previous failure

	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return successResponse("OK", ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !provider.IsHealthy() {
		t.Error("provider should be healthy after successful request")
	}
}

func TestProvider_Complete_DefaultTemperatureWhenNegative(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{
		Prompt:      "Hello",
		Temperature: -1,
	})

	if capturedBody.Temperature != DefaultTemperature {
		t.Errorf("expected default temperature %v for negative input, got %v", DefaultTemperature, capturedBody.Temperature)
	}
}

func TestProvider_Complete_ZeroTemperatureIsValid(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{
		Prompt:      "Hello",
		Temperature: 0,
	})

	if capturedBody.Temperature != 0 {
		t.Errorf("expected temperature 0 (deterministic), got %v", capturedBody.Temperature)
	}
}

func TestProvider_Complete_DefaultMaxTokens(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var capturedBody chatCompletionRequest
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &capturedBody)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
		// MaxTokens not set, should default to 4096
	})

	if capturedBody.MaxTokens != DefaultMaxTokens {
		t.Errorf("expected default max_tokens %d, got %d", DefaultMaxTokens, capturedBody.MaxTokens)
	}
}

func TestProvider_Complete_EmptyResponseChoices(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			resp := chatCompletionResponse{
				ID:    "test",
				Model: ModelMistralSmallLatest,
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
		t.Errorf("expected empty content for no choices, got %q", resp.Content)
	}
	if resp.StopReason != "unknown" {
		t.Errorf("expected stop reason 'unknown' for no choices, got %q", resp.StopReason)
	}
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

func TestProvider_CompleteStream_Success(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Verify streaming headers
			if req.Header.Get("Accept") != "text/event-stream" {
				t.Errorf("expected Accept header 'text/event-stream', got %q", req.Header.Get("Accept"))
			}
			// Verify request body has stream=true
			var body chatCompletionRequest
			json.NewDecoder(req.Body).Decode(&body)
			if !body.Stream {
				t.Error("stream should be true for streaming request")
			}
			return streamingResponse([]string{"Hello", ", ", "world", "!"}, ModelMistralSmallLatest, 10, 20), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	var chunks []string
	var gotDone bool
	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt:    "Say hello",
		MaxTokens: 100,
	}, func(chunk StreamChunk) error {
		if chunk.Type == "content" {
			chunks = append(chunks, chunk.Content)
		}
		if chunk.Type == "done" && chunk.Done {
			gotDone = true
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
		t.Errorf("expected 4 content chunks, got %d: %v", len(chunks), chunks)
	}
	if !gotDone {
		t.Error("expected done chunk to be received")
	}
	if resp.Usage.InputTokens != 10 {
		t.Errorf("expected input tokens 10, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 20 {
		t.Errorf("expected output tokens 20, got %d", resp.Usage.OutputTokens)
	}
	if resp.StopReason != "stop" {
		t.Errorf("expected stop reason %q, got %q", "stop", resp.StopReason)
	}
	if resp.Model != ModelMistralSmallLatest {
		t.Errorf("expected model %q, got %q", ModelMistralSmallLatest, resp.Model)
	}
}

func TestProvider_CompleteStream_Error(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return errorResponse(500, "server_error", "internal_error", "Internal error"), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt: "Hello",
	}, func(chunk StreamChunk) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after 500 error in stream")
	}
}

func TestProvider_CompleteStream_DoneSignal(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	// Build a response with [DONE] signal and verify the handler receives a done chunk
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return streamingResponse([]string{"test"}, ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	var receivedChunks []StreamChunk
	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt: "Hello",
	}, func(chunk StreamChunk) error {
		receivedChunks = append(receivedChunks, chunk)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != "test" {
		t.Errorf("expected content %q, got %q", "test", resp.Content)
	}

	// Should have content chunk + done chunk
	if len(receivedChunks) < 2 {
		t.Fatalf("expected at least 2 chunks (content + done), got %d", len(receivedChunks))
	}
	lastChunk := receivedChunks[len(receivedChunks)-1]
	if lastChunk.Type != "done" || !lastChunk.Done {
		t.Errorf("last chunk should be done signal, got type=%q done=%v", lastChunk.Type, lastChunk.Done)
	}
}

func TestProvider_CompleteStream_HandlerError(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return streamingResponse([]string{"Hello", "world"}, ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	handlerErr := errors.New("handler processing failed")
	_, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt: "Hello",
	}, func(chunk StreamChunk) error {
		return handlerErr
	})

	if err == nil {
		t.Fatal("expected error from handler")
	}
	if !strings.Contains(err.Error(), "handler error") {
		t.Errorf("error should mention handler error, got: %v", err)
	}
}

func TestProvider_CompleteStream_NilHandler(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return streamingResponse([]string{"Hello"}, ModelMistralSmallLatest, 5, 3), nil
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
}

func TestProvider_CompleteStream_NetworkError(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("connection reset")
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt: "Hello",
	}, func(chunk StreamChunk) error {
		return nil
	})

	if err == nil {
		t.Fatal("expected error for network failure")
	}
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after network error")
	}
}

func TestProvider_CompleteStream_ModelFallback(t *testing.T) {
	// When the streaming response has no model field, it should fall back to the request model
	provider, _ := NewProvider(Config{APIKey: "test-key", Model: ModelMistralLargeLatest})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Build SSE response without model field
			var builder strings.Builder
			event := `{"id":"test","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}`
			builder.WriteString("data: ")
			builder.WriteString(event)
			builder.WriteString("\n\ndata: [DONE]\n\n")
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(builder.String())),
				Header:     make(http.Header),
			}, nil
		},
	}
	provider.SetHTTPClient(mockClient)

	resp, err := provider.CompleteStream(context.Background(), CompletionRequest{
		Prompt: "Hello",
	}, nil)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to provider's configured model
	if resp.Model != ModelMistralLargeLatest {
		t.Errorf("expected model fallback to %q, got %q", ModelMistralLargeLatest, resp.Model)
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestProvider_IsHealthy_NewProvider(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	if !provider.IsHealthy() {
		t.Error("new provider should be healthy")
	}
}

func TestProvider_IsHealthy_AfterSetUnhealthy(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	provider.setHealthy(false)
	if provider.IsHealthy() {
		t.Error("provider should be unhealthy after setHealthy(false)")
	}
}

func TestProvider_IsHealthy_Recovery(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	provider.setHealthy(false)
	provider.setHealthy(true)
	if !provider.IsHealthy() {
		t.Error("provider should be healthy after recovery")
	}
}

func TestProvider_IsHealthy_EmptyAPIKey(t *testing.T) {
	// IsHealthy checks both p.healthy and p.apiKey != ""
	provider := &Provider{
		apiKey:  "",
		healthy: true,
	}
	if provider.IsHealthy() {
		t.Error("provider with empty API key should not be healthy")
	}
}

func TestProvider_HealthConcurrency(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})

	const numOps = 100
	done := make(chan bool, numOps*2)

	// Concurrent writers
	for i := 0; i < numOps; i++ {
		go func(healthy bool) {
			provider.setHealthy(healthy)
			done <- true
		}(i%2 == 0)
	}

	// Concurrent readers
	for i := 0; i < numOps; i++ {
		go func() {
			_ = provider.IsHealthy()
			done <- true
		}()
	}

	for i := 0; i < numOps*2; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestProvider_Name(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	if name := provider.Name(); name != "mistral" {
		t.Errorf("expected name %q, got %q", "mistral", name)
	}
}

func TestProvider_SupportsStreaming(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	if !provider.SupportsStreaming() {
		t.Error("provider should support streaming")
	}
}

func TestProvider_Capabilities(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	capabilities := provider.GetCapabilities()

	expected := []string{
		"reasoning",
		"analysis",
		"writing",
		"code_generation",
		"streaming",
	}

	if len(capabilities) != len(expected) {
		t.Errorf("expected %d capabilities, got %d", len(expected), len(capabilities))
	}

	for _, exp := range expected {
		found := false
		for _, cap := range capabilities {
			if cap == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing capability: %s", exp)
		}
	}
}

func TestProvider_EstimateCost(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})

	tests := []struct {
		tokens   int
		expected float64
	}{
		{0, 0},
		{1, 0.0000002},
		{1000, 0.0002},
		{1000000, 0.2},
	}

	for _, tt := range tests {
		cost := provider.EstimateCost(tt.tokens)
		// Use tolerance for floating point comparison
		diff := cost - tt.expected
		if diff < 0 {
			diff = -diff
		}
		if diff > 1e-12 {
			t.Errorf("EstimateCost(%d) = %v, want %v", tt.tokens, cost, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Model helpers
// ---------------------------------------------------------------------------

func TestGetSupportedModels(t *testing.T) {
	models := GetSupportedModels()
	if len(models) == 0 {
		t.Fatal("should return at least one model")
	}

	expectedModels := []string{
		ModelMistralSmallLatest,
		ModelMistralMediumLatest,
		ModelMistralLargeLatest,
		ModelCodestralLatest,
		ModelOpenMistralNemo,
		ModelMinistral8BLatest,
		ModelPixtralLargeLatest,
	}

	if len(models) != len(expectedModels) {
		t.Errorf("expected %d models, got %d", len(expectedModels), len(models))
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
		{ModelMistralSmallLatest, true},
		{ModelMistralLargeLatest, true},
		{ModelCodestralLatest, true},
		{ModelOpenMistralNemo, true},
		{ModelMinistral8BLatest, true},
		{ModelPixtralLargeLatest, true},
		{"mistral-custom-v2", true},       // Custom mistral- prefix
		{"codestral-custom", true},        // Custom codestral- prefix
		{"open-mistral-custom", true},     // Custom open-mistral- prefix
		{"ministral-custom", true},        // Custom ministral- prefix
		{"pixtral-custom", true},          // Custom pixtral- prefix
		{"gpt-4", false},                  // Not a Mistral model
		{"claude-sonnet-4", false},        // Not a Mistral model
		{"gemini-1.5-pro", false},         // Not a Mistral model
		{"", false},                       // Empty string
		{"random-model-name", false},      // Random name
	}

	for _, tt := range tests {
		if result := IsValidModel(tt.model); result != tt.expected {
			t.Errorf("IsValidModel(%q) = %v, want %v", tt.model, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Finish reason mapping
// ---------------------------------------------------------------------------

func TestMapFinishReason(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"stop", "stop"},
		{"length", "max_tokens"},
		{"model_length", "max_tokens"},
		{"content_filter", "content_filter"},
		{"tool_calls", "tool_calls"},     // Unknown, returned as-is
		{"", ""},                          // Empty
		{"custom_reason", "custom_reason"}, // Unknown, returned as-is
	}

	for _, tt := range tests {
		if result := mapFinishReason(tt.input); result != tt.expected {
			t.Errorf("mapFinishReason(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// APIError
// ---------------------------------------------------------------------------

func TestAPIError_Error(t *testing.T) {
	err := &APIError{
		StatusCode: 401,
		Type:       "authentication_error",
		Code:       "invalid_api_key",
		Message:    "Invalid API key provided",
	}
	expected := "mistral API error (status 401, type authentication_error, code invalid_api_key): Invalid API key provided"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAPIError_IsRateLimitError(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   bool
	}{
		{429, true},
		{200, false},
		{500, false},
		{401, false},
	}

	for _, tt := range tests {
		err := &APIError{StatusCode: tt.statusCode}
		if err.IsRateLimitError() != tt.expected {
			t.Errorf("IsRateLimitError(status=%d) = %v, want %v", tt.statusCode, err.IsRateLimitError(), tt.expected)
		}
	}
}

func TestAPIError_IsAuthError(t *testing.T) {
	tests := []struct {
		statusCode int
		errType    string
		expected   bool
	}{
		{401, "", true},
		{403, "", true},
		{200, "authentication_error", true},
		{429, "rate_limit", false},
		{500, "server_error", false},
	}

	for _, tt := range tests {
		err := &APIError{StatusCode: tt.statusCode, Type: tt.errType}
		if err.IsAuthError() != tt.expected {
			t.Errorf("IsAuthError(status=%d, type=%q) = %v, want %v",
				tt.statusCode, tt.errType, err.IsAuthError(), tt.expected)
		}
	}
}

func TestAPIError_IsQuotaExceededError(t *testing.T) {
	tests := []struct {
		statusCode int
		errType    string
		expected   bool
	}{
		{429, "quota_exceeded", true},
		{429, "rate_limit", false},
		{200, "quota_exceeded", false},
		{500, "server_error", false},
	}

	for _, tt := range tests {
		err := &APIError{StatusCode: tt.statusCode, Type: tt.errType}
		if err.IsQuotaExceededError() != tt.expected {
			t.Errorf("IsQuotaExceededError(status=%d, type=%q) = %v, want %v",
				tt.statusCode, tt.errType, err.IsQuotaExceededError(), tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// SetHTTPClient
// ---------------------------------------------------------------------------

func TestProvider_SetHTTPClient(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	called := false
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			called = true
			return successResponse("OK", ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{Prompt: "Hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Error("mock client should have been called")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestProvider_ConcurrentComplete(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			time.Sleep(5 * time.Millisecond)
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
		},
	}
	provider.SetHTTPClient(mockClient)

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

	for i := 0; i < numRequests; i++ {
		<-done
	}

	close(errs)
	for err := range errs {
		t.Errorf("concurrent request error: %v", err)
	}

	if !provider.IsHealthy() {
		t.Error("provider should be healthy after concurrent requests")
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkProviderComplete(b *testing.B) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return successResponse("Response", ModelMistralSmallLatest, 10, 5), nil
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

func BenchmarkProviderCompleteStream(b *testing.B) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})

	ctx := context.Background()
	req := CompletionRequest{
		Prompt:    "Hello",
		MaxTokens: 100,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mockClient := &mockHTTPClient{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return streamingResponse([]string{"Hello", " ", "world"}, ModelMistralSmallLatest, 10, 5), nil
			},
		}
		provider.SetHTTPClient(mockClient)
		_, _ = provider.CompleteStream(ctx, req, nil)
	}
}

// ---------------------------------------------------------------------------
// Edge cases: auth header, 4xx non-rate-limit errors
// ---------------------------------------------------------------------------

func TestProvider_Complete_AuthErrorResponse(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "bad-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			return errorResponse(401, "authentication_error", "invalid_api_key", "Invalid API key"), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, err := provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
	})

	if err == nil {
		t.Fatal("expected error for auth failure")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if !apiErr.IsAuthError() {
		t.Error("error should be an auth error")
	}
	// 401 is < 500, health should remain
	if !provider.IsHealthy() {
		t.Error("provider should remain healthy after auth error (not a server error)")
	}
}

func TestProvider_Complete_FinishReasonLength(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			resp := chatCompletionResponse{
				ID:    "test",
				Model: ModelMistralSmallLatest,
				Choices: []struct {
					Index        int         `json:"index"`
					Message      chatMessage `json:"message"`
					FinishReason string      `json:"finish_reason"`
				}{
					{
						Index:        0,
						Message:      chatMessage{Role: "assistant", Content: "truncated..."},
						FinishReason: "length",
					},
				},
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

	resp, err := provider.Complete(context.Background(), CompletionRequest{Prompt: "Hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StopReason != "max_tokens" {
		t.Errorf("expected stop reason 'max_tokens' for finish_reason 'length', got %q", resp.StopReason)
	}
}

func TestProvider_Complete_BaseURLUsed(t *testing.T) {
	provider, _ := NewProvider(Config{
		APIKey:  "test-key",
		BaseURL: "https://custom-proxy.example.com",
	})
	var capturedURL string
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			capturedURL = req.URL.String()
			return successResponse("OK", ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{Prompt: "Hello"})

	expected := "https://custom-proxy.example.com/v1/chat/completions"
	if capturedURL != expected {
		t.Errorf("expected URL %q, got %q", expected, capturedURL)
	}
}

func TestProvider_Complete_NoTopP(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var rawBody map[string]any
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &rawBody)
			return successResponse("OK", ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
		// TopP not set (zero value), should be omitted from JSON
	})

	if _, exists := rawBody["top_p"]; exists {
		t.Error("top_p should be omitted when not set (zero value)")
	}
}

func TestProvider_Complete_NoStop(t *testing.T) {
	provider, _ := NewProvider(Config{APIKey: "test-key"})
	var rawBody map[string]any
	mockClient := &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(req.Body)
			json.Unmarshal(body, &rawBody)
			return successResponse("OK", ModelMistralSmallLatest, 5, 3), nil
		},
	}
	provider.SetHTTPClient(mockClient)

	_, _ = provider.Complete(context.Background(), CompletionRequest{
		Prompt: "Hello",
		// No StopSequences
	})

	if _, exists := rawBody["stop"]; exists {
		t.Error("stop should be omitted when not set")
	}
}

// Ensure unused import errors are avoided.
var _ = fmt.Sprintf
