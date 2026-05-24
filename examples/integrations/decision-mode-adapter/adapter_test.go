// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package adapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExtractQuery(t *testing.T) {
	tests := []struct {
		name     string
		messages []openAIMessage
		want     string
	}{
		{
			name: "last user message",
			messages: []openAIMessage{
				{Role: "system", Content: "You are helpful"},
				{Role: "user", Content: "first question"},
				{Role: "assistant", Content: "first answer"},
				{Role: "user", Content: "second question"},
			},
			want: "second question",
		},
		{
			name:     "no user message, returns last",
			messages: []openAIMessage{{Role: "system", Content: "system prompt"}},
			want:     "system prompt",
		},
		{
			name:     "empty messages",
			messages: nil,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQuery(openAIChatRequest{Messages: tt.messages})
			if got != tt.want {
				t.Errorf("extractQuery() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInferProvider(t *testing.T) {
	tests := []struct {
		model string
		want  string
	}{
		{"gpt-4o-mini", "openai"},
		{"gpt-3.5-turbo", "openai"},
		{"o4-mini", "openai"},
		{"claude-3-opus", "anthropic"},
		{"gemini-1.5-pro", "google"},
		{"mistral-large", "mistral"},
		{"mixtral-8x7b", "mistral"},
		{"llama-3.1-70b", "meta"},
		{"some-custom-model", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			got := inferProvider(tt.model)
			if got != tt.want {
				t.Errorf("inferProvider(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestMiddleware_NonPOST_PassesThrough(t *testing.T) {
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(Config{AxonFlowEndpoint: "http://unreachable:9999"}, downstream)

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET should pass through, got %d", rr.Code)
	}
}

func TestMiddleware_FailClosed_WhenDecisionAPIUnreachable(t *testing.T) {
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream should not be called in fail-closed mode")
	})
	handler := Middleware(Config{
		AxonFlowEndpoint: "http://127.0.0.1:1", // unreachable
		FailOpen:         false,
	}, downstream)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("fail-closed should return 503, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("response should contain error object")
	}
	if errObj["type"] != "adapter_error" {
		t.Errorf("error type should be adapter_error, got %v", errObj["type"])
	}
}

func TestMiddleware_FailOpen_WhenDecisionAPIUnreachable(t *testing.T) {
	called := false
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(Config{
		AxonFlowEndpoint: "http://127.0.0.1:1", // unreachable
		FailOpen:         true,
		Timeout:          100 * time.Millisecond,
	}, downstream)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("fail-open should forward to downstream")
	}
}

func TestMiddleware_4xxBlocksEvenWithFailOpen(t *testing.T) {
	fakeDecisionAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer fakeDecisionAPI.Close()

	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream must NOT be called when Decision API returns 401, even with FailOpen=true")
	})
	handler := Middleware(Config{
		AxonFlowEndpoint: fakeDecisionAPI.URL,
		FailOpen:         true,
	}, downstream)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("4xx from Decision API should return 502, got %d", rr.Code)
	}
}

func TestMiddleware_Allow_PropagtesTraceID(t *testing.T) {
	fakeDecisionAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecideResponse{
			Verdict:           "allow",
			DecisionID:        "dec-123",
			TraceID:           "abcdef0123456789abcdef0123456789",
			Obligations:       []Obligation{},
			EvaluatedPolicies: []string{},
		})
	}))
	defer fakeDecisionAPI.Close()

	var capturedTraceparent string
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTraceparent = r.Header.Get("traceparent")
		w.WriteHeader(http.StatusOK)
	})
	handler := Middleware(Config{AxonFlowEndpoint: fakeDecisionAPI.URL}, downstream)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("allow verdict should forward, got %d", rr.Code)
	}
	if !strings.Contains(capturedTraceparent, "abcdef0123456789abcdef0123456789") {
		t.Errorf("traceparent should contain trace_id, got %q", capturedTraceparent)
	}
	if rr.Header().Get("X-Axonflow-Trace-Id") != "abcdef0123456789abcdef0123456789" {
		t.Errorf("X-Axonflow-Trace-Id header missing")
	}
	if rr.Header().Get("X-Axonflow-Decision-Id") != "dec-123" {
		t.Errorf("X-Axonflow-Decision-Id header missing")
	}
}

func TestMiddleware_Deny_ReturnsStructuredError(t *testing.T) {
	fakeDecisionAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DecideResponse{
			Verdict:           "deny",
			DecisionID:        "dec-456",
			TraceID:           "99887766554433221100aabbccddeeff",
			Reasons:           []string{"SQL injection detected"},
			Obligations:       []Obligation{},
			EvaluatedPolicies: []string{"security_sqli_detection"},
		})
	}))
	defer fakeDecisionAPI.Close()

	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("downstream should not be called on deny")
	})
	handler := Middleware(Config{AxonFlowEndpoint: fakeDecisionAPI.URL}, downstream)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"DROP TABLE users"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("deny should return 403, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response should be valid JSON: %v", err)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("response should contain error object")
	}
	if errObj["code"] != "policy_deny" {
		t.Errorf("error code should be policy_deny, got %v", errObj["code"])
	}
	if errObj["decision_id"] != "dec-456" {
		t.Errorf("decision_id should be dec-456, got %v", errObj["decision_id"])
	}
	reasons, ok := errObj["reasons"].([]any)
	if !ok || len(reasons) == 0 {
		t.Error("reasons should be non-empty")
	}
}

func TestFormatTraceparent(t *testing.T) {
	got := formatTraceparent("abcdef0123456789abcdef0123456789")
	if !strings.HasPrefix(got, "00-abcdef0123456789abcdef0123456789-") {
		t.Errorf("formatTraceparent() should start with version+trace_id, got %q", got)
	}
	if !strings.HasSuffix(got, "-01") {
		t.Errorf("formatTraceparent() should end with -01 (sampled), got %q", got)
	}
	parts := strings.Split(got, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent should have 4 parts, got %d: %q", len(parts), got)
	}
	if len(parts[2]) != 16 {
		t.Errorf("parent-id should be 16 hex chars, got %d: %q", len(parts[2]), parts[2])
	}
	if parts[2] == "0000000000000000" {
		t.Error("parent-id should not be all zeros")
	}
}
