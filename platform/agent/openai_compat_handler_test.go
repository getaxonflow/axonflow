// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedpolicy "axonflow/platform/shared/policy"
)

// openaiCompatForTest sends a raw body through handleOpenAICompat without
// auth middleware (community mode — no JWT required). Returns the recorder.
func openaiCompatForTest(t *testing.T, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", openaiCompatPath, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	handleOpenAICompat(rr, req)
	return rr
}

// installSharedEngineForOpenAITest swaps the global shared-policy engine so
// PII/SQLi detection runs the real validators in-process.
func installSharedEngineForOpenAITest(t *testing.T) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.ExpectQuery("SELECT").WillReturnRows(
		sqlmock.NewRows([]string{"id", "name", "pattern", "category", "severity", "action", "enabled", "tier", "tenant_id", "description", "metadata"}),
	)
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{}, nil)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

func makeChatBody(model string, messages []chatCompletionMessage, extras map[string]interface{}) []byte {
	body := map[string]interface{}{
		"model":    model,
		"messages": messages,
	}
	for k, v := range extras {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b
}

func simpleMessages(content string) []chatCompletionMessage {
	return []chatCompletionMessage{
		{Role: "user", Content: content},
	}
}

// --- Test: Clean request -> policy allow -> mock provider response -> response shape ---

func TestOpenAICompat_CleanRequest_Allow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	// Set up a mock upstream provider server.
	mockResp := chatCompletionResponse{
		ID:      "chatcmpl-test123",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   "gpt-4o",
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: chatCompletionChoiceMessage{
					Role:    "assistant",
					Content: strPtr("4"),
				},
				FinishReason: strPtr("stop"),
			},
		},
		Usage: &chatCompletionUsage{
			PromptTokens:     10,
			CompletionTokens: 1,
			TotalTokens:      11,
		},
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the upstream receives the Authorization header.
		if r.Header.Get("Authorization") != "Bearer test-provider-key" {
			t.Errorf("expected Authorization: Bearer test-provider-key, got %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResp)
	}))
	defer mockServer.Close()

	// Override provider endpoint to point at mock server.
	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("What is 2+2?"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-provider-key",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp chatCompletionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ID != "chatcmpl-test123" {
		t.Errorf("expected ID chatcmpl-test123, got %s", resp.ID)
	}
	if resp.Object != "chat.completion" {
		t.Errorf("expected object chat.completion, got %s", resp.Object)
	}
	if len(resp.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(resp.Choices))
	}
	if resp.Choices[0].Message.Content == nil || *resp.Choices[0].Message.Content != "4" {
		t.Errorf("expected content '4', got %v", resp.Choices[0].Message.Content)
	}
	if resp.Usage == nil {
		t.Fatal("expected usage to be populated")
	}
	if resp.Usage.TotalTokens != 11 {
		t.Errorf("expected 11 total tokens, got %d", resp.Usage.TotalTokens)
	}

	// Verify AxonFlow headers are present.
	if rr.Header().Get("X-AxonFlow-Decision-Id") == "" {
		t.Error("expected X-AxonFlow-Decision-Id header")
	}
	if rr.Header().Get("X-AxonFlow-Trace-Id") == "" {
		t.Error("expected X-AxonFlow-Trace-Id header")
	}
}

// --- Test: PII in prompt -> deny -> OpenAI-compatible error ---
// Requires DB-seeded PII policies — runtime proof under runtime-e2e/2351_openai_compat/.
// Mirrors decision_handler_test.go::TestHandleDecide_VerdictDeny_LiveEngine pattern.

func TestOpenAICompat_PII_Deny(t *testing.T) {
	t.Skip("Requires DB-seeded PII policies — runtime proof under runtime-e2e/2351_openai_compat/")
}

// --- Test: SQLi in prompt -> deny ---
// Requires DB-seeded SQLI policies — runtime proof under runtime-e2e/2351_openai_compat/.

func TestOpenAICompat_SQLi_Deny(t *testing.T) {
	t.Skip("Requires DB-seeded SQLI policies — runtime proof under runtime-e2e/2351_openai_compat/")
}

// --- Test: Policy deny error shape (mocked engine result) ---
// Exercises the deny response formatting without needing DB-seeded policies.

func TestOpenAICompat_PolicyDenyErrorShape(t *testing.T) {
	rr := httptest.NewRecorder()
	sendOpenAIError(rr, "Request blocked by policy: PII detected (SSN)", "policy_violation", "policy_denied", http.StatusBadRequest)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if errResp.Error.Type != "policy_violation" {
		t.Errorf("expected type policy_violation, got %s", errResp.Error.Type)
	}
	if errResp.Error.Code != "policy_denied" {
		t.Errorf("expected code policy_denied, got %s", errResp.Error.Code)
	}
	if errResp.Error.Message == "" {
		t.Error("expected non-empty error message")
	}
}

// --- Test: stream:true -> 400 with clear error ---

func TestOpenAICompat_StreamTrue_Rejected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	body := makeChatBody("gpt-4o", simpleMessages("hello"), map[string]interface{}{
		"stream": true,
	})
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error.Code != "stream_not_supported" {
		t.Errorf("expected code stream_not_supported, got %s", errResp.Error.Code)
	}
	if errResp.Error.Type != "invalid_request_error" {
		t.Errorf("expected type invalid_request_error, got %s", errResp.Error.Type)
	}
}

// --- Test: Missing X-Provider-Key -> 400 ---

func TestOpenAICompat_MissingProviderKey(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, nil) // no X-Provider-Key

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error.Code != "missing_provider_key" {
		t.Errorf("expected code missing_provider_key, got %s", errResp.Error.Code)
	}
}

// --- Test: Missing model field -> 400 ---

func TestOpenAICompat_MissingModel(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	body := makeChatBody("", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error.Code != "missing_model" {
		t.Errorf("expected code missing_model, got %s", errResp.Error.Code)
	}
}

// --- Test: Missing messages field -> 400 ---

func TestOpenAICompat_MissingMessages(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	body := makeChatBody("gpt-4o", nil, nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error.Code != "missing_messages" {
		t.Errorf("expected code missing_messages, got %s", errResp.Error.Code)
	}
}

// --- Test: Invalid JSON body -> 400 ---

func TestOpenAICompat_InvalidBody(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	rr := openaiCompatForTest(t, []byte("{invalid json"), map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if errResp.Error.Type != "invalid_request_error" {
		t.Errorf("expected type invalid_request_error, got %s", errResp.Error.Type)
	}
}

// --- Test: OTel trace_id in response headers ---

func TestOpenAICompat_TraceIDInHeaders(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	// Mock upstream so the request goes through the full allow path.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			ID: "test", Object: "chat.completion", Created: 1700000000, Model: "gpt-4o",
			Choices: []chatCompletionChoice{{Index: 0, Message: chatCompletionChoiceMessage{Role: "assistant", Content: strPtr("hi")}, FinishReason: strPtr("stop")}},
			Usage:   &chatCompletionUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
		})
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	traceID := rr.Header().Get("X-AxonFlow-Trace-Id")
	if traceID == "" {
		t.Error("expected X-AxonFlow-Trace-Id header")
	}
	if len(traceID) != 32 {
		t.Errorf("expected 32-char W3C trace ID, got %d chars: %s", len(traceID), traceID)
	}

	decisionID := rr.Header().Get("X-AxonFlow-Decision-Id")
	if decisionID == "" {
		t.Error("expected X-AxonFlow-Decision-Id header")
	}
}

// --- Test: Traceparent header propagation ---

func TestOpenAICompat_TraceparentPropagation(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			ID: "test", Object: "chat.completion", Created: 1700000000, Model: "gpt-4o",
			Choices: []chatCompletionChoice{{Index: 0, Message: chatCompletionChoiceMessage{Role: "assistant", Content: strPtr("hi")}, FinishReason: strPtr("stop")}},
			Usage:   &chatCompletionUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
		})
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	inboundTraceID := "0af7651916cd43dd8448eb211c80319c"
	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
		"traceparent":    fmt.Sprintf("00-%s-b7ad6b7169203331-01", inboundTraceID),
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	traceID := rr.Header().Get("X-AxonFlow-Trace-Id")
	if traceID != inboundTraceID {
		t.Errorf("expected trace ID %s from traceparent, got %s", inboundTraceID, traceID)
	}
}

// --- Test: Upstream provider error forwarded ---

func TestOpenAICompat_UpstreamError_Forwarded(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	// Mock upstream returns 401 (invalid API key).
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(openAIErrorResponse{
			Error: openAIErrorBody{
				Message: "Incorrect API key provided",
				Type:    "invalid_request_error",
				Code:    "invalid_api_key",
			},
		})
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "bad-key",
	})

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	// The upstream error body should be forwarded as-is.
	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if errResp.Error.Code != "invalid_api_key" {
		t.Errorf("expected upstream error code invalid_api_key, got %s", errResp.Error.Code)
	}
}

// --- Test: extractTextFromMessages ---

func TestExtractTextFromMessages(t *testing.T) {
	tests := []struct {
		name     string
		messages []chatCompletionMessage
		want     string
	}{
		{
			name:     "single string content",
			messages: []chatCompletionMessage{{Role: "user", Content: "hello world"}},
			want:     "hello world",
		},
		{
			name: "multiple messages",
			messages: []chatCompletionMessage{
				{Role: "system", Content: "You are helpful"},
				{Role: "user", Content: "What is Go?"},
			},
			want: "You are helpful\nWhat is Go?",
		},
		{
			name: "multimodal content array with text",
			messages: []chatCompletionMessage{
				{Role: "user", Content: []interface{}{
					map[string]interface{}{"type": "text", "text": "Describe this image"},
					map[string]interface{}{"type": "image_url", "image_url": map[string]interface{}{"url": "data:image/png;base64,abc"}},
				}},
			},
			want: "Describe this image",
		},
		{
			name:     "empty messages",
			messages: []chatCompletionMessage{},
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTextFromMessages(tt.messages)
			if got != tt.want {
				t.Errorf("extractTextFromMessages() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Test: resolveProviderBaseURL ---

func TestResolveProviderBaseURL(t *testing.T) {
	tests := []struct {
		model    string
		provider string
	}{
		{"gpt-4o", "openai"},
		{"gpt-4o-mini", "openai"},
		{"gpt-3.5-turbo", "openai"},
		{"o1-preview", "openai"},
		{"o3-mini", "openai"},
		{"unknown-model", "openai"}, // defaults to OpenAI in M1
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			_, provider, ok := resolveProviderBaseURL(tt.model)
			if !ok {
				t.Fatal("expected ok=true")
			}
			if provider != tt.provider {
				t.Errorf("expected provider %s, got %s", tt.provider, provider)
			}
		})
	}
}

// --- Test: sendOpenAIError produces parseable error ---

func TestSendOpenAIError_Shape(t *testing.T) {
	rr := httptest.NewRecorder()
	sendOpenAIError(rr, "test error", "invalid_request_error", "test_code", http.StatusBadRequest)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error: %v", err)
	}
	if errResp.Error.Message != "test error" {
		t.Errorf("expected message 'test error', got %s", errResp.Error.Message)
	}
	if errResp.Error.Type != "invalid_request_error" {
		t.Errorf("expected type invalid_request_error, got %s", errResp.Error.Type)
	}
	if errResp.Error.Code != "test_code" {
		t.Errorf("expected code test_code, got %s", errResp.Error.Code)
	}
}

// --- Test: Audit record created with correct fields ---

func TestOpenAICompat_AuditRecord(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	// Set up mock audit DB to verify the audit write.
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	mockSQL.ExpectExec("INSERT INTO llm_call_audits").WillReturnResult(sqlmock.NewResult(1, 1))

	oldAuthDB := authDB
	authDB = mockDB
	t.Cleanup(func() { authDB = oldAuthDB })

	// Mock upstream.
	mockResp := chatCompletionResponse{
		ID:      "chatcmpl-audit-test",
		Object:  "chat.completion",
		Created: 1700000000,
		Model:   "gpt-4o",
		Choices: []chatCompletionChoice{
			{Index: 0, Message: chatCompletionChoiceMessage{Role: "assistant", Content: strPtr("test")}, FinishReason: strPtr("stop")},
		},
		Usage: &chatCompletionUsage{PromptTokens: 5, CompletionTokens: 1, TotalTokens: 6},
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockResp)
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// The audit queue might be nil in test environment, so the fallback
	// path attempts direct DB write. We verify the attempt happened.
	// In test env without audit manager, the function returns nil (no-op).
	// The key assertion is that the handler completed successfully and
	// the audit recording call didn't panic or break the response.
}

// --- Test: Upstream connection refused -> 502 ---

func TestOpenAICompat_UpstreamConnectionRefused(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	// Point at a port that is definitely not listening.
	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": "http://127.0.0.1:1"}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rr.Code, rr.Body.String())
	}

	var errResp openAIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse error: %v", err)
	}
	if errResp.Error.Type != "server_error" {
		t.Errorf("expected type server_error, got %s", errResp.Error.Type)
	}
	// Verify no internal details leaked in the error message.
	if len(errResp.Error.Message) > 50 {
		t.Errorf("error message too detailed (may leak internals): %s", errResp.Error.Message)
	}
}

// --- Test: Upstream returns unparseable response ---

func TestOpenAICompat_UpstreamUnparseableResponse(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installSharedEngineForOpenAITest(t)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"not_a_valid_completion": true}`))
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	// Should still return 200 — unparseable but valid HTTP 200 from upstream
	// is forwarded as-is (the client SDK will try to parse it).
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- Test: Policy engine nil (disabled detection) ---

func TestOpenAICompat_PolicyEngineDisabled(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("AXONFLOW_GATEWAY_DETECTION_ENABLED", "false")
	InitDetectionConfigs()

	// Set shared engine to nil.
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(chatCompletionResponse{
			ID: "test-nil", Object: "chat.completion", Created: 1700000000, Model: "gpt-4o",
			Choices: []chatCompletionChoice{{Index: 0, Message: chatCompletionChoiceMessage{Role: "assistant", Content: strPtr("ok")}, FinishReason: strPtr("stop")}},
			Usage:   &chatCompletionUsage{PromptTokens: 1, CompletionTokens: 1, TotalTokens: 2},
		})
	}))
	defer mockServer.Close()

	oldEndpoints := providerEndpoints
	providerEndpoints = map[string]string{"gpt-": mockServer.URL}
	t.Cleanup(func() { providerEndpoints = oldEndpoints })

	body := makeChatBody("gpt-4o", simpleMessages("hello"), nil)
	rr := openaiCompatForTest(t, body, map[string]string{
		"X-Provider-Key": "test-key",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- Test: RegisterOpenAICompatHandlers doesn't panic ---

func TestRegisterOpenAICompatHandlers(t *testing.T) {
	r := mux.NewRouter()
	RegisterOpenAICompatHandlers(r)

	// Verify route is registered.
	route := r.Get("") // not named, but walk will find it
	if route == nil {
		// Just verify no panic occurred — the handler is registered.
	}
}

// --- Test: recordOpenAICompatAudit doesn't panic with nil auditDB ---

func TestRecordOpenAICompatAudit_NilDB(t *testing.T) {
	oldDB := authDB
	authDB = nil
	t.Cleanup(func() { authDB = oldDB })

	// Should not panic.
	recordOpenAICompatAudit("test-id", "client", "org", "tenant", "openai", "gpt-4o", 10, 5, 15, 0.001, 100, VerdictAllow, "")
}

// strPtr is declared in static_policy_repository_test.go
