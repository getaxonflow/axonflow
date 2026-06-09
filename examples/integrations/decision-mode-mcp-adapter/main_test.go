// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newAdapter(t *testing.T, axonflowURL, mcpURL string) *mcpAdapter {
	t.Helper()
	return &mcpAdapter{
		cfg: AdapterConfig{
			MCPServerURL:     mcpURL,
			AxonFlowEndpoint: axonflowURL,
			GatewayID:        "mcp-gateway",
			TenantID:         "tenant-a",
			ClientID:         "acme",
			ClientSecret:     "lic-123",
			InterceptMethods: map[string]bool{"tools/call": true},
			RequestTimeout:   5 * time.Second,
		},
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func reqRedactObligation() DecisionObligation {
	return DecisionObligation{
		Type:        obligationRedactPII,
		Detail:      "NIK detected",
		Fulfillment: &ObligationFulfillment{Endpoint: requestRedactionPath, Method: "POST", Phase: obligationPhaseRequest, ContentTypes: []string{contentTypeText}},
	}
}

// TestIntercepted_Allow_RedactsArgumentsViaEngine verifies the adapter redacts
// string tool arguments through the engine and forwards rewritten params, and
// that it authenticates to the PDP with HTTP Basic (not X-Client-* headers).
func TestIntercepted_Allow_RedactsArgumentsViaEngine(t *testing.T) {
	var sawBasicAuth bool
	var sawXClientHeader bool
	var redactHits int
	axon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/decide":
			if u, p, ok := r.BasicAuth(); ok && u == "acme" && p == "lic-123" {
				sawBasicAuth = true
			}
			if r.Header.Get("X-Client-Id") != "" || r.Header.Get("X-Client-Secret") != "" {
				sawXClientHeader = true
			}
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: "allow", DecisionID: "d", TraceID: "t", Obligations: []DecisionObligation{reqRedactObligation()}})
		case requestRedactionPath:
			redactHits++
			var in checkInputRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			masked := in.Statement
			if strings.Contains(in.Statement, "3174012509900001") {
				masked = "[REDACTED]"
			}
			_ = json.NewEncoder(w).Encode(checkInputResponse{Allowed: true, RedactionEvaluated: true, Redacted: masked != in.Statement, RedactedStatement: masked})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer axon.Close()

	var forwarded string
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		forwarded = string(b)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer mcp.Close()

	a := newAdapter(t, axon.URL, mcp.URL)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"nik":"3174012509900001","note":"hello"}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, req)

	if !sawBasicAuth {
		t.Error("PDP call did not use HTTP Basic auth")
	}
	if sawXClientHeader {
		t.Error("PDP call still sends X-Client-* headers (ignored by enterprise PDP → 401)")
	}
	// Each string-valued argument is redacted through the engine (nik + note).
	if redactHits != 2 {
		t.Fatalf("expected 2 engine redaction calls (two string args), got %d", redactHits)
	}
	if strings.Contains(forwarded, "3174012509900001") {
		t.Fatalf("forwarded tool call still contains raw NIK: %s", forwarded)
	}
	if !strings.Contains(forwarded, "[REDACTED]") {
		t.Fatalf("forwarded tool call not engine-redacted: %s", forwarded)
	}
	if !strings.Contains(forwarded, `"hello"`) {
		t.Fatalf("non-PII argument should be preserved: %s", forwarded)
	}
}

// TestIntercepted_Allow_FailsClosed_OnRedactionError proves the adapter denies
// the tool call (never forwards unredacted arguments) when fulfillment fails.
func TestIntercepted_Allow_FailsClosed_OnRedactionError(t *testing.T) {
	axon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/decide" {
			_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: "allow", Obligations: []DecisionObligation{reqRedactObligation()}})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer axon.Close()
	mcp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("MCP server must NOT be called when redaction fails")
	}))
	defer mcp.Close()

	a := newAdapter(t, axon.URL, mcp.URL)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"nik":"3174012509900001"}}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	rr := httptest.NewRecorder()
	a.ServeHTTP(rr, req)

	var resp JSONRPCResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Error == nil {
		t.Fatalf("expected JSON-RPC error (fail-closed), got %s", rr.Body.String())
	}
}

func TestEndpointMatches(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{requestRedactionPath, true},
		{"https://pdp:8443/api/v1/mcp/check-input", true},
		{"/api/v1/mcp/check-output", false},
		{"/evil", false},
	}
	for _, tc := range cases {
		if got := endpointMatches(tc.in, requestRedactionPath); got != tc.want {
			t.Errorf("endpointMatches(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestFulfillToolArguments_RefusesBadEndpoint(t *testing.T) {
	a := newAdapter(t, "http://x", "http://y")
	rpc := &JSONRPCRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call"}
	params := ToolCallParams{Name: "t", Arguments: map[string]interface{}{"a": "v"}}
	obs := []DecisionObligation{{Type: obligationRedactPII, Fulfillment: &ObligationFulfillment{Endpoint: "/evil", Phase: obligationPhaseRequest}}}
	_, err := a.fulfillToolArgumentRedaction(context.Background(), rpc, params, obs, "")
	if err == nil || !strings.Contains(err.Error(), "non-redaction endpoint") {
		t.Fatalf("err=%v want refusal", err)
	}
}
