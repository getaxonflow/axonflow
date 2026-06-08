// Copyright 2025-2026 AxonFlow
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// The MCP server is Basic-auth, not OAuth. When an MCP client (e.g. Claude
// Code) probes the OAuth-discovery well-known endpoints after a 401, the agent
// must return a PARSEABLE JSON advisory — not Go's plaintext "404 page not
// found", which makes the client crash with
// "HTTP 404: Invalid OAuth error response ... Raw body: 404 page not found".
func TestOAuthDiscovery_ReturnsParseableAdvisoryNotPlaintext404(t *testing.T) {
	r := mux.NewRouter()
	RegisterMCPServerHandler(r)

	for _, path := range []string{
		"/.well-known/oauth-protected-resource",
		"/.well-known/oauth-authorization-server",
		// RFC 9728 resource-path-suffixed variants — the form Claude Code
		// actually requests. These must be covered by PathPrefix, not just the
		// bare paths, or the plaintext 404 still leaks.
		"/.well-known/oauth-protected-resource/api/v1/mcp-server",
		"/.well-known/oauth-authorization-server/api/v1/mcp-server",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			// 404 (the resource has no OAuth metadata) but JSON, not plaintext.
			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}

			body := rr.Body.String()
			if strings.Contains(body, "404 page not found") {
				t.Fatalf("body is Go's plaintext 404, not the JSON advisory: %q", body)
			}

			var parsed map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("body is not valid JSON (the client's OAuth-error parser would choke): %v; body=%q", err, body)
			}
			// RFC 6749 §5.2-shaped so a client renders error_description cleanly.
			if parsed["error"] == nil || parsed["error_description"] == nil {
				t.Fatalf("missing error/error_description: %v", parsed)
			}
			// Must name the real auth mechanism so the operator knows what to do.
			if !strings.Contains(body, "AXONFLOW_AUTH") {
				t.Fatalf("advisory does not name AXONFLOW_AUTH: %q", body)
			}
			// Must NOT advertise an authorization server (no OAuth flow to start).
			if _, ok := parsed["authorization_servers"]; ok {
				t.Fatalf("advisory advertises authorization_servers — would trigger an OAuth flow: %v", parsed)
			}
		})
	}
}

// The global 404/405 handlers must emit JSON, not Go/mux's plaintext. MCP
// clients probe an open-ended set of OAuth-discovery URLs; ANY plaintext
// non-2xx in that chain crashes their OAuth-error parser ("Invalid OAuth
// error response ... Raw body: 404 page not found"). JSON everywhere keeps
// them degrading gracefully.
func TestGlobalErrorHandlers_AreJSONNotPlaintext(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		status  int
	}{
		{"not_found", jsonNotFoundHandler, http.StatusNotFound},
		{"method_not_allowed", jsonMethodNotAllowedHandler, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.handler(rr, httptest.NewRequest(http.MethodGet, "/anything", nil))
			if rr.Code != tc.status {
				t.Fatalf("status = %d, want %d", rr.Code, tc.status)
			}
			if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			if strings.Contains(rr.Body.String(), "page not found") {
				t.Fatalf("body is plaintext, not JSON: %q", rr.Body.String())
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("not valid JSON: %v", err)
			}
			if parsed["error"] == nil || parsed["error_description"] == nil {
				t.Fatalf("missing error/error_description: %v", parsed)
			}
		})
	}
}
