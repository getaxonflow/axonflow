// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =============================================================================
// Constructor Tests
// =============================================================================

// TestNewMCPQueryRouter tests the constructor
func TestNewMCPQueryRouter(t *testing.T) {
	tests := []struct {
		name          string
		agentEndpoint string
		wantEndpoint  string
	}{
		{
			name:          "with http endpoint",
			agentEndpoint: "http://localhost:8080",
			wantEndpoint:  "http://localhost:8080",
		},
		{
			name:          "with https endpoint",
			agentEndpoint: "https://agent.example.com",
			wantEndpoint:  "https://agent.example.com",
		},
		{
			name:          "with empty endpoint",
			agentEndpoint: "",
			wantEndpoint:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := NewMCPQueryRouter(tt.agentEndpoint)

			if router == nil {
				t.Fatal("Expected non-nil router")
			}

			if router.agentEndpoint != tt.wantEndpoint {
				t.Errorf("Expected endpoint %s, got %s", tt.wantEndpoint, router.agentEndpoint)
			}

			if router.httpClient == nil {
				t.Error("Expected non-nil HTTP client")
			}

			// Verify client timeout
			if router.httpClient.Timeout != 60*time.Second {
				t.Errorf("Expected timeout 60s, got %v", router.httpClient.Timeout)
			}
		})
	}
}

// =============================================================================
// RouteToAgent Tests
// =============================================================================

// TestMCPQueryRouter_RouteToAgent tests routing to the agent
func TestMCPQueryRouter_RouteToAgent(t *testing.T) {
	tests := []struct {
		name         string
		req          OrchestratorRequest
		mockResponse func(w http.ResponseWriter, r *http.Request)
		expectError  bool
		checkResult  func(t *testing.T, resp *OrchestratorResponse)
	}{
		{
			name: "missing connector in context",
			req: OrchestratorRequest{
				RequestID: "test-123",
				Query:     "test query",
				Context:   map[string]interface{}{},
			},
			expectError: true,
		},
		{
			name: "successful query routing",
			req: OrchestratorRequest{
				RequestID: "test-123",
				Query:     "search_flights",
				User:      UserContext{Email: "test@example.com"},
				Client:    ClientContext{ID: "client-1"},
				Context: map[string]interface{}{
					"connector": "amadeus",
					"params": map[string]interface{}{
						"origin":      "PAR",
						"destination": "LON",
					},
				},
			},
			mockResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/mcp/resources/query" {
					t.Errorf("Expected path /mcp/resources/query, got %s", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{
					"success": true,
					"rows": [{"id": "1", "price": "100"}],
					"row_count": 1,
					"duration_ms": 150
				}`))
			},
			expectError: false,
			checkResult: func(t *testing.T, resp *OrchestratorResponse) {
				if !resp.Success {
					t.Error("Expected success to be true")
				}
				if resp.Data == nil {
					t.Error("Expected non-nil data")
				}
			},
		},
		{
			name: "agent returns error",
			req: OrchestratorRequest{
				RequestID: "test-123",
				Query:     "search_flights",
				User:      UserContext{Email: "test@example.com"},
				Client:    ClientContext{ID: "client-1"},
				Context: map[string]interface{}{
					"connector": "amadeus",
					"params":    map[string]interface{}{},
				},
			},
			mockResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error": "invalid request"}`))
			},
			expectError: false, // Returns error in response, not as Go error
			checkResult: func(t *testing.T, resp *OrchestratorResponse) {
				if resp.Success {
					t.Error("Expected success to be false")
				}
				if resp.Error == "" {
					t.Error("Expected error message")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server only if we have a mock response
			var server *httptest.Server
			var router *MCPQueryRouter

			if tt.mockResponse != nil {
				server = httptest.NewServer(http.HandlerFunc(tt.mockResponse))
				defer server.Close()
				router = NewMCPQueryRouter(server.URL)
			} else {
				router = NewMCPQueryRouter("http://invalid-endpoint")
			}

			ctx := context.Background()
			resp, err := router.RouteToAgent(ctx, tt.req)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if resp == nil {
					t.Fatal("Expected non-nil response")
				}
				if tt.checkResult != nil {
					tt.checkResult(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// IsHealthy Tests
// =============================================================================

// TestMCPQueryRouter_IsHealthy tests health check
func TestMCPQueryRouter_IsHealthy(t *testing.T) {
	tests := []struct {
		name          string
		mockResponse  func(w http.ResponseWriter, r *http.Request)
		expectHealthy bool
	}{
		{
			name: "agent is healthy",
			mockResponse: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Errorf("Expected path /health, got %s", r.URL.Path)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status": "ok"}`))
			},
			expectHealthy: true,
		},
		{
			name: "agent returns error",
			mockResponse: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status": "error"}`))
			},
			expectHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.mockResponse))
			defer server.Close()

			router := NewMCPQueryRouter(server.URL)
			healthy := router.IsHealthy()

			if healthy != tt.expectHealthy {
				t.Errorf("Expected healthy=%v, got %v", tt.expectHealthy, healthy)
			}
		})
	}
}

// TestMCPQueryRouter_IsHealthy_UnreachableEndpoint tests health check with unreachable endpoint
func TestMCPQueryRouter_IsHealthy_UnreachableEndpoint(t *testing.T) {
	router := NewMCPQueryRouter("http://localhost:99999") // Invalid port

	healthy := router.IsHealthy()

	if healthy {
		t.Error("Expected router to be unhealthy for unreachable endpoint")
	}
}

// TestRouteToAgentCarriesTheOrganization is #3828's regression.
//
// # WHAT WAS BROKEN, AND WHY NOTHING RED WENT OFF
//
// RouteToAgent rebuilds the agent request from scratch. It carried the tenant
// and not the organization, and the agent's internal-service branch reads the
// org from X-Org-ID. This was the one internal-service caller that never set it.
//
// The HMAC sentence that used to be quoted here is gone deliberately: it holds
// on enterprise and not on community / community-SaaS, where allowFallback
// admits the public fallback constants. What holds everywhere is that this
// header selects a per-organization posture and policy scope and cannot widen
// tenancy.
//
// The request still succeeded. What failed was the EVIDENCE: with no org, the
// MCP call sites evaluate with orgID="", OrgScopePtr("") returns nil,
// orgScopeOf falls back to the tenant id, and planeshadow.Observe refuses every
// observation on the `mcp` plane as "an org scope but no org id". Ten of ten on
// the v10.4.0 gate (b) run, with the plane's gate-18 numerator reading the
// pre-created zero - byte-identical to watched-and-clean.
//
// It asserts on the OUTBOUND REQUEST rather than on a downstream comparison,
// because that is where this function's contract ends and because a test that
// booted an agent to check a header would be an integration test wearing a unit
// test's name. The other half - that the agent turns a present X-Org-ID into a
// user.OrgID - is pinned in package agent by
// TestAnInternalServiceUserCarriesTheAuthenticatedOrganization.
func TestRouteToAgentCarriesTheOrganization(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  OrchestratorRequest
		want string
		why  string
	}{
		{
			name: "the user context carries it",
			req: OrchestratorRequest{
				Query:   "search_flights",
				User:    UserContext{TenantID: "t1", OrgID: "org-from-user"},
				Client:  ClientContext{TenantID: "t2", OrgID: "org-from-client"},
				Context: map[string]interface{}{"connector": "amadeus"},
			},
			want: "org-from-user",
			why:  "the user context is the first rung, exactly as it is for the tenant",
		},
		{
			name: "the user context has none, so the client's is used",
			req: OrchestratorRequest{
				Query:   "search_flights",
				User:    UserContext{TenantID: "t1"},
				Client:  ClientContext{TenantID: "t2", OrgID: "org-from-client"},
				Context: map[string]interface{}{"connector": "amadeus"},
			},
			want: "org-from-client",
			why:  "the second rung, and the same order as the tenant's fall-back above it",
		},
		{
			name: "neither carries one - the header is ABSENT, not empty",
			req: OrchestratorRequest{
				Query:   "search_flights",
				User:    UserContext{TenantID: "t1"},
				Client:  ClientContext{TenantID: "t2"},
				Context: map[string]interface{}{"connector": "amadeus"},
			},
			want: "",
			why: "an empty header and an absent one both read as 'no organization' at the agent, " +
				"and sending the empty one would put a meaningless header on every community hop",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotOrg string
			var sawHeader bool
			var gotBody map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotOrg = r.Header.Get("X-Org-ID")
				_, sawHeader = r.Header[http.CanonicalHeaderKey("X-Org-ID")]
				_ = json.NewDecoder(r.Body).Decode(&gotBody)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
			}))
			defer server.Close()

			if _, err := NewMCPQueryRouter(server.URL).RouteToAgent(context.Background(), tc.req); err != nil {
				t.Fatalf("RouteToAgent: %v", err)
			}

			if gotOrg != tc.want {
				t.Errorf("X-Org-ID = %q, want %q. %s.\n\nWithout it the agent's MCP call sites "+
					"evaluate with an empty organization and the decision shadow refuses every "+
					"`mcp` observation, so the plane's gate-18 window is structurally empty on "+
					"every enterprise stack (#3828).", gotOrg, tc.want, tc.why)
			}
			if tc.want == "" && sawHeader {
				t.Errorf("X-Org-ID was SENT as an empty header; %s", tc.why)
			}

			// THE BODY MUST NOT HAVE GROWN AN org_id. A body-borne tenancy
			// selector on a handler that also serves external callers is the
			// shape X-Tenant-ID was deprecated for.
			//
			// The reason is NOT "the header is trusted only after the HMAC has
			// been checked" - that was asserted here and is false on community /
			// community-SaaS, where allowFallback admits the public fallback
			// constants. The reason that survives on every edition is narrower:
			// the header is read ONLY inside the internal-service branch, so it
			// is scoped to one authentication kind, whereas a body field is read
			// on every path including the external ones. Same header, strictly
			// smaller blast radius.
			if _, present := gotBody["org_id"]; present {
				t.Error("the agent request body carries an org_id. The organization must travel " +
					"on X-Org-ID, which is read only inside the agent's internal-service branch; " +
					"a body field is read on every path, including the external ones, and is an " +
					"unauthenticated second spelling of a tenancy selector.")
			}
			// ANTI-VACUITY: the request really was built and sent.
			if gotBody["tenant_id"] == nil {
				t.Fatal("the agent request carried no tenant_id, so this test did not exercise " +
					"the request-building path at all")
			}
		})
	}
}
