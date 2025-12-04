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

package main

import (
	"context"
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
		name         string
		mockResponse func(w http.ResponseWriter, r *http.Request)
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
