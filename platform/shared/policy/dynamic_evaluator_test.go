// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"axonflow/platform/shared/serviceauth"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestDefaultDynamicPolicyConfig(t *testing.T) {
	config := DefaultDynamicPolicyConfig()

	if config.Enabled {
		t.Error("expected Enabled=false by default")
	}
	if config.OrchestratorEndpoint != "http://localhost:8081" {
		t.Errorf("expected default endpoint=http://localhost:8081, got %s", config.OrchestratorEndpoint)
	}
	if config.Timeout != 5*time.Second {
		t.Errorf("expected Timeout=5s, got %v", config.Timeout)
	}
	if !config.GracefulDegradation {
		t.Error("expected GracefulDegradation=true by default")
	}
	if config.MaxCustomPolicyConnectorsCommunity != 2 {
		t.Errorf("expected MaxCustomPolicyConnectorsCommunity=2, got %d", config.MaxCustomPolicyConnectorsCommunity)
	}
}

func TestNewDynamicPolicyEvaluator(t *testing.T) {
	config := DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://test:8081",
		Timeout:              10 * time.Second,
		GracefulDegradation:  false,
	}

	evaluator := NewDynamicPolicyEvaluator(config)
	if evaluator == nil {
		t.Fatal("expected non-nil evaluator")
	}

	got := evaluator.GetConfig()
	if !got.Enabled {
		t.Error("expected Enabled=true")
	}
	if got.OrchestratorEndpoint != "http://test:8081" {
		t.Errorf("expected endpoint=http://test:8081, got %s", got.OrchestratorEndpoint)
	}
	if got.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", got.Timeout)
	}
}

func TestDynamicPolicyEvaluator_IsEnabled_Disabled(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled: false,
	})

	if evaluator.IsEnabled("postgres") {
		t.Error("expected IsEnabled=false when config.Enabled=false")
	}
}

func TestDynamicPolicyEvaluator_IsEnabled_AllConnectors(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:           true,
		EnabledConnectors: nil, // Empty = all connectors
	})

	if !evaluator.IsEnabled("postgres") {
		t.Error("expected IsEnabled=true for postgres")
	}
	if !evaluator.IsEnabled("mysql") {
		t.Error("expected IsEnabled=true for mysql")
	}
}

func TestDynamicPolicyEvaluator_IsEnabled_SpecificConnectors(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:           true,
		EnabledConnectors: []string{"postgres", "redis"},
	})

	if !evaluator.IsEnabled("postgres") {
		t.Error("expected IsEnabled=true for postgres")
	}
	if !evaluator.IsEnabled("redis") {
		t.Error("expected IsEnabled=true for redis")
	}
	if evaluator.IsEnabled("mysql") {
		t.Error("expected IsEnabled=false for mysql (not in list)")
	}
}

func TestDynamicPolicyEvaluator_Evaluate_Success(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/mcp/evaluate-policies" {
			t.Errorf("expected /api/v1/mcp/evaluate-policies, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{
			Allowed:           true,
			PoliciesEvaluated: 5,
		})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	resp, err := evaluator.Evaluate(ctx, DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Statement:     "SELECT * FROM users",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true")
	}
	if resp.PoliciesEvaluated != 5 {
		t.Errorf("expected PoliciesEvaluated=5, got %d", resp.PoliciesEvaluated)
	}
}

func TestDynamicPolicyEvaluator_Evaluate_Blocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{
			Allowed:           false,
			BlockReason:       "Rate limit exceeded",
			PoliciesEvaluated: 3,
			MatchedPolicies: []DynamicPolicyMatch{
				{PolicyID: "rate-1", PolicyType: "rate-limit", Action: "block"},
			},
		})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	resp, err := evaluator.Evaluate(ctx, DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed {
		t.Error("expected Allowed=false")
	}
	if resp.BlockReason != "Rate limit exceeded" {
		t.Errorf("expected BlockReason='Rate limit exceeded', got %s", resp.BlockReason)
	}
	if len(resp.MatchedPolicies) != 1 {
		t.Errorf("expected 1 matched policy, got %d", len(resp.MatchedPolicies))
	}
}

func TestDynamicPolicyEvaluator_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal error"))
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	_, err := evaluator.Evaluate(ctx, DynamicPolicyRequest{
		TenantID: "tenant-1",
	})

	if err == nil {
		t.Error("expected error for server error")
	}
}

func TestDynamicPolicyEvaluator_Evaluate_ConnectionError(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999", // Invalid port
		Timeout:              1 * time.Second,
	})

	ctx := context.Background()
	_, err := evaluator.Evaluate(ctx, DynamicPolicyRequest{
		TenantID: "tenant-1",
	})

	if err == nil {
		t.Error("expected error for connection error")
	}
}

func TestDynamicPolicyEvaluator_EvaluateWithGracefulDegradation_Allowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{
			Allowed:           true,
			PoliciesEvaluated: 2,
		})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  true,
	})

	ctx := context.Background()
	resp, info, err := evaluator.EvaluateWithGracefulDegradation(ctx, DynamicPolicyRequest{
		TenantID: "tenant-1",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true")
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if !info.OrchestratorReachable {
		t.Error("expected OrchestratorReachable=true")
	}
	if info.PoliciesEvaluated != 2 {
		t.Errorf("expected PoliciesEvaluated=2, got %d", info.PoliciesEvaluated)
	}
}

func TestDynamicPolicyEvaluator_EvaluateWithGracefulDegradation_ErrorGraceful(t *testing.T) {
	// #3068: this test covers the TRANSIENT-outage case — orchestrator
	// unreachable, graceful degradation absorbs it. A configured
	// internal-service secret is required for that path, because a MISSING
	// secret is a permanent misconfiguration that now deliberately fails
	// closed regardless of GracefulDegradation (see
	// TestDynamicPolicyEvaluator_MissingSecretFailsClosed).
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "graceful-degradation-test-secret-32chars")

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999",
		Timeout:              1 * time.Second,
		GracefulDegradation:  true,
	})

	ctx := context.Background()
	resp, info, err := evaluator.EvaluateWithGracefulDegradation(ctx, DynamicPolicyRequest{
		TenantID: "tenant-1",
	})

	// With graceful degradation, should not return error
	if err != nil {
		t.Fatalf("expected no error with graceful degradation, got: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true with graceful degradation")
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.OrchestratorReachable {
		t.Error("expected OrchestratorReachable=false")
	}
}

func TestDynamicPolicyEvaluator_EvaluateWithGracefulDegradation_ErrorStrict(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999",
		Timeout:              1 * time.Second,
		GracefulDegradation:  false, // Strict mode
	})

	ctx := context.Background()
	_, _, err := evaluator.EvaluateWithGracefulDegradation(ctx, DynamicPolicyRequest{
		TenantID: "tenant-1",
	})

	// Without graceful degradation, should return error
	if err == nil {
		t.Error("expected error without graceful degradation")
	}
}

func TestDynamicPolicyEvaluator_UpdateConfig(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled: false,
		Timeout: 5 * time.Second,
	})

	if evaluator.IsEnabled("postgres") {
		t.Error("expected disabled initially")
	}

	if err := evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://new:8081",
		Timeout:              10 * time.Second,
		GracefulDegradation:  true,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	config := evaluator.GetConfig()
	if !config.Enabled {
		t.Error("expected Enabled=true after update")
	}
	if config.OrchestratorEndpoint != "http://new:8081" {
		t.Errorf("expected updated endpoint, got %s", config.OrchestratorEndpoint)
	}
	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", config.Timeout)
	}
}

func TestDynamicPolicyEvaluator_IsGracefulDegradationEnabled(t *testing.T) {
	evaluatorGraceful := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		GracefulDegradation: true,
	})
	if !evaluatorGraceful.IsGracefulDegradationEnabled() {
		t.Error("expected IsGracefulDegradationEnabled=true")
	}

	evaluatorStrict := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		GracefulDegradation: false,
	})
	if evaluatorStrict.IsGracefulDegradationEnabled() {
		t.Error("expected IsGracefulDegradationEnabled=false")
	}
}

func TestNewDynamicPolicyEvaluatorFromEnv(t *testing.T) {
	// Save original env vars
	origEnabled := os.Getenv("MCP_DYNAMIC_POLICIES_ENABLED")
	origTimeout := os.Getenv("MCP_DYNAMIC_POLICIES_TIMEOUT")
	origGraceful := os.Getenv("MCP_DYNAMIC_POLICIES_GRACEFUL")
	origConnectors := os.Getenv("MCP_DYNAMIC_POLICIES_CONNECTORS")
	origMode := os.Getenv("DEPLOYMENT_MODE")

	defer func() {
		restoreEnv("MCP_DYNAMIC_POLICIES_ENABLED", origEnabled)
		restoreEnv("MCP_DYNAMIC_POLICIES_TIMEOUT", origTimeout)
		restoreEnv("MCP_DYNAMIC_POLICIES_GRACEFUL", origGraceful)
		restoreEnv("MCP_DYNAMIC_POLICIES_CONNECTORS", origConnectors)
		restoreEnv("DEPLOYMENT_MODE", origMode)
	}()

	// Use enterprise mode so connector limit doesn't interfere with env parsing test
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	os.Setenv("MCP_DYNAMIC_POLICIES_ENABLED", "true")
	os.Setenv("MCP_DYNAMIC_POLICIES_TIMEOUT", "10s")
	os.Setenv("MCP_DYNAMIC_POLICIES_GRACEFUL", "false")
	os.Setenv("MCP_DYNAMIC_POLICIES_CONNECTORS", "postgres, mysql, redis")

	evaluator := NewDynamicPolicyEvaluatorFromEnv()
	config := evaluator.GetConfig()

	if !config.Enabled {
		t.Error("expected Enabled=true from env")
	}
	// Endpoint uses default since MCP_DYNAMIC_POLICIES_ENDPOINT is no longer parsed
	// Agent sets it via SetOrchestratorEndpoint() using its standard URL resolution
	if config.OrchestratorEndpoint != "http://localhost:8081" {
		t.Errorf("expected default endpoint=http://localhost:8081, got %s", config.OrchestratorEndpoint)
	}
	if config.Timeout != 10*time.Second {
		t.Errorf("expected Timeout=10s, got %v", config.Timeout)
	}
	if config.GracefulDegradation {
		t.Error("expected GracefulDegradation=false from env")
	}
	if len(config.EnabledConnectors) != 3 {
		t.Errorf("expected 3 enabled connectors, got %d", len(config.EnabledConnectors))
	}
}

func TestNewDynamicPolicyEvaluatorFromEnv_InvalidTimeout(t *testing.T) {
	origTimeout := os.Getenv("MCP_DYNAMIC_POLICIES_TIMEOUT")
	defer restoreEnv("MCP_DYNAMIC_POLICIES_TIMEOUT", origTimeout)

	os.Setenv("MCP_DYNAMIC_POLICIES_TIMEOUT", "invalid")

	evaluator := NewDynamicPolicyEvaluatorFromEnv()
	config := evaluator.GetConfig()

	// Should use default timeout
	if config.Timeout != 5*time.Second {
		t.Errorf("expected default Timeout=5s, got %v", config.Timeout)
	}
}

func TestGlobalDynamicPolicyEvaluator(t *testing.T) {
	// Reset global state
	ResetGlobalDynamicPolicyEvaluator()

	// Should be nil initially
	if GetGlobalDynamicPolicyEvaluator() != nil {
		t.Error("expected nil before initialization")
	}

	// Initialize with config
	config := DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://test:8081",
	}
	InitGlobalDynamicPolicyEvaluatorWithConfig(config)

	evaluator := GetGlobalDynamicPolicyEvaluator()
	if evaluator == nil {
		t.Fatal("expected non-nil after initialization")
	}

	got := evaluator.GetConfig()
	if got.OrchestratorEndpoint != "http://test:8081" {
		t.Errorf("expected endpoint=http://test:8081, got %s", got.OrchestratorEndpoint)
	}

	// Test SetGlobalDynamicPolicyEvaluator
	newEvaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		OrchestratorEndpoint: "http://other:9000",
	})
	SetGlobalDynamicPolicyEvaluator(newEvaluator)

	if GetGlobalDynamicPolicyEvaluator().GetConfig().OrchestratorEndpoint != "http://other:9000" {
		t.Error("expected SetGlobalDynamicPolicyEvaluator to work")
	}

	// Cleanup
	ResetGlobalDynamicPolicyEvaluator()
}

func TestDynamicPolicyEvaluator_ConcurrentAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{Allowed: true})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  true,
	})

	ctx := context.Background()
	done := make(chan bool)

	// Concurrent evaluations
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_, _, _ = evaluator.EvaluateWithGracefulDegradation(ctx, DynamicPolicyRequest{
					TenantID: "tenant-1",
				})
				_ = evaluator.GetConfig()
				_ = evaluator.IsEnabled("postgres")
			}
			done <- true
		}()
	}

	// Concurrent config updates
	for i := 0; i < 3; i++ {
		go func(n int) {
			for j := 0; j < 5; j++ {
				_ = evaluator.UpdateConfig(DynamicPolicyConfig{
					Enabled:              true,
					OrchestratorEndpoint: server.URL,
					Timeout:              time.Duration(n+1) * time.Second,
				})
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 13; i++ {
		<-done
	}
}

// Helper to restore env var
func restoreEnv(key, value string) {
	if value != "" {
		os.Setenv(key, value)
	} else {
		os.Unsetenv(key)
	}
}

// Benchmark tests
func BenchmarkDynamicPolicyEvaluator_IsEnabled(b *testing.B) {
	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:           true,
		EnabledConnectors: []string{"postgres", "mysql", "redis"},
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.IsEnabled("postgres")
	}
}

func BenchmarkDynamicPolicyEvaluator_Evaluate(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{Allowed: true})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	req := DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.Evaluate(ctx, req)
	}
}

func TestInitGlobalDynamicPolicyEvaluator(t *testing.T) {
	// Reset global state
	ResetGlobalDynamicPolicyEvaluator()

	// Save and clear env vars
	origEnabled := os.Getenv("MCP_DYNAMIC_POLICIES_ENABLED")
	origTimeout := os.Getenv("MCP_DYNAMIC_POLICIES_TIMEOUT")
	origGraceful := os.Getenv("MCP_DYNAMIC_POLICIES_GRACEFUL")
	defer restoreEnv("MCP_DYNAMIC_POLICIES_ENABLED", origEnabled)
	defer restoreEnv("MCP_DYNAMIC_POLICIES_TIMEOUT", origTimeout)
	defer restoreEnv("MCP_DYNAMIC_POLICIES_GRACEFUL", origGraceful)

	os.Setenv("MCP_DYNAMIC_POLICIES_ENABLED", "true")
	os.Setenv("MCP_DYNAMIC_POLICIES_TIMEOUT", "15s")
	os.Setenv("MCP_DYNAMIC_POLICIES_GRACEFUL", "false")

	InitGlobalDynamicPolicyEvaluator()

	evaluator := GetGlobalDynamicPolicyEvaluator()
	if evaluator == nil {
		t.Fatal("expected non-nil evaluator after InitGlobalDynamicPolicyEvaluator")
	}

	config := evaluator.GetConfig()
	if !config.Enabled {
		t.Error("expected Enabled=true")
	}
	// Endpoint uses default - Agent sets it via SetGlobalOrchestratorEndpoint()
	if config.OrchestratorEndpoint != "http://localhost:8081" {
		t.Errorf("expected default endpoint=http://localhost:8081, got %s", config.OrchestratorEndpoint)
	}
	if config.Timeout != 15*time.Second {
		t.Errorf("expected Timeout=15s, got %v", config.Timeout)
	}
	if config.GracefulDegradation {
		t.Error("expected GracefulDegradation=false")
	}

	// Cleanup
	ResetGlobalDynamicPolicyEvaluator()
}

func TestSetOrchestratorEndpoint(t *testing.T) {
	evaluator := NewDynamicPolicyEvaluator(DefaultDynamicPolicyConfig())

	// Default should be localhost
	config := evaluator.GetConfig()
	if config.OrchestratorEndpoint != "http://localhost:8081" {
		t.Errorf("expected default endpoint, got %s", config.OrchestratorEndpoint)
	}

	// Set custom endpoint
	evaluator.SetOrchestratorEndpoint("http://orchestrator:8081")

	config = evaluator.GetConfig()
	if config.OrchestratorEndpoint != "http://orchestrator:8081" {
		t.Errorf("expected custom endpoint, got %s", config.OrchestratorEndpoint)
	}
}

func TestSetGlobalOrchestratorEndpoint(t *testing.T) {
	// Reset global state
	ResetGlobalDynamicPolicyEvaluator()

	// Set endpoint on nil evaluator should not panic
	SetGlobalOrchestratorEndpoint("http://test:8081")

	// Initialize
	InitGlobalDynamicPolicyEvaluatorWithConfig(DefaultDynamicPolicyConfig())

	// Now set endpoint
	SetGlobalOrchestratorEndpoint("http://custom-orchestrator:8081")

	evaluator := GetGlobalDynamicPolicyEvaluator()
	config := evaluator.GetConfig()
	if config.OrchestratorEndpoint != "http://custom-orchestrator:8081" {
		t.Errorf("expected custom endpoint, got %s", config.OrchestratorEndpoint)
	}

	// Cleanup
	ResetGlobalDynamicPolicyEvaluator()
}

func TestDynamicPolicyEvaluator_Evaluate_EmptyRequestTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req DynamicPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Verify request time was set
		if req.RequestTime.IsZero() {
			t.Error("expected RequestTime to be set when empty")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(DynamicPolicyResponse{Allowed: true})
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	// Explicitly omit RequestTime
	req := DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}

	resp, err := evaluator.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true")
	}
}

func TestDynamicPolicyEvaluator_Evaluate_InvalidJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	req := DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}

	_, err := evaluator.Evaluate(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	if !contains(err.Error(), "failed to parse response") {
		t.Errorf("expected 'failed to parse response' error, got: %v", err)
	}
}

func TestDynamicPolicyEvaluator_Evaluate_WithMatchedPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := DynamicPolicyResponse{
			Allowed:           true,
			PoliciesEvaluated: 3,
			MatchedPolicies: []DynamicPolicyMatch{
				{
					PolicyID:   "rate-limit-1",
					PolicyName: "Rate Limit Default",
					PolicyType: "rate-limit",
					Action:     "allow",
				},
				{
					PolicyID:   "role-1",
					PolicyName: "Admin Access",
					PolicyType: "role-access",
					Action:     "allow",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
	})

	ctx := context.Background()
	req := DynamicPolicyRequest{
		TenantID:      "tenant-1",
		UserID:        "user-1",
		UserRole:      "admin",
		ConnectorName: "postgres",
		Operation:     "query",
		Statement:     "SELECT * FROM users",
	}

	resp, err := evaluator.Evaluate(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true")
	}
	if resp.PoliciesEvaluated != 3 {
		t.Errorf("expected PoliciesEvaluated=3, got %d", resp.PoliciesEvaluated)
	}
	if len(resp.MatchedPolicies) != 2 {
		t.Errorf("expected 2 matched policies, got %d", len(resp.MatchedPolicies))
	}
	if resp.MatchedPolicies[0].PolicyID != "rate-limit-1" {
		t.Errorf("expected first policy ID=rate-limit-1, got %s", resp.MatchedPolicies[0].PolicyID)
	}
}

func TestDynamicPolicyEvaluator_EvaluateWithGracefulDegradation_Info(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := DynamicPolicyResponse{
			Allowed:           true,
			PoliciesEvaluated: 2,
			MatchedPolicies: []DynamicPolicyMatch{
				{PolicyID: "p1", PolicyType: "budget", Action: "allow"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  true,
	})

	ctx := context.Background()
	req := DynamicPolicyRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}

	resp, info, err := evaluator.EvaluateWithGracefulDegradation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Allowed {
		t.Error("expected Allowed=true")
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if !info.OrchestratorReachable {
		t.Error("expected OrchestratorReachable=true")
	}
	if info.PoliciesEvaluated != 2 {
		t.Errorf("expected PoliciesEvaluated=2, got %d", info.PoliciesEvaluated)
	}
	if len(info.MatchedPolicies) != 1 {
		t.Errorf("expected 1 matched policy, got %d", len(info.MatchedPolicies))
	}
	// ProcessingTimeMs can be 0 for very fast responses (sub-millisecond)
	if info.ProcessingTimeMs < 0 {
		t.Error("expected ProcessingTimeMs >= 0")
	}
}

// Helper to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestValidateCustomPolicyConnectorLimit_CommunityMode(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	tests := []struct {
		name              string
		deploymentMode    string
		licenseKey        string
		connectors        []string
		maxConnectors     int
		maxConnectorsEval int
		wantErr           bool
	}{
		{
			name:           "community tier (no license) with 2 connectors (at limit)",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql"},
			maxConnectors:  2,
			wantErr:        false,
		},
		{
			name:           "community tier (no license) with 3 connectors (over limit)",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql", "redis"},
			maxConnectors:  2,
			wantErr:        true,
		},
		{
			name:           "empty deployment mode no license with 3 connectors (over community limit)",
			deploymentMode: "",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql", "redis"},
			maxConnectors:  2,
			wantErr:        true,
		},
		{
			name:           "enterprise deployment mode with 5 connectors (no limit)",
			deploymentMode: "enterprise",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql", "redis", "mongo", "s3"},
			maxConnectors:  2,
			wantErr:        false,
		},
		{
			name:           "community tier (no license) with 1 connector (under limit)",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"postgres"},
			maxConnectors:  2,
			wantErr:        false,
		},
		{
			name:           "community tier (no license) with nil connectors (no limit applied)",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     nil,
			maxConnectors:  2,
			wantErr:        false,
		},
		{
			name:           "community tier (no license) with empty connectors list",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{},
			maxConnectors:  2,
			wantErr:        false,
		},
		{
			name:              "evaluation tier (has license) with 5 connectors (at eval limit)",
			deploymentMode:    "community",
			licenseKey:        "AXON-test-evaluation-key",
			connectors:        []string{"postgres", "mysql", "redis", "mongo", "s3"},
			maxConnectors:     2,
			maxConnectorsEval: 5,
			wantErr:           false,
		},
		{
			name:              "evaluation tier (has license) with 6 connectors (over eval limit)",
			deploymentMode:    "community",
			licenseKey:        "AXON-test-evaluation-key",
			connectors:        []string{"pg", "mysql", "redis", "mongo", "s3", "http"},
			maxConnectors:     2,
			maxConnectorsEval: 5,
			wantErr:           true,
		},
		{
			name:              "evaluation tier (has license, empty mode) with 3 connectors (under eval limit)",
			deploymentMode:    "",
			licenseKey:        "AXON-test-evaluation-key",
			connectors:        []string{"postgres", "mysql", "redis"},
			maxConnectors:     2,
			maxConnectorsEval: 5,
			wantErr:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deploymentMode == "" {
				os.Unsetenv("DEPLOYMENT_MODE")
			} else {
				os.Setenv("DEPLOYMENT_MODE", tt.deploymentMode)
			}
			if tt.licenseKey == "" {
				os.Unsetenv("AXONFLOW_LICENSE_KEY")
			} else {
				os.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			}

			config := DynamicPolicyConfig{
				EnabledConnectors:                   tt.connectors,
				MaxCustomPolicyConnectorsCommunity:  tt.maxConnectors,
				MaxCustomPolicyConnectorsEvaluation: tt.maxConnectorsEval,
			}

			err := ValidateCustomPolicyConnectorLimit(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCustomPolicyConnectorLimit() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnforceCustomPolicyConnectorLimit(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	tests := []struct {
		name              string
		deploymentMode    string
		licenseKey        string
		connectors        []string
		maxConnectors     int
		maxConnectorsEval int
		wantCount         int
		wantConnectors    []string
	}{
		{
			name:           "community tier (no license) at limit — keep all",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql"},
			maxConnectors:  2,
			wantCount:      2,
			wantConnectors: []string{"postgres", "mysql"},
		},
		{
			name:           "community tier (no license) over limit — truncate to 2",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"postgres", "mysql", "redis"},
			maxConnectors:  2,
			wantCount:      2,
			wantConnectors: []string{"postgres", "mysql"},
		},
		{
			name:           "community tier (no license) way over — truncate to 2",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     []string{"pg", "mysql", "redis", "mongo", "s3"},
			maxConnectors:  2,
			wantCount:      2,
			wantConnectors: []string{"pg", "mysql"},
		},
		{
			name:           "enterprise deployment — keep all",
			deploymentMode: "enterprise",
			licenseKey:     "",
			connectors:     []string{"pg", "mysql", "redis", "mongo", "s3"},
			maxConnectors:  2,
			wantCount:      5,
			wantConnectors: []string{"pg", "mysql", "redis", "mongo", "s3"},
		},
		{
			name:           "empty mode no license over limit — truncate (community tier)",
			deploymentMode: "",
			licenseKey:     "",
			connectors:     []string{"pg", "mysql", "redis"},
			maxConnectors:  2,
			wantCount:      2,
			wantConnectors: []string{"pg", "mysql"},
		},
		{
			name:           "nil connectors — return nil",
			deploymentMode: "community",
			licenseKey:     "",
			connectors:     nil,
			maxConnectors:  2,
			wantCount:      0,
		},
		{
			name:              "evaluation tier (has license) at eval limit — keep all 5",
			deploymentMode:    "community",
			licenseKey:        "AXON-test-evaluation-key",
			connectors:        []string{"pg", "mysql", "redis", "mongo", "s3"},
			maxConnectors:     2,
			maxConnectorsEval: 5,
			wantCount:         5,
			wantConnectors:    []string{"pg", "mysql", "redis", "mongo", "s3"},
		},
		{
			name:              "evaluation tier (has license) over eval limit — truncate to 5",
			deploymentMode:    "",
			licenseKey:        "AXON-test-evaluation-key",
			connectors:        []string{"pg", "mysql", "redis", "mongo", "s3", "http", "gcs"},
			maxConnectors:     2,
			maxConnectorsEval: 5,
			wantCount:         5,
			wantConnectors:    []string{"pg", "mysql", "redis", "mongo", "s3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deploymentMode == "" {
				os.Unsetenv("DEPLOYMENT_MODE")
			} else {
				os.Setenv("DEPLOYMENT_MODE", tt.deploymentMode)
			}
			if tt.licenseKey == "" {
				os.Unsetenv("AXONFLOW_LICENSE_KEY")
			} else {
				os.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			}

			config := DynamicPolicyConfig{
				EnabledConnectors:                   tt.connectors,
				MaxCustomPolicyConnectorsCommunity:  tt.maxConnectors,
				MaxCustomPolicyConnectorsEvaluation: tt.maxConnectorsEval,
			}

			result := EnforceCustomPolicyConnectorLimit(config)
			if len(result) != tt.wantCount {
				t.Errorf("EnforceCustomPolicyConnectorLimit() returned %d connectors, want %d", len(result), tt.wantCount)
			}
			if tt.wantConnectors != nil {
				for i, c := range tt.wantConnectors {
					if i < len(result) && result[i] != c {
						t.Errorf("EnforceCustomPolicyConnectorLimit()[%d] = %s, want %s", i, result[i], c)
					}
				}
			}
		})
	}
}

func TestResolveConnectorLimitTier(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	tests := []struct {
		name           string
		deploymentMode string
		licenseKey     string
		wantTier       string
	}{
		{"community mode no license", "community", "", "community"},
		{"empty mode no license", "", "", "community"},
		{"community mode with license", "community", "AXON-key", "evaluation"},
		{"empty mode with license", "", "AXON-key", "evaluation"},
		{"enterprise mode no license", "enterprise", "", "enterprise"},
		{"enterprise mode with license", "enterprise", "AXON-key", "enterprise"},
		{"saas mode", "saas", "", "enterprise"},
		{"in-vpc-enterprise mode", "in-vpc-enterprise", "", "enterprise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.deploymentMode == "" {
				os.Unsetenv("DEPLOYMENT_MODE")
			} else {
				os.Setenv("DEPLOYMENT_MODE", tt.deploymentMode)
			}
			if tt.licenseKey == "" {
				os.Unsetenv("AXONFLOW_LICENSE_KEY")
			} else {
				os.Setenv("AXONFLOW_LICENSE_KEY", tt.licenseKey)
			}

			got := resolveConnectorLimitTier()
			if got != tt.wantTier {
				t.Errorf("resolveConnectorLimitTier() = %q, want %q", got, tt.wantTier)
			}
		})
	}
}

func TestUpdateConfig_ConnectorLimitEnforced(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	// Community tier: no license key
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Unsetenv("AXONFLOW_LICENSE_KEY")

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled: false,
		Timeout: 5 * time.Second,
	})

	// Should fail with 3 connectors in community tier
	err := evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:                            true,
		OrchestratorEndpoint:               "http://test:8081",
		Timeout:                            5 * time.Second,
		EnabledConnectors:                  []string{"postgres", "mysql", "redis"},
		MaxCustomPolicyConnectorsCommunity: 2,
	})

	if err == nil {
		t.Error("expected error when exceeding connector limit in community tier")
	}

	// Should succeed with 2 connectors
	err = evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:                            true,
		OrchestratorEndpoint:               "http://test:8081",
		Timeout:                            5 * time.Second,
		EnabledConnectors:                  []string{"postgres", "mysql"},
		MaxCustomPolicyConnectorsCommunity: 2,
	})

	if err != nil {
		t.Errorf("unexpected error with 2 connectors: %v", err)
	}
}

func TestUpdateConfig_EvaluationTierLimit(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	// Evaluation tier: community mode + license key
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("AXONFLOW_LICENSE_KEY", "AXON-test-evaluation-key")

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled: false,
		Timeout: 5 * time.Second,
	})

	// Should succeed with 5 connectors (evaluation limit)
	err := evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:                             true,
		OrchestratorEndpoint:                "http://test:8081",
		Timeout:                             5 * time.Second,
		EnabledConnectors:                   []string{"pg", "mysql", "redis", "mongo", "s3"},
		MaxCustomPolicyConnectorsCommunity:  2,
		MaxCustomPolicyConnectorsEvaluation: 5,
	})

	if err != nil {
		t.Errorf("unexpected error with 5 connectors in evaluation tier: %v", err)
	}

	// Should fail with 6 connectors (over evaluation limit)
	err = evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:                             true,
		OrchestratorEndpoint:                "http://test:8081",
		Timeout:                             5 * time.Second,
		EnabledConnectors:                   []string{"pg", "mysql", "redis", "mongo", "s3", "http"},
		MaxCustomPolicyConnectorsCommunity:  2,
		MaxCustomPolicyConnectorsEvaluation: 5,
	})

	if err == nil {
		t.Error("expected error when exceeding connector limit in evaluation tier")
	}
}

func TestUpdateConfig_EnterpriseUnlimited(t *testing.T) {
	origMode := os.Getenv("DEPLOYMENT_MODE")
	origLicense := os.Getenv("AXONFLOW_LICENSE_KEY")
	defer restoreEnv("DEPLOYMENT_MODE", origMode)
	defer restoreEnv("AXONFLOW_LICENSE_KEY", origLicense)

	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	os.Unsetenv("AXONFLOW_LICENSE_KEY")

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled: false,
		Timeout: 5 * time.Second,
	})

	// Should succeed with 5 connectors in enterprise deployment
	err := evaluator.UpdateConfig(DynamicPolicyConfig{
		Enabled:                            true,
		OrchestratorEndpoint:               "http://test:8081",
		Timeout:                            5 * time.Second,
		EnabledConnectors:                  []string{"postgres", "mysql", "redis", "mongo", "s3"},
		MaxCustomPolicyConnectorsCommunity: 2,
	})

	if err != nil {
		t.Errorf("unexpected error in enterprise deployment: %v", err)
	}
}

// TestDynamicPolicyEvaluator_MissingSecretFailsClosed pins the #3068 rule that
// a MISSING AXONFLOW_INTERNAL_SERVICE_SECRET must NOT be absorbed by graceful
// degradation.
//
// Why this matters more than it looks: the orchestrator now refuses every
// token-less call, so without a secret this evaluator gets a deterministic 403
// on every request forever. If graceful degradation swallowed that, MCP
// connector policy enforcement would silently become allow-all with
// policies_evaluated: 0 — strictly worse than the bug #3068 fixes, and the
// exact failure shape of #3048/#3049. Fail closed instead.
func TestDynamicPolicyEvaluator_MissingSecretFailsClosed(t *testing.T) {
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "")

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: "http://localhost:99999",
		Timeout:              1 * time.Second,
		GracefulDegradation:  true, // explicitly on — must still NOT mask this
	})

	resp, info, err := evaluator.EvaluateWithGracefulDegradation(
		context.Background(), DynamicPolicyRequest{TenantID: "tenant-1"})

	if err == nil {
		t.Fatal("missing internal-service secret was absorbed by graceful degradation — " +
			"connector policy enforcement would silently allow everything")
	}
	if resp != nil && resp.Allowed {
		t.Error("returned Allowed=true despite being unable to authenticate to the orchestrator")
	}
	if info == nil {
		t.Fatal("expected non-nil info")
	}
	if info.OrchestratorReachable {
		t.Error("expected OrchestratorReachable=false")
	}
}

// TestDynamicPolicyEvaluator_SecretConfiguredStampsToken proves the evaluator
// actually sends the header when a secret IS configured — the positive control
// for the fail-closed test above, and for the fail-open the gate would
// otherwise cause.
func TestDynamicPolicyEvaluator_SecretConfiguredStampsToken(t *testing.T) {
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "evaluator-token-test-secret-at-least-32c")

	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Axonflow-Proxy-Auth")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true,"policies_evaluated":3}`))
	}))
	defer srv.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: srv.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  true,
	})

	if _, err := evaluator.Evaluate(context.Background(), DynamicPolicyRequest{TenantID: "t"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotToken == "" {
		t.Fatal("evaluator sent NO X-Axonflow-Proxy-Auth header — the orchestrator would 403 this")
	}
	valid, _, err := serviceauth.NewTokenValidator(
		"evaluator-token-test-secret-at-least-32c", nil, serviceauth.DefaultClockSkew).ValidateToken(gotToken)
	if !valid {
		t.Errorf("evaluator sent a token the real validator rejects: %q (%v)", gotToken, err)
	}
}

// TestDynamicPolicyEvaluator_AuthRejectionFailsClosed is the #3068 B-1 pin.
//
// TestDynamicPolicyEvaluator_MissingSecretFailsClosed above covers only the
// tokenGen == nil spelling. A secret that is PRESENT but not accepted by the
// orchestrator produces a permanent deterministic 401/403, which graceful
// degradation (default true) used to absorb into
// {Allowed: true, PoliciesEvaluated: 0} — MCP connector enforcement silently
// off, the #3048/#3049 shape.
//
// This needs no operator error to reach: the proxy-auth token is
// timestamp-signed with serviceauth.DefaultClockSkew, so NTP failure on either
// host, a rotation skew, or two drifted task definitions all land here.
func TestDynamicPolicyEvaluator_AuthRejectionFailsClosed(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// Secret IS configured — this is NOT the missing-secret case.
			t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "agent-side-secret-that-is-at-least-32-chars")

			var sawToken bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawToken = r.Header.Get("X-Axonflow-Proxy-Auth") != ""
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"Unauthorized: request must be routed through AxonFlow Agent"}`))
			}))
			defer srv.Close()

			evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
				Enabled:              true,
				OrchestratorEndpoint: srv.URL,
				Timeout:              5 * time.Second,
				GracefulDegradation:  true, // explicitly ON — must NOT mask an auth rejection
			})

			resp, info, err := evaluator.EvaluateWithGracefulDegradation(
				context.Background(), DynamicPolicyRequest{TenantID: "tenant-1", ConnectorName: "postgres"})

			if !sawToken {
				t.Fatal("evaluator sent no proxy-auth token; this test must exercise the " +
					"present-but-rejected credential path, not the missing-secret path")
			}
			if err == nil {
				t.Fatalf("status %d was absorbed by graceful degradation — connector policy "+
					"enforcement silently degraded to allow-all", status)
			}
			if !errors.Is(err, ErrOrchestratorAuthRejected) {
				t.Errorf("error does not carry the auth-rejection sentinel through errors.Is: %v", err)
			}
			if resp != nil && resp.Allowed {
				t.Errorf("returned Allowed=true (policies_evaluated=%d) despite an orchestrator "+
					"auth rejection", resp.PoliciesEvaluated)
			}
			if info == nil {
				t.Fatal("expected non-nil info")
			}
			if info.OrchestratorReachable {
				t.Error("expected OrchestratorReachable=false")
			}
		})
	}
}

// TestDynamicPolicyEvaluator_ClockSkewFailsClosed reproduces the specific
// no-misconfiguration route into B-1: both sides hold the SAME secret, but the
// orchestrator's clock disagrees far enough that the real validator rejects a
// freshly minted token. The result must be a refusal, not allow-all.
func TestDynamicPolicyEvaluator_ClockSkewFailsClosed(t *testing.T) {
	const sharedSecret = "identical-on-both-sides-at-least-32-chars"
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", sharedSecret)

	// Real validator with the real DefaultClockSkew window, but reading a clock
	// one hour ahead — i.e. the orchestrator host's NTP has drifted. Nothing is
	// misconfigured: same secret, same code, same window.
	validator := serviceauth.NewTokenValidator(
		sharedSecret, skewedClock{offset: time.Hour}, serviceauth.DefaultClockSkew)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid, _, _ := validator.ValidateToken(r.Header.Get("X-Axonflow-Proxy-Auth"))
		if !valid {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Unauthorized: request must be routed through AxonFlow Agent"}`))
			return
		}
		_, _ = w.Write([]byte(`{"allowed":true,"policies_evaluated":7}`))
	}))
	defer srv.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: srv.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  true,
	})

	resp, _, err := evaluator.EvaluateWithGracefulDegradation(
		context.Background(), DynamicPolicyRequest{TenantID: "tenant-1"})

	if err == nil {
		t.Fatal("clock drift past the signing window degraded enforcement to allow-all instead of failing closed")
	}
	if !errors.Is(err, ErrOrchestratorAuthRejected) {
		t.Errorf("clock-skew 403 not classified as an auth rejection: %v", err)
	}
	if resp != nil && resp.Allowed {
		t.Error("returned Allowed=true under clock skew")
	}
}

// TestDynamicPolicyEvaluator_TransientErrorStillDegrades is the positive
// control for the two tests above: graceful degradation must still absorb the
// TRANSIENT conditions it exists for. Without this, a fix that simply disabled
// graceful degradation everywhere would pass.
func TestDynamicPolicyEvaluator_TransientErrorStillDegrades(t *testing.T) {
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "agent-side-secret-that-is-at-least-32-chars")

	for _, status := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()

			evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
				Enabled:              true,
				OrchestratorEndpoint: srv.URL,
				Timeout:              5 * time.Second,
				GracefulDegradation:  true,
			})

			resp, _, err := evaluator.EvaluateWithGracefulDegradation(
				context.Background(), DynamicPolicyRequest{TenantID: "tenant-1"})
			if err != nil {
				t.Fatalf("a transient %d must still be absorbed by graceful degradation, got %v", status, err)
			}
			if resp == nil || !resp.Allowed {
				t.Fatalf("expected the degraded allow for a transient %d, got %+v", status, resp)
			}
			if errors.Is(err, ErrOrchestratorAuthRejected) {
				t.Errorf("a %d must not be classified as an auth rejection", status)
			}
		})
	}
}

// TestDynamicPolicyEvaluator_AuthRejectionStrictModeUnchanged pins that the
// sentinel does not alter behaviour when graceful degradation is already off:
// still an error, and still carrying the sentinel for callers that branch on it.
func TestDynamicPolicyEvaluator_AuthRejectionStrictModeUnchanged(t *testing.T) {
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "agent-side-secret-that-is-at-least-32-chars")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	evaluator := NewDynamicPolicyEvaluator(DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: srv.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
	})

	_, _, err := evaluator.EvaluateWithGracefulDegradation(
		context.Background(), DynamicPolicyRequest{TenantID: "tenant-1"})
	if err == nil {
		t.Fatal("expected an error with graceful degradation off")
	}
	if !errors.Is(err, ErrOrchestratorAuthRejected) {
		t.Errorf("sentinel lost in strict mode: %v", err)
	}
}

// skewedClock is a serviceauth.Clock whose notion of "now" is offset, standing
// in for a host whose NTP has failed.
type skewedClock struct{ offset time.Duration }

func (c skewedClock) Now() time.Time { return time.Now().Add(c.offset) }
