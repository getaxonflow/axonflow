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

package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// TransparencyContext Unit Tests
// =============================================================================

func TestNewTransparencyContext(t *testing.T) {
	tc := NewTransparencyContext()

	if tc == nil {
		t.Fatal("NewTransparencyContext returned nil")
	}
	if tc.RequestID == "" {
		t.Error("RequestID should not be empty")
	}
	if tc.ChainID == "" {
		t.Error("ChainID should not be empty")
	}
	if tc.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if !strings.HasPrefix(tc.SystemID, "axonflow-agent/") {
		t.Errorf("SystemID should start with 'axonflow-agent/', got %s", tc.SystemID)
	}
	if tc.ProcessingType != "policy-enforcement" {
		t.Errorf("ProcessingType should be 'policy-enforcement', got %s", tc.ProcessingType)
	}
	if tc.RiskLevel != "limited" {
		t.Errorf("RiskLevel should be 'limited', got %s", tc.RiskLevel)
	}
	if tc.PoliciesApplied == nil || len(tc.PoliciesApplied) != 0 {
		t.Error("PoliciesApplied should be empty slice, not nil")
	}
	if tc.DataSources == nil || len(tc.DataSources) != 0 {
		t.Error("DataSources should be empty slice, not nil")
	}
}

func TestNewTransparencyContextWithChain(t *testing.T) {
	existingChainID := "existing-chain-123"
	tc := NewTransparencyContextWithChain(existingChainID)

	if tc.ChainID != existingChainID {
		t.Errorf("ChainID should be %s, got %s", existingChainID, tc.ChainID)
	}

	// Empty chain ID should generate a new one
	tc2 := NewTransparencyContextWithChain("")
	if tc2.ChainID == "" {
		t.Error("ChainID should be generated when empty string is passed")
	}
}

func TestTransparencyContextAddPolicy(t *testing.T) {
	tc := NewTransparencyContext()

	tc.AddPolicy("policy-1")
	tc.AddPolicy("policy-2")
	tc.AddPolicy("") // Empty should be ignored

	if len(tc.PoliciesApplied) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(tc.PoliciesApplied))
	}
	if tc.PoliciesApplied[0] != "policy-1" {
		t.Errorf("Expected policy-1, got %s", tc.PoliciesApplied[0])
	}
}

func TestTransparencyContextAddPolicies(t *testing.T) {
	tc := NewTransparencyContext()

	tc.AddPolicies([]string{"policy-1", "policy-2", "", "policy-3"})

	// Empty strings should be filtered
	if len(tc.PoliciesApplied) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(tc.PoliciesApplied))
	}
}

func TestTransparencyContextPolicyCap(t *testing.T) {
	tc := NewTransparencyContext()

	// Add more than maxPolicies
	for i := 0; i < maxPolicies+20; i++ {
		tc.AddPolicy(fmt.Sprintf("policy-%d", i))
	}

	if len(tc.PoliciesApplied) != maxPolicies {
		t.Errorf("Expected policies capped at %d, got %d", maxPolicies, len(tc.PoliciesApplied))
	}
}

func TestTransparencyContextAddDataSource(t *testing.T) {
	tc := NewTransparencyContext()

	tc.AddDataSource("postgres")
	tc.AddDataSource("redis")
	tc.AddDataSource("") // Empty should be ignored

	if len(tc.DataSources) != 2 {
		t.Errorf("Expected 2 data sources, got %d", len(tc.DataSources))
	}
}

func TestTransparencyContextDataSourceCap(t *testing.T) {
	tc := NewTransparencyContext()

	// Add more than maxDataSources
	for i := 0; i < maxDataSources+20; i++ {
		tc.AddDataSource(fmt.Sprintf("source-%d", i))
	}

	if len(tc.DataSources) != maxDataSources {
		t.Errorf("Expected data sources capped at %d, got %d", maxDataSources, len(tc.DataSources))
	}
}

func TestTransparencyContextMarkBlocked(t *testing.T) {
	tc := NewTransparencyContext()

	tc.MarkBlocked("PII detected")

	if !tc.DecisionBlocked {
		t.Error("DecisionBlocked should be true")
	}
	if tc.BlockReason != "PII detected" {
		t.Errorf("BlockReason should be 'PII detected', got %s", tc.BlockReason)
	}
}

func TestTransparencyContextMarkFiltered(t *testing.T) {
	tc := NewTransparencyContext()

	if tc.ContentFiltered {
		t.Error("ContentFiltered should be false initially")
	}

	tc.MarkFiltered()

	if !tc.ContentFiltered {
		t.Error("ContentFiltered should be true after MarkFiltered")
	}
}

func TestTransparencyContextRequireHumanOversight(t *testing.T) {
	tc := NewTransparencyContext()

	tc.RequireHumanOversight()

	if !tc.HumanOversight {
		t.Error("HumanOversight should be true")
	}
	if tc.RiskLevel != "high" {
		t.Errorf("RiskLevel should be elevated to 'high', got %s", tc.RiskLevel)
	}

	// Test that unacceptable risk level is not downgraded
	tc2 := NewTransparencyContext()
	tc2.RiskLevel = "unacceptable"
	tc2.RequireHumanOversight()

	if tc2.RiskLevel != "unacceptable" {
		t.Errorf("RiskLevel should remain 'unacceptable', got %s", tc2.RiskLevel)
	}
}

func TestTransparencyContextSetProcessingTime(t *testing.T) {
	tc := NewTransparencyContext()
	start := time.Now().Add(-100 * time.Millisecond)

	tc.SetProcessingTime(start)

	if tc.ProcessingTimeMs < 100 {
		t.Errorf("ProcessingTimeMs should be >= 100, got %d", tc.ProcessingTimeMs)
	}
}

func TestTransparencyContextSetProcessingDuration(t *testing.T) {
	tc := NewTransparencyContext()

	tc.SetProcessingDuration(250 * time.Millisecond)

	if tc.ProcessingTimeMs != 250 {
		t.Errorf("ProcessingTimeMs should be 250, got %d", tc.ProcessingTimeMs)
	}
}

func TestTransparencyContextSetModel(t *testing.T) {
	tc := NewTransparencyContext()

	tc.SetModel("anthropic", "claude-3-opus")

	if tc.ModelProvider != "anthropic" {
		t.Errorf("ModelProvider should be 'anthropic', got %s", tc.ModelProvider)
	}
	if tc.ModelID != "claude-3-opus" {
		t.Errorf("ModelID should be 'claude-3-opus', got %s", tc.ModelID)
	}
	if tc.ProcessingType != "hybrid" {
		t.Errorf("ProcessingType should be 'hybrid' after SetModel, got %s", tc.ProcessingType)
	}
}

func TestTransparencyContextSetTenantContext(t *testing.T) {
	tc := NewTransparencyContext()

	tc.SetTenantContext("org-123", "tenant-456", "client-789", "user-abc")

	if tc.OrgID != "org-123" {
		t.Errorf("OrgID should be 'org-123', got %s", tc.OrgID)
	}
	if tc.TenantID != "tenant-456" {
		t.Errorf("TenantID should be 'tenant-456', got %s", tc.TenantID)
	}
	if tc.ClientID != "client-789" {
		t.Errorf("ClientID should be 'client-789', got %s", tc.ClientID)
	}
	if tc.UserID != "user-abc" {
		t.Errorf("UserID should be 'user-abc', got %s", tc.UserID)
	}
}

// =============================================================================
// Audit Hash Tests
// =============================================================================

func TestTransparencyContextComputeAuditHash(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "fixed-request-id"
	tc.ChainID = "fixed-chain-id"
	tc.Timestamp = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	tc.OrgID = "org-123"
	tc.TenantID = "tenant-456"
	tc.ClientID = "client-789"
	tc.UserID = "user-abc"
	tc.DecisionBlocked = false
	tc.ContentFiltered = false
	tc.HumanOversight = false
	tc.ProcessingTimeMs = 100

	hash1 := tc.ComputeAuditHash()

	if hash1 == "" {
		t.Error("AuditHash should not be empty")
	}
	if len(hash1) != 64 {
		t.Errorf("AuditHash should be 64 characters (SHA-256 hex), got %d", len(hash1))
	}

	// Same inputs should produce same hash (deterministic)
	hash2 := tc.ComputeAuditHash()
	if hash1 != hash2 {
		t.Error("Same inputs should produce same hash")
	}

	// Different input should produce different hash
	tc.ProcessingTimeMs = 200
	hash3 := tc.ComputeAuditHash()
	if hash1 == hash3 {
		t.Error("Different inputs should produce different hash")
	}
}

func TestAuditHashCollisionResistance(t *testing.T) {
	// Test that different field boundaries produce different hashes
	// This tests the length-prefixed encoding that prevents collision attacks

	tc1 := NewTransparencyContext()
	tc1.RequestID = "a"
	tc1.ChainID = "bc"

	tc2 := NewTransparencyContext()
	tc2.RequestID = "ab"
	tc2.ChainID = "c"

	// Make timestamps identical for fair comparison
	tc1.Timestamp = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	tc2.Timestamp = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	hash1 := tc1.ComputeAuditHash()
	hash2 := tc2.ComputeAuditHash()

	if hash1 == hash2 {
		t.Error("Different field boundaries should produce different hashes (collision detected)")
	}
}

// =============================================================================
// SetHeaders Tests
// =============================================================================

func TestTransparencyContextSetHeaders(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "req-123"
	tc.ChainID = "chain-456"
	tc.ProcessingType = "policy-enforcement"
	tc.RiskLevel = "high"
	tc.DecisionBlocked = true
	tc.ContentFiltered = true
	tc.HumanOversight = true
	tc.ProcessingTimeMs = 150
	tc.ModelProvider = "openai"
	tc.ModelID = "gpt-4"
	tc.AddPolicy("policy-1")
	tc.AddPolicy("policy-2")
	tc.AddDataSource("postgres")
	tc.ComputeAuditHash()

	w := httptest.NewRecorder()
	tc.SetHeaders(w)

	headers := w.Header()

	tests := []struct {
		header   string
		expected string
	}{
		{HeaderAIRequestID, "req-123"},
		{HeaderAIChainID, "chain-456"},
		{HeaderAIProcessingType, "policy-enforcement"},
		{HeaderAIRiskLevel, "high"},
		{HeaderAIDecisionBlocked, "true"},
		{HeaderAIContentFiltered, "true"},
		{HeaderAIHumanOversightRequired, "true"},
		{HeaderAIProcessingTimeMs, "150"},
		{HeaderAIModelProvider, "openai"},
		{HeaderAIModelID, "gpt-4"},
		{HeaderAIPoliciesApplied, "policy-1,policy-2"},
		{HeaderAIDataSources, "postgres"},
	}

	for _, tt := range tests {
		if headers.Get(tt.header) != tt.expected {
			t.Errorf("Header %s: expected '%s', got '%s'", tt.header, tt.expected, headers.Get(tt.header))
		}
	}

	// SystemID should be set
	if headers.Get(HeaderAISystemID) == "" {
		t.Error("SystemID header should be set")
	}

	// Timestamp should be set and parseable
	ts := headers.Get(HeaderAITimestamp)
	if ts == "" {
		t.Error("Timestamp header should be set")
	}
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("Timestamp should be RFC3339Nano format, got error: %v", err)
	}

	// AuditHash should be 64 chars
	if len(headers.Get(HeaderAIAuditHash)) != 64 {
		t.Errorf("AuditHash header should be 64 chars, got %d", len(headers.Get(HeaderAIAuditHash)))
	}
}

func TestSetHeadersNilContext(t *testing.T) {
	var tc *TransparencyContext
	w := httptest.NewRecorder()

	// Should not panic
	tc.SetHeaders(w)

	// No headers should be set
	if len(w.Header()) > 0 {
		t.Error("No headers should be set for nil context")
	}
}

// =============================================================================
// Header Injection Prevention Tests
// =============================================================================

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal value", "normal value"},
		{"value\r\nX-Injected: bad", "valueX-Injected: bad"},
		{"value\rinjection", "valueinjection"},
		{"value\ninjection", "valueinjection"},
		{"value\x00null", "valuenull"},
		{"\r\n\r\n", ""},
		{"safe-value-123", "safe-value-123"},
	}

	for _, tt := range tests {
		result := sanitizeHeaderValue(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeHeaderValue(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}

func TestHeaderInjectionPrevention(t *testing.T) {
	tc := NewTransparencyContext()
	// Try to inject a header via policy name
	tc.AddPolicy("policy-1\r\nX-Injected: malicious")
	tc.AddDataSource("source\r\nX-Injected: bad")
	tc.ModelProvider = "provider\r\nX-Injected: evil"
	tc.ModelID = "model\r\nX-Injected: nasty"
	tc.ProcessingType = "type\r\nX-Injected: horrible"
	tc.RiskLevel = "high\r\nX-Injected: terrible"

	w := httptest.NewRecorder()
	tc.SetHeaders(w)

	// Check that no injection occurred
	if w.Header().Get("X-Injected") != "" {
		t.Error("Header injection detected!")
	}

	// Verify sanitized values don't contain CRLF
	for name, values := range w.Header() {
		for _, v := range values {
			if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
				t.Errorf("Header %s contains unsanitized CRLF: %q", name, v)
			}
		}
	}
}

// =============================================================================
// Nil Safety Tests
// =============================================================================

func TestNilContextMethodsDoNotPanic(t *testing.T) {
	var tc *TransparencyContext

	// All these should not panic
	tc.MarkBlocked("reason")
	tc.MarkFiltered()
	tc.RequireHumanOversight()
	tc.SetProcessingTime(time.Now())
	tc.SetProcessingDuration(100 * time.Millisecond)
	tc.AddPolicy("policy")
	tc.AddPolicies([]string{"p1", "p2"})
	tc.AddDataSource("source")
	tc.SetModel("provider", "model")
	tc.SetTenantContext("org", "tenant", "client", "user")
	tc.SetHeaders(httptest.NewRecorder())

	// Test passed if no panic
}

// =============================================================================
// Context Storage Tests
// =============================================================================

func TestTransparencyContextStorage(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "test-request-123"

	ctx := context.Background()
	ctx = SetTransparencyContext(ctx, tc)

	retrieved := GetTransparencyContext(ctx)

	if retrieved == nil {
		t.Fatal("Retrieved context should not be nil")
	}
	if retrieved.RequestID != "test-request-123" {
		t.Errorf("RequestID mismatch: expected 'test-request-123', got %s", retrieved.RequestID)
	}
}

func TestGetTransparencyContextFromEmptyContext(t *testing.T) {
	ctx := context.Background()
	tc := GetTransparencyContext(ctx)

	if tc != nil {
		t.Error("Should return nil for context without transparency")
	}
}

func TestGetOrCreateTransparencyContext(t *testing.T) {
	// Test with empty context - should create new
	ctx := context.Background()
	tc1, newCtx := GetOrCreateTransparencyContext(ctx)

	if tc1 == nil {
		t.Fatal("Should create new context")
	}
	if tc1.RequestID == "" {
		t.Error("New context should have RequestID")
	}

	// Test with existing context - should return existing
	tc2, _ := GetOrCreateTransparencyContext(newCtx)

	if tc2.RequestID != tc1.RequestID {
		t.Error("Should return same context when already exists")
	}
}

// =============================================================================
// Middleware Tests
// =============================================================================

func TestTransparencyMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := GetTransparencyContext(r.Context())
		if tc == nil {
			t.Error("Middleware should add transparency context")
			return
		}
		if tc.RequestID == "" {
			t.Error("Context should have RequestID")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := TransparencyMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestTransparencyMiddlewareInheritsChainID(t *testing.T) {
	existingChainID := "existing-chain-id-xyz"
	var capturedChainID string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := GetTransparencyContext(r.Context())
		capturedChainID = tc.ChainID
		w.WriteHeader(http.StatusOK)
	})

	middleware := TransparencyMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(HeaderAIChainID, existingChainID)
	w := httptest.NewRecorder()

	middleware.ServeHTTP(w, req)

	if capturedChainID != existingChainID {
		t.Errorf("ChainID should be inherited: expected %s, got %s", existingChainID, capturedChainID)
	}
}

// =============================================================================
// TransparencyResponseWriter Tests
// =============================================================================

func TestTransparencyResponseWriter(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "response-writer-test"
	tc.DecisionBlocked = true

	baseW := httptest.NewRecorder()
	trw := NewTransparencyResponseWriter(baseW, tc)

	trw.WriteHeader(http.StatusOK)

	// Headers should be set
	if baseW.Header().Get(HeaderAIRequestID) != "response-writer-test" {
		t.Error("Headers should be set on WriteHeader")
	}
	if baseW.Header().Get(HeaderAIDecisionBlocked) != "true" {
		t.Error("DecisionBlocked header should be set")
	}
}

func TestTransparencyResponseWriterWriteOnly(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "write-only-test"

	baseW := httptest.NewRecorder()
	trw := NewTransparencyResponseWriter(baseW, tc)

	// Write without calling WriteHeader
	_, err := trw.Write([]byte("body content"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Headers should still be set
	if baseW.Header().Get(HeaderAIRequestID) != "write-only-test" {
		t.Error("Headers should be set on Write even without WriteHeader")
	}
}

func TestTransparencyResponseWriterSetOnce(t *testing.T) {
	tc := NewTransparencyContext()
	tc.RequestID = "set-once-test"

	baseW := httptest.NewRecorder()
	trw := NewTransparencyResponseWriter(baseW, tc)

	trw.WriteHeader(http.StatusOK)

	// Change the context
	tc.RequestID = "changed-id"

	// Write - should not change headers since already written
	_, _ = trw.Write([]byte("body"))

	if baseW.Header().Get(HeaderAIRequestID) != "set-once-test" {
		t.Error("Headers should only be set once")
	}
}

func TestTransparencyResponseWriterNilContext(t *testing.T) {
	baseW := httptest.NewRecorder()
	trw := NewTransparencyResponseWriter(baseW, nil)

	// Should not panic
	trw.WriteHeader(http.StatusOK)
	_, _ = trw.Write([]byte("body"))

	// No transparency headers should be set
	if baseW.Header().Get(HeaderAIRequestID) != "" {
		t.Error("No headers should be set with nil context")
	}
}

func TestTransparencyResponseWriterGetWrapped(t *testing.T) {
	baseW := httptest.NewRecorder()
	trw := NewTransparencyResponseWriter(baseW, nil)

	if trw.GetWrappedResponseWriter() != baseW {
		t.Error("GetWrappedResponseWriter should return underlying writer")
	}
}

// =============================================================================
// Version Validation Tests
// =============================================================================

func TestGetSystemIDWithValidVersion(t *testing.T) {
	t.Setenv("AXONFLOW_VERSION", "2.5.3")
	id := getSystemID()
	if id != "axonflow-agent/2.5.3" {
		t.Errorf("Expected 'axonflow-agent/2.5.3', got %s", id)
	}
}

func TestGetSystemIDWithPrerelease(t *testing.T) {
	t.Setenv("AXONFLOW_VERSION", "1.0.0-beta.1")
	id := getSystemID()
	if id != "axonflow-agent/1.0.0-beta.1" {
		t.Errorf("Expected 'axonflow-agent/1.0.0-beta.1', got %s", id)
	}
}

func TestGetSystemIDWithInvalidVersion(t *testing.T) {
	t.Setenv("AXONFLOW_VERSION", "invalid")
	id := getSystemID()
	if id != "axonflow-agent/1.0.0" {
		t.Errorf("Invalid version should fall back to default, got %s", id)
	}
}

func TestGetSystemIDWithEmptyVersion(t *testing.T) {
	t.Setenv("AXONFLOW_VERSION", "")
	id := getSystemID()
	if id != "axonflow-agent/1.0.0" {
		t.Errorf("Empty version should fall back to default, got %s", id)
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestTransparencyContextConcurrentPolicyAdd(t *testing.T) {
	tc := NewTransparencyContext()
	const numGoroutines = 100
	const numPoliciesEach = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numPoliciesEach; j++ {
				tc.AddPolicy(fmt.Sprintf("policy-%d-%d", goroutineID, j))
			}
		}(i)
	}

	wg.Wait()

	// Should be capped at maxPolicies
	tc.mu.RLock()
	count := len(tc.PoliciesApplied)
	tc.mu.RUnlock()

	if count > maxPolicies {
		t.Errorf("Policy count should be capped at %d, got %d", maxPolicies, count)
	}
}

func TestTransparencyContextConcurrentDataSourceAdd(t *testing.T) {
	tc := NewTransparencyContext()
	const numGoroutines = 100
	const numSourcesEach = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < numSourcesEach; j++ {
				tc.AddDataSource(fmt.Sprintf("source-%d-%d", goroutineID, j))
			}
		}(i)
	}

	wg.Wait()

	// Should be capped at maxDataSources
	tc.mu.RLock()
	count := len(tc.DataSources)
	tc.mu.RUnlock()

	if count > maxDataSources {
		t.Errorf("Data source count should be capped at %d, got %d", maxDataSources, count)
	}
}

func TestTransparencyContextConcurrentMixedOperations(t *testing.T) {
	tc := NewTransparencyContext()
	const numGoroutines = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 5)

	// Concurrent AddPolicy
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tc.AddPolicy(fmt.Sprintf("policy-%d", id))
		}(i)
	}

	// Concurrent AddDataSource
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tc.AddDataSource(fmt.Sprintf("source-%d", id))
		}(i)
	}

	// Concurrent state changes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			if id%3 == 0 {
				tc.MarkBlocked("reason")
			} else if id%3 == 1 {
				tc.MarkFiltered()
			} else {
				tc.RequireHumanOversight()
			}
		}(i)
	}

	// Concurrent SetProcessingDuration
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			tc.SetProcessingDuration(time.Duration(id) * time.Millisecond)
		}(i)
	}

	// Concurrent ComputeAuditHash
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			tc.ComputeAuditHash()
		}()
	}

	wg.Wait()

	// If we get here without a race detector panic, the test passes
}

func TestTransparencyContextConcurrentSetHeaders(t *testing.T) {
	tc := NewTransparencyContext()
	tc.AddPolicy("policy-1")
	tc.AddDataSource("source-1")

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			tc.SetHeaders(w)
		}()
	}

	wg.Wait()
	// If we get here without a race condition, the test passes
}

func TestTransparencyResponseWriterConcurrentWrite(t *testing.T) {
	// Test that multiple TransparencyResponseWriters sharing the same
	// TransparencyContext can set headers concurrently without race conditions
	tc := NewTransparencyContext()
	tc.RequestID = "concurrent-write-test"

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Track how many times headers were set successfully
	var successCount int32
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			// Each goroutine gets its own ResponseWriter (realistic usage)
			w := httptest.NewRecorder()
			trw := NewTransparencyResponseWriter(w, tc)

			if id%2 == 0 {
				trw.WriteHeader(http.StatusOK)
			} else {
				_, _ = trw.Write([]byte(fmt.Sprintf("content-%d", id)))
			}

			// Verify headers were set
			if w.Header().Get(HeaderAIRequestID) == "concurrent-write-test" {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// All goroutines should have successfully set headers
	if int(successCount) != numGoroutines {
		t.Errorf("Expected %d successful header sets, got %d", numGoroutines, successCount)
	}
}

func TestTransparencyResponseWriterSingleWriterConcurrentHeaders(t *testing.T) {
	// Test that a single TransparencyResponseWriter can handle concurrent
	// calls to WriteHeader/Write without corrupting internal state.
	// The key invariant is that headers are set exactly once, even with
	// concurrent WriteHeader/Write calls.
	tc := NewTransparencyContext()
	tc.RequestID = "single-writer-test"

	// Use a thread-safe mock writer that counts SetHeader calls
	mockW := &mockResponseWriter{header: make(http.Header)}
	trw := NewTransparencyResponseWriter(mockW, tc)

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				trw.WriteHeader(http.StatusOK)
			} else {
				_, _ = trw.Write([]byte("test"))
			}
		}(i)
	}

	wg.Wait()

	// Check that headers were actually set (the transparency headers)
	mockW.mu.Lock()
	requestIDValue := mockW.header.Get(HeaderAIRequestID)
	mockW.mu.Unlock()

	if requestIDValue != "single-writer-test" {
		t.Errorf("Expected request ID header to be set, got %q", requestIDValue)
	}

	// The key test: headersWritten flag should have prevented multiple SetHeaders calls.
	// We can't directly test SetHeaders call count, but we can verify the response
	// writer's internal state through its behavior.
	if !trw.headersWritten {
		t.Error("headersWritten should be true after concurrent access")
	}
}

// mockResponseWriter is a thread-safe mock for testing concurrent access
type mockResponseWriter struct {
	mu     sync.Mutex
	header http.Header
}

func (m *mockResponseWriter) Header() http.Header {
	// Note: returning the same header map is intentional to match real behavior
	// Real ResponseWriter.Header() returns the same map that can be modified
	return m.header
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(data), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.mu.Lock()
	defer m.mu.Unlock()
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkNewTransparencyContext(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewTransparencyContext()
	}
}

func BenchmarkTransparencyContextAddPolicy(b *testing.B) {
	tc := NewTransparencyContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc.AddPolicy(fmt.Sprintf("policy-%d", i%100))
	}
}

func BenchmarkTransparencyContextSetHeaders(b *testing.B) {
	tc := NewTransparencyContext()
	tc.AddPolicy("policy-1")
	tc.AddPolicy("policy-2")
	tc.AddDataSource("postgres")
	tc.SetModel("openai", "gpt-4")
	tc.ComputeAuditHash()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		tc.SetHeaders(w)
	}
}

func BenchmarkComputeAuditHash(b *testing.B) {
	tc := NewTransparencyContext()
	tc.SetTenantContext("org", "tenant", "client", "user")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc.ComputeAuditHash()
	}
}

func BenchmarkSanitizeHeaderValue(b *testing.B) {
	input := "some-value-with\r\ninjection-attempt"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeHeaderValue(input)
	}
}
