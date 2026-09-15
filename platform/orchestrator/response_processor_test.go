// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"testing"
)

// Test IsHealthy
func TestResponseProcessor_IsHealthy(t *testing.T) {
	processor := NewResponseProcessor()

	if !processor.IsHealthy() {
		t.Error("ResponseProcessor should always report healthy")
	}
}

// Helper function to extract string representation from result
func getString(result interface{}) string {
	if m, ok := result.(map[string]interface{}); ok {
		if data, ok := m["data"]; ok {
			return fmt.Sprint(data)
		}
		return fmt.Sprint(m)
	}
	return fmt.Sprint(result)
}

// TestNewResponseEnricher tests enricher initialization
func TestNewResponseEnricher(t *testing.T) {
	enricher := NewResponseEnricher()

	if enricher == nil {
		t.Fatal("NewResponseEnricher should not return nil")
	}

	if len(enricher.enrichmentRules) == 0 {
		t.Error("NewResponseEnricher should initialize with enrichment rules")
	}

	// Verify required enrichment rules exist
	foundTimestamp := false
	foundRequestContext := false

	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "timestamp" {
			foundTimestamp = true
		}
		if rule.Name == "request_context" {
			foundRequestContext = true
		}
	}

	if !foundTimestamp {
		t.Error("NewResponseEnricher should include 'timestamp' enrichment rule")
	}

	if !foundRequestContext {
		t.Error("NewResponseEnricher should include 'request_context' enrichment rule")
	}
}

// TestResponseEnricher_TimestampEnrichment tests timestamp enrichment
func TestResponseEnricher_TimestampEnrichment(t *testing.T) {
	enricher := NewResponseEnricher()
	ctx := context.Background()
	response := map[string]interface{}{
		"data": "test",
	}

	// Find and test timestamp enricher
	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "timestamp" {
			enrichment := rule.Enricher(ctx, response)

			if _, ok := enrichment["processed_at"]; !ok {
				t.Error("Timestamp enricher should add 'processed_at' field")
			}
		}
	}
}

// TestResponseEnricher_RequestContextEnrichment tests request context enrichment
func TestResponseEnricher_RequestContextEnrichment(t *testing.T) {
	enricher := NewResponseEnricher()

	// Test with request ID in context
	ctx := context.WithValue(context.Background(), "request_id", "test-req-123")
	response := map[string]interface{}{
		"data": "test",
	}

	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "request_context" {
			enrichment := rule.Enricher(ctx, response)

			if enrichment["request_id"] != "test-req-123" {
				t.Errorf("Expected request_id 'test-req-123', got %v", enrichment["request_id"])
			}
		}
	}

	// Test without request ID in context
	ctxEmpty := context.Background()
	for _, rule := range enricher.enrichmentRules {
		if rule.Name == "request_context" {
			enrichment := rule.Enricher(ctxEmpty, response)

			// Should return empty map if no request_id
			if len(enrichment) != 0 {
				t.Error("Request context enricher should return empty map when no request_id in context")
			}
		}
	}
}

// --- #2626: response-plane verdict on RedactionInfo --------------------------
