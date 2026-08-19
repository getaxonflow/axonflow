//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package fincrime

import (
	"context"
	"testing"
)

// The community stub must be inert even when a deployment sets the scorer env
// and a caller sends a full fincrime context: the add-on does not exist on
// community builds, and the request proceeds bit-identically.
func TestCommunityStubIsInert(t *testing.T) {
	t.Setenv(EnvScorerURL, "http://risk-scorer:9333")
	e := NewEngineFromEnv()
	if e != nil {
		t.Fatal("community NewEngineFromEnv must return nil")
	}
	if e.ScorerConfigured() {
		t.Fatal("community ScorerConfigured must be false")
	}
	ctx := WithDecisionMeta(context.Background(), "decide", "d1")
	got := e.Evaluate(ctx, Input{Parameters: map[string]interface{}{
		TransactionContextKey: map[string]interface{}{"amount": "malformed-on-purpose"},
	}})
	if got != nil {
		t.Fatalf("community Evaluate must return nil, got %+v", got)
	}
	// And the audit merge stays a no-op.
	details := MergeAuditDetails(ctx, map[string]interface{}{"policy_ids": []string{"x"}})
	if _, present := details["ml_inference_layer_status"]; present {
		t.Fatal("community build must never stamp fincrime audit fields")
	}
}
