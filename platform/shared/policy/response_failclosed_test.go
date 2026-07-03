// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"testing"
)

// #2820: the shared engine must let response-plane callers tell "scanned,
// found nothing" apart from "could not scan" (policy-load/degradation error),
// so a redactor can fail CLOSED on the latter instead of forwarding raw PII.
//
// Trigger: an engine with a nil DB and an EMPTY cache — a cache miss falls
// through to loadFromDatabase, which errors on the nil DB. A cache HIT (a
// seeded tenant) is the clean path.

func newLoadErroringEngine() *UnifiedPolicyEngine {
	config := DefaultEngineConfig()
	config.RefreshInterval = 0
	config.EnableMetrics = false
	config.GracefulDegradation = true // the agent's default — the fail-open regime
	cache := NewPolicyCache(config.CacheTTL, config.MaxPatternCache)
	return &UnifiedPolicyEngine{
		config:    config,
		cache:     cache, // empty → every GetPolicies is a cache miss → load error
		loader:    NewPolicyLoader(nil, cache),
		evaluator: NewPatternEvaluator(config.EnableValidators),
		redactor:  NewFieldRedactor(),
		metrics:   NewMetricsCollector(&NoOpAuditQueue{}),
		stopChan:  make(chan struct{}),
	}
}

func TestEvaluateResponse_EvaluationErrorOnLoadFailure(t *testing.T) {
	engine := newLoadErroringEngine()

	// Content that a naive "clean" result would forward verbatim.
	res := engine.EvaluateResponse(context.Background(),
		[]map[string]interface{}{{"note": "contact andi@example.com"}},
		EvalOptions{TenantID: "unseeded-tenant"})

	if !res.EvaluationError {
		t.Fatal("load error must set EvaluationError=true (couldn't-scan), not look like scanned-clean")
	}
	if res.Redacted {
		t.Error("a couldn't-scan result must not claim it redacted anything")
	}
}

func TestEvaluateResponse_CleanScanHasNoEvaluationError(t *testing.T) {
	// Seeded tenant → cache hit → real (empty) policy set → clean scan.
	engine := createTestEngine([]CompiledPolicy{})
	res := engine.EvaluateResponse(context.Background(),
		[]map[string]interface{}{{"note": "nothing sensitive here"}},
		EvalOptions{TenantID: "test-tenant"})

	if res.EvaluationError {
		t.Error("a clean scan must NOT set EvaluationError (would force needless fail-closed)")
	}
	if res.Blocked || res.Redacted {
		t.Error("clean scan should neither block nor redact")
	}
}

func TestPoliciesLoadable(t *testing.T) {
	loadErr := newLoadErroringEngine()
	if err := loadErr.PoliciesLoadable(context.Background(), "unseeded-tenant", nil, PhaseResponse); err == nil {
		t.Error("PoliciesLoadable must return the load error on a cache-miss + nil DB")
	}

	seeded := createTestEngine([]CompiledPolicy{})
	if err := seeded.PoliciesLoadable(context.Background(), "test-tenant", nil, PhaseResponse); err != nil {
		t.Errorf("PoliciesLoadable must succeed on a warm cache: %v", err)
	}
}
