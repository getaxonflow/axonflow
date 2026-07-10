// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"testing"
)

// #2862: the request plane is the symmetric counterpart of #2820. A request
// gate (decide / mcp check-input / resources.query / tools.execute / gateway /
// openai-compat) that could not load policies has NOT scanned the input for
// SQLi / dangerous-command / PII-block content, so it MUST fail CLOSED — unlike
// the response plane there is no "return unprocessed content" middle ground on
// the request plane: the request either proceeds ungoverned or is blocked.
//
// Trigger: an engine with a nil DB and an EMPTY cache — a cache miss falls
// through to loadFromDatabase, which errors on the nil DB. A cache HIT (a
// seeded tenant) is the clean path. Mirrors newLoadErroringEngine in
// response_failclosed_test.go, but with GracefulDegradation=true to prove the
// fail-closed posture holds under the agent's default fail-open regime.

func TestEvaluateRequest_FailsClosedOnLoadFailure(t *testing.T) {
	engine := newLoadErroringEngine() // GracefulDegradation = true

	// A SQLi payload a naive fail-open result would admit ungoverned.
	res := engine.EvaluateRequest(context.Background(),
		"SELECT * FROM users UNION SELECT * FROM passwords",
		EvalOptions{TenantID: "unseeded-tenant"})

	if !res.Blocked {
		t.Fatal("load error must BLOCK on the request plane (fail-closed), not admit the request")
	}
	if !res.EvaluationError {
		t.Error("a couldn't-scan block must set EvaluationError=true, distinct from a policy verdict")
	}
	if res.BlockedBy != nil {
		t.Error("an availability-failure block has no blocking policy (BlockedBy must be nil)")
	}
}

func TestEvaluateRequest_CleanScanHasNoEvaluationError(t *testing.T) {
	// Seeded tenant → cache hit → real (empty) policy set → clean scan.
	engine := createTestEngine([]CompiledPolicy{})
	res := engine.EvaluateRequest(context.Background(),
		"SELECT id, name FROM users WHERE active = true",
		EvalOptions{TenantID: "test-tenant"})

	if res.EvaluationError {
		t.Error("a clean scan must NOT set EvaluationError (would force needless fail-closed)")
	}
	if res.Blocked {
		t.Error("a clean scan must not block")
	}
}
