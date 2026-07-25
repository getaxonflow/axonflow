// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #2820: the orchestrator response plane must fail CLOSED when the shared
// policy engine cannot LOAD policies — otherwise a transient degradation
// forwards the LLM response with PII unredacted. Trigger: a real engine with a
// nil DB + empty cache (every GetPolicies is a cache miss → load error).

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

func TestProcessResponse_FailsClosedOnLoadError(t *testing.T) {
	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	cfg.GracefulDegradation = true
	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)

	processor := NewResponseProcessor()
	processor.SetSharedPolicyEngine(engine)

	user := UserContext{ID: 1, Role: "user", TenantID: "unseeded-tenant"}
	response := &LLMResponse{Content: "User email andi@example.com and SSN 123-45-6789.", Model: "test-model"}

	result, redactionInfo := processor.ProcessResponse(context.Background(), user, response)

	if redactionInfo == nil || redactionInfo.Verdict != responseVerdictBlocked {
		t.Fatalf("load error must fail closed (verdict=blocked); got %+v", redactionInfo)
	}
	// The raw PII must not survive as the forwarded content.
	if strings.Contains(getString(result), "123-45-6789") {
		t.Error("raw SSN must not be forwarded when the scan could not run")
	}
}

func TestProcessResponse_CleanEngineDoesNotFailClosed(t *testing.T) {
	// A DB-backed engine that LOADS successfully (empty policy set) scans clean
	// — the load-error gate must NOT fire, so a normal response is not blocked.
	// sqlmock returns an empty policy result on every load (a genuine, non-error
	// load), unlike the nil-DB engine which errors.
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	// #3048: a load whose result carries ZERO system-tier policies now fails
	// CLOSED — the "loads successfully, scans clean" premise is expressed
	// with a benign never-matching system row instead of an empty set.
	for i := 0; i < 8; i++ {
		mockSQL.ExpectQuery("SELECT").WillReturnRows(
			policytest.SystemPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
				"00000000-0000-0000-0000-00000000f0f0", "sys_test_never_matches",
				"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1),
		)
	}
	policytest.ScopedTxPlumbing(mockSQL, 8)

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)

	processor := NewResponseProcessor()
	processor.SetSharedPolicyEngine(engine)

	user := UserContext{ID: 1, Role: "user", TenantID: "seeded-tenant"}
	response := &LLMResponse{Content: "nothing sensitive here", Model: "test-model"}

	_, redactionInfo := processor.ProcessResponse(context.Background(), user, response)
	if redactionInfo != nil && redactionInfo.Verdict == responseVerdictBlocked {
		t.Error("a clean scan must not fail closed (that would block every response on a healthy empty policy set)")
	}
}
