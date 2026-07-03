// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Decision-plane capability scoping (#2801): /decide forwards target.tool
// (previously accepted-but-unused) into EvalOptions.ToolIdentity, so a PEP
// declaring a text-document tool target skips execution-class detectors while
// an unknown/absent target keeps full evaluation.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/circuitbreaker"
	sharedpolicy "axonflow/platform/shared/policy"
)

// installCircuitBreakerWithMockDB swaps the breaker for one whose repository
// is backed by sqlmock. Needed because this test drives a real DENY verdict
// through handleDecide: the ENTERPRISE breaker records the policy violation
// via its repository, and a nil *sql.DB there segfaults (the community stub
// never touches the DB). Unexpected sqlmock calls return errors, which the
// repository degrades on gracefully.
func installCircuitBreakerWithMockDB(t *testing.T) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	old := circuitBreakerInstance
	circuitBreakerInstance = circuitbreaker.New(circuitbreaker.NewRepository(mockDB), circuitbreaker.Config{})
	t.Cleanup(func() { circuitBreakerInstance = old })
}

// installSharedEngineWithPolicyRows swaps the global engine for one whose
// sqlmock DB serves the given static_policies rows (loader column order per
// loadFromDatabase) on every load.
func installSharedEngineWithPolicyRows(t *testing.T) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	cols := []string{"id", "policy_id", "name", "category", "tier", "pattern", "severity",
		"description", "phase", "action_request", "action_response",
		"enabled", "priority", "tenant_id", "organization_id", "metadata"}
	for i := 0; i < 8; i++ {
		rows := sqlmock.NewRows(cols).AddRow(
			"11111111-1111-1111-1111-111111111111", "sys_sqli_revoke", "REVOKE Privileges Statement",
			"security-sqli", "system", `(?i)\bREVOKE\s+`, "critical",
			"Detects REVOKE privilege statement", "request", "block", nil,
			true, 100, "global", nil, []byte(`{}`),
		)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

func TestHandleDecide_ToolTargetCapabilityScope(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("SQLI_ACTION", "block")
	installSharedEngineWithPolicyRows(t)
	installCircuitBreakerWithMockDB(t)

	const docProse = "We will revoke the temporary access immediately after the single edit call."

	decide := func(target DecisionTarget) map[string]interface{} {
		t.Helper()
		body, _ := json.Marshal(DecideRequest{
			Stage:          DecisionStageTool,
			CallerIdentity: DecisionCallerIdentity{GatewayID: "test-gw", TenantID: "test-tenant"},
			Target:         target,
			Query:          docProse,
		})
		rr := decideForTest(t, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
		}
		var env map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return env
	}

	// Unknown tool target: full evaluation, prose "revoke" denies (pre-#2801
	// behavior preserved, fail-closed).
	env := decide(DecisionTarget{Type: "tool", Tool: "run_sql_query"})
	if env["verdict"] != VerdictDeny {
		t.Errorf("unknown tool: verdict got %v want %q", env["verdict"], VerdictDeny)
	}

	// No target at all: full evaluation.
	env = decide(DecisionTarget{})
	if env["verdict"] != VerdictDeny {
		t.Errorf("no target: verdict got %v want %q", env["verdict"], VerdictDeny)
	}

	// Text-document tool target: execution-class SQLi detector is scoped out.
	env = decide(DecisionTarget{Type: "tool", Tool: "editJiraIssue"})
	if env["verdict"] != VerdictAllow {
		t.Errorf("text-document tool: verdict got %v want %q (body=%v)", env["verdict"], VerdictAllow, env)
	}

	// The tool name only counts for a TOOL target: an llm-target request
	// must not inherit scoping from a stray tool field.
	env = decide(DecisionTarget{Type: "llm", Model: "gpt-4o", Tool: "editJiraIssue"})
	if env["verdict"] != VerdictDeny {
		t.Errorf("llm target with stray tool field: verdict got %v want %q", env["verdict"], VerdictDeny)
	}
}
