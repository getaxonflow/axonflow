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
	"axonflow/platform/decision/contract"
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
	installCircuitBreakerWithConfig(t, circuitbreaker.Config{})
}

// installCircuitBreakerWithConfig is installCircuitBreakerWithMockDB with the
// breaker's configuration given, and returns the breaker it installed.
func installCircuitBreakerWithConfig(t *testing.T, cfg circuitbreaker.Config) *circuitbreaker.CircuitBreaker {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	cb := circuitbreaker.New(circuitbreaker.NewRepository(mockDB), cfg)
	old := circuitBreakerInstance
	circuitBreakerInstance = cb
	t.Cleanup(func() { circuitBreakerInstance = old })
	return cb
}

// installSharedEngineWithPolicyRows installs the shared engine over the shipped
// rows with one execution-class control the decide scope binds matching REVOKE
// statements (executionClassDecideControl): prose a SQL detector false-positives
// on, which capability scoping exists to stop flagging for a document tool. The
// control is the organization template's, so it denies while the organization
// has published nothing, with no override recorded and no environment variable
// setting an action (#3961).
func installSharedEngineWithPolicyRows(t *testing.T) {
	t.Helper()
	enfInstallDetectors(t, map[string]string{executionClassDecideControl(t): `(?i)\bREVOKE\s+`}, nil)
}

// executionClassDecideControl is the census row of the first constraint the
// decide scope's organization template binds on a detector capability scoping
// treats as execution-class (sharedpolicy.IsExecutionScopedPolicy): a control
// that denies what its detector matches, where a requirement would allow.
func executionClassDecideControl(t *testing.T) string {
	t.Helper()
	controls, err := templateControls(decideSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range controls {
		if c.policy.Authority == contract.AuthorityConstraint &&
			sharedpolicy.IsExecutionScopedPolicy(&sharedpolicy.CompiledPolicy{PolicyID: c.row.PolicyID, Category: sharedpolicy.PolicyCategory(c.row.Category)}) {
			return c.row.PolicyID
		}
	}
	t.Fatal("the decide scope's organization template binds no execution-class constraint, so capability scoping has nothing to scope")
	return ""
}

func TestHandleDecide_ToolTargetCapabilityScope(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
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
