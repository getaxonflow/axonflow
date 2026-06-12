// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/orchestrator/cost"
)

// =============================================================================
// #2684 (Gap A): clientRequestHandler agent /api/request canonical audit.
//
// clientRequestHandler is the agent proxy PEP (it calls EvaluateRequest +
// EvaluatePolicy). Every terminal deny — circuit breaker, static/tenant policy,
// HITL gate, budget — previously recorded only the legacy agent_audit_logs plane
// (no portal reader; retire #2674 / ADR-058 Phase 4). It now emits a canonical
// plane=agent audit_logs row via the established decide writer (recordDecideDecision)
// on every deny.
//
// This drives the BUDGET deny deterministically (an injected always-exceeded cost
// service) — the same auditProxyDeny seam every deny branch uses — and pins the
// canonical INSERT. Red-on-revert: drop the auditProxyDeny call from the budget
// branch and the sqlmock expectation goes unmet. The static-policy / HITL block
// branches require a DB-backed live policy cache (per the package convention noted
// in mcp_connector_exec_audit_test.go) and are covered at the live surface by
// runtime-e2e/2684_agent_request_audit.
// =============================================================================

func TestClientRequestHandler_BudgetDeny_WritesCanonicalAgentAudit(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}

	// Deterministic environment: community circuit breaker (allows), NO tenant
	// policy engine (so a benign query is not blocked before the budget check).
	oldCB := circuitBreakerInstance
	circuitBreakerInstance = circuitbreaker.New(circuitbreaker.NewRepository(nil), circuitbreaker.Config{})
	defer func() { circuitBreakerInstance = oldCB }()

	oldTier := tierAwarePolicyEngine
	tierAwarePolicyEngine = nil
	defer func() { tierAwarePolicyEngine = oldTier }()

	// client.OrgID resolves to "budget-test" (the V2 license org) — scope the
	// over-limit org budget to it so CheckBudget fails closed (proven pattern from
	// gateway_handlers_test.go).
	oldCost := costService
	costService = cost.NewService(&mockCostRepository{
		budgets: map[string]*cost.Budget{
			"budget-1": {
				ID:       "budget-1",
				Name:     "Test Budget",
				Scope:    cost.ScopeOrganization,
				ScopeID:  "budget-test",
				LimitUSD: 100.0,
				Period:   cost.PeriodMonthly,
				OnExceed: cost.OnExceedBlock,
				OrgID:    "budget-test",
				TenantID: "budget-test",
				Enabled:  true,
			},
		},
		usageSum: map[string]float64{
			"organization:budget-test": 150.0, // exceeded
		},
	}, nil)
	defer func() { costService = oldCost }()

	mock, restore := setUsageDBMock(t)
	defer restore()

	testLicenseKey := generateTestLicenseKey("budget-test", "Enterprise", "20351231")
	knownClients["test-client-budget"] = &ClientAuth{
		ClientID:   "test-client-budget",
		LicenseKey: testLicenseKey,
		Name:       "Budget Test Client",
		TenantID:   "budget-test",
		Enabled:    true,
	}
	defer delete(knownClients, "test-client-budget")

	userToken := generateTestJWT(1, "budget-test", []string{"query"}, "agent")

	// Expect the canonical plane=agent 'blocked' row (request_type=decision_llm).
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(),    // id
			sqlmock.AnyArg(),    // request_id
			sqlmock.AnyArg(),    // timestamp
			sqlmock.AnyArg(),    // user_id
			sqlmock.AnyArg(),    // user_email
			sqlmock.AnyArg(),    // user_role
			sqlmock.AnyArg(),    // client_id
			sqlmock.AnyArg(),    // tenant_id
			sqlmock.AnyArg(),    // org_id
			"decision_llm",      // request_type
			sqlmock.AnyArg(),    // query
			sqlmock.AnyArg(),    // query_hash
			AuditVerdictBlocked, // policy_decision — canonical 'blocked', stored verbatim on plane=agent
			sqlmock.AnyArg(),    // policy_details
			sqlmock.AnyArg(),    // decision_id
			PlaneAgent,          // plane=agent
			sqlmock.AnyArg(),    // obligations
			sqlmock.AnyArg(),    // correlation_id
			sqlmock.AnyArg(),    // redacted_fields
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	reqBody := ClientRequest{
		ClientID:    "test-client-budget",
		RequestType: "sql",
		Query:       "SELECT id FROM products", // benign — not statically blocked
		UserToken:   userToken,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	setOAuth2BasicAuth(req, reqBody.ClientID, testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 budget block, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("canonical plane=agent audit row not written (revert of the #2684 fix): %v", err)
	}
}
