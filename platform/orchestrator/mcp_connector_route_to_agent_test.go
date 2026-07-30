// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3067 R3 BLOCKER — the agent-routing fallback must not take its tenancy
// from the request body.
//
// The tenant-scoped local registry lookup (mcp_connector_processor.go) denies
// a caller who names another tenant's connector. But a MISS is exactly what
// that denial produces, and a miss falls through to routeToAgent — which used
// to let `execution.Input["tenant_id"]` pick the tenancy of the outbound call.
// The agent's internal-service auth path adopts that value verbatim
// (authenticator.go: `tenantID := hints.TenantID`), so the victim's connector
// was re-acquired on the agent side with the victim's decrypted credentials:
// the local fix was bypassable through its own fallback.
//
// This drives a REAL MCPQueryRouter at an httptest stand-in agent and asserts
// the `tenant_id` that actually goes on the wire.

package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// standInAgent captures the body the orchestrator POSTs to /mcp/resources/query.
func standInAgent(t *testing.T, captured *map[string]interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got map[string]interface{}
		_ = json.Unmarshal(body, &got)
		*captured = got
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"rows":[]}}`))
	}))
}

func TestRouteToAgent_TenancyIsNotTakenFromTheRequestBody(t *testing.T) {
	origRegistry := connectorRegistry
	origRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = origRegistry
		mcpQueryRouter = origRouter
	}()

	var captured map[string]interface{}
	srv := standInAgent(t, &captured)
	defer srv.Close()

	// Empty local registry: every lookup misses, which is exactly the shape a
	// cross-tenant connector name produces and the ONLY way into routeToAgent.
	connectorRegistry = nil
	mcpQueryRouter = NewMCPQueryRouter(srv.URL)

	exec := &WorkflowExecution{
		ID:     "exec-forgery",
		Status: "running",
		// The forged claim: the request body says the step belongs to the victim.
		Input: map[string]interface{}{
			"tenant_id": "org-victim",
			"client_id": "org-victim",
		},
		// The authenticated identity, overlaid by the handler from the agent's
		// auth chain, says otherwise.
		UserContext: UserContext{TenantID: "org-attacker", OrgID: "org-attacker"},
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{
		Name:      "exfiltrate",
		Type:      "connector-call",
		Connector: "customer-db",
		Operation: "query",
		Statement: "SELECT * FROM customers",
	}

	if _, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, exec); err != nil {
		t.Fatalf("routed step returned an unexpected error: %v", err)
	}
	if captured == nil {
		t.Fatal("the step was not routed to the agent — this test proves nothing unless the fallback ran")
	}

	got, _ := captured["tenant_id"].(string)
	if got == "org-victim" {
		t.Fatal("SECURITY: the forged body tenant_id reached the agent — the tenant-keyed local lookup is bypassable via routeToAgent")
	}
	if got != "org-attacker" {
		t.Errorf("routed tenant_id = %q, want org-attacker (the authenticated identity)", got)
	}
}

// TestRouteToAgent_CarriesTheAuthenticatedTenancy is the positive control: a
// legitimate routed call must still carry its own tenancy, otherwise the
// assertion above would be satisfied by simply dropping the field.
func TestRouteToAgent_CarriesTheAuthenticatedTenancy(t *testing.T) {
	origRegistry := connectorRegistry
	origRouter := mcpQueryRouter
	defer func() {
		connectorRegistry = origRegistry
		mcpQueryRouter = origRouter
	}()

	var captured map[string]interface{}
	srv := standInAgent(t, &captured)
	defer srv.Close()

	connectorRegistry = nil
	mcpQueryRouter = NewMCPQueryRouter(srv.URL)

	exec := &WorkflowExecution{
		ID:          "exec-legit",
		Status:      "running",
		Input:       map[string]interface{}{},
		UserContext: UserContext{TenantID: "org-owner", OrgID: "org-owner"},
	}

	processor := NewMCPConnectorProcessor()
	step := WorkflowStep{Name: "read", Type: "connector-call", Connector: "own-db", Operation: "query", Statement: "SELECT 1"}

	if _, err := processor.ExecuteStep(context.Background(), step, map[string]interface{}{}, exec); err != nil {
		t.Fatalf("routed step failed: %v", err)
	}
	if got, _ := captured["tenant_id"].(string); got != "org-owner" {
		t.Fatalf("positive control: routed call lost its tenancy (tenant_id=%q)", got)
	}
}
