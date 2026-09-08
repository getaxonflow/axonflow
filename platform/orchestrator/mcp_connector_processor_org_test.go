// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAWorkflowStepsConnectorCallCarriesTheOrganization covers RouteToAgent's
// SECOND caller (#3828).
//
// # WHY A SECOND TEST RATHER THAN TRUSTING THE FIRST
//
// TestRouteToAgentCarriesTheOrganization proves the router SENDS X-Org-ID when
// the request it is handed carries an org on either rung. It cannot prove that
// this caller PUTS one there, and this caller is the one that did not: it built
// its OrchestratorRequest fresh, set the tenancy from the execution's
// authenticated identity, and left both org fields empty. RouteToAgent then
// found nothing on either rung and sent no header - so every connector call
// made from a workflow step reproduced the exact defect #3828 fixes on the
// user-facing path, while the router's own test stayed green.
//
// That is the shape worth pinning: a fix applied to one of two callers, with
// the shared code's test unable to see the difference.
func TestAWorkflowStepsConnectorCallCarriesTheOrganization(t *testing.T) {
	for _, tc := range []struct {
		name string
		user UserContext
		want string
		why  string
	}{
		{
			// These two identifiers DIFFER, and that is the point of the case
			// rather than incidental naming: OrgID and TenantID come from
			// independent sources (the license payload vs the client record),
			// so a bug that sent the tenant in the org header would pass a case
			// where they happened to be equal.
			//
			// An earlier revision had a second case here with byte-identical
			// inputs and a different name - two rows, one test. Dropped rather
			// than left as filler: a suite whose row count overstates its
			// coverage is the thing an assertion floor is supposed to prevent.
			name: "the execution's organization reaches the agent, and it is the ORG not the tenant",
			user: UserContext{TenantID: "customer-tenant", OrgID: "license-org"},
			want: "license-org",
			why: "the workflow step is executed for a real organization and the agent must " +
				"evaluate as that organization; sending the tenant id in the org header is the " +
				"shape the decision shadow refuses by name",
		},
		{
			name: "no organization on the execution - the header is ABSENT, not the tenant id",
			user: UserContext{TenantID: "customer-tenant"},
			want: "",
			why: "executionOrgID does not fall back to the tenant id. An org scope carrying a " +
				"tenant id would convert a refusal that is VISIBLE in the observation window " +
				"into a comparison recorded against the wrong scope",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotOrg string
			var sawHeader bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotOrg = r.Header.Get("X-Org-ID")
				_, sawHeader = r.Header[http.CanonicalHeaderKey("X-Org-ID")]
				var discard map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&discard)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true,"data":{"rows":[]}}`))
			}))
			defer server.Close()

			// The global the processor routes through. Restored so this test
			// cannot leak a test server into another test's run.
			saved := mcpQueryRouter
			mcpQueryRouter = NewMCPQueryRouter(server.URL)
			defer func() { mcpQueryRouter = saved }()

			exec := &WorkflowExecution{
				ID:          "exec-org",
				Status:      "running",
				Input:       map[string]interface{}{},
				Output:      map[string]interface{}{},
				UserContext: tc.user,
			}
			step := WorkflowStep{
				Name: "read", Type: "connector-call",
				Connector: "crm", Operation: "query", Statement: "/",
			}

			processor := NewMCPConnectorProcessor()
			if _, err := processor.routeToAgent(context.Background(), step, map[string]interface{}{}, exec); err != nil {
				t.Fatalf("routeToAgent: %v", err)
			}

			if gotOrg != tc.want {
				t.Errorf("X-Org-ID = %q, want %q. %s.\n\nA workflow step's connector call that "+
					"carries no organization makes the agent's MCP call sites evaluate with an "+
					"empty org: OrgScopePtr(\"\") returns nil, orgScopeOf falls back to the tenant "+
					"id, and the decision shadow refuses the observation. The `mcp` plane's window "+
					"is then empty for every workflow-driven query while reading exactly like a "+
					"clean one (#3828).", gotOrg, tc.want, tc.why)
			}
			// An empty header and an absent one both read as "no organization"
			// at the agent, but only the absent one says so honestly - and
			// asserting the value alone would let a regression that always sets
			// the header pass on the empty case.
			if tc.want == "" && sawHeader {
				t.Errorf("X-Org-ID was SENT as an empty header. %s", tc.why)
			}
		})
	}
}

// TestExecutionOrgIDDoesNotSubstituteTheTenant pins the asymmetry with
// executionTenantID directly, because it is the part a reader is most likely to
// "make consistent" (#3828).
//
// executionTenantID DOES fall back to OrgID: a missing tenant would miss the
// tenant's own connector, which is a lockout. The reverse is not the mirror
// image of that, and the two helpers sitting next to each other invites making
// them symmetrical.
func TestExecutionOrgIDDoesNotSubstituteTheTenant(t *testing.T) {
	both := &WorkflowExecution{UserContext: UserContext{TenantID: "customer-tenant", OrgID: "license-org"}}
	if got := executionOrgID(both); got != "license-org" {
		t.Errorf("executionOrgID = %q, want license-org", got)
	}

	tenantOnly := &WorkflowExecution{UserContext: UserContext{TenantID: "customer-tenant"}}
	if got := executionOrgID(tenantOnly); got != "" {
		t.Errorf("executionOrgID = %q for an execution with no org; it must NOT fall back to the "+
			"tenant id (%q). `orgScopeOf` already substitutes the tenant when no org is present, "+
			"and that substituted value is exactly what Observe refuses as \"an org scope but no "+
			"org id\". Supplying one here does not fix the refusal - it hides it, recording a "+
			"comparison against a scope that is not an organization (#3828).",
			got, "customer-tenant")
	}

	// The forgeable-input rule the tenancy already follows: the value comes
	// from the authenticated UserContext, never from the request body.
	forged := &WorkflowExecution{
		Input:       map[string]interface{}{"org_id": "org-victim"},
		UserContext: UserContext{TenantID: "customer-tenant", OrgID: "org-attacker"},
	}
	if got := executionOrgID(forged); got != "org-attacker" {
		t.Errorf("executionOrgID = %q; the organization must come from the authenticated "+
			"UserContext and never from execution.Input, which is the client-supplied body", got)
	}

	if got := executionOrgID(nil); got != "" {
		t.Errorf("executionOrgID(nil) = %q, want empty", got)
	}
}
