// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// A "DEBUG" QUERY ON /api/v1/process IS DECIDED BY THE DEPLOYMENT ENVIRONMENT
// (#4254, Q4).
//
// The shipped corpus's corpus:dynamic_policies:sys__dyn__debug__restrict blocks
// on the workflow control plane's scope whenever env.environment is not
// development and the debug detector fires. The orchestrator states
// env.environment from its process ENVIRONMENT only, and states nothing when it
// is unset. This pins what the route answers in each state, through the real
// enforcer and the real fact producer over the shipped seed rows.
func TestADebugQueryOnProcessIsDecidedByTheDeploymentEnvironment(t *testing.T) {
	const debug = "corpus:dynamic_policies:sys__dyn__debug__restrict"
	rows := seedDynamicRows(t)

	decide := func(t *testing.T, environment string) *PolicyEvaluationResult {
		t.Helper()
		t.Setenv("DEPLOYMENT_MODE", "enterprise")
		t.Setenv("ENVIRONMENT", environment)
		previous := orchestratorEnforcerInstance.Load()
		orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: stepDecisionEnforcer(t)})
		t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
		previousFactory := newRouteRequestFactProducer
		newRouteRequestFactProducer = func() (routeFactSource, error) { return testFactProducer(t, rows), nil }
		resetRouteRequestFacts()
		t.Cleanup(func() {
			newRouteRequestFactProducer = previousFactory
			resetRouteRequestFacts()
		})

		h := http.Header{}
		h.Set("X-Org-ID", "org-a")
		h.Set("X-Client-ID", "client-a")
		req := OrchestratorRequest{
			RequestID: "req-debug", Query: "please debug the parser", RequestType: "llm_chat",
			User:   UserContext{OrgID: "org-a", TenantID: "t1"},
			Client: ClientContext{ID: "client-a", OrgID: "org-a", TenantID: "t1"},
		}
		return decideRouteRequest(context.Background(), h, req, processRouteAction).result
	}
	names := func(actions []string, reason contract.ReasonCode) bool {
		return slices.ContainsFunc(actions, func(a string) bool { return strings.Contains(a, string(reason)) })
	}

	t.Run("ENVIRONMENT unset withholds it as unknown_constraint", func(t *testing.T) {
		r := decide(t, "")
		if r.Allowed || !names(r.RequiredActions, contract.ReasonUnknownConstraint) {
			t.Fatalf("allowed=%v required_actions=%v applied=%v; want withheld naming %s", r.Allowed, r.RequiredActions, r.AppliedPolicies, contract.ReasonUnknownConstraint)
		}
	})
	t.Run("a production deployment blocks it by the debug constraint", func(t *testing.T) {
		r := decide(t, "production")
		if r.Allowed || !slices.Contains(r.AppliedPolicies, debug) || !names(r.RequiredActions, contract.ReasonExplicitConstraint) {
			t.Fatalf("allowed=%v required_actions=%v applied=%v; want blocked by %s", r.Allowed, r.RequiredActions, r.AppliedPolicies, debug)
		}
	})
	t.Run("a development deployment allows it", func(t *testing.T) {
		r := decide(t, "development")
		if !r.Allowed {
			t.Fatalf("allowed=%v required_actions=%v applied=%v; want allowed", r.Allowed, r.RequiredActions, r.AppliedPolicies)
		}
	})
}
