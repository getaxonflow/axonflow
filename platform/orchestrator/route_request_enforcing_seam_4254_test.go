// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: /api/v1/process and /api/v1/plan/execute decide on the anchored engine
// under the workflow control plane's scope, present their query, and cannot
// hold: a challenge refuses the request as approval_required and nothing is
// queued.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/anchoredenforcer"
)

// recordingRouteFacts is a route fact source that records every request the
// facts were produced for: the request the plane decided.
type recordingRouteFacts struct {
	captured []OrchestratorRequest
	routes   routeEffects
	err      error
}

func (r *recordingRouteFacts) Produce(_ context.Context, req OrchestratorRequest) (contract.AttributeSet, routeEffects, error) {
	r.captured = append(r.captured, req)
	return contract.AttributeSet{}, r.routes, r.err
}

func resetRouteRequestFacts() {
	routeRequestFactsOnce = sync.Once{}
	routeRequestFacts, routeRequestFactsErr = nil, nil
}

// withRouteRequestEngine installs the enforcer double and a recording route fact
// source for the test's lifetime.
func withRouteRequestEngine(t *testing.T, verdict anchoredenforcer.Verdict) (*stepGateEnforcerDouble, *recordingRouteFacts) {
	t.Helper()
	d := &stepGateEnforcerDouble{verdict: verdict}
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: d})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })

	src := &recordingRouteFacts{}
	previousFactory := newRouteRequestFactProducer
	newRouteRequestFactProducer = func() (routeFactSource, error) { return src, nil }
	resetRouteRequestFacts()
	t.Cleanup(func() {
		newRouteRequestFactProducer = previousFactory
		resetRouteRequestFacts()
	})
	return d, src
}

// withRecordingRouteFacts is withRouteRequestEngine for a test that reads only
// the request the plane decided.
func withRecordingRouteFacts(t *testing.T, verdict anchoredenforcer.Verdict) *recordingRouteFacts {
	t.Helper()
	_, src := withRouteRequestEngine(t, verdict)
	return src
}

// routeDenyReason is the reason routeDenyVerdict denies with.
var routeDenyReason = string(contract.ReasonExplicitConstraint)

// routeDenyVerdict is an explicit-constraint deny naming ids.
func routeDenyVerdict(ids ...string) anchoredenforcer.Verdict {
	return stepGateVerdict(contract.StateDeny, contract.ReasonExplicitConstraint, contract.Determining{MatchedConstraints: ids})
}

// withRecordingHITL installs an HITL workflow engine whose approvals are
// recorded, so a test can read back that nothing was queued.
func withRecordingHITL(t *testing.T) *recordingApprovalService {
	t.Helper()
	previousEnabled, previousEngine := hitlEnabled, hitlWorkflowEngine
	approval := &recordingApprovalService{}
	hitlEnabled = true
	hitlWorkflowEngine = NewHITLWorkflowEngine(NewWorkflowEngine(), &MAPHITLPolicyChecker{}, approval)
	t.Cleanup(func() { hitlEnabled, hitlWorkflowEngine = previousEnabled, previousEngine })
	return approval
}

// A challenge on /api/v1/process refuses the request by the contract's reason,
// with the engine envelope, and queues nothing: the route cannot hold.
func TestAProcessChallengeIsRefusedApprovalRequiredAndQueuesNothing(t *testing.T) {
	previousAudit := auditLogger
	auditLogger = NewAuditLogger("")
	t.Cleanup(func() { auditLogger = previousAudit })
	_, src := withRouteRequestEngine(t, heldStepVerdict())
	approval := withRecordingHITL(t)

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	rr := gs3066Post(t, handler, "/api/v1/process",
		map[string]string{"X-Org-ID": gs3066AttackerOrg, "X-Tenant-ID": gs3066AttackerTenat},
		map[string]any{"query": "move the funds", "request_type": "llm"})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(src.captured) != 1 {
		t.Fatalf("PREMISE: the plane decided %d request(s), want 1", len(src.captured))
	}
	var resp OrchestratorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if resp.Error != "Request blocked by policy" {
		t.Errorf("error = %q, want the engine-neutral refusal", resp.Error)
	}
	if resp.PolicyInfo == nil || resp.PolicyInfo.Allowed {
		t.Fatalf("policy_info = %+v, want a withheld result", resp.PolicyInfo)
	}
	if want := []string{"blocked: " + anchoredenforcer.ApprovalRequiredReason(wcpSeamScope)}; !reflect.DeepEqual(resp.PolicyInfo.RequiredActions, want) {
		t.Errorf("required_actions = %v, want %v: the refusal names the contract's reason, then the plane (PRD v11 §1 item 13)", resp.PolicyInfo.RequiredActions, want)
	}
	if got := resp.PolicyInfo.RequiredActions; len(got) != 1 || !strings.HasPrefix(got[0], "blocked: approval_required:") || !strings.Contains(got[0], "the wcp plane") {
		t.Errorf("required_actions = %v, want the reason code first and the wcp plane named", got)
	}
	if want := []string{"wsp-approval-policy"}; !reflect.DeepEqual(resp.PolicyInfo.AppliedPolicies, want) {
		t.Errorf("applied_policies = %v, want the policy that required approval %v", resp.PolicyInfo.AppliedPolicies, want)
	}
	if resp.Engine != anchoredenforcer.EngineAnchored || resp.Verdict != routeRequestVerdictBlocked {
		t.Errorf("envelope engine=%q verdict=%q, want %q and %q", resp.Engine, resp.Verdict, anchoredenforcer.EngineAnchored, routeRequestVerdictBlocked)
	}
	if approval.calls != 0 {
		t.Errorf("approvals created = %d, want none: /api/v1/process cannot hold", approval.calls)
	}
}

// A challenge on plan execute refuses the plan by the contract's reason, keeps
// the route's refusal text, and queues nothing.
func TestAPlanExecuteChallengeIsRefusedApprovalRequiredAndQueuesNothing(t *testing.T) {
	previousPlans, previousWorkflow, previousAudit := planService, workflowEngine, auditLogger
	t.Cleanup(func() { planService, workflowEngine, auditLogger = previousPlans, previousWorkflow, previousAudit })
	repo := planning.NewMockRepository()
	if err := repo.SavePlan(context.Background(), &planning.Plan{
		TenantID:           "tenant_1",
		PlanID:             "plan_challenge_4254",
		Status:             planning.PlanStatusPending,
		StepCount:          1,
		Query:              "transfer the funds",
		Domain:             "generic",
		OrgID:              "org_1",
		WorkflowDefinition: json.RawMessage(`{"metadata":{"name":"test"},"spec":{"steps":[]}}`),
		ExpiresAt:          time.Now().Add(time.Hour),
		CreatedAt:          time.Now(),
	}); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	planService = planning.NewService(repo)
	workflowEngine = NewWorkflowEngine()
	auditLogger = NewAuditLogger("")
	_, src := withRouteRequestEngine(t, heldStepVerdict())
	approval := withRecordingHITL(t)

	body, _ := json.Marshal(PlanRequest{
		Query:   "run it",
		User:    UserContext{ID: 1, Email: "user@example.com"},
		Context: map[string]interface{}{"plan_id": "plan_challenge_4254"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plan/execute", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	w := httptest.NewRecorder()
	executePlanHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", w.Code, w.Body.String())
	}
	if len(src.captured) != 1 || src.captured[0].Query != "transfer the funds" {
		t.Fatalf("PREMISE: the plane decided %+v, want one request carrying the plan's query", src.captured)
	}
	var resp PlanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Error != "Policy blocked MAP execution" {
		t.Errorf("error = %q, want the route's unchanged refusal text", resp.Error)
	}
	if want := []string{"blocked: " + anchoredenforcer.ApprovalRequiredReason(wcpSeamScope)}; resp.PolicyInfo == nil || !reflect.DeepEqual(resp.PolicyInfo.RequiredActions, want) {
		t.Errorf("policy_info = %+v, want required_actions %v: the reason code, then the plane (PRD v11 §1 item 13)", resp.PolicyInfo, want)
	}
	if approval.calls != 0 {
		t.Errorf("approvals created = %d, want none: plan execute cannot hold", approval.calls)
	}
}

// The routes present their query, their action and the client credential the
// agent authenticated, under the workflow control plane's scope.
func TestTheRoutesPresentTheirQueryTheirActionAndTheCredentialSubject(t *testing.T) {
	for _, action := range []string{processRouteAction, planExecuteRouteAction} {
		t.Run(action, func(t *testing.T) {
			d, src := withRouteRequestEngine(t, allowedStepVerdict())
			h := http.Header{}
			h.Set("X-Org-ID", "org-route")
			h.Set("X-Client-ID", "client-route")
			req := OrchestratorRequest{RequestID: "req-1", Query: "the caller's query", Client: ClientContext{OrgID: "org-route"}}

			decision := decideRouteRequest(context.Background(), h, req, action)

			if !decision.result.Allowed {
				t.Fatalf("an allowed verdict withheld the request: %+v", decision.result)
			}
			call := d.lastCall(t)
			if call.Scope != wcpSeamScope || call.Action != action || call.OrgID != "org-route" {
				t.Errorf("call scope=%v action=%q org=%q, want %v %q org-route", call.Scope, call.Action, call.OrgID, wcpSeamScope, action)
			}
			if call.Query != "the caller's query" || call.EmptyContent {
				t.Errorf("query=%q empty content=%v, want the request's query presented", call.Query, call.EmptyContent)
			}
			if call.Subject == nil {
				t.Error("no credential subject was presented")
			}
			if len(src.captured) != 1 || src.captured[0].RequestID != "req-1" {
				t.Errorf("facts were produced for %+v, want the decided request", src.captured)
			}
		})
	}
}

// An admitted request carries the routing hints of the rows that apply; a
// withheld one carries none.
func TestAnAllowedRouteRequestCarriesTheRoutingHints(t *testing.T) {
	hints := routeEffects{PreferredProvider: "bedrock", RoutingReason: "eu residency", AllowedProviders: []string{"bedrock"}}

	_, src := withRouteRequestEngine(t, allowedStepVerdict())
	src.routes = hints
	allowed := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction).result
	if !allowed.Allowed || allowed.PreferredProvider != "bedrock" || allowed.RoutingReason != "eu residency" ||
		!reflect.DeepEqual(allowed.AllowedProviders, []string{"bedrock"}) {
		t.Errorf("allowed result = %+v, want the routing hints %+v", allowed, hints)
	}

	_, src = withRouteRequestEngine(t, routeDenyVerdict("pol-a"))
	src.routes = hints
	withheld := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction).result
	if withheld.PreferredProvider != "" || len(withheld.AllowedProviders) != 0 {
		t.Errorf("a withheld request carried routing hints: %+v", withheld)
	}
}

// A deny names its blocking policy and its reason.
func TestARouteDenyNamesItsPolicyAndReason(t *testing.T) {
	withRouteRequestEngine(t, routeDenyVerdict("pol-a"))
	result := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction).result
	if result.Allowed {
		t.Fatal("a deny admitted the request")
	}
	if !reflect.DeepEqual(result.AppliedPolicies, []string{"pol-a"}) {
		t.Errorf("applied_policies = %v, want [pol-a]", result.AppliedPolicies)
	}
	if want := []string{"blocked: " + routeDenyReason}; !reflect.DeepEqual(result.RequiredActions, want) {
		t.Errorf("required_actions = %v, want %v", result.RequiredActions, want)
	}
}

// A route that cannot reach a verdict withholds the request naming the cause.
func TestARouteRequestFailsClosedNamingTheCause(t *testing.T) {
	t.Run("no enforcer", func(t *testing.T) {
		withRouteRequestEngine(t, allowedStepVerdict())
		orchestratorEnforcerInstance.Store(nil)
		result := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{}, processRouteAction).result
		if result.Allowed || !result.EvaluationError ||
			!reflect.DeepEqual(result.AppliedPolicies, []string{"decision_enforcement_unavailable"}) ||
			!reflect.DeepEqual(result.RequiredActions, []string{"blocked: " + anchoredenforcer.CauseNotWired}) {
			t.Errorf("result = %+v, want withheld naming %s", result, anchoredenforcer.CauseNotWired)
		}
	})
	t.Run("segment resolution outage", func(t *testing.T) {
		d, src := withRouteRequestEngine(t, allowedStepVerdict())
		src.err = errDynamicFactsUnavailable
		result := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{}, processRouteAction).result
		if result.Allowed || !reflect.DeepEqual(result.AppliedPolicies, []string{"segment_resolution_failed"}) {
			t.Errorf("result = %+v, want withheld as segment_resolution_failed", result)
		}
		if n := d.callCount(); n != 0 {
			t.Errorf("the enforcer was called %d times although the facts could not be produced", n)
		}
	})
	t.Run("any other fact error", func(t *testing.T) {
		_, src := withRouteRequestEngine(t, allowedStepVerdict())
		src.err = errors.New("boom")
		result := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{}, processRouteAction).result
		if result.Allowed || !reflect.DeepEqual(result.RequiredActions, []string{"blocked: " + anchoredenforcer.CauseEvaluation}) {
			t.Errorf("result = %+v, want withheld naming %s", result, anchoredenforcer.CauseEvaluation)
		}
	})
}

// The routes' production source presents content: every row's content detector
// runs over the query. Every other test here overrides the factory.
func TestTheRouteRequestsProductionSourcePresentsContent(t *testing.T) {
	previous := dynamicPolicyEngine
	dynamicPolicyEngine = &mockPolicyEngineForHITL{}
	t.Cleanup(func() { dynamicPolicyEngine = previous })

	src, err := newRouteRequestFactProducer()
	if err != nil {
		t.Fatalf("newRouteRequestFactProducer: %v", err)
	}
	p, ok := src.(*dynamicFactProducer)
	if !ok {
		t.Fatalf("the production source is %T, want the dynamic fact producer", src)
	}
	if p.presentsNoContent {
		t.Error("the routes' production producer presents no content, so their query would never be scanned")
	}
}

// A route result carries the platform's risk floor on every path, admitted,
// withheld or unavailable: the calculator the legacy engine seeded its
// evaluation with, which policy_info.risk_score and the audit row report.
func TestARouteResultCarriesThePlatformRiskFloor(t *testing.T) {
	req := OrchestratorRequest{RequestID: "req-risk", Query: "select * from orders", Client: ClientContext{OrgID: "o"}}
	want := dbRiskCalculator.CalculateRiskScore(req)
	if want <= 0 {
		t.Fatalf("PREMISE: the calculator scores %q %v; a zero floor would prove nothing", req.Query, want)
	}
	paths := []struct {
		name    string
		install func(t *testing.T)
		allowed bool
	}{
		{"admitted", func(t *testing.T) { withRouteRequestEngine(t, allowedStepVerdict()) }, true},
		{"withheld", func(t *testing.T) { withRouteRequestEngine(t, routeDenyVerdict("pol-a")) }, false},
		{"unavailable", func(t *testing.T) {
			withRouteRequestEngine(t, allowedStepVerdict())
			orchestratorEnforcerInstance.Store(nil)
		}, false},
	}
	for _, p := range paths {
		t.Run(p.name, func(t *testing.T) {
			p.install(t)
			result := decideRouteRequest(context.Background(), http.Header{}, req, processRouteAction).result
			if result.Allowed != p.allowed {
				t.Fatalf("allowed = %v, want %v: the path under test was not taken", result.Allowed, p.allowed)
			}
			if result.RiskScore != want {
				t.Errorf("risk_score = %v, want the platform floor %v", result.RiskScore, want)
			}
		})
	}
}
