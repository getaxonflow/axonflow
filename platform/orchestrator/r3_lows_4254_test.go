// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/execution"
)

// THE R3 LOWS (#4254): one label for a refused subject, a challenge with no
// terms, a fact under action.*, step mode's first step, and resume's tracker.

// subjectRefusals is the decision counter for a refused subject under one
// verdict label.
func subjectRefusals(scope legacycompile.EnforcementScope, verdict string) float64 {
	return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(scope.String(), anchoredenforcer.EngineAnchored, verdict, anchoredenforcer.CauseSubjectUnverifiable))
}

// B-L1: a step refused for having no subject is counted as the enforcer counts
// that cause, "unavailable", on both planes, and never as a deny.
func TestAStepWithNoSubjectIsCountedUnavailableOnBothPlanes(t *testing.T) {
	cases := []struct {
		name  string
		scope legacycompile.EnforcementScope
		run   func(t *testing.T)
	}{
		{"map", mapSeamScope, func(t *testing.T) {
			withMAPEngine(t, allowedStepVerdict())
			if _, err := (&MAPHITLPolicyChecker{}).CheckPolicy(context.Background(), WorkflowStep{Name: "s", Type: "llm-call"}, mapExecution()); err != nil {
				t.Fatalf("CheckPolicy returned an error: %v", err)
			}
		}},
		{"wcp", wcpSeamScope, func(t *testing.T) {
			withStepGateEngine(t, allowedStepVerdict())
			NewWCPPolicyAdapter().EvaluateStepGate(context.Background(), seamStepContext())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unavailable, deny := subjectRefusals(tc.scope, "unavailable"), subjectRefusals(tc.scope, "deny")
			tc.run(t)
			if got := subjectRefusals(tc.scope, "unavailable") - unavailable; got != 1 {
				t.Errorf("the unavailable series moved by %v for a refused subject, want 1", got)
			}
			if got := subjectRefusals(tc.scope, "deny") - deny; got != 0 {
				t.Errorf("the deny series moved by %v for a refused subject, want 0", got)
			}
		})
	}
}

// challengeWithoutTerms is heldStepVerdict's challenge with its approval
// requirement removed.
func challengeWithoutTerms() anchoredenforcer.Verdict {
	v := heldStepVerdict()
	v.Decision.Approval = nil
	return v
}

// B-L2: a challenge with no approval requirement is withheld as an evaluation
// failure on every plane that reads a challenge, rather than held with no terms.
func TestAChallengeWithNoApprovalRequirementIsWithheldOnEveryPlane(t *testing.T) {
	const unavailable = "decision_enforcement_unavailable"
	cause := "(" + anchoredenforcer.CauseEvaluation + ")"

	t.Run("wcp", func(t *testing.T) {
		// PREMISE: the same challenge WITH its requirement holds the step, so the
		// refusal below is the missing requirement's.
		withStepGateEngine(t, heldStepVerdict())
		if ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext()); ev.Decision != workflow_control.GateDecisionRequireApproval {
			t.Fatalf("PREMISE: a challenge with its requirement answered %q, want require_approval", ev.Decision)
		}
		withStepGateEngine(t, challengeWithoutTerms())
		ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())
		if ev.Decision != workflow_control.GateDecisionBlock || !reflect.DeepEqual(ev.PolicyIDs, []string{unavailable}) || !strings.HasSuffix(ev.Reason, cause) {
			t.Fatalf("decision %q ids %v reason %q; want a block naming %s and %s", ev.Decision, ev.PolicyIDs, ev.Reason, unavailable, cause)
		}
	})
	t.Run("map", func(t *testing.T) {
		withMAPEngine(t, challengeWithoutTerms())
		result, err := (&MAPHITLPolicyChecker{}).CheckPolicy(mapSubjectContext(), WorkflowStep{Name: "s", Type: "llm-call"}, mapExecution())
		if err != nil {
			t.Fatalf("CheckPolicy returned an error: %v", err)
		}
		if result == nil || result.Action != "block" || result.PolicyID != unavailable || !strings.HasSuffix(result.Reason, cause) {
			t.Fatalf("result = %+v; want a block naming %s and %s", result, unavailable, cause)
		}
	})
	t.Run("route", func(t *testing.T) {
		withRouteRequestEngine(t, challengeWithoutTerms())
		r := decideRouteRequest(context.Background(), http.Header{}, OrchestratorRequest{Client: ClientContext{OrgID: "o"}}, processRouteAction).result
		if r.Allowed || !r.EvaluationError || !reflect.DeepEqual(r.AppliedPolicies, []string{unavailable}) ||
			!reflect.DeepEqual(r.RequiredActions, []string{"blocked: " + anchoredenforcer.CauseEvaluation}) {
			t.Fatalf("result = %+v; want withheld naming %s as an evaluation failure", r, unavailable)
		}
	})
}

// A-LOW: a seam's fact under action.* is refused by the real enforcer, so the
// request is unbuildable and nothing is decided.
func TestAFactUnderTheActionNamespaceMakesTheRequestUnbuildable(t *testing.T) {
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	enforcer := stepDecisionEnforcer(t)
	evaluate := func(facts contract.AttributeSet) anchoredenforcer.Verdict {
		return enforcer.Evaluate(context.Background(), anchoredenforcer.Call{
			Scope:     wcpSeamScope,
			OrgID:     "org-a",
			RequestID: "wf_1_step_1",
			Action:    authoringcatalog.ActionToolCall,
			Subject:   headerCredentialSubject(h),
			Query:     "summarise the quarter",
			Facts:     facts,
		})
	}
	if v := evaluate(nil); v.Unavailable != "" || v.Decision == nil {
		t.Fatalf("PREMISE: the same call with no facts reached no decision (unavailable %q)", v.Unavailable)
	}
	v := evaluate(contract.AttributeSet{"action.seam_stated": contract.Known("high", contract.ProvPlatform, 1, time.Now())})
	if v.Unavailable != anchoredenforcer.CauseRequest || v.Decision != nil {
		t.Fatalf("unavailable %q decision %+v; want %s and no decision", v.Unavailable, v.Decision, anchoredenforcer.CauseRequest)
	}
}

// workflowLister is the listing a mock workflow repository answers.
type workflowLister interface {
	List(ctx context.Context, opts workflow_control.ListWorkflowsOptions) ([]workflow_control.Workflow, int, error)
}

// Step mode runs its first step without a gate, so a first step of a type the
// map does not name stops the plan before it starts, naming the token, and
// leaves no workflow behind. TestExecuteWithConfirmRefusesAStepTypeTheMapDoesNotName
// is confirm mode's twin.
func TestExecuteWithStepRefusesAStepTypeTheMapDoesNotNameAtItsFirstStep(t *testing.T) {
	unmapped := func() (*planning.Plan, *Workflow) {
		return &planning.Plan{OrgID: "org_1", TenantID: "tenant_1", PlanID: "step-unmapped-1", Domain: "test", Query: "a step this plane cannot present"},
			&Workflow{Spec: WorkflowSpec{Steps: []WorkflowStep{{Name: "only-step", Type: "tool-call"}}}}
	}
	workflows := func(t *testing.T, repo workflowLister) int {
		t.Helper()
		_, total, err := repo.List(context.Background(), workflow_control.ListWorkflowsOptions{TenantID: "t1", OrgID: "o1"})
		if err != nil {
			t.Fatalf("listing workflows: %v", err)
		}
		return total
	}

	// PREMISE: confirm mode refuses the same plan after creating its workflow, so
	// the listing does see a workflow a refusal leaves behind.
	confirmRepo := workflow_control.NewMockRepository()
	plan, wf := unmapped()
	if _, err := NewMAPWCPExecutor(workflow_control.NewService(confirmRepo, nil, nil), nil).ExecuteWithConfirm(context.Background(), plan, wf, "t1", "o1", "u1", "c1"); err == nil {
		t.Fatal("PREMISE: confirm mode admitted a step of an unmapped type")
	}
	if n := workflows(t, confirmRepo); n != 1 {
		t.Fatalf("PREMISE: the listing saw %d workflows after confirm mode's refusal, want 1", n)
	}

	repo := workflow_control.NewMockRepository()
	plan, wf = unmapped()
	result, err := NewMAPWCPExecutor(workflow_control.NewService(repo, nil, nil), nil).ExecuteWithStep(context.Background(), plan, wf, "t1", "o1", "u1", "c1")
	if err == nil {
		t.Fatalf("step mode admitted a first step of an unmapped type: %+v", result)
	}
	if !strings.Contains(err.Error(), strconv.Quote("tool-call")) {
		t.Errorf("the refusal does not name the step type: %v", err)
	}
	if result != nil {
		t.Errorf("a refused plan still returned an execution result: %+v", result)
	}
	if n := workflows(t, repo); n != 0 {
		t.Errorf("step mode's refusal left %d workflows behind, want none", n)
	}
}

// A resume whose step cannot run fails the unified execution too, as every
// sibling refusal does, so the plan's status does not stay running.
func TestAResumeWhoseStepCannotRunFailsTheUnifiedExecution(t *testing.T) {
	const planID = "plan_resume_tracker"
	cleanup := setupResumeTestWCP(t, planID, "confirm")
	defer cleanup()
	previousEngine := workflowEngine
	workflowEngine = nil // ExecuteSingleStep refuses a step with no engine to run it
	t.Cleanup(func() { workflowEngine = previousEngine })

	repo := NewMockMAPRepository()
	previousTracker := mapExecutionTracker
	mapExecutionTracker = NewMAPExecutionTracker(repo, planService)
	t.Cleanup(func() { mapExecutionTracker = previousTracker })
	plan := &planning.Plan{
		OrgID: "org_1", TenantID: "tenant_1", PlanID: planID, Query: "test query", Domain: "generic",
		WorkflowDefinition: json.RawMessage(`{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"test"},"spec":{"steps":[{"name":"step1","type":"llm-call"},{"name":"step2","type":"tool-call"}]}}`),
	}
	if _, err := mapExecutionTracker.StartPlanExecution(context.Background(), plan); err != nil {
		t.Fatalf("starting the unified execution: %v", err)
	}
	if before, err := repo.GetByPlanID(context.Background(), planID); err != nil || before.Status == execution.StatusFailed {
		t.Fatalf("PREMISE: the started execution is (%+v, %v), want one that has not failed", before, err)
	}

	w := resumeThePlan(t, planID)

	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Step execution failed") {
		t.Fatalf("status %d body %s; want 500 naming the step failure", w.Code, w.Body.String())
	}
	after, err := repo.GetByPlanID(context.Background(), planID)
	if err != nil {
		t.Fatalf("reading the unified execution: %v", err)
	}
	if after.Status != execution.StatusFailed {
		t.Errorf("the unified execution is %q after the resume's step failed, want %q", after.Status, execution.StatusFailed)
	}
}
