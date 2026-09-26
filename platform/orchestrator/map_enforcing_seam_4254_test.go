// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4254: the multi-agent plane decides each step on the anchored engine, holds a
// challenge in memory with the typed approval, and fails closed through the
// checker's result, never through an error.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
)

func resetMAPFacts() {
	mapFactSource.reset()
}

// withMAPEngine installs the enforcer double as the process enforcer, and the
// map plane's step-plane fact producer over rows, for the test's lifetime.
func withMAPEngine(t *testing.T, verdict anchoredenforcer.Verdict, rows ...DynamicPolicy) *stepGateEnforcerDouble {
	t.Helper()
	d := &stepGateEnforcerDouble{verdict: verdict}
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: d})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })

	previousFactory := newMAPFactProducer
	newMAPFactProducer = func() (*dynamicFactProducer, error) {
		p, err := newDynamicFactProducer(fixedFactRows(rows))
		if err != nil {
			return nil, err
		}
		p.segments = func(context.Context, string, string) ([]string, bool) { return nil, true }
		return asStepPlane(p), nil
	}
	resetMAPFacts()
	t.Cleanup(func() {
		newMAPFactProducer = previousFactory
		resetMAPFacts()
	})
	return d
}

// mapSubjectContext is a context carrying the credential subject the execution
// handlers install.
func mapSubjectContext() context.Context {
	h := http.Header{}
	h.Set("X-Org-ID", "org-map")
	h.Set("X-Client-ID", "client-map")
	return withMAPPlaneSubject(context.Background(), headerCredentialSubject(h))
}

func mapExecution() *WorkflowExecution {
	return &WorkflowExecution{ID: "exec-map", UserContext: UserContext{OrgID: "org-map", TenantID: "tenant-map"}}
}

// Each cause the plane cannot decide through withholds the step through the
// checker's result, naming the cause, and never as an error: the engine that
// calls the checker proceeds on an error.
func TestTheMAPCheckerBlocksEveryCauseItCannotDecideThroughAndNeverErrors(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T)
		step    WorkflowStep
		wantID  string
		wantIn  string
	}{
		{
			name: "no enforcer",
			install: func(t *testing.T) {
				withMAPEngine(t, allowedStepVerdict())
				orchestratorEnforcerInstance.Store(nil)
			},
			step:   WorkflowStep{Name: "s", Type: "llm-call"},
			wantID: "decision_enforcement_unavailable",
			wantIn: anchoredenforcer.CauseNotWired,
		},
		{
			name: "an unavailable verdict",
			install: func(t *testing.T) {
				withMAPEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseActivation})
			},
			step:   WorkflowStep{Name: "s", Type: "llm-call"},
			wantID: "decision_enforcement_unavailable",
			wantIn: anchoredenforcer.CauseActivation,
		},
		{
			name: "a refused subject",
			install: func(t *testing.T) {
				withMAPEngine(t, anchoredenforcer.Verdict{Refusal: &sharedidentity.Admission{
					State:  sharedidentity.AdmissionDeny,
					Reason: sharedidentity.ReasonUnknownRealm,
					Detail: "no realm admits this credential",
				}})
			},
			step:   WorkflowStep{Name: "s", Type: "llm-call"},
			wantID: "unknown_realm",
			wantIn: "unknown_realm: no realm admits this credential",
		},
		{
			name: "a step type the map does not name",
			install: func(t *testing.T) {
				withMAPEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseRequest})
			},
			step:   WorkflowStep{Name: "s", Type: "made-up-type"},
			wantID: "decision_enforcement_unavailable",
			wantIn: anchoredenforcer.CauseRequest,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.install(t)
			result, err := (&MAPHITLPolicyChecker{}).CheckPolicy(mapSubjectContext(), c.step, StepContent{}, mapExecution())
			if err != nil {
				t.Fatalf("CheckPolicy returned an error (%v): the engine proceeds on an error, so this must be a block", err)
			}
			if result == nil || result.Action != "block" || result.Allowed {
				t.Fatalf("result = %+v, want a block", result)
			}
			if result.PolicyID != c.wantID {
				t.Errorf("policy id = %q, want %q", result.PolicyID, c.wantID)
			}
			if !strings.Contains(result.Reason, c.wantIn) {
				t.Errorf("reason = %q, want it to name %q", result.Reason, c.wantIn)
			}
		})
	}
}

// An unmapped step type reaches the enforcer as an action error naming the type,
// never as a guessed action.
func TestAnUnmappedMAPStepTypeReachesTheEnforcerAsAnActionError(t *testing.T) {
	d := withMAPEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseRequest})
	_, _ = (&MAPHITLPolicyChecker{}).CheckPolicy(mapSubjectContext(), WorkflowStep{Name: "s", Type: "made-up-type"}, StepContent{}, mapExecution())
	call := d.lastCall(t)
	if call.ActionErr == nil || !strings.Contains(call.ActionErr.Error(), "made-up-type") {
		t.Errorf("action error = %v, want one naming the unmapped type", call.ActionErr)
	}
}

// A step with no subject installed on its context is refused and never decided.
func TestAMAPStepWithNoSubjectIsRefusedAndNeverDecided(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	result, err := (&MAPHITLPolicyChecker{}).CheckPolicy(context.Background(), WorkflowStep{Name: "s", Type: "llm-call"}, StepContent{}, mapExecution())
	if err != nil {
		t.Fatalf("CheckPolicy returned an error: %v", err)
	}
	if result == nil || result.Action != "block" || result.PolicyID != anchoredenforcer.CauseSubjectUnverifiable {
		t.Fatalf("result = %+v, want a block naming %s", result, anchoredenforcer.CauseSubjectUnverifiable)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the enforcer was called %d times for a step with no subject; want never", n)
	}
}

// The plane presents the step's action, and a step with no prompt, statement,
// parameters or input presents EMPTY content: its name, type, provider and
// model are never content (#4249 row 5666236540 made the plane present what a
// step carries; see map_step_content_4249_test.go).
func TestTheMAPCheckerPresentsItsStepsActionAndAnEmptyStepAsEmptyContent(t *testing.T) {
	d := withMAPEngine(t, allowedStepVerdict())
	step := WorkflowStep{Name: "MAP step: summarise", Type: "llm-call", Provider: "openai", Model: "gpt"}
	result, err := (&MAPHITLPolicyChecker{}).CheckPolicy(mapSubjectContext(), step, StepContent{}, mapExecution())
	if err != nil || result == nil || !result.Allowed || result.Action != "allow" {
		t.Fatalf("an allowed step = (%+v, %v), want an allow result, so it runs and its decision is recorded", result, err)
	}
	call := d.lastCall(t)
	if call.Scope != mapSeamScope {
		t.Errorf("scope = %v, want %v", call.Scope, mapSeamScope)
	}
	if call.Action != authoringcatalog.ActionLLMCompletion || call.ActionErr != nil {
		t.Errorf("action = (%q, %v), want %q", call.Action, call.ActionErr, authoringcatalog.ActionLLMCompletion)
	}
	if call.Query != "" || !call.EmptyContent {
		t.Errorf("query = %q, empty content = %v; want an empty step presented as empty content", call.Query, call.EmptyContent)
	}
	if call.OrgID != "org-map" || call.Subject == nil {
		t.Errorf("org = %q, subject installed = %v; want org-map and the credential subject", call.OrgID, call.Subject != nil)
	}
}

// The production factory is where the plane's content contract is set, and
// every other test here overrides it: the map plane presents the step's content
// (#4249 row 5666236540).
func TestTheMAPPlanesProductionProducerPresentsContent(t *testing.T) {
	previous := dynamicPolicyEngine
	dynamicPolicyEngine = &mockPolicyEngineForHITL{}
	t.Cleanup(func() { dynamicPolicyEngine = previous })

	p, err := newMAPFactProducer()
	if err != nil {
		t.Fatalf("newMAPFactProducer: %v", err)
	}
	if p.presentsNoContent {
		t.Error("the map plane's production producer states that the plane presents no content; it presents the step's content")
	}
}

// recordingStepProcessor records that a step ran.
type recordingStepProcessor struct{ ran int }

func (p *recordingStepProcessor) ExecuteStep(context.Context, WorkflowStep, map[string]interface{}, *WorkflowExecution) (map[string]interface{}, error) {
	p.ran++
	return map[string]interface{}{"ok": true}, nil
}

// mapGatedEngine is the multi-agent workflow engine deciding every step through
// the plane's checker, its rows written to audit (nil writes none), over one
// recording llm-call processor.
func mapGatedEngine(audit hitlAuditLogger) (*WorkflowEngine, *recordingStepProcessor) {
	processor := &recordingStepProcessor{}
	engine := &WorkflowEngine{
		stepProcessors: map[string]StepProcessor{"llm-call": processor},
		storage:        NewInMemoryWorkflowStorage(),
	}
	engine.SetStepGate(&MAPHITLPolicyChecker{}, audit)
	return engine, processor
}

func oneStepWorkflow() Workflow {
	return Workflow{
		Metadata: WorkflowMetadata{Name: "map-4254"},
		Spec:     WorkflowSpec{Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}}},
	}
}

// A MAP challenge carrying a typed approval is WITHHELD (#4382; #4249 row
// 5670730156): the multi-agent engine keeps no durable queue row and nothing
// resumes it, so the approval's eligible pools, quorum and separation of duties
// could never be decided. Nothing runs, and the reason is named.
func TestAMAPTypedChallengeIsWithheldForWantOfADurableRecord(t *testing.T) {
	expiresAt := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	withMAPEngine(t, typedHoldVerdict("dec-map-hold", typedApproval(expiresAt)))
	engine, processor := mapGatedEngine(nil)

	exec, err := engine.ExecuteWorkflow(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"})
	if err == nil || exec == nil || exec.Status != "failed" {
		t.Fatalf("execution = (%+v, %v), want a failed execution", exec, err)
	}
	if !strings.Contains(err.Error(), mapApprovalRequiresDurableRecord) || !strings.Contains(exec.Error, mapApprovalRequiresDurableRecord) {
		t.Errorf("err = %v, exec.Error = %q; want both to name %s", err, exec.Error, mapApprovalRequiresDurableRecord)
	}
	if processor.ran != 0 {
		t.Errorf("the withheld step ran %d times, want never", processor.ran)
	}
}

// A MAP approval that already timed out withholds the step as approval_expired.
func TestAMAPApprovalThatAlreadyExpiredWithholdsTheStep(t *testing.T) {
	expiresAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	withMAPEngine(t, typedHoldVerdict("dec-map-lapsed", typedApproval(expiresAt)))
	engine, processor := mapGatedEngine(nil)

	exec, err := engine.ExecuteWorkflow(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"})
	if err == nil || exec == nil || exec.Status != "failed" {
		t.Fatalf("execution = (%+v, %v), want a failed execution blocked by policy", exec, err)
	}
	if processor.ran != 0 {
		t.Errorf("the step ran %d times, want never", processor.ran)
	}
	if want := approvalExpiredReason("dec-map-lapsed", expiresAt); !strings.Contains(exec.Error, want) {
		t.Errorf("execution error = %q, want it to carry %q", exec.Error, want)
	}
}

// The step the checker cannot decide never runs. This is the test that catches
// a checker returning an error instead of a block: the engine proceeds on an
// error, and the step would run.
func TestAMAPStepTheCheckerCannotDecideNeverRuns(t *testing.T) {
	withMAPEngine(t, allowedStepVerdict())
	orchestratorEnforcerInstance.Store(nil)
	engine, processor := mapGatedEngine(nil)

	exec, _ := engine.ExecuteWorkflow(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"})
	if processor.ran != 0 {
		t.Fatalf("the step ran %d times with no enforcer: the plane failed open", processor.ran)
	}
	if exec == nil || exec.Status != "failed" {
		t.Errorf("execution = %+v, want failed", exec)
	}
}
