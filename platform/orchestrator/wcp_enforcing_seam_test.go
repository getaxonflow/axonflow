// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
)

// stepGateEnforcerDouble stands in for the process enforcer: it answers every
// call with one verdict and records the calls, so a test can assert both what
// the seam presented and what it did with the answer.
type stepGateEnforcerDouble struct {
	mu      sync.Mutex
	verdict anchoredenforcer.Verdict
	calls   []anchoredenforcer.Call
}

func (d *stepGateEnforcerDouble) Evaluate(_ context.Context, call anchoredenforcer.Call) anchoredenforcer.Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, call)
	return d.verdict
}

func (d *stepGateEnforcerDouble) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *stepGateEnforcerDouble) lastCall(t *testing.T) anchoredenforcer.Call {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		t.Fatal("the step gate never called the enforcer")
	}
	return d.calls[len(d.calls)-1]
}

// withStepGateEngine installs a double as the process enforcer, and a fact
// producer over rows, for the test's lifetime.
func withStepGateEngine(t *testing.T, verdict anchoredenforcer.Verdict, rows ...DynamicPolicy) *stepGateEnforcerDouble {
	t.Helper()
	d := &stepGateEnforcerDouble{verdict: verdict}
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: d})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
	withStepGateFacts(t, true, rows...)
	return d
}

// withStepGateFacts installs the step gate's fact producer over rows. With
// segmentsResolve false the caller's segments cannot be resolved, which is the
// producer's outage.
func withStepGateFacts(t *testing.T, segmentsResolve bool, rows ...DynamicPolicy) {
	t.Helper()
	previous := newWCPFactProducer
	newWCPFactProducer = func() (*dynamicFactProducer, error) {
		p, err := newDynamicFactProducer(func(string, []string) []DynamicPolicy { return rows })
		if err != nil {
			return nil, err
		}
		p.segments = func(context.Context, string, string) ([]string, bool) { return nil, segmentsResolve }
		p.presentsNoContent = true
		return p, nil
	}
	resetWCPFacts()
	t.Cleanup(func() {
		newWCPFactProducer = previous
		resetWCPFacts()
	})
}

func resetWCPFacts() {
	wcpFactsOnce = sync.Once{}
	wcpFacts, wcpFactsErr = nil, nil
}

// stepGateVerdict is the engine's decision in state. A challenge carries its
// approval requirement, as a real one does; challengeWithoutTerms is the test
// double of one that carries none.
func stepGateVerdict(state contract.OperationalState, reason contract.ReasonCode, d contract.Determining) anchoredenforcer.Verdict {
	dec := &contract.Decision{State: state, Reason: reason, Determining: d}
	if state == contract.StateChallenge {
		dec.Approval = &contract.ApprovalRequirement{AllOf: []contract.ApprovalClause{
			{Quorum: 1, Eligible: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::mars:reviewers")}},
		}}
	}
	return anchoredenforcer.Verdict{Decision: dec}
}

// heldStepVerdict is the engine's challenge: the verdict that holds a step and
// reaches the enqueue path. allowedStepVerdict admits it.
func heldStepVerdict() anchoredenforcer.Verdict {
	return stepGateVerdict(contract.StateChallenge, contract.ReasonApprovalRequired,
		contract.Determining{MatchedRequirement: []string{"wsp-approval-policy"}})
}

func allowedStepVerdict() anchoredenforcer.Verdict {
	return stepGateVerdict(contract.StateAllow, contract.ReasonPermitted, contract.Determining{})
}

func seamStepContext() *workflow_control.StepGateContext {
	return &workflow_control.StepGateContext{
		WorkflowID: "wf-seam",
		StepID:     "step-1",
		StepName:   "call_the_tool",
		StepType:   workflow_control.StepTypeToolCall,
		OrgID:      "org-seam",
		TenantID:   "tenant-seam",
		ClientID:   "client-seam",
	}
}

// #4254: a step gate with no enforcer WITHHOLDS the step and names why. The
// legacy adapter admitted every step when no engine was configured; on the
// anchored engine that would be an outage answering as a governance decision.
func TestTheStepGateFailsClosedWithNoEnforcer(t *testing.T) {
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(nil)
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
	withStepGateFacts(t, true)

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q with no enforcer; want block", ev.Decision)
	}
	if !reflect.DeepEqual(ev.PolicyIDs, []string{"decision_enforcement_unavailable"}) {
		t.Errorf("policy ids = %v; want [decision_enforcement_unavailable]", ev.PolicyIDs)
	}
	if !strings.Contains(ev.Reason, anchoredenforcer.CauseNotWired) {
		t.Errorf("reason %q does not name %s", ev.Reason, anchoredenforcer.CauseNotWired)
	}
}

// An enforcer that could not reach a verdict withholds the step, naming the
// cause it failed closed on.
func TestAnUnavailableVerdictWithholdsTheStepNamingTheCause(t *testing.T) {
	withStepGateEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseActiveDocument})

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q on an unavailable verdict; want block", ev.Decision)
	}
	if !strings.Contains(ev.Reason, anchoredenforcer.CauseActiveDocument) {
		t.Errorf("reason %q does not name %s", ev.Reason, anchoredenforcer.CauseActiveDocument)
	}
}

// PRD v11 §1 item 13: this plane can hold, so a challenge is require_approval
// and never a block.
func TestAChallengeHoldsTheStepAndIsNeverABlock(t *testing.T) {
	withStepGateEngine(t, stepGateVerdict(contract.StateChallenge, contract.ReasonApprovalRequired, contract.Determining{}))

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionRequireApproval {
		t.Fatalf("decision = %q on a challenge; want require_approval", ev.Decision)
	}
	if ev.Reason != "Step requires human approval" {
		t.Errorf("reason = %q; want the hold's own reason", ev.Reason)
	}
}

// #4254: the call the step gate presents. The plane presents NO content and
// says so; the action is the one the step's type maps to; the subject is the
// credential the agent authenticated, installed on the request context at the
// orchestrator's HTTP boundary.
func TestTheStepGatePresentsNoContentTheStepsActionAndACredentialSubject(t *testing.T) {
	d := withStepGateEngine(t, stepGateVerdict(contract.StateAllow, contract.ReasonPermitted, contract.Determining{}))
	step := seamStepContext()

	NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), step)
	call := d.lastCall(t)

	if call.Scope != wcpSeamScope {
		t.Errorf("scope = %s; want %s", call.Scope, wcpSeamScope)
	}
	if call.OrgID != step.OrgID {
		t.Errorf("organization = %q; want %q", call.OrgID, step.OrgID)
	}
	if call.Query != "" || !call.EmptyContent {
		t.Errorf("query = %q, empty content = %v; the plane presents no content, so want \"\" and true", call.Query, call.EmptyContent)
	}
	if call.Observation != nil {
		t.Error("the step gate passed a detector observation; its detector facts come from the producer")
	}
	if call.Action != authoringcatalog.ActionToolCall || call.ActionErr != nil {
		t.Errorf("action = (%q, %v); want %q with no error for a tool_call step", call.Action, call.ActionErr, authoringcatalog.ActionToolCall)
	}
	if call.Subject == nil {
		t.Fatal("the call carries no subject builder")
	}
	subject, ok := call.Subject(time.Now())
	if !ok || !subject.Credential {
		t.Errorf("subject = (%+v, %v); want the credential subject installed from the request's headers", subject, ok)
	}
}

// A step type the workflow control plane's map does not name reaches the
// enforcer as an action error naming the token, which the enforcer refuses as
// request_unbuildable - it is never defaulted to an action nobody chose.
func TestAnUnmappedStepTypeReachesTheEnforcerAsAnActionErrorNamingIt(t *testing.T) {
	d := withStepGateEngine(t, anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseRequest})
	step := seamStepContext()
	step.StepType = workflow_control.StepType("tool-call")

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), step)
	call := d.lastCall(t)

	if call.ActionErr == nil {
		t.Fatalf("an unmapped step type reached the enforcer as action %q with no error", call.Action)
	}
	if !strings.Contains(call.ActionErr.Error(), strconv.Quote("tool-call")) {
		t.Errorf("the action error does not name the step type: %v", call.ActionErr)
	}
	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Errorf("decision = %q; want block", ev.Decision)
	}
}

// The identity plane refusing the step's subject withholds the step, named as
// every other plane names a refusal: the admission's reason, then its detail.
func TestASubjectRefusalWithholdsTheStepNamingTheReason(t *testing.T) {
	withStepGateEngine(t, anchoredenforcer.Verdict{Refusal: &sharedidentity.Admission{
		State:  sharedidentity.AdmissionDeny,
		Reason: sharedidentity.ReasonUnknownRealm,
		Detail: "no realm admits this credential",
	}})

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q on a refused subject; want block", ev.Decision)
	}
	if ev.Reason != "unknown_realm: no realm admits this credential" {
		t.Errorf("reason = %q; want the admission's reason then its detail", ev.Reason)
	}
	if !reflect.DeepEqual(ev.PolicyIDs, []string{"unknown_realm"}) {
		t.Errorf("policy ids = %v; want [unknown_realm]", ev.PolicyIDs)
	}
}

// An ERROR is a constraint the engine could not evaluate. It withholds the step
// and names that constraint: unknown input never becomes an admission.
func TestAnUnknownConstraintWithholdsTheStepNamingIt(t *testing.T) {
	const constraint = "corpus:dynamic_policies:sys__dyn__debug__restrict"
	withStepGateEngine(t, stepGateVerdict(contract.StateError, contract.ReasonUnknownConstraint, contract.Determining{
		Unknown: []contract.UnknownPolicy{{
			PolicyID:  constraint,
			Authority: contract.AuthorityConstraint,
			Reason:    contract.ReasonNotSupplied,
			Paths:     []string{"env.environment"},
		}},
	}))

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q on an unknown constraint; want block", ev.Decision)
	}
	if !reflect.DeepEqual(ev.PolicyIDs, []string{constraint}) {
		t.Errorf("policy ids = %v; want [%s]", ev.PolicyIDs, constraint)
	}
}

// ADR-060 #2989 P3b, kept across the move: when the caller's segments cannot be
// resolved the step is withheld with the id every route has always named that
// outage by, and the enforcer is never asked, because which rows govern the
// caller is not known.
func TestASegmentResolutionOutageWithholdsTheStepNamingIt(t *testing.T) {
	d := withStepGateEngine(t, stepGateVerdict(contract.StateAllow, contract.ReasonPermitted, contract.Determining{}))
	withStepGateFacts(t, false)

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q on a segment-resolution outage; want block", ev.Decision)
	}
	if ev.Decision == workflow_control.GateDecisionRequireApproval {
		t.Fatal("an outage was turned into a hold, which an external caller can simply never release")
	}
	if !reflect.DeepEqual(ev.PolicyIDs, []string{"segment_resolution_failed"}) {
		t.Errorf("policy ids = %v; want [segment_resolution_failed]", ev.PolicyIDs)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the enforcer was called %d times although the caller's facts could not be produced", n)
	}
}

// The step gate's PRODUCTION fact producer presents no content, and it is not
// built without a dynamic engine to read rows from. Every other seam test
// overrides newWCPFactProducer, so this is the one test that holds the plane's
// contract where a serving process takes it.
func TestTheStepGatesProductionProducerPresentsNoContent(t *testing.T) {
	previous := dynamicPolicyEngine
	t.Cleanup(func() { dynamicPolicyEngine = previous })

	dynamicPolicyEngine = nil
	if _, err := newWCPFactProducer(); err == nil {
		t.Error("the step gate's fact producer was built with no dynamic engine wired")
	}

	dynamicPolicyEngine = &mockPolicyEngineForWCP{}
	p, err := newWCPFactProducer()
	if err != nil {
		t.Fatalf("building the step gate's production fact producer: %v", err)
	}
	if !p.presentsNoContent {
		t.Fatal("the step gate's production fact producer does not state that the plane presents no content")
	}
}
