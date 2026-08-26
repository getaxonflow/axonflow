// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3408: the decide-plane HITL mirror must resolve when the workflow-plane
// step resolves.

package workflow_control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type mirrorCall struct {
	OrgID, TenantID, WorkflowID, StepID, Status, ReviewerID, Comment string
}

type recordingMirrorResolver struct {
	calls []mirrorCall
}

func (r *recordingMirrorResolver) ResolveStepMirror(_ context.Context, orgID, tenantID, workflowID, stepID, status, reviewerID, comment string) {
	r.calls = append(r.calls, mirrorCall{orgID, tenantID, workflowID, stepID, status, reviewerID, comment})
}

func approvableWorkflow(t *testing.T, svc *Service) string {
	t.Helper()
	ctx := context.Background()
	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "mirror-3408"},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	if _, err := svc.StepGate(ctx, wf.WorkflowID, "step-1",
		&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
		"tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	return wf.WorkflowID
}

// TestApproveStepResolvesTheMirror is the regression pin for #3408's core
// defect: the workflow step was approved and the decide-plane mirror stayed
// `pending` for ever, so the portal's Approvals badge counted a decision that
// had already been made.
//
// The mutant that kills it is deleting the s.resolveHITLMirror call from
// ApproveStep - which compiles, and which is precisely the state main is in.
func TestApproveStepResolvesTheMirror(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	resolver := &recordingMirrorResolver{}
	svc.SetHITLMirrorResolver(resolver)

	wfID := approvableWorkflow(t, svc)

	if err := svc.ApproveStep(context.Background(), wfID, "step-1",
		"tenant-1", "org-1", "approver@example.com", "looks fine"); err != nil {
		t.Fatalf("ApproveStep: %v", err)
	}

	if len(resolver.calls) != 1 {
		t.Fatalf("mirror resolver called %d times, want exactly 1", len(resolver.calls))
	}
	got := resolver.calls[0]
	// Asserting the FIELDS, not merely that a call happened. A resolver
	// invoked with the wrong org can never match a row - under mig 025's RLS
	// it would silently update nothing, which is indistinguishable from the
	// bug itself.
	want := mirrorCall{"org-1", "tenant-1", wfID, "step-1", string(ApprovalStatusApproved), "approver@example.com", "looks fine"}
	if got != want {
		t.Errorf("mirror resolved with %+v, want %+v", got, want)
	}
}

// TestRejectStepResolvesTheMirror covers the worse half of #3408: a REJECTED
// step whose mirror stayed pending advertised an outstanding decision for a
// workflow that had already been aborted.
func TestRejectStepResolvesTheMirror(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	resolver := &recordingMirrorResolver{}
	svc.SetHITLMirrorResolver(resolver)

	wfID := approvableWorkflow(t, svc)

	if err := svc.RejectStep(context.Background(), wfID, "step-1",
		"tenant-1", "org-1", "rejecter@example.com", "not approved"); err != nil {
		t.Fatalf("RejectStep: %v", err)
	}

	if len(resolver.calls) != 1 {
		t.Fatalf("mirror resolver called %d times, want exactly 1", len(resolver.calls))
	}
	if got, want := resolver.calls[0].Status, string(ApprovalStatusRejected); got != want {
		t.Errorf("mirror resolved to %q, want %q", got, want)
	}
}

// TestMirrorIsNotResolvedWhenTheApprovalItselfFails is the other direction,
// and it is the assertion that stops the resolver being wired somewhere that
// runs unconditionally.
//
// Resolving the mirror for a step that was NOT in fact approved would mark an
// oversight record as decided when no decision was made - a compliance defect
// strictly worse than the phantom row. The call must sit AFTER
// UpdateStepApproval succeeds, and this fails if it is hoisted above the
// state-transition guards.
func TestMirrorIsNotResolvedWhenTheApprovalItselfFails(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	resolver := &recordingMirrorResolver{}
	svc.SetHITLMirrorResolver(resolver)

	wfID := approvableWorkflow(t, svc)
	ctx := context.Background()

	// First approval succeeds and resolves the mirror once.
	if err := svc.ApproveStep(ctx, wfID, "step-1", "tenant-1", "org-1", "a@example.com", ""); err != nil {
		t.Fatalf("first ApproveStep: %v", err)
	}
	// Second is refused - the step is no longer pending.
	if err := svc.ApproveStep(ctx, wfID, "step-1", "tenant-1", "org-1", "b@example.com", ""); err == nil {
		t.Fatal("second ApproveStep succeeded; the fixture is not exercising the refusal path")
	}
	if len(resolver.calls) != 1 {
		t.Errorf("mirror resolver called %d times, want 1 - a refused approval resolved a mirror",
			len(resolver.calls))
	}

	// A cross-tenant caller is refused by the ownership check, well before any
	// state transition, and must likewise resolve nothing.
	wf2 := approvableWorkflow(t, svc)
	before := len(resolver.calls)
	if err := svc.ApproveStep(ctx, wf2, "step-1", "other-tenant", "other-org", "c@example.com", ""); err == nil {
		t.Fatal("cross-tenant ApproveStep succeeded; the fixture is not exercising the ownership guard")
	} else if !errors.Is(err, ErrWorkflowNotFound) {
		t.Logf("cross-tenant refusal was %v (not ErrWorkflowNotFound); still a refusal", err)
	}
	if len(resolver.calls) != before {
		t.Errorf("a cross-tenant refusal resolved a mirror (%d -> %d calls)", before, len(resolver.calls))
	}
}

// TestNilMirrorResolverIsSafe pins that a deployment with no HITL adapter - the
// ordinary community case - approves normally rather than panicking on a nil
// interface.
func TestNilMirrorResolverIsSafe(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	// Deliberately no SetHITLMirrorResolver.
	wfID := approvableWorkflow(t, svc)
	if err := svc.ApproveStep(context.Background(), wfID, "step-1",
		"tenant-1", "org-1", "approver@example.com", ""); err != nil {
		t.Fatalf("ApproveStep with no mirror resolver: %v", err)
	}
}

// enqueueClassifyingEvaluator answers require_approval and reports a fixed
// enqueue classification, standing in for WCPPolicyAdapter (which lives in
// the orchestrator package and cannot be imported here).
type enqueueClassifyingEvaluator struct{ enqueue string }

func (e *enqueueClassifyingEvaluator) EvaluateStepGate(context.Context, *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:        GateDecisionRequireApproval,
		Reason:          "step is held: the tenant's pending-approval limit is reached",
		PolicyIDs:       []string{"cap-policy"},
		ApprovalEnqueue: e.enqueue,
	}
}

// TestStepGateResponseCarriesTheEnqueueClassification pins the last hop of
// scope item D: the classification has to reach the WIRE, not just the
// evaluation struct.
//
// A refusal that stops at the service boundary is the same invisible dead end
// as no refusal at all - the client sees `require_approval` with no
// approval_id and cannot tell a healthy hold from a permanent one.
func TestStepGateResponseCarriesTheEnqueueClassification(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &enqueueClassifyingEvaluator{enqueue: "cap_reached"}, nil)
	ctx := context.Background()

	wf, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "enqueue-wire"},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	resp, err := svc.StepGate(ctx, wf.WorkflowID, "step-1",
		&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate: %v", err)
	}

	if resp.Decision != GateDecisionRequireApproval {
		t.Fatalf("decision = %q, want require_approval - the caller must stay HELD", resp.Decision)
	}
	if resp.ApprovalEnqueue != "cap_reached" {
		t.Errorf("approval_enqueue = %q, want %q", resp.ApprovalEnqueue, "cap_reached")
	}
	if resp.ApprovalID != "" {
		t.Errorf("approval_id = %q on a refused enqueue, want empty", resp.ApprovalID)
	}
}

// TestStepGateOmitsTheClassificationWhenNoEnqueueWasAttempted keeps the wire
// field honest: present always means "a HITL write was tried". A field that is
// always populated cannot be filtered on, and `omitempty` is what makes the
// absence meaningful.
func TestStepGateOmitsTheClassificationWhenNoEnqueueWasAttempted(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &enqueueClassifyingEvaluator{enqueue: ""}, nil)
	ctx := context.Background()

	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "enqueue-wire-empty"},
		"tenant-1", "org-1", "user-1", "client-1")
	resp, err := svc.StepGate(ctx, wf.WorkflowID, "step-1",
		&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
		"tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	if resp.ApprovalEnqueue != "" {
		t.Errorf("approval_enqueue = %q with no enqueue attempted, want empty", resp.ApprovalEnqueue)
	}

	// And it must be omitted from the JSON, not serialised as "".
	blob, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "approval_enqueue") {
		t.Errorf("approval_enqueue is present in the JSON when empty: %s", blob)
	}
}
