// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// AN APPROVAL THAT TIMES OUT BETWEEN THE DECISION AND THE ENQUEUE IS A DENY
// (#4254). The seam withholds an approval that had already expired when it was
// decided; this is the moment after that, when the queue refuses the row. The
// step is withheld as approval_expired with no queue row, and never held as an
// enqueue error that could still be approved.
func TestAnApprovalThatLapsesBeforeItIsQueuedWithholdsTheStep(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	withStepGateEngine(t, anchoredStampVerdict(typedHoldVerdict("dec-lapsed", typedApproval(expiresAt)), "dec-lapsed"))
	creator := &mockHITLApprovalCreator{err: errApprovalExpiredBeforeQueue}
	adapter := NewWCPPolicyAdapter()
	adapter.SetHITLApproval(creator)

	ev := adapter.EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if creator.callCount != 1 {
		t.Fatalf("PREMISE: the enqueue was attempted %d times, want once", creator.callCount)
	}
	if ev.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision = %q, want block: a timed-out approval is a deny, not a hold", ev.Decision)
	}
	if want := []string{"approval_expired"}; !reflect.DeepEqual(ev.PolicyIDs, want) {
		t.Errorf("policy ids = %v, want %v", ev.PolicyIDs, want)
	}
	if want := approvalExpiredReason("dec-lapsed", expiresAt); ev.Reason != want {
		t.Errorf("reason = %q, want %q", ev.Reason, want)
	}
	if ev.ApprovalEnqueue != "" || ev.ApprovalID != "" {
		t.Errorf("approval_enqueue = %q, approval_id = %q; want neither, because no row exists to approve", ev.ApprovalEnqueue, ev.ApprovalID)
	}
	if ev.Plane != "wcp" || ev.Engine != anchoredenforcer.EngineAnchored || ev.EngineDecisionID != "dec-lapsed" {
		t.Errorf("anchored decision = %q/%q/%q, want the stamp kept", ev.Plane, ev.Engine, ev.EngineDecisionID)
	}
}

// CONTROL: any other enqueue failure still holds the step and says the enqueue
// failed, so the arm above is the lapse alone.
func TestAnEnqueueFailureOtherThanALapseStillHoldsTheStep(t *testing.T) {
	withStepGateEngine(t, typedHoldVerdict("dec-held", typedApproval(time.Now().Add(time.Hour))))
	adapter := NewWCPPolicyAdapter()
	adapter.SetHITLApproval(&mockHITLApprovalCreator{err: errors.New("connection refused")})

	ev := adapter.EvaluateStepGate(wcpSubjectContext(), seamStepContext())

	if ev.Decision != workflow_control.GateDecisionRequireApproval || ev.ApprovalEnqueue != "error" {
		t.Errorf("decision = %q, approval_enqueue = %q; want require_approval and error", ev.Decision, ev.ApprovalEnqueue)
	}
}

// The resolver's expiry read reports no row where none can exist: no resolver,
// no database, or a workflow with no org_id, which the queue's writer refuses.
func TestTheMirrorExpiryReadReportsNoRowWhereNoRowCanExist(t *testing.T) {
	cases := map[string]struct {
		r     *wcpHITLMirrorResolver
		orgID string
	}{
		"no resolver":            {nil, "org-1"},
		"no database":            {&wcpHITLMirrorResolver{}, "org-1"},
		"a workflow with no org": {&wcpHITLMirrorResolver{db: &sql.DB{}}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			expiresAt, expired, found, err := c.r.StepMirrorExpiry(context.Background(), c.orgID, "tenant-1", "wf-1", "step-1")
			if err != nil || found || expired || !expiresAt.IsZero() {
				t.Errorf("(%s, %v, %v, %v), want no row and no error", expiresAt, expired, found, err)
			}
		})
	}
}
