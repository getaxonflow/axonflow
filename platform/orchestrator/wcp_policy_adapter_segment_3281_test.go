// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3281 (ADR-060 #2989 P3b) - segment resolution on WCP workflow step gates.
//
// WHAT CHANGED IN v11 (#4254). The step gate decides on the anchored engine, and
// an organization's activation is built from the shipped corpus, its typed
// document, its recorded overrides and its packs. A TENANT dynamic_policies row
// is not among those: under PRD v11 §1.2 ruling R2 the dynamic condition matcher
// produces facts and decides nothing, so a segment-scoped tenant row no longer
// blocks or admits a step on its own. That is the documented v11 behaviour for
// every v10-authored rule, which stops deciding until it is imported. The tests
// that pinned such a row blocking a member and sparing a non-member were
// retired with it.
//
// WHAT STILL HOLDS, AND IS PINNED HERE:
//   - the #3281 wiring fix: the step gate threads the caller's organization and
//     verified email into segment resolution;
//   - the segment set that resolution returns is the one the dynamic rows are
//     selected with, and an empty email never calls the resolver;
//   - a genuine resolution failure withholds the step, named
//     segment_resolution_failed, the id every route answers that outage by.

import (
	"errors"
	"reflect"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/workflow_control"
)

func stepGateCtxFor(orgID, email string) *workflow_control.StepGateContext {
	return &workflow_control.StepGateContext{
		WorkflowID: "wf-3281",
		StepID:     "step-1",
		StepName:   "export_finance_report",
		StepType:   workflow_control.StepTypeToolCall,
		TenantID:   "global",
		OrgID:      orgID,
		ClientID:   "client-3281",
		Email:      email,
	}
}

// segmentRowsProbe records the organization and segment set the dynamic rows
// were selected with, which is what resolution feeds.
type segmentRowsProbe struct {
	calls    int
	orgID    string
	segments []string
}

func (p *segmentRowsProbe) rows(orgID string, segmentIDs []string) []DynamicPolicy {
	p.calls++
	p.orgID = orgID
	p.segments = append([]string(nil), segmentIDs...)
	return nil
}

// withStepGateResolvingProducer installs a step-gate fact producer that
// resolves the caller's segments through the process resolver, as a serving
// process does, and selects its rows through probe.
func withStepGateResolvingProducer(t *testing.T, probe *segmentRowsProbe) {
	t.Helper()
	previous := newWCPFactProducer
	newWCPFactProducer = func() (*dynamicFactProducer, error) {
		p, err := newDynamicFactProducer(probe.rows)
		if err != nil {
			return nil, err
		}
		p.presentsNoContent = true
		return p, nil
	}
	resetWCPFacts()
	t.Cleanup(func() {
		newWCPFactProducer = previous
		resetWCPFacts()
	})
}

// The bug #3281 closed: the step gate built its request with the tenant alone,
// so every step resolved segments on the "no verified identity" path.
func TestWCPPolicyAdapter_ConvertToOrchestratorRequest_ThreadsOrgAndEmail(t *testing.T) {
	req := NewWCPPolicyAdapter().convertToOrchestratorRequest(&workflow_control.StepGateContext{
		WorkflowID: "wf-wiring",
		StepID:     "step-1",
		StepType:   workflow_control.StepTypeToolCall,
		TenantID:   "tenant-9",
		OrgID:      "org-9",
		Email:      "carol@example.com",
	})

	if req.User.TenantID != "tenant-9" {
		t.Errorf("User.TenantID = %q, want tenant-9", req.User.TenantID)
	}
	if req.User.OrgID != "org-9" {
		t.Errorf("User.OrgID = %q, want org-9 (was previously left zero - the #3281 bug)", req.User.OrgID)
	}
	if req.User.Email != "carol@example.com" {
		t.Errorf("User.Email = %q, want carol@example.com (was previously left empty - the #3281 bug)", req.User.Email)
	}
}

// The caller's organization and verified email reach segment resolution, and the
// segment set it returns is the one the dynamic rows are selected with.
func TestTheStepGateSelectsDynamicRowsWithTheCallersResolvedSegments(t *testing.T) {
	withStepGateEngine(t, allowedStepVerdict())
	probe := &segmentRowsProbe{}
	withStepGateResolvingProducer(t, probe)
	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))

	NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), stepGateCtxFor("org-shared", "alice@example.com"))

	if probe.calls == 0 {
		t.Fatal("PREMISE: the dynamic rows were never selected, so the segment set they were selected with proves nothing")
	}
	if probe.orgID != "org-shared" {
		t.Errorf("rows selected for organization %q; want org-shared", probe.orgID)
	}
	if !reflect.DeepEqual(probe.segments, []string{"seg-finance"}) {
		t.Errorf("rows selected with segments %v; want [seg-finance], the set the resolver returned", probe.segments)
	}
}

// With no verified email there is no identity to resolve, so the resolver is
// never called and the rows are selected org-only. That is not a failure: the
// step is decided, not withheld.
func TestAnEmptyEmailNeverCallsTheSegmentResolver(t *testing.T) {
	withStepGateEngine(t, allowedStepVerdict())
	probe := &segmentRowsProbe{}
	withStepGateResolvingProducer(t, probe)
	fake := resolverReturning("seg-finance")
	withOrchestratorSegmentResolver(t, fake)

	ev := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), stepGateCtxFor("org-shared", ""))

	if fake.callCount() != 0 {
		t.Errorf("the resolver was called %d times with no verified email", fake.callCount())
	}
	if probe.calls == 0 {
		t.Fatal("PREMISE: the dynamic rows were never selected, so the org-only selection is not shown")
	}
	if len(probe.segments) != 0 {
		t.Errorf("rows selected with segments %v for an unverified caller; want none (org-only)", probe.segments)
	}
	if ev.Decision != workflow_control.GateDecisionAllow {
		t.Errorf("decision = %q for an unverified caller; want the engine's allow, not a resolution failure (%s)", ev.Decision, ev.Reason)
	}
}

// A genuine resolution failure withholds the step, named by the id every route
// answers that outage by, and never becomes a hold an external caller could
// simply leave unanswered.
func TestWCPPolicyAdapter_EvaluateStepGate_ResolverError_FailsClosed(t *testing.T) {
	d := withStepGateEngine(t, allowedStepVerdict())
	withStepGateResolvingProducer(t, &segmentRowsProbe{})
	withOrchestratorSegmentResolver(t, &fakeOrchestratorSegmentResolver{err: errors.New("scim query failed")})

	result := NewWCPPolicyAdapter().EvaluateStepGate(wcpSubjectContext(), stepGateCtxFor("org-shared", "alice@example.com"))

	if result.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("a segment resolution error must DENY the step gate (fail-closed, ADR-060 §Fail-closed), got decision=%s", result.Decision)
	}
	if !reflect.DeepEqual(result.PolicyIDs, []string{"segment_resolution_failed"}) {
		t.Errorf("policy ids = %v; want [segment_resolution_failed]", result.PolicyIDs)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the enforcer was called %d times although which rows govern the caller is unknown", n)
	}
	_ = contract.StateAllow // the engine double's verdict is irrelevant here: it must not be consulted
}
