// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #4249 row 5667311128: a typed challenge's queue row carries the severity its
// mandatory approval states. v11.0.0 derived it from the risk score, which the
// workflow step gate computes over no content, so every held step there was
// queued low.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/decision/contract"
)

// heldWithObligations holds one step through the WCP adapter over a challenge
// whose composed obligations are obs, composed by the real algebra.
func heldWithObligations(t *testing.T, obs []contract.Obligation) *mockHITLApprovalCreator {
	t.Helper()
	now := time.Now().UTC()
	pep := &contract.PEPProfile{ID: "wcp-severity", Capabilities: []contract.Capability{{Type: contract.ObApprovalChallenge, Version: 1}}}
	out := contract.ComposeObligations(contract.ComposeInput{Obligations: obs, PEP: pep, ApprovalExpiry: now.Add(time.Hour), Now: now})
	if out.Denied || out.Approval == nil {
		t.Fatalf("PREMISE: composition = denied %v (%s %s), approval %v", out.Denied, out.Reason, out.Detail, out.Approval)
	}
	v := typedHoldVerdict("dec-4249-severity", out.Approval)
	v.Decision.Obligations = out.Obligations
	withStepGateEngine(t, v)
	creator := &mockHITLApprovalCreator{resp: &HITLApprovalResponse{ApprovalID: uuid.New(), Status: "pending", Enqueue: string(queue.OutcomeCreated)}}
	adapter := NewWCPPolicyAdapter()
	adapter.SetHITLApproval(creator)
	adapter.EvaluateStepGate(wcpSubjectContext(), seamStepContext())
	if creator.callCount != 1 || creator.lastReq == nil {
		t.Fatalf("the approval was queued %d times, want once", creator.callCount)
	}
	return creator
}

func severityObligation(src string, mandatory bool, severity string) contract.Obligation {
	params := map[string]string{"quorum": "1", "eligible": "Group::mars:" + src}
	if severity != "" {
		params[contract.ParamApprovalSeverity] = severity
	}
	return contract.Obligation{Type: contract.ObApprovalChallenge, SchemaVersion: 1, Mandatory: mandatory, SourcePolicy: src, Params: params}
}

func TestAHeldStepsQueueRowCarriesTheSeverityItsMandatoryApprovalStates(t *testing.T) {
	creator := heldWithObligations(t, []contract.Obligation{severityObligation("finance", true, "critical")})
	if creator.lastReq.Severity != "critical" {
		t.Errorf("queued severity = %q, want critical, the severity the policy stated", creator.lastReq.Severity)
	}
}

func TestAnAdvisoryApprovalsSeverityDoesNotReachTheQueueRow(t *testing.T) {
	creator := heldWithObligations(t, []contract.Obligation{
		severityObligation("finance", true, ""),
		severityObligation("detector", false, "critical"),
	})
	// No mandatory approval states one, so the risk-score derivation stands:
	// the step gate presents no content here, so the score is 0 and that is low.
	if creator.lastReq.Severity != "low" {
		t.Errorf("queued severity = %q, want low (derived): an advisory approval's severity reached the row", creator.lastReq.Severity)
	}
}
