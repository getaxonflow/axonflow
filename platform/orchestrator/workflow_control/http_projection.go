// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// HITL HTTP response projection (Issue #1677 Phase 2)
//
// Both WCP (/api/v1/workflows/{id}/steps/{step_id}/approve|reject) and MAP
// (/api/v1/plans/{id}/steps/{step_id}/approve|reject) project approval outcomes
// through the single helper ProjectStepGateToHTTP. Adding a new field on
// StepGateHTTPResponse surfaces on both planes automatically — divergence
// becomes the opt-out, not the default.
//
// See technical-docs/architecture-decisions/046-hitl-response-parity.md for
// the parity rule, and TestHITLResponseParity (platform/orchestrator) for the
// cross-plane contract test that asserts the two response shapes stay aligned.

package workflow_control

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// wcpHITLNamespace is the fixed UUID v5 namespace that the WCP HITL adapter
// uses to derive deterministic request_ids from (workflow_id, step_id). It is
// duplicated here so workflow_control can compute the same ID without pulling
// in the orchestrator package — both sites must stay in sync. See
// hitl_wcp_enterprise.go:wcpHITLAdapter.CreateApproval for the write path.
var wcpHITLNamespace = uuid.MustParse("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

// DeriveHITLApprovalID reconstructs the HITL queue request_id for a given
// (workflow_id, step_id) pair's FIRST hold. The queue row itself is written by
// wcpHITLAdapter in the orchestrator package using the same derivation. A step
// held again has one row per hold (DeriveHITLApprovalIDForHold), so the
// approve/reject responses project the current hold's id
// (Service.CurrentApprovalID), not this one.
//
// Returns an empty string when either argument is empty — callers should treat
// that as "no HITL queue entry for this step".
func DeriveHITLApprovalID(workflowID, stepID string) string {
	if workflowID == "" || stepID == "" {
		return ""
	}
	return uuid.NewSHA1(wcpHITLNamespace, []byte(workflowID+":"+stepID)).String()
}

// DeriveHITLApprovalIDForHold names the queue row of the n-th hold of a step
// (#4249 row 5700138809). A step whose earlier hold was decided and is held
// again gets a NEW row rather than reusing the decided one, because that row
// is the record of the earlier decision. Hold 1 is DeriveHITLApprovalID
// unchanged, so every row written before this existed keeps its id; hold n >= 2
// is UUID v5 over workflowID+":"+stepID+"#"+n.
//
// This is a name, not an identity check: a step literally named "a#2" hashes
// the same string as hold 2 of step "a". The queue's enqueue refuses a
// conflicting row that belongs to another step, so the collision fails closed.
//
// Returns an empty string for an empty argument or n < 1.
func DeriveHITLApprovalIDForHold(workflowID, stepID string, n int) string {
	if n < 1 {
		return ""
	}
	if n == 1 {
		return DeriveHITLApprovalID(workflowID, stepID)
	}
	if workflowID == "" || stepID == "" {
		return ""
	}
	return uuid.NewSHA1(wcpHITLNamespace, []byte(workflowID+":"+stepID+"#"+strconv.Itoa(n))).String()
}

// StepGateHTTPResponse is the rich HTTP response for approve / reject across
// WCP and MAP. It mirrors the field set returned by StepGate (StepGateResponse)
// plus approver metadata so clients see parity between the gate response and
// the approve/reject response for the same step.
//
// Fields are omitempty-tagged where empty carries meaning ("approver metadata
// unknown because no HITL queue entry exists for the step"), but
// retry_context is always present per the wire contract (see RetryContext).
type StepGateHTTPResponse struct {
	// WorkflowID is the underlying WCP workflow id. In MAP's confirm/step mode
	// this is the WCP workflow derived from the plan; callers that only know
	// plan_id can resolve it via the response's PlanID field.
	WorkflowID string `json:"workflow_id"`

	// PlanID is populated on MAP responses; empty for native WCP responses.
	PlanID string `json:"plan_id,omitempty"`

	// StepID is the step that was approved / rejected.
	StepID string `json:"step_id"`

	// Status is a flat string alias of ApprovalStatus. Both fields always
	// carry the same value when populated — `status` is easier to read for
	// loggers, dashboards, and clients that prefer a simple string over a
	// nullable enum pointer; `approval_status` is the typed source of truth.
	// First-class on both planes so existing SDK properties declared as
	// `status` and code paths that prefer `approval_status` both keep
	// working without client-side branching.
	Status string `json:"status,omitempty"`

	// Decision is the gate decision after approval resolution:
	//   - "allow" once the step is approved (the step can now proceed)
	//   - "block" once the step is rejected (workflow aborted)
	//   - "require_approval" if the step is still pending (should be rare on
	//     /approve or /reject responses — exposed to match StepGate shape)
	Decision GateDecision `json:"decision"`

	// Reason is the decision reason text, if any.
	Reason string `json:"reason,omitempty"`

	// ApprovalStatus is the current approval state of the step.
	ApprovalStatus *ApprovalStatus `json:"approval_status,omitempty"`

	// ApprovalID is the HITL queue entry UUID. Empty when no queue entry
	// exists for the step.
	ApprovalID string `json:"approval_id,omitempty"`

	// ApprovedBy / ApprovedAt come from the workflow_steps row (PR #1670).
	// Populated once the step has been approved. For rejection responses the
	// rejector identity lives in RejectedBy / RejectedAt instead.
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`

	// RejectedBy / RejectedAt carry the rejector identity (rejection path only).
	RejectedBy string     `json:"rejected_by,omitempty"`
	RejectedAt *time.Time `json:"rejected_at,omitempty"`

	// PoliciesMatched are the policies that produced the original
	// require_approval decision. Reconstructed from workflow_steps.policies_matched.
	PoliciesMatched []PolicyMatch `json:"policies_matched,omitempty"`

	// RetryContext is always present — same shape as StepGateResponse.RetryContext.
	// See technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md §3.
	RetryContext RetryContext `json:"retry_context"`

	// Message is a human-readable status summary suitable for UI display or logs.
	Message string `json:"message,omitempty"`
}

// ApproverMeta carries HITL queue identifiers that aren't stored on the
// workflow_steps row. Today the only such field is the HITL queue entry UUID of
// the step's current hold (Service.CurrentApprovalID - see wcpHITLAdapter).
// Leaving this as a struct lets us extend the HITL-queue-side metadata (e.g.
// reviewer role, override justification) without changing the function
// signature of ProjectStepGateToHTTP.
type ApproverMeta struct {
	// ApprovalID is the HITL queue entry UUID. Empty when no queue row was
	// created.
	ApprovalID string
}

// ProjectStepGateToHTTP builds the rich HTTP response returned by WCP and MAP
// approve/reject endpoints. It is the single projection point — both planes
// call this so the response shape cannot drift without explicit intent.
//
// Arguments:
//   - workflowID: the WCP workflow id (required; empty if step is nil)
//   - planID: MAP plan id when projecting a MAP response; "" for native WCP
//   - step: the persisted WorkflowStep row after the approval mutation landed.
//     Must reflect post-update state (ApprovedBy / ApprovedAt populated on
//     approval, ApprovalStatus set to approved/rejected) so retry_context
//     and approval metadata are correct. Pass nil to produce a minimal
//     response (workflow_id + message only — for when no WCP step row
//     could be read).
//   - approver: approver metadata from the HITL queue row (optional; zero
//     value is fine — the response simply omits ApprovalID).
//   - message: human-readable status summary ("Step approved", "Step rejected,
//     workflow aborted"), echoed to response.message.
//   - includePriorOutput: pass-through to buildRetryContext; controls whether
//     retry_context.prior_output is populated (opt-in via ?include_prior_output
//     query param).
//
// The function never reads from the database — callers are responsible for
// ensuring step reflects post-write state before invoking the projector.
func ProjectStepGateToHTTP(
	workflowID string,
	planID string,
	step *WorkflowStep,
	approver ApproverMeta,
	message string,
	includePriorOutput bool,
) StepGateHTTPResponse {
	if step == nil {
		// Minimal shell when no WCP step row could be read (the in-memory MAP
		// flow that also produced it is retired, #4249 row 5774060413).
		// retry_context stays at its zero value — GateCount: 0 signals "no WCP
		// state tracked".
		return StepGateHTTPResponse{
			WorkflowID: workflowID,
			PlanID:     planID,
			ApprovalID: approver.ApprovalID,
			Message:    message,
		}
	}

	var policiesMatched []PolicyMatch
	if step.PoliciesMatched != nil {
		_ = json.Unmarshal(step.PoliciesMatched, &policiesMatched)
	}

	// Derive the response-time decision so callers see the post-approval state:
	// an approved require_approval becomes "allow"; rejected becomes "block".
	decision := step.Decision
	reason := step.DecisionReason
	if step.Decision == GateDecisionRequireApproval && step.ApprovalStatus != nil {
		switch *step.ApprovalStatus {
		case ApprovalStatusApproved:
			decision = GateDecisionAllow
			if reason != "" {
				reason = "Approved: " + reason
			} else {
				reason = "Approved"
			}
		case ApprovalStatusRejected:
			decision = GateDecisionBlock
			if reason != "" {
				reason = "Rejected: " + reason
			} else {
				reason = "Rejected"
			}
		case ApprovalStatusExpired:
			// Auto-timeout — blocked like a reject, but surfaced distinctly so
			// it is never reported as a human rejection (#2654).
			decision = GateDecisionBlock
			if reason != "" {
				reason = "Expired (approval timed out): " + reason
			} else {
				reason = "Expired (approval timed out)"
			}
		}
	}

	resp := StepGateHTTPResponse{
		WorkflowID:      workflowID,
		PlanID:          planID,
		StepID:          step.StepID,
		Decision:        decision,
		Reason:          reason,
		ApprovalStatus:  step.ApprovalStatus,
		ApprovalID:      approver.ApprovalID,
		PoliciesMatched: policiesMatched,
		RetryContext:    buildRetryContext(step, includePriorOutput),
		Message:         message,
	}
	if step.ApprovalStatus != nil {
		// `status` always mirrors `approval_status` — see Status doc on
		// StepGateHTTPResponse for why both fields exist.
		resp.Status = string(*step.ApprovalStatus)
	}

	// Route approver identity into approved_* or rejected_* based on terminal state.
	// Both fields share the workflow_steps.approved_by / approved_at columns —
	// semantic split happens at projection time.
	if step.ApprovalStatus != nil {
		switch *step.ApprovalStatus {
		case ApprovalStatusApproved:
			resp.ApprovedBy = step.ApprovedBy
			resp.ApprovedAt = step.ApprovedAt
		case ApprovalStatusRejected:
			resp.RejectedBy = step.ApprovedBy
			resp.RejectedAt = step.ApprovedAt
		case ApprovalStatusPending:
			// Pending — neither approved_* nor rejected_* populated yet.
		}
	}

	return resp
}

// HITLResponseFieldSet enumerates the JSON field names that every HITL response
// (WCP approve/reject, MAP approve/reject) must surface. Both planes assert
// parity against this list via TestHITLResponseParity. Adding a field to
// StepGateHTTPResponse requires adding it here — the contract test fails
// otherwise, forcing cross-plane attention.
//
// Field presence-or-absence on the JSON wire depends on the response path
// (approve vs reject) and whether a WCP step row exists. The
// parity assertion is about the *field set being identical* across planes for
// the same scenario — not every field being populated.
var HITLResponseFieldSet = []string{
	"workflow_id",
	"plan_id",
	"step_id",
	"status",
	"decision",
	"reason",
	"approval_status",
	"approval_id",
	"approved_by",
	"approved_at",
	"rejected_by",
	"rejected_at",
	"policies_matched",
	"retry_context",
	"message",
}
