// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// The WCP require_approval -> HITL queue write path, for BOTH editions.
//
// Issue #1082 wired the step gate to the queue. It did so with two direct
// `INSERT INTO hitl_approval_queue` statements - one per edition, in
// hitl_wcp_community.go and hitl_wcp_enterprise.go - which is what made the
// WCP plane the last bypass of the enforcement chokepoint run.go:1634
// describes as "the single enforcement chokepoint for the tier gate + pending
// cap + history". It was not single. Both copies now delegate to
// platform/agent/hitl/queue, which owns the only INSERT in the tree.
//
// NO BUILD TAG. The write path is now identical on both editions, so keeping
// two copies of it would reintroduce exactly the drift this change removes.
// What genuinely differs per edition is only WHEN the adapter is wired at all
// and with which limits, and that stays in the two InitializeWCPHITL functions
// (hitl_wcp_{community,enterprise}.go).
//
// FOUR DEFECTS THIS CLOSES, all of them consequences of the write path being
// duplicated rather than shared:
//
//  1. NO TIER GATE ON THE ENTERPRISE BINARY. hitl_wcp_enterprise.go's
//     InitializeWCPHITL consulted no licence at all, so an enterprise image
//     running with no (or an expired) AXONFLOW_LICENSE_KEY resolved to
//     Community tier and still wrote queue rows. That is the same hole #1998
//     closed for `axonflow_request_approval`, on a different door.
//
//  2. NO PENDING CAP ON THE ENTERPRISE BINARY. MaxPendingApprovals is -1
//     (unlimited) for Enterprise but 5 for Community/Free/Pro/Premium and 25
//     for Evaluation (license/tier_support.go). The enterprise adapter applied
//     no cap to any of them.
//
//  3. NO DEDUP ON THE COMMUNITY/EVALUATION BINARY, AND A REQUEST_ID THAT DID
//     NOT MATCH THE ONE THE API HANDED OUT. The eval adapter minted
//     `uuid.New()` per call, so (a) every re-gate of the same step appended
//     ANOTHER pending row, and (b) the approve/reject response projects
//     workflow_control.DeriveHITLApprovalID(workflow_id, step_id) as its
//     approval_id - a deterministic UUID v5 that, on Evaluation, resolved to
//     no row at all. Both editions now derive the same id, so the id a client
//     is handed is the id of the row.
//
//  4. NO hitl_approval_history ROW FROM EITHER. The EU AI Act Article 14
//     trail recorded a `created` action for approvals made through the agent
//     and nothing for approvals made by a workflow gate.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"
)

// wcpHITLRequestType is the request_type stamped on every row this adapter
// writes. It is what tells the decide-plane surfaces that the row mirrors a
// workflow step gate whose approval is resolved on the WORKFLOW plane, not by
// approving the queue row (#3408).
const wcpHITLRequestType = queue.RequestTypeWCPStepGate

// wcpHITLAdapter implements HITLApprovalCreator by routing through the shared
// enqueue chokepoint.
type wcpHITLAdapter struct {
	enq *queue.Enqueuer
}

// newWCPHITLAdapter builds the adapter over an Enqueuer configured with the
// caller's tier limits.
func newWCPHITLAdapter(enq *queue.Enqueuer) *wcpHITLAdapter {
	return &wcpHITLAdapter{enq: enq}
}

// CreateApproval implements HITLApprovalCreator for WCP require_approval
// actions.
//
// Idempotency: request_id is derived from (workflow_id, step_id) with
// workflow_control.DeriveHITLApprovalID - a fixed-namespace UUID v5, stable
// across processes and restarts, and the SAME value the approve/reject
// response projects. Combined with the unique index on request_id
// (mig core/025:87) and the chokepoint's ON CONFLICT, concurrent first-time
// calls and re-gates alike resolve to exactly one row.
//
// The fallback to uuid.New() is reached only by a caller with no
// (workflow_id, step_id) pair in its request context, which is not a WCP step
// gate. It is preserved from the pre-existing enterprise adapter rather than
// turned into an error: refusing here would fail a governed pause closed with
// nothing for a reviewer to act on, which is the failure mode this whole
// change exists to remove.
func (a *wcpHITLAdapter) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	if a.enq == nil {
		return nil, fmt.Errorf("HITL enqueue chokepoint not available")
	}

	workflowID, _ := req.RequestContext["workflow_id"].(string)
	stepID, _ := req.RequestContext["step_id"].(string)

	var requestID uuid.UUID
	if derived := workflow_control.DeriveHITLApprovalID(workflowID, stepID); derived != "" {
		parsed, err := uuid.Parse(derived)
		if err != nil {
			// DeriveHITLApprovalID builds the value with uuid.NewSHA1, so
			// this is unreachable short of that function changing shape.
			// Handled rather than panicked (the pre-existing adapter used
			// uuid.MustParse here) because a panic in a governance gate takes
			// the orchestrator down for every tenant, not just this one.
			return nil, fmt.Errorf("derive HITL approval id for %s/%s: %w", workflowID, stepID, err)
		}
		requestID = parsed
	}

	row, outcome, err := a.enq.Enqueue(ctx, queue.Input{
		RequestID: requestID,
		OrgID:     req.OrgID,
		TenantID:  req.TenantID,
		ClientID:  req.ClientID,
		UserID:    req.UserID,
		// original_query carries the STEP NAME, not step input. That is the
		// pre-existing in-table convention for this request_type and it is
		// deliberate: hitl_approval_queue.original_query is copied verbatim
		// into WebhookEnvelope.OriginalQuery and POSTed to a
		// customer-configured notify_url on every terminal transition, so it
		// leaves the platform's retention and RLS boundary.
		OriginalQuery:       req.StepName,
		RequestType:         wcpHITLRequestType,
		RequestContext:      req.RequestContext,
		TriggeredPolicyID:   req.PolicyID,
		TriggeredPolicyName: req.PolicyName,
		TriggerReason:       req.TriggerReason,
		Severity:            req.Severity,
	})
	if err != nil {
		return nil, err
	}

	switch outcome {
	case queue.OutcomeReused:
		log.Printf("[WCP-HITL] Reusing existing approval %s for %s/%s (created %s)",
			row.RequestID, logutil.Sanitize(workflowID), logutil.Sanitize(stepID),
			row.CreatedAt.Format(time.RFC3339))
	default:
		log.Printf("[WCP-HITL] Created approval request: %s for step %s (expires %s)",
			row.RequestID, logutil.Sanitize(req.StepName), row.ExpiresAt.Format(time.RFC3339))
	}

	return &HITLApprovalResponse{
		ApprovalID: row.RequestID,
		Status:     row.Status,
		CreatedAt:  row.CreatedAt,
		ExpiresAt:  row.ExpiresAt,
		Enqueue:    string(outcome),
	}, nil
}

// classifyEnqueueFailure maps an enqueue error onto the machine-readable
// `approval_enqueue` value the step gate puts on the wire and on the audit
// row, plus the human-readable half.
//
// Every arm HOLDS the caller. Admitting the step because the review queue is
// full - or because the process is unlicensed - would turn a capacity limit
// or a licence gate into a governance bypass. What changes is that the
// refusal is now VISIBLE: previously wcp_policy_adapter.go logged the error
// to stdout and returned uuid.Nil, so the gate answered `require_approval`
// with no approval_id and nothing anywhere said why. That is the same
// invisible dead end #3509 documented on the FinCrime seam.
func classifyEnqueueFailure(err error) (outcome string, reason string) {
	switch {
	case errors.Is(err, queue.ErrPendingCapReached):
		return string(queue.OutcomeCapReached),
			"step is held: the tenant's pending-approval limit is reached, so no review entry could be created - " + err.Error()
	case errors.Is(err, queue.ErrTierDisabled):
		return string(queue.OutcomeTierDisabled),
			"step is held: this deployment's licence tier does not enable HITL approvals, so no review entry could be created"
	default:
		// GENERIC ON PURPOSE. err here wraps the driver's error - constraint
		// names, relation names, connection detail - and `reason` is
		// serialised as StepGateResponse.reason AND persisted on the audit
		// row. Before this change the failure was log.Printf-only, so
		// classifying it must not also publish it. The detail still reaches
		// the operator: wcp_policy_adapter.go logs the full error next to the
		// outcome, and axonflow_hitl_enqueue_total counts it.
		//
		// The two classified arms above are safe to be specific: neither
		// carries anything the caller did not already know about their own
		// tenant.
		return string(queue.OutcomeError),
			"step is held: the approval could not be queued (see approval_enqueue)"
	}
}
