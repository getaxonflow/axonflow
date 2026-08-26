// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3408: resolve the decide-plane HITL mirror when the workflow-plane step
// resolves. Edition-neutral - the defect and the fix are identical on both.

package orchestrator

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/google/uuid"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"
)

// wcpHITLMirrorResolver implements workflow_control.HITLMirrorResolver.
type wcpHITLMirrorResolver struct {
	db *sql.DB
}

// ResolveStepMirror flips the `wcp_step_gate` row for (workflowID, stepID) to
// a terminal status and writes its hitl_approval_history entry.
//
// The row is addressed by workflow_control.DeriveHITLApprovalID - the same
// fixed-namespace UUID v5 the adapter wrote it under and the same value the
// approve/reject HTTP response projects as `approval_id`. There is no lookup
// and no scan: the identifier is a pure function of the pair, so this cannot
// resolve the wrong row and cannot miss a row whose id drifted.
//
// WHY NOT REUSE hitl.Repository.UpdateStatus, WHICH DOES THE SAME UPDATE.
// Two reasons, both structural rather than stylistic:
//
//   - hitl.Repository is `//go:build enterprise`, so it does not exist in the
//     community binary, which still compiles this resolver and still has to
//     resolve mirrors written BEFORE a licence downgrade. (Until the
//     2026-08-26 operator decision the sharper reason was that Evaluation ran
//     that binary AND wrote mirrors; Evaluation is no longer entitled to HITL,
//     so the standing reason is the leftover-rows one.)
//   - The agent process constructs the Repository with a BYPASSRLS lookup
//     pool for its by-id discovery reads; the orchestrator has no such HITL
//     wiring and needs none, because this path already knows the org.
//
// What IS shared is the statement itself: queue.ResolveMirror runs
// queue.UpdateStatusSQL, the same UPDATE the agent's approve/reject API runs.
// So "resolves in the test but not through the real portal" is not a shape
// this can take - the portal's own path and this path are one statement.
func (r *wcpHITLMirrorResolver) ResolveStepMirror(ctx context.Context, orgID, tenantID, workflowID, stepID, status, reviewerID, comment string) {
	if r == nil || r.db == nil {
		return
	}
	derived := workflow_control.DeriveHITLApprovalID(workflowID, stepID)
	if derived == "" {
		return
	}
	requestID, err := uuid.Parse(derived)
	if err != nil {
		log.Printf("[WCP-HITL] mirror resolve: cannot parse derived approval id for %s/%s: %v",
			logutil.Sanitize(workflowID), logutil.Sanitize(stepID), err)
		return
	}
	if orgID == "" {
		// The mirror's RLS wrap refuses an empty org outright
		// (rls.WithOrgScope), so calling on would produce a guaranteed error
		// rather than an attempt. Report it as the wiring defect it is: a
		// workflow row with no org_id is the reason a mirror would be left
		// pending here, and silence is what #3408 was made of.
		log.Printf("[WCP-HITL] mirror resolve SKIPPED for %s/%s: workflow carries no org_id",
			logutil.Sanitize(workflowID), logutil.Sanitize(stepID))
		queue.RecordMirrorResolve("no_org")
		return
	}

	// migrations/core/025:77 declares
	//   CHECK (status NOT IN ('approved','rejected') OR reviewer_id IS NOT NULL)
	// and an empty reviewer binds SQL NULL, so an unattributed approval would
	// fail the mirror resolution with a 23514 and leave the row pending - #3408
	// unfixed, on the one route that produces it.
	//
	// That route is real, not hypothetical: run.go's plan-resume handler passes
	// r.Header.Get("X-User-ID") with no fallback, and the identity headers are
	// STRIPPED unless AXONFLOW_TRUST_IDENTITY_HEADERS is on - which is the
	// default. Every other approve path substitutes "system"
	// (workflow_control/handlers.go:785 and :866, map_hitl_adapter.go:259 and
	// :447); that gap is fixed at its source too, and this is the fail-safe
	// backstop so a future caller cannot reintroduce it.
	//
	// "system" is the honest record of an unattributable approval, and it is
	// the value every one of the four approve/reject call sites substitutes,
	// so on the ordinary paths workflow_steps.approved_by carries it too.
	//
	// NOT GUARANTEED to match, and the difference matters exactly here:
	// repo.UpdateStepApproval writes approved_by verbatim, so a FUTURE caller
	// that reaches ApproveStep with an empty actor would store "" there while
	// this backstop stores "system". That divergence is the price of the
	// backstop existing at all - the alternative is a mirror that fails its
	// CHECK and stays pending - and it is strictly better than the two rows
	// disagreeing about whether a decision was made.
	if reviewerID == "" {
		reviewerID = "system"
	}

	err = queue.ResolveMirror(ctx, r.db, queue.StatusParams{
		OrgID:     orgID,
		RequestID: requestID,
		Status:    status,
		// The workflow plane records ONE reviewer identity string
		// (workflow_steps.approved_by, resolved header-authoritatively by
		// workflow_control.Handler.getUserID / mapHITLActorIdentity). It is
		// written to both reviewer_id and reviewer_email because the decide
		// plane splits what this plane does not, and dropping it into only
		// one of them would make the same human look like two different
		// reviewers depending on which surface the auditor reads.
		ReviewerID:    reviewerID,
		ReviewerEmail: reviewerID,
		ReviewerRole:  "workflow_approver",
		Comment:       comment,
	}, tenantID)

	switch {
	case err == nil:
		log.Printf("[WCP-HITL] mirror %s resolved to %s for %s/%s",
			requestID, status, logutil.Sanitize(workflowID), logutil.Sanitize(stepID))
		queue.RecordMirrorResolve(status)
	case errors.Is(err, queue.ErrNotPending):
		// Normal: no adapter was wired when the gate fired, or a second
		// approve attempt found the mirror already terminal. Counted rather
		// than logged at WARN so an operator can still see if it becomes the
		// common case.
		queue.RecordMirrorResolve("not_pending")
	default:
		log.Printf("[WCP-HITL] mirror resolve FAILED for %s/%s (approval %s): %v",
			logutil.Sanitize(workflowID), logutil.Sanitize(stepID), requestID, err)
		queue.RecordMirrorResolve("error")
	}
}
