//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Community + Evaluation HITL wiring for WCP.
// Community mode: HITL disabled (no queue).
// Evaluation mode: HITL enabled with the tier's expiry and pending limit.
// The write path itself is edition-neutral - see hitl_wcp_adapter.go.
//
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"axonflow/platform/agent/hitl/queue"
	"axonflow/platform/agent/license"
)

// InitializeWCPHITL initializes the HITL adapter for WCP.
// In Community mode (no license): HITL is disabled.
// In Evaluation mode: HITL is enabled with the tier's expiry and pending limits.
//
// THE WRITE PATH MOVED, THE GATE DID NOT MOVE - IT MULTIPLIED. The
// IsEvaluationOrHigher check below still short-circuits the wiring so an
// unlicensed community process never even gets an adapter (and the log line
// an operator greps for is unchanged). The SAME gate is now also applied
// per-call inside queue.Enqueuer, which is what makes a licence that expires
// while the process is running take effect at the next gate instead of at the
// next restart.
//
// The adapter itself is the edition-neutral wcpHITLAdapter - see
// hitl_wcp_adapter.go for the three defects the eval-specific copy carried
// (a random request_id that did not match the one the approve/reject response
// projects, no dedup on re-gate, and no hitl_approval_history row).
func InitializeWCPHITL(db *sql.DB, wcpAdapter *WCPPolicyAdapter) error {
	if wcpAdapter == nil {
		return nil
	}

	if db == nil {
		log.Println("⚠️  WCP HITL disabled (no database) - require_approval actions will block but not queue")
		return nil
	}

	// THE EXPIRY SWEEPER STARTS REGARDLESS OF ENTITLEMENT, and it starts
	// BEFORE the tier check. It is what times out pending rows and aborts
	// their workflows, so an unentitled deployment that still HOLDS rows -
	// every Evaluation deployment upgrading across the 2026-08-26
	// Enterprise-only decision - needs it more than an entitled one, not
	// less. Starting it only when entitled left those rows pending for ever:
	// the phantom-row defect #3408 exists to close, reintroduced by the
	// entitlement change itself.
	//
	// The goroutine runs until the context is cancelled (server shutdown).
	ctx, cancel := context.WithCancel(context.Background())
	go runEvalApprovalExpiryLoop(ctx, db)
	evalExpiryCancel = cancel

	tier := license.GetCurrentTier(context.Background())
	limits := license.GetTierLimits(tier)
	expiry := time.Duration(limits.HITLExpiryHours) * time.Hour
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}

	// THE ADAPTER IS WIRED UNCONDITIONALLY, AS ON THE ENTERPRISE BUILD.
	//
	// R3 round 2: this function used to `return nil` here when the tier was
	// unentitled, leaving wcpAdapter.hitlApproval nil. wcp_policy_adapter.go
	// only enters the enqueue block `if ... && a.hitlApproval != nil`, so with
	// no adapter the gate was held with ApprovalEnqueue left "" - and the
	// field is `omitempty`, whose documented meaning is "no enqueue was
	// attempted, the ordinary case for an allow/block decision". The refusal
	// was therefore INDISTINGUISHABLE ON THE WIRE from an ordinary gate, which
	// is the exact ambiguity approval_enqueue was added to remove.
	//
	// The log line three lines below promised `tier_disabled`, the API spec
	// declares it in the enum, and two docs pages document it. All four were
	// describing the ENTERPRISE build: round 1 made that build wire
	// unconditionally and did not carry the same change here, so the two
	// editions disagreed about a field in the published contract, and the
	// edition that disagreed is the one an Evaluation licensee actually runs.
	//
	// Wiring unconditionally is also the position round 1 already argued for
	// on the enterprise twin: the refusal belongs at the per-call gate inside
	// queue.Enqueuer, where a licence renewed at runtime starts working at the
	// next gate rather than at the next restart. The cap and expiry read from
	// an unentitled tier are inert - no call gets past the gate to spend them.
	wcpAdapter.SetHITLApproval(newWCPHITLAdapter(queue.NewEnqueuer(db, queue.Config{
		Plane:               wcpHITLRequestType,
		MaxPendingApprovals: limits.MaxPendingApprovals,
		DefaultExpiry:       expiry,
	})))

	if !license.IsHITLApprovalEntitled(tier) {
		// Names the RESOLVED TIER, not a deployment mode. This line used to
		// read "(Community mode)", which is a lie to an operator holding a
		// valid Evaluation licence - and since the entitlement change,
		// Evaluation is exactly who reaches it.
		log.Printf("ℹ️  WCP HITL disabled by licence tier %q - require_approval actions will block "+
			"and report approval_enqueue=tier_disabled, creating no reviewer entry "+
			"(existing entries still expire and can still be approved or rejected)", string(tier))
		return nil
	}

	log.Printf("✅ WCP HITL adapter initialized (tier %s) - %s expiry, max %d pending per tenant (-1 = unlimited)",
		string(tier), expiry, limits.MaxPendingApprovals)
	return nil
}

// evalExpiryCancel is the cancel function for the eval approval expiry goroutine.
// Called during graceful shutdown to stop the background loop.
var evalExpiryCancel context.CancelFunc

// StopEvalApprovalExpiry stops the eval approval expiry goroutine.
// Safe to call even if the goroutine was never started (evalExpiryCancel == nil).
func StopEvalApprovalExpiry() {
	if evalExpiryCancel != nil {
		evalExpiryCancel()
	}
}

// runEvalApprovalExpiryLoop periodically checks for timed-out pending approvals and auto-expires them.
// Runs every 5 minutes until ctx is cancelled.
func runEvalApprovalExpiryLoop(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("ℹ️  [HITL-Expiry] Stopping eval approval expiry loop")
			return
		case <-ticker.C:
			expireEvalApprovals(db)
		}
	}
}

// expireEvalApprovals auto-EXPIRES timed-out pending approvals and aborts their
// workflows. A timeout is NOT a human rejection, so it MUST be recorded as
// status='expired', distinct from the explicit reject API path (service.RejectStep)
// which writes 'rejected'. Mislabeling timeouts as 'rejected' inflated the
// eu_ai_act_hitl_metrics rejected_count — the regulator-facing reject rate — with
// auto-timeouts (#2654, audit epic #2625 sibling #1).
//
// This path:
// 1. Updates hitl_approval_queue status to 'expired' (NOT 'rejected')
// 2. Updates workflow_steps.approval_status to 'expired' (NOT 'rejected')
// 3. Aborts the associated workflow
//
// The 'expired' value is permitted by the hitl_valid_status CHECK (migration 025)
// and matches the canonical expire_hitl_requests() SQL function. reviewed_at is
// intentionally NOT set: an auto-expiry is not a human review, so setting it would
// pollute the view's avg_review_time_seconds (which filters reviewed_at IS NOT NULL).
func expireEvalApprovals(db *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Find expired pending approvals with their request_context
	// (contains workflow_id and step_id for precise workflow_steps targeting).
	rows, err := db.QueryContext(ctx,
		`UPDATE hitl_approval_queue
		 SET status = 'expired', updated_at = NOW()
		 WHERE status = 'pending' AND expires_at < NOW()
		 RETURNING request_id, tenant_id, original_query, request_context`)
	if err != nil {
		log.Printf("⚠️  [HITL-Expiry] Failed to expire approvals: %v", err)
		return
	}
	defer rows.Close()

	type expiredApproval struct {
		requestID  string
		tenantID   string
		stepName   string
		workflowID string // from request_context
		stepID     string // from request_context
	}
	var expired []expiredApproval
	for rows.Next() {
		var ea expiredApproval
		var contextJSON []byte
		if err := rows.Scan(&ea.requestID, &ea.tenantID, &ea.stepName, &contextJSON); err != nil {
			log.Printf("⚠️  [HITL-Expiry] Failed to scan expired approval: %v", err)
			continue
		}
		// Extract workflow_id and step_id from request_context JSON
		if len(contextJSON) > 0 {
			var rc map[string]interface{}
			if err := json.Unmarshal(contextJSON, &rc); err == nil {
				if wid, ok := rc["workflow_id"].(string); ok {
					ea.workflowID = wid
				}
				if sid, ok := rc["step_id"].(string); ok {
					ea.stepID = sid
				}
			}
		}
		expired = append(expired, ea)
	}
	if err := rows.Err(); err != nil {
		log.Printf("⚠️  [HITL-Expiry] Row iteration error: %v", err)
	}

	if len(expired) == 0 {
		return
	}

	log.Printf("🕐 [HITL-Expiry] Auto-expired %d timed-out approval(s)", len(expired))

	// Step 2: For each expired approval, update workflow_steps and abort the workflow.
	// Uses workflow_id + step_id from request_context for precise targeting,
	// falling back to tenant + step_name if context is missing (legacy approvals).
	for _, ea := range expired {
		if ea.workflowID != "" && ea.stepID != "" {
			// Precise path: target exact workflow_step by (workflow_id, step_id).
			// approval_status='expired' (NOT 'rejected'): a timeout is not a human
			// reject. approved_by='system:auto-expired' is preserved as the system
			// actor marker (also matched by the fallback abort query below).
			_, err := db.ExecContext(ctx,
				`UPDATE workflow_steps
				 SET approval_status = 'expired', approved_by = 'system:auto-expired', approved_at = NOW()
				 WHERE workflow_id = $1
				 AND step_id = $2
				 AND approval_status = 'pending'`,
				ea.workflowID, ea.stepID)
			if err != nil {
				log.Printf("⚠️  [HITL-Expiry] Failed to update workflow_steps for %s: %v", ea.requestID, err)
			}
		} else {
			// Fallback for approvals created before workflow_id/step_id were stored in context.
			// Uses broader tenant + step_name matching (safe for legacy data only).
			log.Printf("⚠️  [HITL-Expiry] Approval %s missing workflow_id/step_id in context, using fallback matching", ea.requestID)
			_, err := db.ExecContext(ctx,
				`UPDATE workflow_steps ws
				 SET approval_status = 'expired', approved_by = 'system:auto-expired', approved_at = NOW()
				 FROM workflows w
				 WHERE ws.workflow_id = w.workflow_id
				 AND w.tenant_id = $1
				 AND ws.step_name = $2
				 AND ws.approval_status = 'pending'`,
				ea.tenantID, ea.stepName)
			if err != nil {
				log.Printf("⚠️  [HITL-Expiry] Failed to update workflow_steps (fallback) for %s: %v", ea.requestID, err)
			}
		}

		// Build abort reason with safe JSON encoding to prevent injection
		abortReason, _ := json.Marshal(map[string]string{
			"abort_reason": "Step " + ea.stepName + " auto-expired after its approval window",
		})

		if ea.workflowID != "" {
			// Precise path: abort the specific workflow
			_, err = db.ExecContext(ctx,
				`UPDATE workflows
				 SET status = 'aborted', completed_at = NOW(), updated_at = NOW(),
					 metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb
				 WHERE workflow_id = $2
				 AND status NOT IN ('completed', 'failed', 'aborted')`,
				string(abortReason), ea.workflowID)
			if err != nil {
				log.Printf("⚠️  [HITL-Expiry] Failed to abort workflow for %s: %v", ea.requestID, err)
			}
		} else {
			// Fallback: broader matching via step_name
			_, err = db.ExecContext(ctx,
				`UPDATE workflows
				 SET status = 'aborted', completed_at = NOW(), updated_at = NOW(),
					 metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb
				 WHERE workflow_id IN (
					 SELECT ws.workflow_id FROM workflow_steps ws
					 JOIN workflows w ON ws.workflow_id = w.workflow_id
					 WHERE w.tenant_id = $2
					 AND ws.step_name = $3
					 AND ws.approved_by = 'system:auto-expired'
				 ) AND status NOT IN ('completed', 'failed', 'aborted')`,
				string(abortReason), ea.tenantID, ea.stepName)
			if err != nil {
				log.Printf("⚠️  [HITL-Expiry] Failed to abort workflow (fallback) for %s: %v", ea.requestID, err)
			}
		}
	}
}
