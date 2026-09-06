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
	// ...but it starts ONLY WITH A CROSS-TENANT POOL (#3520). The goroutine
	// runs until the context is cancelled (server shutdown).
	// ONE SWEEPER, AND IT OWNS ITS POOL (#3520 R3).
	//
	// Two defects the first cut had, both reachable from a second
	// InitializeWCPHITL - which a test harness and a licence reload both do:
	// the previous goroutine was ORPHANED (evalExpiryCancel was overwritten,
	// so nothing could ever cancel it) and its BYPASSRLS pool was LEAKED (two
	// axonflow_platform_admin connections per call, never closed). Two live
	// sweepers do not corrupt anything - FOR UPDATE SKIP LOCKED keeps them off
	// each other's rows - but they double the effective batch rate, which
	// defeats the bound that exists to make the first tick after an upgrade
	// survivable.
	if evalExpiryCancel != nil {
		StopEvalApprovalExpiry()
	}
	if sweepDB := hitlExpirySweepPool(db); sweepDB != nil {
		ctx, cancel := context.WithCancel(context.Background())
		// Only a pool WE opened is ours to close, and that answer is CAPTURED
		// AT LAUNCH rather than read from a global later:
		// hitlExpirySweepPool returns the caller's own db when app-role is off,
		// and closing that would take the orchestrator's main pool down with
		// the sweeper.
		go runEvalApprovalExpiryLoop(ctx, sweepDB, sweepDB != db)
		evalExpiryCancel = cancel
	}

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

// StopEvalApprovalExpiry stops the eval approval expiry goroutine and releases
// the pool it opened.
//
// Safe to call when nothing was started, and safe to call twice - both fields
// are cleared, so a second call is a no-op rather than a double Close.
//
// KNOWN, and stated rather than implied: this has no production caller. It is
// invoked by tests and by a re-initialisation; the orchestrator does not run a
// graceful-shutdown hook that reaches it, so on a real shutdown the process
// exit is what releases both. That is pre-existing (#3520 did not introduce it)
// and is why the re-init path above calls it explicitly rather than relying on
// anyone else to.
func StopEvalApprovalExpiry() {
	if evalExpiryCancel != nil {
		evalExpiryCancel()
		evalExpiryCancel = nil
	}
	// The pool is NOT closed here - the goroutine closes it on its way out, once
	// its last query has run. See runEvalApprovalExpiryLoop.
}

// evalExpiryBatchSize bounds ONE tick of the sweeper.
//
// #3520: this sweep has been INERT on every app-role deployment since v9 - a
// cross-tenant UPDATE with no org scope matches zero rows under FORCE RLS and
// reports success (#3048). Turning it on therefore finds, on the first tick
// after an upgrade, every approval that has sat falsely `pending` for as long
// as that deployment has been on app_role - and each one aborts a workflow.
//
// A batch bound makes the first tick after an upgrade the same size as every
// other tick: the backlog drains over successive five-minute ticks instead of
// in one transaction. 200 is the count of workflows one tick may abort, chosen
// to be larger than any plausible steady-state five-minute expiry volume (a
// deployment expiring more than 200 approvals per five minutes has a
// configuration problem the sweeper should not be masking) and small enough
// that a first-run backlog is visible in the log as a sequence of full batches
// rather than as one silent avalanche.
const evalExpiryBatchSize = 200

// runEvalApprovalExpiryLoop periodically checks for timed-out pending approvals and auto-expires them.
// Runs every 5 minutes until ctx is cancelled.
//
// sweepDB MUST be cross-tenant (BYPASSRLS). See expireEvalApprovals.
func runEvalApprovalExpiryLoop(ctx context.Context, sweepDB *sql.DB, ownsPool bool) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	// THE GOROUTINE CLOSES ITS OWN POOL, after its last use (#3520 R3 round 2).
	//
	// StopEvalApprovalExpiry used to Close() it directly, but cancel() is not
	// observed until the next select - it does NOT interrupt a sweep already
	// running - so the Close landed mid-sweep. Go lets started queries finish
	// and fails every SUBSEQUENT one with ErrDBClosed, and this function runs
	// the expiring UPDATE first and the per-row workflow aborts afterwards. The
	// result is rows marked `expired` whose workflows are still running: the
	// exact divergence expireEvalApprovals exists to prevent, produced by its
	// own shutdown path.
	//
	// Closing here happens after the loop has returned, so no query can follow.
	// ownsPool is a PARAMETER, not the package global it started as (#3520 R3).
	//
	// Two reasons, and the second is the one that matters. The global was read
	// from INSIDE this goroutine, so a second InitializeWCPHITL - which a test
	// harness and a licence reload both do - would rewrite it under a sweeper
	// still running, and the old goroutine would then decide whether to close
	// ITS pool by reading the NEW sweeper's answer. Nothing synchronises those
	// two writes. Captured at launch, the question each goroutine asks is about
	// its own pool. (The first reason is smaller: the global had no remaining
	// reader once the close moved here, and `unused` reds the required Lint
	// Summary - on the UNTAGGED arm only, because this file is !enterprise.)
	defer func() {
		if sweepDB != nil && ownsPool {
			_ = sweepDB.Close()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Println("ℹ️  [HITL-Expiry] Stopping eval approval expiry loop")
			return
		case <-ticker.C:
			expireEvalApprovals(sweepDB)
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
// db MUST be a cross-tenant (BYPASSRLS) pool: every statement in this function
// operates across tenants, and on an RLS-scoped pool they all silently match
// nothing. InitializeWCPHITL opens axonflow_platform_admin for it and REFUSES
// TO START THE SWEEPER when it cannot (#3520), rather than starting one that
// reports success while doing nothing.
func expireEvalApprovals(db *sql.DB) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: Find expired pending approvals with their request_context
	// (contains workflow_id and step_id for precise workflow_steps targeting).
	//
	// THE STATEMENT MOVED TO platform/agent/hitl/queue (#3714) and THE POOL
	// CHANGED (#3520). Both matter and they are the same defect from two sides:
	//
	//   - the statement was the eighth authored `UPDATE hitl_approval_queue` in
	//     a tree whose chokepoint guarded only INSERT, so it could and did
	//     diverge from the transitions the agent plane runs;
	//   - it ran on whatever pool InitializeWCPHITL was handed, which under
	//     AXONFLOW_DB_USE_APP_ROLE=true is axonflow_app_role. A cross-tenant
	//     UPDATE with no org GUC set matches ZERO ROWS AND REPORTS SUCCESS
	//     under FORCE RLS - the #3048 shape - so the Evaluation-tier 24h
	//     auto-expiry has done nothing at all on every app-role deployment,
	//     which the SaaS stacks are. It was recorded in
	//     platform/agent/rls_write_audit_test.go's allow-list as "runtime needs
	//     admin-pool plumbing... filed for follow-up". This is that plumbing.
	rows, err := queue.ExpireDueReturning(ctx, db, evalExpiryBatchSize)
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
	// updated counts rows THE STATEMENT RETURNED; expired counts rows that also
	// SCANNED. They are not the same number and the difference is load-bearing
	// (#3520 R3): a scan error `continue`s, so a full 200-row batch containing
	// one unparseable row leaves len(expired) == 199. Deriving "was this batch
	// full" from the parsed slice therefore reports a below-batch number - the
	// operator reads it as "the backlog is drained" while 200 rows were expired
	// and more remain. The batch-full signal must count what the database did,
	// not what this loop understood.
	updated := 0
	var expired []expiredApproval
	for rows.Next() {
		updated++
		var ea expiredApproval
		var contextJSON []byte
		if err := rows.Scan(&ea.requestID, &ea.tenantID, &ea.stepName, &contextJSON); err != nil {
			log.Printf("⚠️  [HITL-Expiry] Failed to scan expired approval: %v (the row IS expired; "+
				"its workflow will NOT be aborted by this tick)", err)
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

	if updated == 0 {
		return
	}
	if len(expired) != updated {
		// Rows were expired that this tick cannot follow up on. Said out loud:
		// the queue row is terminal but its workflow is still running, which is
		// the inverse of the phantom-row defect and just as invisible.
		log.Printf("⚠️  [HITL-Expiry] %d of %d expired row(s) failed to scan; their workflows are "+
			"NOT aborted and will not be retried - the rows are no longer pending", updated-len(expired), updated)
	}

	// A FULL BATCH means there is more to do and the next tick will do it. Said
	// out loud because the alternative reading of a steady 200 - "we expire
	// exactly 200 approvals every five minutes" - is the one an operator would
	// otherwise reach on the day an upgrade turns this sweeper on for the first
	// time and it starts draining a backlog (#3520).
	if updated == evalExpiryBatchSize {
		// A FULL BATCH means more remain, and the log says HOW MANY rather than
		// just "more" (#3520 R3). Without the remaining count, a one-time
		// backlog draining and a deployment PERMANENTLY behind the arrival rate
		// produce byte-identical lines - and the second is the dangerous one,
		// because the sweeper is the only thing that aborts a timed-out
		// workflow, so a permanent deficit means approvals sit past expires_at
		// for ever with their workflows still running.
		//
		// One extra COUNT, only on a full batch, on the same cross-tenant pool.
		// It is advisory: a failure logs and does not stop the tick.
		remaining := -1
		_ = db.QueryRowContext(ctx,
			`SELECT count(*) FROM hitl_approval_queue WHERE status = 'pending' AND expires_at < NOW()`,
		).Scan(&remaining)
		log.Printf("🕐 [HITL-Expiry] Auto-expired %d timed-out approval(s) - BATCH FULL, %d still due. "+
			"If this number does not FALL across ticks, arrivals exceed %d per 5 minutes and the "+
			"sweeper is permanently behind: timed-out approvals stay pending and their workflows are "+
			"never aborted. (-1 = the backlog count itself failed.)",
			updated, remaining, evalExpiryBatchSize)
	} else {
		log.Printf("🕐 [HITL-Expiry] Auto-expired %d timed-out approval(s)", updated)
	}

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
