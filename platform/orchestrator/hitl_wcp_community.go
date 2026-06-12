//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// Community + Evaluation HITL wiring for WCP.
// Community mode: HITL disabled (no queue).
// Evaluation mode: HITL enabled with 24h fixed expiry and pending limit.
//
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	logutil "axonflow/platform/shared/logger"

	"github.com/google/uuid"

	"axonflow/platform/agent"
	"axonflow/platform/agent/license"
)

// evalWCPHITLAdapter is the Evaluation tier HITL adapter for WCP.
// It creates HITL queue entries with a fixed 24h expiry and enforces pending limits.
type evalWCPHITLAdapter struct {
	db               *sql.DB
	expiryDuration   time.Duration
	maxPendingPerTenant int
}

// CreateApproval creates an HITL queue entry for WCP require_approval actions (Evaluation tier).
func (a *evalWCPHITLAdapter) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// Enforce pending approval limit
	var pendingCount int
	err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`,
		req.TenantID,
	).Scan(&pendingCount)
	if err != nil {
		return nil, fmt.Errorf("failed to check pending approvals: %w", err)
	}
	if pendingCount >= a.maxPendingPerTenant {
		return nil, fmt.Errorf("pending approval limit exceeded (%d/%d) - upgrade to Enterprise for unlimited approvals: https://getaxonflow.com/pricing", pendingCount, a.maxPendingPerTenant)
	}

	requestID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(a.expiryDuration)

	contextJSON, err := json.Marshal(req.RequestContext)
	if err != nil {
		contextJSON = []byte("{}")
	}

	query := `
		INSERT INTO hitl_approval_queue (
			request_id, org_id, tenant_id, client_id, user_id,
			original_query, request_type, request_context,
			triggered_policy_id, triggered_policy_name, trigger_reason,
			severity, status, created_at, expires_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11,
			$12, 'pending', $13, $14
		)
	`

	// v9 Phase 8 PR-C2 (#2384): hitl_approval_queue is mig 025 ENABLE RLS with
	// policy `org_id = get_current_org_id()`. Wrap so the INSERT WITH CHECK
	// sees the orgID under axonflow_app_role. req.OrgID is the canonical
	// post-Phase-6 identifier; the row's org_id column also gets it.
	if req.OrgID == "" {
		return nil, fmt.Errorf("HITLApprovalRequest.OrgID is required under RLS")
	}
	if wrapErr := agent.WithOrgScope(ctx, a.db, req.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			requestID,
			req.OrgID,
			req.TenantID,
			req.ClientID,
			req.UserID,
			req.StepName,
			"wcp_step_gate",
			contextJSON,
			req.PolicyID,
			req.PolicyName,
			req.TriggerReason,
			req.Severity,
			now,
			expiresAt,
		)
		return execErr
	}); wrapErr != nil {
		log.Printf("❌ [WCP-HITL-Eval] Failed to create approval: %v", wrapErr)
		return nil, fmt.Errorf("failed to create HITL approval: %w", wrapErr)
	}

	log.Printf("✅ [WCP-HITL-Eval] Created approval request: %s for step %s (expires %s)", requestID, logutil.Sanitize(req.StepName), expiresAt.Format(time.RFC3339))

	return &HITLApprovalResponse{
		ApprovalID: requestID,
		Status:     "pending",
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	}, nil
}

// InitializeWCPHITL initializes the HITL adapter for WCP.
// In Community mode (no license): HITL is disabled.
// In Evaluation mode: HITL is enabled with fixed 24h expiry and pending limits.
func InitializeWCPHITL(db *sql.DB, wcpAdapter *WCPPolicyAdapter) error {
	if wcpAdapter == nil {
		return nil
	}

	// Check if we have an eval license
	tier := license.GetCurrentTier(context.Background())
	if !license.IsEvaluationOrHigher(tier) {
		log.Println("ℹ️  WCP HITL disabled (Community mode) - require_approval actions will block but not queue")
		return nil
	}

	if db == nil {
		log.Println("⚠️  WCP HITL disabled (no database) - require_approval actions will block but not queue")
		return nil
	}

	limits := license.GetTierLimits(tier)
	adapter := &evalWCPHITLAdapter{
		db:                  db,
		expiryDuration:      time.Duration(limits.HITLExpiryHours) * time.Hour,
		maxPendingPerTenant: limits.MaxPendingApprovals,
	}
	wcpAdapter.SetHITLApproval(adapter)

	// Start auto-expiry goroutine for timed-out eval approvals.
	// The goroutine runs until the context is cancelled (server shutdown).
	ctx, cancel := context.WithCancel(context.Background())
	go runEvalApprovalExpiryLoop(ctx, db)

	// Store cancel func so it can be called on shutdown.
	// In practice the process exits and the goroutine is cleaned up,
	// but this makes the lifecycle explicit and testable.
	evalExpiryCancel = cancel

	log.Printf("✅ WCP HITL adapter initialized (Evaluation tier) - 24h expiry, max %d pending", limits.MaxPendingApprovals)
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
			"abort_reason": "Step " + ea.stepName + " auto-expired after 24h (Evaluation tier)",
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
