// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build !enterprise

// Real-Postgres proof for #2654: the Evaluation-tier auto-timeout path
// (expireEvalApprovals) must record status='expired' on hitl_approval_queue, and
// the regulator-facing eu_ai_act_hitl_metrics view (migration 025) must therefore
// bucket the timed-out request as expired_count, NOT rejected_count.
//
// This file carries the same //go:build !enterprise tag as the function under
// test (hitl_wcp_community.go). Gated on TEST_PG_INTEGRATION=1 + docker.

package orchestrator

import (
	"database/sql"
	"testing"

	"axonflow/platform/agent/approletest"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// TestExpireEvalApprovals_MetricBucketsExpiredNotRejected_RealPostgres inserts a
// pending EU-AI-Act HITL approval that is already past expiry, runs the production
// auto-timeout path against a REAL Postgres with the REAL migration-025 schema +
// view, and asserts:
//   - the queue row's status is 'expired' (NOT 'rejected');
//   - the eu_ai_act_hitl_metrics view reports rejected_count=0 + expired_count=1
//     for the org — i.e. the timeout does not inflate the human reject rate.
//
// Red-on-revert: reverting the queue UPDATE's SET clause to status='rejected'
// flips the view to rejected_count=1 / expired_count=0 and fails the assertions.
func TestExpireEvalApprovals_MetricBucketsExpiredNotRejected_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	// Master DSN is the postgres superuser (BYPASSRLS), matching the agent's
	// migration-time pool; expireEvalApprovals issues unscoped UPDATEs.
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = db.Close() }()

	const orgID = "hitl-2654-expiry-org"
	reqID := uuid.New().String()

	// A pending, already-expired Article-14 approval. eu_ai_act_article must be
	// set: the metrics view filters WHERE eu_ai_act_article IS NOT NULL.
	if _, err := db.Exec(`
		INSERT INTO hitl_approval_queue (
			request_id, org_id, tenant_id, client_id, user_id,
			original_query, request_type, request_context,
			triggered_policy_id, triggered_policy_name, trigger_reason,
			severity, status, eu_ai_act_article, created_at, expires_at
		) VALUES (
			$1, $2, $2, 'client-1', 'user-1',
			'sensitive request', 'wcp_step_gate', '{}'::jsonb,
			'pol-1', 'High-Risk Gate', 'auto-expiry metric test',
			'high', 'pending', '14', NOW() - INTERVAL '48 hours', NOW() - INTERVAL '24 hours'
		)`, reqID, orgID); err != nil {
		t.Fatalf("seed pending approval: %v", err)
	}

	// Production auto-timeout path under test.
	expireEvalApprovals(db)

	// 1) The durable queue row is 'expired', not 'rejected'.
	var status string
	if err := db.QueryRow(
		`SELECT status FROM hitl_approval_queue WHERE request_id = $1`, reqID,
	).Scan(&status); err != nil {
		t.Fatalf("read back status: %v", err)
	}
	if status != "expired" {
		t.Fatalf("queue status = %q, want 'expired' (timeout must not be a reject)", status)
	}

	// 2) reviewed_at must remain NULL — an auto-expiry is not a human review, so
	//    it must not contribute to the view's avg_review_time_seconds.
	var reviewedAt sql.NullTime
	if err := db.QueryRow(
		`SELECT reviewed_at FROM hitl_approval_queue WHERE request_id = $1`, reqID,
	).Scan(&reviewedAt); err != nil {
		t.Fatalf("read back reviewed_at: %v", err)
	}
	if reviewedAt.Valid {
		t.Errorf("reviewed_at = %v, want NULL on auto-expiry (would pollute avg_review_time)", reviewedAt.Time)
	}

	// 3) The regulator-facing metric view buckets it as expired, not rejected.
	var rejected, expired int
	if err := db.QueryRow(`
		SELECT COALESCE(SUM(rejected_count), 0), COALESCE(SUM(expired_count), 0)
		FROM eu_ai_act_hitl_metrics WHERE org_id = $1`, orgID,
	).Scan(&rejected, &expired); err != nil {
		t.Fatalf("query eu_ai_act_hitl_metrics: %v", err)
	}
	if rejected != 0 {
		t.Errorf("rejected_count = %d, want 0 (timeout must not inflate the human reject rate)", rejected)
	}
	if expired != 1 {
		t.Errorf("expired_count = %d, want 1", expired)
	}
}
