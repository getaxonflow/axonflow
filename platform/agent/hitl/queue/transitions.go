// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

// THE STATE-TRANSITION WRITERS for hitl_approval_queue (#3714).
//
// writer.go made the count of authored `INSERT INTO hitl_approval_queue` ONE,
// because two duplicated CREATE writers had diverged unnoticed for seven
// months. It left the TRANSITIONS alone, and the transitions are the dangerous
// half:
//
//	a creation that diverges produces a malformed row, which is visible.
//	a transition that diverges approves, rejects or expires a request on one
//	path and not the other - the compliance record and the enforcement decision
//	disagree, and nothing is malformed enough to notice.
//
// WHAT WAS THERE BEFORE. Eight authored `UPDATE hitl_approval_queue` statements
// in the non-test tree: UpdateStatusSQL (already shared, in writer.go), and
// then Override, ExpireStaleReturning and ConsumeGrant duplicated ACROSS THE
// TWIN PAIR (platform/agent/hitl/repository.go and its ee/ overlay, six
// statements between them), plus expireEvalApprovals in
// platform/orchestrator/hitl_wcp_community.go.
//
// writer.go's own census said SIX and named five of them. It was written when
// that was true; ConsumeGrant arrived later (#3509) and nothing updated it. A
// hand-written census is bounded by the moment it was written, which is the
// argument for a guard derived from the TABLE NAME rather than from a list -
// see scripts/lint-hitl-queue-choke-point.sh, extended in the same change.
//
// WHY THE TWIN PAIR COLLAPSES HERE RATHER THAN BEING KEPT IN SYNC.
// platform/agent/Dockerfile copies ee/platform/agent/hitl/* OVER
// platform/agent/hitl/ for EDITION=enterprise, so the ee/ copy is what SHIPS
// while the platform/ copy is what the unit tests exercise. Nothing can make
// two files in that arrangement stay equal except a person remembering, and
// the ConsumeGrant predicate needed a twin-equality test because a person did
// not (both went with the grant path, #4254). This package carries no build
// tag and is not overlaid, so a statement
// that lives here exists ONCE for both.
//
// This file adds no new table, no new column and no new statement: every SQL
// string below is the statement that was already running, moved.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent/rls"
)

// ---------------------------------------------------------------------------
// Override
// ---------------------------------------------------------------------------

// ErrLostRace is returned by Override when the target row is absent or has
// already left `pending`.
//
// The concurrent-actor guard is `AND status = 'pending'` in the statement: a
// second caller that lost the race matches no row, so the service layer knows
// not to fire a duplicate terminal webhook. Distinct from ErrNotPending only in
// name - the two callers have historically used different sentinels and the
// repository maps this one onto its own ErrApprovalLostRace, which is the name
// its handler surfaces.
var ErrLostRace = errors.New("approval request is not pending (absent, or already resolved)")

// OverrideSQL moves a PENDING row to `overridden` and records the
// justification and the authorizing actor.
const OverrideSQL = `
		UPDATE hitl_approval_queue
		SET status = 'overridden',
			override_justification = $1,
			override_authorized_by = $2,
			updated_at = CURRENT_TIMESTAMP
		WHERE request_id = $3 AND status = 'pending'
		RETURNING updated_at`

// OverrideParams is one override.
type OverrideParams struct {
	OrgID         string
	RequestID     uuid.UUID
	Justification string
	AuthorizedBy  string
}

// Override runs OverrideSQL under an org scope. Returns ErrLostRace when no
// pending row matched.
func Override(ctx context.Context, db *sql.DB, p OverrideParams) error {
	if p.OrgID == "" {
		return fmt.Errorf("Override: OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	var updatedAt time.Time
	err := rls.WithOrgScope(ctx, db, p.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, OverrideSQL, p.Justification, p.AuthorizedBy, p.RequestID).Scan(&updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrLostRace
	}
	if err != nil {
		return fmt.Errorf("override approval request: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

// ExpireByIDsSQL marks a known set of rows expired.
//
// `expired`, NOT `rejected`: a timeout is not a human rejection, and
// mislabelling one inflated eu_ai_act_hitl_metrics.rejected_count - the
// regulator-facing reject rate - with auto-timeouts (#2654). reviewed_at is
// deliberately left unset for the same reason: an auto-expiry is not a human
// review, so setting it would pollute the view's avg_review_time_seconds, which
// filters `reviewed_at IS NOT NULL`.
const ExpireByIDsSQL = `
		UPDATE hitl_approval_queue
		SET status = 'expired', updated_at = CURRENT_TIMESTAMP
		WHERE id = ANY($1)
	`

// ExpireDueReturningSQL expires every PENDING row past its expires_at and
// returns what a sweeper needs to drive the downstream workflow abort.
//
// CROSS-TENANT BY NATURE, so it must run on a BYPASSRLS pool. Under
// axonflow_app_role with FORCE RLS and no org GUC set this statement matches
// ZERO ROWS AND REPORTS SUCCESS - the #3048 shape - which is exactly what
// #3520 recorded about platform/orchestrator's expireEvalApprovals: the
// Evaluation-tier auto-expiry has been inert on every app-role deployment, and
// the SaaS stacks are app-role deployments.
//
// The LIMIT is not decoration. Turning this sweeper on for the first time on an
// upgraded deployment finds every row that has sat falsely `pending` since the
// deployment moved to app_role, and expiring them all in one statement aborts
// their workflows in one transaction. Draining a backlog over successive ticks
// keeps the first tick after an upgrade the same size as every other tick.
// THE SUBSELECT MATCHES ON `id`, THE PRIMARY KEY - not on request_id (#3714 R3).
//
// R3 raised that matching `request_id IN (subselect)` is correct only because
// migrations/core/025:87 declares a global UNIQUE index on request_id: drop it,
// make it partial, or scope it per-org, and a second row sharing a request_id
// in ANY status is flipped to `expired` and returned to the caller, which then
// aborts that row's workflow. A real dependence on an artifact this file cannot
// see.
//
// THE OBVIOUS FIX WAS WRONG AND THE TEST CAUGHT IT. Adding `status = 'pending'`
// to the OUTER where - self-guarding, apparently free - BROKE THE BATCH BOUND:
// tick 1 expired 7 of 7 rows with LIMIT 3. A subquery carrying FOR UPDATE takes
// row locks, so PostgreSQL cannot hoist it into a once-only InitPlan; with a
// second outer predicate it becomes a SubPlan re-executed PER OUTER ROW, and
// each execution takes another LIMIT rows. The union is every row, and the
// blast-radius control that is the entire point of the #3520 change silently
// stops bounding anything.
//
// Matching on the PRIMARY KEY fixes the real problem instead: `id` is
// BIGSERIAL PRIMARY KEY, so uniqueness is guaranteed by the table's own
// definition rather than by a separate index, and the outer WHERE stays a
// single IN so the subselect runs ONCE.
const ExpireDueReturningSQL = `
		UPDATE hitl_approval_queue
		SET status = 'expired', updated_at = NOW()
		WHERE id IN (
			SELECT id FROM hitl_approval_queue
			WHERE status = 'pending' AND expires_at < NOW()
			ORDER BY expires_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING request_id, tenant_id, original_query, request_context`

// ExpireByIDs runs ExpireByIDsSQL inside a caller-supplied transaction.
//
// The transaction is the caller's because ExpireStaleReturning selects
// FOR UPDATE SKIP LOCKED, updates and writes history rows as ONE unit on an
// admin pool; handing it a *sql.DB here would break that atomicity.
// ids is []int64 and the pq.Array wrapping happens HERE, not at the call sites
// (#3714 R3). An `interface{}` parameter accepts a raw []int64, which lib/pq
// rejects at EXECUTE time with a driver error rather than at compile time - and
// this function is already the single choke point, so the one place that knows
// the statement is the place that should know its binding.
func ExpireByIDs(ctx context.Context, tx *sql.Tx, ids []int64) error {
	if len(ids) == 0 {
		// `= ANY('{}')` matches nothing, so this is a no-op either way; refused
		// explicitly because a caller reaching here with no ids has lost its
		// row set somewhere upstream and should not be told it succeeded.
		return fmt.Errorf("ExpireByIDs: no ids supplied")
	}
	if _, err := tx.ExecContext(ctx, ExpireByIDsSQL, pq.Array(ids)); err != nil {
		return fmt.Errorf("update expiring rows: %w", err)
	}
	return nil
}

// ExpireDueReturning runs ExpireDueReturningSQL on the supplied pool, which
// MUST be cross-tenant (BYPASSRLS). Returns the raw rows for the caller to
// scan, because what a sweeper needs from them is caller-specific.
//
// limit must be positive; a non-positive limit is refused rather than silently
// meaning "no limit", because an unbounded first tick is the blast radius this
// parameter exists to bound.
func ExpireDueReturning(ctx context.Context, adminDB *sql.DB, limit int) (*sql.Rows, error) {
	// DOUBLY GUARDED, and that is recorded rather than tidied (#3714 R3):
	// expireEvalApprovals returns on a nil db before reaching here, and
	// hitlExpirySweepPool returns nil rather than a nil-wrapped pool. So a
	// mutant deleting EITHER guard survives, and this diagnostic string can
	// never actually be printed by today's only caller. It is kept because this
	// is an exported function in a shared package: the next caller is not
	// obliged to have the same guard, and a cross-tenant sweep silently
	// matching nothing is the exact defect #3520 is about.
	if adminDB == nil {
		return nil, fmt.Errorf("ExpireDueReturning: adminDB is nil (a cross-tenant sweep needs a BYPASSRLS pool; under axonflow_app_role an RLS-scoped pool matches zero rows and reports success - #3048/#3520)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("ExpireDueReturning: limit must be positive, got %d", limit)
	}
	rows, err := adminDB.QueryContext(ctx, ExpireDueReturningSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("expire due approvals: %w", err)
	}
	return rows, nil
}
