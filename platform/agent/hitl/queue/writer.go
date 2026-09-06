// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package queue holds the ONE writer for `hitl_approval_queue` and
// `hitl_approval_history`, plus the enforcement chokepoint that fronts it on
// the WCP plane (see enqueuer.go).
//
// WHY THIS PACKAGE EXISTS AND WHY IT CARRIES NO BUILD TAG.
//
// Before #3408's sibling fix there were THREE non-test writers of
// `INSERT INTO hitl_approval_queue`:
//
//	platform/agent/hitl/repository.go        (//go:build enterprise) - behind hitl.Service
//	ee/platform/agent/hitl/repository.go     (overlay twin of the above)
//	platform/orchestrator/hitl_wcp_community.go   (//go:build !enterprise)
//	platform/orchestrator/hitl_wcp_enterprise.go  (//go:build enterprise)
//
// The last two were the bypass: the WCP step gate wrote the row itself and so
// skipped the licence-tier gate, the MaxPendingApprovals cap and the
// `hitl_approval_history` trail that hitl.Service applies to every other
// caller. #1998 closed the identical bypass for the MCP tool
// `axonflow_request_approval` by routing it through the Service.
//
// WHY THE SAME REMEDY WAS NOT USED, AND WHY THAT REASONING CHANGED.
//
// The original argument was that hitl.Service does not exist in the community
// build - platform/agent/hitl/hitl_community.go (//go:build !enterprise)
// defines Service.CreateApprovalRequest as an unconditional
// `return nil, ErrHITLApprovalDisabledByTier` - and that EVALUATION licensees
// run that binary, so routing through it would have made Evaluation-tier
// workflow approvals impossible rather than merely ungoverned.
//
// THAT ARGUMENT NO LONGER HOLDS. The 2026-08-26 operator decision made HITL
// Enterprise-only: the entitled set is Professional, Enterprise and Enterprise
// Plus, all of which run the ENTERPRISE binary, where hitl.Service is real.
// The community stub's unconditional refusal is now the CORRECT answer for
// every tier that binary can serve. Recorded rather than quietly deleted,
// because a comment that exists to stop someone deleting the code under it has
// to be right about the mechanism.
//
// THE PACKAGE STILL EARNS ITS PLACE, on two standing grounds that do not
// depend on which tiers are entitled:
//
//  1. It is what makes the count ONE. Routing through hitl.Service leaves the
//     statement in both Repository copies (platform/ and the ee/ overlay twin
//     that actually ships), so the tree carries two authored writers that must
//     be kept in lockstep by hand. There is now exactly ONE authored
//     `INSERT INTO hitl_approval_queue` in the entire non-test tree, and
//     scripts/lint-hitl-queue-choke-point.sh fails CI if a second appears.
//     That is the invariant #1998 shipped without, which is why these two
//     writers went unnoticed for seven months - they were added 2026-01-25
//     (#1082) and so already existed when #1998's fix landed 2026-05-07.
//  2. The community orchestrator still compiles hitl_wcp_community.go and
//     still has to REFUSE. A tag-free chokepoint gives it the same refusal,
//     with the same wording and the same counter, rather than a second
//     refusal path that can drift from the enterprise one.
//
// EDITION (HARD RULE 11, by reachability): this package is reached by the
// COMMUNITY orchestrator binary - not to serve approvals any more, but to
// refuse them - so it is Community code and lives under platform/. Nothing in
// it is enterprise-only; the tier gate it applies is a REFUSAL, and refusals
// belong on the side that ships to everybody.
package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/rls"
)

// RequestTypeWCPStepGate is the `request_type` stamped on the decide-plane row
// a WCP require_approval step gate writes.
//
// It is the single authored spelling: the orchestrator writes rows with it,
// the agent's actionable queue listing excludes it, and the agent's
// approve/reject refuses it. Three surfaces, one literal - a rename that
// reached only two of them is how #3408's mirror became invisible to its own
// resolution in the first place.
const RequestTypeWCPStepGate = "wcp_step_gate"

// insertStatement is the single authored INSERT for hitl_approval_queue.
//
// Both exported statements below are built from it, so the column list and
// the bind-parameter ordering exist once. scripts/lint-hitl-queue-choke-point.sh
// asserts that the literal `INSERT INTO hitl_approval_queue` appears in exactly
// this one non-test file.
//
// The 18 columns are the union every caller needs. The four a WCP step gate
// does not populate (eu_ai_act_article, compliance_framework,
// risk_classification, notify_url) bind NULL through nullString, which is what
// the pre-#3408 WCP INSERT achieved by omitting them from its column list.
// created_at/updated_at are deliberately NOT bound: migration core/025 defaults
// both to CURRENT_TIMESTAMP, so the row is stamped by the DATABASE clock. The
// pre-existing WCP writers bound the orchestrator process clock instead, which
// is the same class of defect as the password-reset expiry (#3510) - two
// clocks deciding one ordering.
const insertStatement = `
	INSERT INTO hitl_approval_queue (
		request_id, org_id, tenant_id, client_id, user_id,
		original_query, request_type, request_context,
		triggered_policy_id, triggered_policy_name, trigger_reason, severity,
		eu_ai_act_article, compliance_framework, risk_classification,
		status, expires_at, notify_url
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8,
		$9, $10, $11, $12,
		$13, $14, $15,
		$16, $17, $18
	)`

// InsertSQL is the plain (non-idempotent) form used by hitl.Repository.Create.
//
// Its RETURNING list is byte-for-byte what Repository.Create scanned before
// this package existed - deliberately, so no caller's Scan target and no
// sqlmock row set had to change when the statement moved here.
const InsertSQL = insertStatement + ` RETURNING id, created_at, updated_at`

// InsertIdempotentSQL is the form the WCP step gate needs: a caller-supplied
// deterministic request_id plus ON CONFLICT, so a re-gate or a concurrent
// first-time call returns the EXISTING row rather than double-listing the
// same approval.
//
// The conflict target is `request_id`, which migration core/025:87 backs with
// `CREATE UNIQUE INDEX idx_hitl_request_id`. DO UPDATE (rather than DO
// NOTHING) is load-bearing: DO NOTHING returns no row at all on conflict, so
// the caller could not learn the existing row's id without a second read and
// a race window. Assigning request_id to itself is the conventional no-op
// update that makes RETURNING fire on both arms.
//
// `(xmax = 0) AS inserted` distinguishes the two arms. On a real INSERT the
// new tuple's xmax is 0; on the DO UPDATE arm it carries the updating
// transaction's id. This is verified against a real PostgreSQL by
// TestEnqueueDistinguishesInsertFromConflict rather than trusted as folklore -
// the pre-existing enterprise adapter guessed at it with a one-second
// created_at heuristic, which silently mislabels a conflict that lands inside
// the same second.
const InsertIdempotentSQL = insertStatement + `
	ON CONFLICT (request_id) DO UPDATE SET
		request_id = hitl_approval_queue.request_id
	RETURNING id, request_id, status, created_at, updated_at, expires_at, (xmax = 0) AS inserted`

// InsertHistorySQL is the statement hitl.Repository.AddHistory and this
// package's Enqueuer both run.
//
// NOT THE ONLY ONE, and an earlier version of this comment said it was.
// Untruncated census, non-test: three authored `INSERT INTO
// hitl_approval_history` statements exist - this one, and one in each
// Repository copy's ExpireStaleReturning
// (platform/agent/hitl/repository.go, ee/platform/agent/hitl/repository.go),
// which writes its expiry rows on the admin pool inside its own cross-tenant
// transaction and so cannot share this org-scoped helper.
//
// scripts/lint-hitl-queue-choke-point.sh guards `INSERT INTO
// hitl_approval_queue` ONLY - its self-test pins that hitl_approval_history
// does not trip it - so nothing ratchets that count. Stated plainly rather
// than claimed away: a comment written to stop the next person adding a
// writer has to be right about how many there are.
const InsertHistorySQL = `
	INSERT INTO hitl_approval_history (
		request_id, org_id, tenant_id, action,
		actor_id, actor_email, actor_role, actor_ip,
		comment, justification,
		previous_status, new_status
	) VALUES (
		$1, $2, $3, $4,
		$5, $6, $7, $8,
		$9, $10,
		$11, $12
	) RETURNING id, created_at`

// UpdateStatusSQL moves a PENDING row to a terminal status and records the
// reviewer. hitl.Repository.UpdateStatus (both copies) runs it for the agent's
// approve/reject API, and ResolveMirror runs it for the WCP step-gate mirror.
//
// That sharing is the point, not a tidy-up. #3408's second half is a mirror
// row that "resolves in the test but not through the real portal"; making the
// workflow-plane resolution use the SAME statement the portal's own approve
// path uses removes the class of divergence where one of them updates a
// column the other forgets.
//
// IT IS NOT THE ONLY STATUS MUTATION on the table, and no version of this
// comment has ever been right about how many there are.
//
//	round 1: "this is the only one."                        Wrong: five others.
//	round 2: "six - this one, Override and ExpireStaleReturning in each
//	          Repository copy, and expireEvalApprovals."     Wrong: EIGHT. It
//	          was written before ConsumeGrant arrived (#3509) and nothing
//	          updated it, so it named five of the eight and asserted six.
//
// THAT IS WHY THE COUNT NO LONGER LIVES IN A COMMENT (#3714). Every statement
// that writes this table is now in this package - UpdateStatusSQL here,
// Override / ExpireByIDs / ExpireDueReturning / ConsumeGrant in
// transitions.go - and scripts/lint-hitl-queue-choke-point.sh counts them per
// file against an allow-list, matching every write VERB against the TABLE NAME
// rather than the one statement somebody thought of. A prose census is bounded
// by the day it was written; the guard is bounded by the table.
//
// The two writers OUTSIDE this package are both allow-listed by name with a
// justification, and neither is Go: the schema's own expire_hitl_requests()
// function, and one inert fixture. #3520's unscoped sweeper - which matched
// nothing under axonflow_app_role and reported success (#3048) - is gone: it
// runs ExpireDueReturning on a BYPASSRLS pool, or does not start.
//
// `AND status = 'pending'` is the concurrent-actor guard: a second caller that
// lost the race matches no row and gets ErrNotPending, so the service layer
// does not fire a duplicate terminal webhook.
const UpdateStatusSQL = `
	UPDATE hitl_approval_queue
	SET status = $1,
		reviewer_id = $2,
		reviewer_email = $3,
		reviewer_role = $4,
		review_comment = $5,
		reviewed_at = CURRENT_TIMESTAMP,
		updated_at = CURRENT_TIMESTAMP
	WHERE request_id = $6 AND status = 'pending'
	RETURNING updated_at`

// CountPendingSQL counts a tenant's pending approvals. It is the predicate the
// MaxPendingApprovals cap is measured with, and it is shared so the cap and
// any diagnostic that reports it cannot drift apart.
const CountPendingSQL = `SELECT COUNT(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`

// Params carries the 18 bound values for InsertSQL / InsertIdempotentSQL.
//
// It is a plain struct rather than a reference to hitl.ApprovalRequest because
// that type exists in three separate compilations (the enterprise
// platform/ copy, the ee/ overlay twin, and the community stub) and this
// package must not depend on any of them.
type Params struct {
	RequestID           uuid.UUID
	OrgID               string
	TenantID            string
	ClientID            string
	UserID              string
	OriginalQuery       string
	RequestType         string
	RequestContext      map[string]interface{}
	TriggeredPolicyID   string
	TriggeredPolicyName string
	TriggerReason       string
	Severity            string
	EUAIActArticle      string
	ComplianceFramework string
	RiskClassification  string
	Status              string
	ExpiresAt           time.Time
	NotifyURL           string
}

// Args renders p as the ordered bind list for InsertSQL / InsertIdempotentSQL.
//
// A nil/empty RequestContext binds the literal `{}` rather than SQL NULL,
// matching what every pre-existing writer did: mig 025 declares
// request_context JSONB and readers unmarshal it without a NULL check.
func Args(p Params) ([]interface{}, error) {
	contextJSON := []byte("{}")
	if p.RequestContext != nil {
		var err error
		contextJSON, err = json.Marshal(p.RequestContext)
		if err != nil {
			return nil, fmt.Errorf("marshal request context: %w", err)
		}
	}
	return []interface{}{
		p.RequestID,
		p.OrgID,
		p.TenantID,
		p.ClientID,
		nullString(p.UserID),
		p.OriginalQuery,
		p.RequestType,
		contextJSON,
		p.TriggeredPolicyID,
		p.TriggeredPolicyName,
		p.TriggerReason,
		p.Severity,
		nullString(p.EUAIActArticle),
		nullString(p.ComplianceFramework),
		nullString(p.RiskClassification),
		p.Status,
		p.ExpiresAt,
		nullString(p.NotifyURL),
	}, nil
}

// HistoryParams carries the 12 bound values for InsertHistorySQL.
type HistoryParams struct {
	RequestID      uuid.UUID
	OrgID          string
	TenantID       string
	Action         string
	ActorID        string
	ActorEmail     string
	ActorRole      string
	ActorIP        string
	Comment        string
	Justification  string
	PreviousStatus string
	NewStatus      string
}

// HistoryArgs renders h as the ordered bind list for InsertHistorySQL.
func HistoryArgs(h HistoryParams) []interface{} {
	return []interface{}{
		h.RequestID, h.OrgID, h.TenantID, h.Action,
		nullString(h.ActorID), nullString(h.ActorEmail), nullString(h.ActorRole), nullString(h.ActorIP),
		nullString(h.Comment), nullString(h.Justification),
		nullString(h.PreviousStatus), nullString(h.NewStatus),
	}
}

// Row is what the idempotent insert returns.
type Row struct {
	ID        int64
	RequestID uuid.UUID
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time
	// Inserted is true when this call created the row and false when it
	// matched an existing one via ON CONFLICT. It is the authority for
	// "should this attempt be charged against the pending cap", and for the
	// created/reused metric label.
	Inserted bool
}

// insertIdempotent runs InsertIdempotentSQL inside an already-open, already
// org-scoped transaction.
func insertIdempotent(ctx context.Context, tx *sql.Tx, p Params) (*Row, error) {
	args, err := Args(p)
	if err != nil {
		return nil, err
	}
	row := &Row{}
	if err := tx.QueryRowContext(ctx, InsertIdempotentSQL, args...).Scan(
		&row.ID, &row.RequestID, &row.Status,
		&row.CreatedAt, &row.UpdatedAt, &row.ExpiresAt, &row.Inserted,
	); err != nil {
		return nil, fmt.Errorf("insert approval request: %w", err)
	}
	return row, nil
}

// countPending runs CountPendingSQL inside an already-open, already org-scoped
// transaction.
//
// The org scope is not optional decoration. hitl_approval_queue is
// ENABLE ROW LEVEL SECURITY (mig core/025:199) with a policy keyed on
// `org_id = get_current_org_id()`, so under axonflow_app_role a bare COUNT
// reads 0 and the cap never engages - that was #3048, and the pending-approval
// limit was silently inert on the app-role deployments for its whole life.
func countPending(ctx context.Context, tx *sql.Tx, tenantID string) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, CountPendingSQL, tenantID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending approvals: %w", err)
	}
	return n, nil
}

// insertHistory runs InsertHistorySQL inside an already-open, already
// org-scoped transaction, discarding the RETURNING values the caller does not
// need.
func insertHistory(ctx context.Context, tx *sql.Tx, h HistoryParams) error {
	var id int64
	var createdAt time.Time
	if err := tx.QueryRowContext(ctx, InsertHistorySQL, HistoryArgs(h)...).Scan(&id, &createdAt); err != nil {
		return fmt.Errorf("insert approval history: %w", err)
	}
	return nil
}

// Insert executes the plain InsertSQL under an org scope and returns the
// RETURNING triple. hitl.Repository.Create (both the platform copy and the
// ee/ overlay twin) is its only caller.
//
// v9 Phase 8 #2384 PR-C1: the RLS INSERT WITH CHECK predicate is
// `org_id = current_setting('app.current_org_id')`, so the wrap must pin the
// same org the row stores.
func Insert(ctx context.Context, db *sql.DB, p Params) (id int64, createdAt, updatedAt time.Time, err error) {
	if p.OrgID == "" {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("Insert: OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	args, argErr := Args(p)
	if argErr != nil {
		return 0, time.Time{}, time.Time{}, argErr
	}
	err = rls.WithOrgScope(ctx, db, p.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, InsertSQL, args...).Scan(&id, &createdAt, &updatedAt)
	})
	if err != nil {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("insert approval request: %w", err)
	}
	return id, createdAt, updatedAt, nil
}

// InsertHistory executes InsertHistorySQL under an org scope.
// hitl.Repository.AddHistory (both copies) is its only caller.
func InsertHistory(ctx context.Context, db *sql.DB, h HistoryParams) (id int64, createdAt time.Time, err error) {
	if h.OrgID == "" {
		return 0, time.Time{}, fmt.Errorf("InsertHistory: OrgID must be non-empty (RLS on hitl_approval_history)")
	}
	err = rls.WithOrgScope(ctx, db, h.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, InsertHistorySQL, HistoryArgs(h)...).Scan(&id, &createdAt)
	})
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("insert approval history: %w", err)
	}
	return id, createdAt, nil
}

// CountPending executes CountPendingSQL under an org scope.
// hitl.Repository.CountPendingByTenant (both copies) is its only caller.
func CountPending(ctx context.Context, db *sql.DB, orgID, tenantID string) (int, error) {
	var n int
	if err := rls.WithOrgScope(ctx, db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		n, scanErr = countPending(ctx, tx, tenantID)
		return scanErr
	}); err != nil {
		return 0, err
	}
	return n, nil
}

// ErrNotPending is returned by UpdateStatus and ResolveMirror when the target
// row is absent or has already left `pending`.
//
// The two cases deliberately collapse: distinguishing them would require a
// prior read, and a caller that has one (hitl.Service does) can distinguish
// them itself. A caller that does not - the WCP mirror resolution - treats
// both as "nothing to resolve", which is correct for an already-terminal
// mirror and for a deployment whose adapter never wrote one.
var ErrNotPending = errors.New("approval request is not pending (absent, or already resolved)")

// StatusParams is one status mutation.
type StatusParams struct {
	OrgID         string
	RequestID     uuid.UUID
	Status        string
	ReviewerID    string
	ReviewerEmail string
	ReviewerRole  string
	Comment       string
}

func statusArgs(p StatusParams) []interface{} {
	return []interface{}{
		p.Status,
		nullString(p.ReviewerID),
		nullString(p.ReviewerEmail),
		nullString(p.ReviewerRole),
		nullString(p.Comment),
		p.RequestID,
	}
}

// UpdateStatus runs UpdateStatusSQL under an org scope. Returns ErrNotPending
// when no pending row matched.
func UpdateStatus(ctx context.Context, db *sql.DB, p StatusParams) error {
	if p.OrgID == "" {
		return fmt.Errorf("UpdateStatus: OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	var updatedAt time.Time
	err := rls.WithOrgScope(ctx, db, p.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, UpdateStatusSQL, statusArgs(p)...).Scan(&updatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotPending
	}
	if err != nil {
		return fmt.Errorf("update approval request status: %w", err)
	}
	return nil
}

// ResolveMirror resolves the decide-plane `wcp_step_gate` row that a WCP
// require_approval step gate wrote, when the WORKFLOW-plane step reaches a
// terminal approval state. Status flip and history entry land in ONE
// transaction.
//
// #3408: without this the mirror stayed `pending` forever. The workflow step
// was approved, the re-gate returned allow, the workflow ran - and the row
// that recorded the human-oversight event was still advertising an
// outstanding decision. It inflated the portal's pending badge permanently,
// and it made the EU AI Act Article 14 record say a review never concluded.
//
// WHY THE MIRROR IS RESOLVED RATHER THAN NOT WRITTEN AT ALL. #3408 offers
// both options. It must exist, for three reasons that are all live on main:
//
//   - It is the human-oversight evidence store. audit_cleanup.go:432 maps the
//     `hitl_oversight` data type onto hitl_approval_history, and the SEBI and
//     OJK regulator exports read this family. Dropping the row would remove
//     workflow gates from that record entirely.
//
//     Precisely, because "the EU AI Act Article 14 record" is broader than
//     this row earns: the view actually NAMED for that,
//     `eu_ai_act_hitl_metrics` (mig core/025), filters
//     `eu_ai_act_article IS NOT NULL`, and the WCP plane has never populated
//     that column - it is one of the four this statement binds NULL for. So
//     no workflow step-gate mirror has ever appeared in that view, before or
//     after this change. The history-table justification stands on its own
//     and does not need the view.
//
//   - The Evaluation-tier auto-expiry loop (hitl_wcp_community.go
//     expireEvalApprovals) drives workflow abortion FROM these rows. No row,
//     no 24h timeout.
//
//   - ee/examples/workflows/wcp-hitl/go/main.go asserts the row exists and is
//     pending. It is a shipped example and HARD RULE 8 applies to it.
//
// The DOUBLE-LISTING half of #3408 is fixed separately, by excluding this
// request_type from the agent's actionable pending queue - see
// hitl.Handler's queue listing. Resolution and exclusion are both needed:
// exclusion stops one gate rendering as two rows while pending, resolution
// stops the row outliving the decision.
//
// ErrNotPending is returned (not an error the caller must surface) when there
// is nothing to resolve: a community deployment with no adapter wired never
// wrote a mirror, and a second approve attempt finds it already terminal.
func ResolveMirror(ctx context.Context, db *sql.DB, p StatusParams, tenantID string) error {
	if p.OrgID == "" {
		return fmt.Errorf("ResolveMirror: OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	prevStatus := "pending"
	err := rls.WithOrgScope(ctx, db, p.OrgID, func(tx *sql.Tx) error {
		var updatedAt time.Time
		if scanErr := tx.QueryRowContext(ctx, UpdateStatusSQL, statusArgs(p)...).Scan(&updatedAt); scanErr != nil {
			if errors.Is(scanErr, sql.ErrNoRows) {
				return ErrNotPending
			}
			return fmt.Errorf("resolve mirror status: %w", scanErr)
		}
		return insertHistory(ctx, tx, HistoryParams{
			RequestID:      p.RequestID,
			OrgID:          p.OrgID,
			TenantID:       tenantID,
			Action:         p.Status,
			ActorID:        p.ReviewerID,
			ActorEmail:     p.ReviewerEmail,
			ActorRole:      p.ReviewerRole,
			Comment:        p.Comment,
			PreviousStatus: prevStatus,
			NewStatus:      p.Status,
		})
	})
	if errors.Is(err, ErrNotPending) {
		return ErrNotPending
	}
	return err
}

// capLockKey derives the advisory-lock key that serialises cap accounting for
// one (org, tenant) pair.
//
// Computed in Go with FNV-1a rather than in SQL with hashtext(): hashtext is
// an undocumented internal and its output is not contracted across major
// versions, whereas this value only has to be stable within one running
// cluster and identical across the processes contending for it.
//
// Two orgs colliding on the same key costs a little contention and nothing
// else - the lock only orders the count-then-insert pair, it is not part of
// any correctness predicate.
func capLockKey(orgID, tenantID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(orgID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tenantID))
	// Reinterpret as signed: pg_advisory_xact_lock(bigint) takes int8, and a
	// uint64 above math.MaxInt64 would overflow the driver's int64 encoding.
	return int64(h.Sum64())
}

// nullString maps "" to SQL NULL, matching every pre-existing writer's
// treatment of the optional columns.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
