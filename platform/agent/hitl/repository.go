// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue Repository
// EU AI Act Article 14 - Human Oversight API Data Access Layer

//go:build enterprise

package hitl

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent/rls"

	"axonflow/platform/shared/tenantscope"
)

// ApprovalRequest represents a pending approval request in the HITL queue.
type ApprovalRequest struct {
	ID                   int64                  `json:"id"`
	RequestID            uuid.UUID              `json:"request_id"`
	OrgID                string                 `json:"org_id"`
	TenantID             string                 `json:"tenant_id"`
	ClientID             string                 `json:"client_id"`
	UserID               string                 `json:"user_id,omitempty"`
	OriginalQuery        string                 `json:"original_query"`
	RequestType          string                 `json:"request_type"`
	RequestContext       map[string]interface{} `json:"request_context,omitempty"`
	TriggeredPolicyID    string                 `json:"triggered_policy_id"`
	TriggeredPolicyName  string                 `json:"triggered_policy_name"`
	TriggerReason        string                 `json:"trigger_reason"`
	Severity             string                 `json:"severity"`
	EUAIActArticle       string                 `json:"eu_ai_act_article,omitempty"`
	ComplianceFramework  string                 `json:"compliance_framework,omitempty"`
	RiskClassification   string                 `json:"risk_classification,omitempty"`
	Status               string                 `json:"status"`
	ReviewerID           string                 `json:"reviewer_id,omitempty"`
	ReviewerEmail        string                 `json:"reviewer_email,omitempty"`
	ReviewerRole         string                 `json:"reviewer_role,omitempty"`
	ReviewComment        string                 `json:"review_comment,omitempty"`
	ReviewedAt           *time.Time             `json:"reviewed_at,omitempty"`
	OverrideJustify      string                 `json:"override_justification,omitempty"`
	OverrideAuthorizedBy string                 `json:"override_authorized_by,omitempty"`
	NotifyURL            string                 `json:"notify_url,omitempty"`
	ExpiresAt            time.Time              `json:"expires_at"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// ApprovalHistory represents an immutable audit trail entry.
type ApprovalHistory struct {
	ID             int64     `json:"id"`
	RequestID      uuid.UUID `json:"request_id"`
	OrgID          string    `json:"org_id"`
	TenantID       string    `json:"tenant_id"`
	Action         string    `json:"action"`
	ActorID        string    `json:"actor_id,omitempty"`
	ActorEmail     string    `json:"actor_email,omitempty"`
	ActorRole      string    `json:"actor_role,omitempty"`
	ActorIP        string    `json:"actor_ip,omitempty"`
	Comment        string    `json:"comment,omitempty"`
	Justification  string    `json:"justification,omitempty"`
	PreviousStatus string    `json:"previous_status,omitempty"`
	NewStatus      string    `json:"new_status,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// PendingStats represents dashboard metrics for pending approvals.
type PendingStats struct {
	TotalPending       int64    `json:"total_pending"`
	HighPriority       int64    `json:"high_priority"`
	CriticalPriority   int64    `json:"critical_priority"`
	OldestPendingHours *float64 `json:"oldest_pending_hours,omitempty"`
}

// ListFilter defines filters for listing approval requests.
type ListFilter struct {
	Status   []string
	Severity []string
	PolicyID string
	ClientID string
	UserID   string
	// OrgID scopes the listing to one organization (#3048 R3 BLOCKER-2).
	// The HTTP handler always sets it from the middleware-derived X-Org-ID;
	// an empty value is the deployment-wide ops view (internal callers on
	// owner/admin pools only).
	OrgID    string
	Limit    int
	Offset   int
	OrderBy  string
	OrderDir string
}

// Repository provides data access for HITL queue operations.
type Repository struct {
	db *sql.DB
	// lookupDB serves the by-request-id DISCOVERY reads (GetByRequestID,
	// GetHistory) and the queue List: the row itself establishes which org
	// an approval belongs to, so no GUC can be set first — under
	// axonflow_app_role the bare reads matched 0 rows through mig 025's RLS
	// and every approve/reject/override flow died on "approval request not
	// found" (#3048). Route through the BYPASSRLS admin pool (same trust
	// shape as execution repo lookups, #3039). BYPASSRLS means the SQL/Go
	// layers own tenancy here: List carries a mandatory-from-the-handler
	// org predicate, and the service flows compare the fetched row's OrgID
	// to the authenticated caller org BEFORE acting (#3048 R3 BLOCKER-2 —
	// the discovery read alone does NOT authorize anything). Falls back to
	// db when unset (tests, owner-pool deployments where db sees everything
	// — the pre-v9 behavior).
	lookupDB *sql.DB
}

// SetCrossOrgDB installs a BYPASSRLS (axonflow_platform_admin) pool for the
// repository's discovery/list reads. See the lookupDB field comment (#3048).
func (r *Repository) SetCrossOrgDB(db *sql.DB) {
	r.lookupDB = db
}

func (r *Repository) lookup() *sql.DB {
	if r.lookupDB != nil {
		return r.lookupDB
	}
	return r.db
}

// NewRepository creates a new HITL repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Create inserts a new approval request into the queue.
//
// v9 Phase 8 #2384 PR-C1: hitl_approval_queue is ENABLE-RLS (mig 025).
// Under axonflow_app_role the INSERT WITH CHECK predicate
// org_id = current_setting('app.current_org_id') fires; wrap in
// WithOrgScope so SET LOCAL matches req.OrgID, which is also the value
// stored in the row's org_id column.
func (r *Repository) Create(ctx context.Context, req *ApprovalRequest) error {
	if req.OrgID == "" {
		return fmt.Errorf("Create: req.OrgID must be non-empty (RLS on hitl_approval_queue)")
	}
	query := `
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
		) RETURNING id, created_at, updated_at`

	contextJSON := []byte("{}")
	if req.RequestContext != nil {
		var err error
		contextJSON, err = json.Marshal(req.RequestContext)
		if err != nil {
			return fmt.Errorf("marshal request context: %w", err)
		}
	}

	err := rls.WithOrgScope(ctx, r.db, req.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			req.RequestID, req.OrgID, req.TenantID, req.ClientID, nullString(req.UserID),
			req.OriginalQuery, req.RequestType, contextJSON,
			req.TriggeredPolicyID, req.TriggeredPolicyName, req.TriggerReason, req.Severity,
			nullString(req.EUAIActArticle), nullString(req.ComplianceFramework), nullString(req.RiskClassification),
			req.Status, req.ExpiresAt, nullString(req.NotifyURL),
		).Scan(&req.ID, &req.CreatedAt, &req.UpdatedAt)
	})
	if err != nil {
		return fmt.Errorf("insert approval request: %w", err)
	}

	return nil
}

// GetByRequestID retrieves an approval request by its UUID.
func (r *Repository) GetByRequestID(ctx context.Context, requestID uuid.UUID) (*ApprovalRequest, error) {
	query := `
		SELECT
			id, request_id, org_id, tenant_id, client_id, user_id,
			original_query, request_type, request_context,
			triggered_policy_id, triggered_policy_name, trigger_reason, severity,
			eu_ai_act_article, compliance_framework, risk_classification,
			status, reviewer_id, reviewer_email, reviewer_role, review_comment, reviewed_at,
			override_justification, override_authorized_by, notify_url,
			expires_at, created_at, updated_at
		FROM hitl_approval_queue
		WHERE request_id = $1`

	req := &ApprovalRequest{}
	var userID, euArticle, framework, riskClass sql.NullString
	var reviewerID, reviewerEmail, reviewerRole, reviewComment sql.NullString
	var overrideJustify, overrideAuth, notifyURL sql.NullString
	var reviewedAt sql.NullTime
	var contextJSON []byte

	// Discovery read — runs on the lookup pool (see lookupDB field comment).
	err := r.lookup().QueryRowContext(ctx, query, requestID).Scan(
		&req.ID, &req.RequestID, &req.OrgID, &req.TenantID, &req.ClientID, &userID,
		&req.OriginalQuery, &req.RequestType, &contextJSON,
		&req.TriggeredPolicyID, &req.TriggeredPolicyName, &req.TriggerReason, &req.Severity,
		&euArticle, &framework, &riskClass,
		&req.Status, &reviewerID, &reviewerEmail, &reviewerRole, &reviewComment, &reviewedAt,
		&overrideJustify, &overrideAuth, &notifyURL,
		&req.ExpiresAt, &req.CreatedAt, &req.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query approval request: %w", err)
	}

	req.UserID = userID.String
	req.EUAIActArticle = euArticle.String
	req.ComplianceFramework = framework.String
	req.RiskClassification = riskClass.String
	req.ReviewerID = reviewerID.String
	req.ReviewerEmail = reviewerEmail.String
	req.ReviewerRole = reviewerRole.String
	req.ReviewComment = reviewComment.String
	req.OverrideJustify = overrideJustify.String
	req.OverrideAuthorizedBy = overrideAuth.String
	req.NotifyURL = notifyURL.String
	if reviewedAt.Valid {
		req.ReviewedAt = &reviewedAt.Time
	}

	if len(contextJSON) > 0 {
		if err := json.Unmarshal(contextJSON, &req.RequestContext); err != nil {
			return nil, fmt.Errorf("unmarshal request context: %w", err)
		}
	}

	return req, nil
}

// List retrieves approval requests with filters.
func (r *Repository) List(ctx context.Context, filter ListFilter) ([]*ApprovalRequest, int64, error) {
	// Build WHERE clause
	where := "WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if len(filter.Status) > 0 {
		where += fmt.Sprintf(" AND status = ANY($%d)", argIdx)
		args = append(args, pq.Array(filter.Status))
		argIdx++
	}
	if len(filter.Severity) > 0 {
		where += fmt.Sprintf(" AND severity = ANY($%d)", argIdx)
		args = append(args, pq.Array(filter.Severity))
		argIdx++
	}
	if filter.PolicyID != "" {
		where += fmt.Sprintf(" AND triggered_policy_id = $%d", argIdx)
		args = append(args, filter.PolicyID)
		argIdx++
	}
	if filter.ClientID != "" {
		where += fmt.Sprintf(" AND client_id = $%d", argIdx)
		args = append(args, filter.ClientID)
		argIdx++
	}
	if filter.UserID != "" {
		where += fmt.Sprintf(" AND user_id = $%d", argIdx)
		args = append(args, filter.UserID)
		argIdx++
	}
	// #3048 R3 BLOCKER-2: org isolation. List runs on the BYPASSRLS lookup
	// pool, so this SQL predicate is the tenancy boundary on every posture.
	//
	// #3065 (R3 round 1): the predicate was appended only when filter.OrgID
	// was non-empty — so an empty org left it off entirely and the query
	// became a deployment-wide `WHERE 1=1`, listing every org's approval
	// queue including original_query, the governed prompt. That is the same
	// fail-open shape #3065 closed on the by-id path (rejectCrossOrg) two
	// files over, one layer down. It is now mandatory: no org, no listing.
	if err := tenantscope.ValidateOrgKey(filter.OrgID); err != nil {
		return nil, 0, fmt.Errorf("cannot list approval requests without an authenticated org: %w", err)
	}
	where += fmt.Sprintf(" AND org_id = $%d", argIdx)
	args = append(args, filter.OrgID)
	argIdx++

	// Count total. ListFilter has no tenant dimension — this is the
	// deployment-wide queue view — so the read runs on the lookup pool
	// (#3048; bare on the app-role pool it listed nothing).
	countQuery := "SELECT COUNT(*) FROM hitl_approval_queue " + where
	var total int64
	if err := r.lookup().QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count approval requests: %w", err)
	}

	// Build ORDER BY with allowlist validation (prevent SQL injection)
	orderBy := "created_at"
	if filter.OrderBy != "" {
		// SECURITY: Validate orderBy against allowlist of valid column names
		validColumns := map[string]bool{
			"created_at": true, "updated_at": true, "status": true,
			"severity": true, "expires_at": true, "reviewed_at": true,
		}
		if validColumns[filter.OrderBy] {
			orderBy = filter.OrderBy
		}
	}
	orderDir := "DESC"
	if filter.OrderDir == "ASC" {
		orderDir = "ASC"
	}

	// Add LIMIT and OFFSET
	limit := 50
	if filter.Limit > 0 && filter.Limit <= 100 {
		limit = filter.Limit
	}
	offset := 0
	if filter.Offset > 0 {
		offset = filter.Offset
	}

	query := fmt.Sprintf(`
		SELECT
			id, request_id, org_id, tenant_id, client_id, user_id,
			original_query, request_type, request_context,
			triggered_policy_id, triggered_policy_name, trigger_reason, severity,
			eu_ai_act_article, compliance_framework, risk_classification,
			status, reviewer_id, reviewer_email, reviewer_role, review_comment, reviewed_at,
			override_justification, override_authorized_by, notify_url,
			expires_at, created_at, updated_at
		FROM hitl_approval_queue
		%s
		ORDER BY %s %s
		LIMIT %d OFFSET %d`,
		where, orderBy, orderDir, limit, offset)

	rows, err := r.lookup().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query approval requests: %w", err)
	}
	defer rows.Close()

	var requests []*ApprovalRequest
	for rows.Next() {
		req := &ApprovalRequest{}
		var userID, euArticle, framework, riskClass sql.NullString
		var reviewerID, reviewerEmail, reviewerRole, reviewComment sql.NullString
		var overrideJustify, overrideAuth, notifyURL sql.NullString
		var reviewedAt sql.NullTime
		var contextJSON []byte

		err := rows.Scan(
			&req.ID, &req.RequestID, &req.OrgID, &req.TenantID, &req.ClientID, &userID,
			&req.OriginalQuery, &req.RequestType, &contextJSON,
			&req.TriggeredPolicyID, &req.TriggeredPolicyName, &req.TriggerReason, &req.Severity,
			&euArticle, &framework, &riskClass,
			&req.Status, &reviewerID, &reviewerEmail, &reviewerRole, &reviewComment, &reviewedAt,
			&overrideJustify, &overrideAuth, &notifyURL,
			&req.ExpiresAt, &req.CreatedAt, &req.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan approval request: %w", err)
		}

		req.UserID = userID.String
		req.EUAIActArticle = euArticle.String
		req.ComplianceFramework = framework.String
		req.RiskClassification = riskClass.String
		req.ReviewerID = reviewerID.String
		req.ReviewerEmail = reviewerEmail.String
		req.ReviewerRole = reviewerRole.String
		req.ReviewComment = reviewComment.String
		req.OverrideJustify = overrideJustify.String
		req.OverrideAuthorizedBy = overrideAuth.String
		req.NotifyURL = notifyURL.String
		if reviewedAt.Valid {
			req.ReviewedAt = &reviewedAt.Time
		}

		if len(contextJSON) > 0 {
			if err := json.Unmarshal(contextJSON, &req.RequestContext); err != nil {
				return nil, 0, fmt.Errorf("unmarshal request context: %w", err)
			}
		}

		requests = append(requests, req)
	}

	return requests, total, nil
}

// ErrApprovalLostRace is returned when an UPDATE/Override targets a row
// whose status has already moved out of `pending` between the caller's
// read + write. Callers (Service.ApproveRequest etc.) translate this into
// a 409-shaped business error and MUST NOT fire the outbound notify_url
// webhook on lost-race — the actual decider's webhook will/has fired.
var ErrApprovalLostRace = fmt.Errorf("approval request is no longer pending (lost race to another reviewer)")

// UpdateStatus updates the status of an approval request.
//
// v9 Phase 8 #2384 PR-C1: hitl_approval_queue UPDATE under app_role is gated
// by mig 018's tenant_isolation_update USING predicate. orgID is required so
// the wrap can pin app.current_org_id; the caller (EE service.ApproveRequest
// / RejectRequest) reads it from the prior GetByRequestID(req).
//
// Concurrent-approver guard: the UPDATE WHERE clause includes
// `status = 'pending'`. A second caller that lost the race sees
// sql.ErrNoRows on RETURNING and gets ErrApprovalLostRace, so the
// service-layer dispatchTerminal does NOT fire a duplicate webhook for
// the same approval_id.
func (r *Repository) UpdateStatus(ctx context.Context, orgID string, requestID uuid.UUID, status string, reviewer *Reviewer, comment string) error {
	if orgID == "" {
		return fmt.Errorf("UpdateStatus: orgID must be non-empty (RLS on hitl_approval_queue)")
	}
	query := `
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

	var updatedAt time.Time
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			status,
			nullString(reviewer.ID),
			nullString(reviewer.Email),
			nullString(reviewer.Role),
			nullString(comment),
			requestID,
		).Scan(&updatedAt)
	})
	if err == sql.ErrNoRows {
		// Two cases collapse here: row truly doesn't exist (caller bug) AND
		// row exists but is no longer pending (lost race). The service layer
		// distinguishes via a prior GetByRequestID lookup; if that lookup
		// returned non-nil, this ErrNoRows means lost-race. If the row
		// genuinely vanished between the GET and the UPDATE that's a separate
		// integrity issue and the lost-race translation is still correct
		// (caller must not fire a duplicate webhook either way).
		return ErrApprovalLostRace
	}
	if err != nil {
		return fmt.Errorf("update approval request status: %w", err)
	}

	return nil
}

// Override overrides an approval request with justification.
//
// v9 Phase 8 #2384 PR-C1: scope-wrap rationale identical to UpdateStatus.
// Concurrent-actor guard identical too — the WHERE clause includes
// `status = 'pending'` so a lost-race returns ErrApprovalLostRace and
// the service layer skips the outbound webhook.
func (r *Repository) Override(ctx context.Context, orgID string, requestID uuid.UUID, justification string, authorizedBy string) error {
	if orgID == "" {
		return fmt.Errorf("Override: orgID must be non-empty (RLS on hitl_approval_queue)")
	}
	query := `
		UPDATE hitl_approval_queue
		SET status = 'overridden',
			override_justification = $1,
			override_authorized_by = $2,
			updated_at = CURRENT_TIMESTAMP
		WHERE request_id = $3 AND status = 'pending'
		RETURNING updated_at`

	var updatedAt time.Time
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, justification, authorizedBy, requestID).Scan(&updatedAt)
	})
	if err == sql.ErrNoRows {
		return ErrApprovalLostRace
	}
	if err != nil {
		return fmt.Errorf("override approval request: %w", err)
	}

	return nil
}

// GetPendingStats retrieves pending approval statistics.
func (r *Repository) GetPendingStats(ctx context.Context, orgID string) (*PendingStats, error) {
	query := `SELECT * FROM get_hitl_pending_count($1)`

	stats := &PendingStats{}
	var oldestHours sql.NullFloat64

	// #3048: get_hitl_pending_count is SECURITY INVOKER — it inherits the
	// caller's RLS scope, so under axonflow_app_role the bare call counted 0.
	// Scope by the org the stats are for.
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID).Scan(
			&stats.TotalPending,
			&stats.HighPriority,
			&stats.CriticalPriority,
			&oldestHours,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("get pending stats: %w", err)
	}

	if oldestHours.Valid {
		stats.OldestPendingHours = &oldestHours.Float64
	}

	return stats, nil
}

// CountPendingByTenant returns the number of pending approval requests for a
// tenant. orgID scopes the read under mig 025's RLS (#3048 — bare, the COUNT
// read 0 under axonflow_app_role and the pending-approval limit never
// engaged); it is the same key Create stamps on the row.
func (r *Repository) CountPendingByTenant(ctx context.Context, orgID, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`
	var count int
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(&count)
	}); err != nil {
		return 0, fmt.Errorf("count pending by tenant: %w", err)
	}
	return count, nil
}

// ExpireStale expires stale pending requests via the SQL function.
//
// CAVEAT: the SQL function expire_hitl_requests() inherits the caller's
// role + RLS scope. Under v9 FORCE RLS as axonflow_app_role with no GUC
// set, this UPDATEs zero rows. Production callers must invoke
// ExpireStaleReturning with an admin pool. Kept for back-compat with
// existing call sites (handler ExpireStale endpoint, tests).
func (r *Repository) ExpireStale(ctx context.Context) (int, error) {
	query := `SELECT expire_hitl_requests()`
	var count int
	if err := r.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("expire stale requests: %w", err)
	}
	return count, nil
}

// ExpireStaleReturning expires stale pending requests and returns the rows
// affected. Uses the supplied admin pool (BYPASSRLS) so the cross-tenant
// scan is not masked by RLS. Sister fix for the same class of bug as
// #2400 (heartbeat): a long-lived background updater under
// axonflow_app_role would otherwise update zero rows under FORCE RLS.
//
// Implementation: a single transaction selects the expiring rows FOR
// UPDATE SKIP LOCKED, marks them expired, writes history rows, and
// returns enough columns for the caller to dispatch terminal-state
// webhooks for each.
func (r *Repository) ExpireStaleReturning(ctx context.Context, adminDB *sql.DB) ([]*ApprovalRequest, error) {
	if adminDB == nil {
		return nil, fmt.Errorf("ExpireStaleReturning: adminDB is nil (admin pool required for cross-tenant scan under FORCE RLS)")
	}

	tx, err := adminDB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	selectQuery := `
		SELECT id, request_id, org_id, tenant_id, client_id, user_id,
		       original_query, request_type, severity, notify_url
		FROM hitl_approval_queue
		WHERE status = 'pending' AND expires_at < CURRENT_TIMESTAMP
		FOR UPDATE SKIP LOCKED
	`
	rows, err := tx.QueryContext(ctx, selectQuery)
	if err != nil {
		return nil, fmt.Errorf("select expiring rows: %w", err)
	}
	var expired []*ApprovalRequest
	for rows.Next() {
		req := &ApprovalRequest{}
		var userID, notifyURL sql.NullString
		if err := rows.Scan(
			&req.ID, &req.RequestID, &req.OrgID, &req.TenantID, &req.ClientID, &userID,
			&req.OriginalQuery, &req.RequestType, &req.Severity, &notifyURL,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan expiring row: %w", err)
		}
		req.UserID = userID.String
		req.NotifyURL = notifyURL.String
		req.Status = "expired"
		expired = append(expired, req)
	}
	rows.Close()

	if len(expired) == 0 {
		return nil, tx.Commit()
	}

	updateQuery := `
		UPDATE hitl_approval_queue
		SET status = 'expired', updated_at = CURRENT_TIMESTAMP
		WHERE id = ANY($1)
	`
	ids := make([]int64, len(expired))
	for i, e := range expired {
		ids[i] = e.ID
	}
	if _, err := tx.ExecContext(ctx, updateQuery, pq.Array(ids)); err != nil {
		return nil, fmt.Errorf("update expiring rows: %w", err)
	}

	histQuery := `
		INSERT INTO hitl_approval_history (
			request_id, org_id, tenant_id, action,
			previous_status, new_status, created_at
		) VALUES ($1, $2, $3, 'expired', 'pending', 'expired', CURRENT_TIMESTAMP)
	`
	for _, e := range expired {
		if _, err := tx.ExecContext(ctx, histQuery, e.RequestID, e.OrgID, e.TenantID); err != nil {
			return nil, fmt.Errorf("insert history for %s: %w", e.RequestID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit expire tx: %w", err)
	}
	return expired, nil
}

// AddHistory adds an entry to the approval history.
//
// v9 Phase 8 #2384 PR-C1: hitl_approval_history scope-wrap rationale —
// identical to Create on hitl_approval_queue above.
func (r *Repository) AddHistory(ctx context.Context, entry *ApprovalHistory) error {
	if entry.OrgID == "" {
		return fmt.Errorf("AddHistory: entry.OrgID must be non-empty (RLS on hitl_approval_history)")
	}
	query := `
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

	err := rls.WithOrgScope(ctx, r.db, entry.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			entry.RequestID, entry.OrgID, entry.TenantID, entry.Action,
			nullString(entry.ActorID), nullString(entry.ActorEmail), nullString(entry.ActorRole), nullString(entry.ActorIP),
			nullString(entry.Comment), nullString(entry.Justification),
			nullString(entry.PreviousStatus), nullString(entry.NewStatus),
		).Scan(&entry.ID, &entry.CreatedAt)
	})
	if err != nil {
		return fmt.Errorf("insert approval history: %w", err)
	}

	return nil
}

// GetHistory retrieves history for a specific request.
func (r *Repository) GetHistory(ctx context.Context, requestID uuid.UUID) ([]*ApprovalHistory, error) {
	query := `
		SELECT
			id, request_id, org_id, tenant_id, action,
			actor_id, actor_email, actor_role, actor_ip,
			comment, justification,
			previous_status, new_status, created_at
		FROM hitl_approval_history
		WHERE request_id = $1
		ORDER BY created_at ASC`

	// Discovery read (by request UUID) — runs on the lookup pool (#3048).
	rows, err := r.lookup().QueryContext(ctx, query, requestID)
	if err != nil {
		return nil, fmt.Errorf("query approval history: %w", err)
	}
	defer rows.Close()

	var history []*ApprovalHistory
	for rows.Next() {
		h := &ApprovalHistory{}
		var actorID, actorEmail, actorRole, actorIP sql.NullString
		var comment, justification sql.NullString
		var prevStatus, newStatus sql.NullString

		err := rows.Scan(
			&h.ID, &h.RequestID, &h.OrgID, &h.TenantID, &h.Action,
			&actorID, &actorEmail, &actorRole, &actorIP,
			&comment, &justification,
			&prevStatus, &newStatus, &h.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan approval history: %w", err)
		}

		h.ActorID = actorID.String
		h.ActorEmail = actorEmail.String
		h.ActorRole = actorRole.String
		h.ActorIP = actorIP.String
		h.Comment = comment.String
		h.Justification = justification.String
		h.PreviousStatus = prevStatus.String
		h.NewStatus = newStatus.String

		history = append(history, h)
	}

	return history, nil
}

// Reviewer represents a human reviewer.
type Reviewer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
	IP    string `json:"ip,omitempty"`
}

// nullString returns a sql.NullString for the given string.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
