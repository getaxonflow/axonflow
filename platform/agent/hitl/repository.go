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
)

// ApprovalRequest represents a pending approval request in the HITL queue.
type ApprovalRequest struct {
	ID                  int64                  `json:"id"`
	RequestID           uuid.UUID              `json:"request_id"`
	OrgID               string                 `json:"org_id"`
	TenantID            string                 `json:"tenant_id"`
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id,omitempty"`
	OriginalQuery       string                 `json:"original_query"`
	RequestType         string                 `json:"request_type"`
	RequestContext      map[string]interface{} `json:"request_context,omitempty"`
	TriggeredPolicyID   string                 `json:"triggered_policy_id"`
	TriggeredPolicyName string                 `json:"triggered_policy_name"`
	TriggerReason       string                 `json:"trigger_reason"`
	Severity            string                 `json:"severity"`
	EUAIActArticle      string                 `json:"eu_ai_act_article,omitempty"`
	ComplianceFramework string                 `json:"compliance_framework,omitempty"`
	RiskClassification  string                 `json:"risk_classification,omitempty"`
	Status              string                 `json:"status"`
	ReviewerID          string                 `json:"reviewer_id,omitempty"`
	ReviewerEmail       string                 `json:"reviewer_email,omitempty"`
	ReviewerRole        string                 `json:"reviewer_role,omitempty"`
	ReviewComment       string                 `json:"review_comment,omitempty"`
	ReviewedAt          *time.Time             `json:"reviewed_at,omitempty"`
	OverrideJustify     string                 `json:"override_justification,omitempty"`
	OverrideAuthorizedBy string               `json:"override_authorized_by,omitempty"`
	ExpiresAt           time.Time              `json:"expires_at"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
}

// ApprovalHistory represents an immutable audit trail entry.
type ApprovalHistory struct {
	ID             int64      `json:"id"`
	RequestID      uuid.UUID  `json:"request_id"`
	OrgID          string     `json:"org_id"`
	TenantID       string     `json:"tenant_id"`
	Action         string     `json:"action"`
	ActorID        string     `json:"actor_id,omitempty"`
	ActorEmail     string     `json:"actor_email,omitempty"`
	ActorRole      string     `json:"actor_role,omitempty"`
	ActorIP        string     `json:"actor_ip,omitempty"`
	Comment        string     `json:"comment,omitempty"`
	Justification  string     `json:"justification,omitempty"`
	PreviousStatus string     `json:"previous_status,omitempty"`
	NewStatus      string     `json:"new_status,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
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
	Status     []string
	Severity   []string
	PolicyID   string
	ClientID   string
	UserID     string
	Limit      int
	Offset     int
	OrderBy    string
	OrderDir   string
}

// Repository provides data access for HITL queue operations.
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new HITL repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Create inserts a new approval request into the queue.
func (r *Repository) Create(ctx context.Context, req *ApprovalRequest) error {
	query := `
		INSERT INTO hitl_approval_queue (
			request_id, org_id, tenant_id, client_id, user_id,
			original_query, request_type, request_context,
			triggered_policy_id, triggered_policy_name, trigger_reason, severity,
			eu_ai_act_article, compliance_framework, risk_classification,
			status, expires_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11, $12,
			$13, $14, $15,
			$16, $17
		) RETURNING id, created_at, updated_at`

	contextJSON := []byte("{}")
	if req.RequestContext != nil {
		var err error
		contextJSON, err = json.Marshal(req.RequestContext)
		if err != nil {
			return fmt.Errorf("marshal request context: %w", err)
		}
	}

	err := r.db.QueryRowContext(ctx, query,
		req.RequestID, req.OrgID, req.TenantID, req.ClientID, nullString(req.UserID),
		req.OriginalQuery, req.RequestType, contextJSON,
		req.TriggeredPolicyID, req.TriggeredPolicyName, req.TriggerReason, req.Severity,
		nullString(req.EUAIActArticle), nullString(req.ComplianceFramework), nullString(req.RiskClassification),
		req.Status, req.ExpiresAt,
	).Scan(&req.ID, &req.CreatedAt, &req.UpdatedAt)
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
			override_justification, override_authorized_by,
			expires_at, created_at, updated_at
		FROM hitl_approval_queue
		WHERE request_id = $1`

	req := &ApprovalRequest{}
	var userID, euArticle, framework, riskClass sql.NullString
	var reviewerID, reviewerEmail, reviewerRole, reviewComment sql.NullString
	var overrideJustify, overrideAuth sql.NullString
	var reviewedAt sql.NullTime
	var contextJSON []byte

	err := r.db.QueryRowContext(ctx, query, requestID).Scan(
		&req.ID, &req.RequestID, &req.OrgID, &req.TenantID, &req.ClientID, &userID,
		&req.OriginalQuery, &req.RequestType, &contextJSON,
		&req.TriggeredPolicyID, &req.TriggeredPolicyName, &req.TriggerReason, &req.Severity,
		&euArticle, &framework, &riskClass,
		&req.Status, &reviewerID, &reviewerEmail, &reviewerRole, &reviewComment, &reviewedAt,
		&overrideJustify, &overrideAuth,
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

	// Count total
	countQuery := "SELECT COUNT(*) FROM hitl_approval_queue " + where
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
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
			override_justification, override_authorized_by,
			expires_at, created_at, updated_at
		FROM hitl_approval_queue
		%s
		ORDER BY %s %s
		LIMIT %d OFFSET %d`,
		where, orderBy, orderDir, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query approval requests: %w", err)
	}
	defer rows.Close()

	var requests []*ApprovalRequest
	for rows.Next() {
		req := &ApprovalRequest{}
		var userID, euArticle, framework, riskClass sql.NullString
		var reviewerID, reviewerEmail, reviewerRole, reviewComment sql.NullString
		var overrideJustify, overrideAuth sql.NullString
		var reviewedAt sql.NullTime
		var contextJSON []byte

		err := rows.Scan(
			&req.ID, &req.RequestID, &req.OrgID, &req.TenantID, &req.ClientID, &userID,
			&req.OriginalQuery, &req.RequestType, &contextJSON,
			&req.TriggeredPolicyID, &req.TriggeredPolicyName, &req.TriggerReason, &req.Severity,
			&euArticle, &framework, &riskClass,
			&req.Status, &reviewerID, &reviewerEmail, &reviewerRole, &reviewComment, &reviewedAt,
			&overrideJustify, &overrideAuth,
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

// UpdateStatus updates the status of an approval request.
func (r *Repository) UpdateStatus(ctx context.Context, requestID uuid.UUID, status string, reviewer *Reviewer, comment string) error {
	query := `
		UPDATE hitl_approval_queue
		SET status = $1,
			reviewer_id = $2,
			reviewer_email = $3,
			reviewer_role = $4,
			review_comment = $5,
			reviewed_at = CURRENT_TIMESTAMP,
			updated_at = CURRENT_TIMESTAMP
		WHERE request_id = $6
		RETURNING updated_at`

	var updatedAt time.Time
	err := r.db.QueryRowContext(ctx, query,
		status,
		nullString(reviewer.ID),
		nullString(reviewer.Email),
		nullString(reviewer.Role),
		nullString(comment),
		requestID,
	).Scan(&updatedAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("approval request not found")
	}
	if err != nil {
		return fmt.Errorf("update approval request status: %w", err)
	}

	return nil
}

// Override overrides an approval request with justification.
func (r *Repository) Override(ctx context.Context, requestID uuid.UUID, justification string, authorizedBy string) error {
	query := `
		UPDATE hitl_approval_queue
		SET status = 'overridden',
			override_justification = $1,
			override_authorized_by = $2,
			updated_at = CURRENT_TIMESTAMP
		WHERE request_id = $3
		RETURNING updated_at`

	var updatedAt time.Time
	err := r.db.QueryRowContext(ctx, query, justification, authorizedBy, requestID).Scan(&updatedAt)
	if err == sql.ErrNoRows {
		return fmt.Errorf("approval request not found")
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

	err := r.db.QueryRowContext(ctx, query, orgID).Scan(
		&stats.TotalPending,
		&stats.HighPriority,
		&stats.CriticalPriority,
		&oldestHours,
	)
	if err != nil {
		return nil, fmt.Errorf("get pending stats: %w", err)
	}

	if oldestHours.Valid {
		stats.OldestPendingHours = &oldestHours.Float64
	}

	return stats, nil
}

// CountPendingByTenant returns the number of pending approval requests for a tenant.
func (r *Repository) CountPendingByTenant(ctx context.Context, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND status = 'pending'`
	var count int
	if err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count pending by tenant: %w", err)
	}
	return count, nil
}

// ExpireStale expires stale pending requests.
func (r *Repository) ExpireStale(ctx context.Context) (int, error) {
	query := `SELECT expire_hitl_requests()`
	var count int
	if err := r.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, fmt.Errorf("expire stale requests: %w", err)
	}
	return count, nil
}

// AddHistory adds an entry to the approval history.
func (r *Repository) AddHistory(ctx context.Context, entry *ApprovalHistory) error {
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

	err := r.db.QueryRowContext(ctx, query,
		entry.RequestID, entry.OrgID, entry.TenantID, entry.Action,
		nullString(entry.ActorID), nullString(entry.ActorEmail), nullString(entry.ActorRole), nullString(entry.ActorIP),
		nullString(entry.Comment), nullString(entry.Justification),
		nullString(entry.PreviousStatus), nullString(entry.NewStatus),
	).Scan(&entry.ID, &entry.CreatedAt)
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

	rows, err := r.db.QueryContext(ctx, query, requestID)
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

