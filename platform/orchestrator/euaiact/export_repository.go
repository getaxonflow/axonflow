// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/shared/audit"
)

// ExportRepository defines the interface for export persistence.
type ExportRepository interface {
	// Create creates a new export record.
	Create(ctx context.Context, export *Export) error

	// GetByID retrieves an export by ID.
	GetByID(ctx context.Context, id string) (*Export, error)

	// List retrieves exports for an organization.
	List(ctx context.Context, orgID string, limit, offset int) ([]*Export, int64, error)

	// Update updates an export record.
	Update(ctx context.Context, export *Export) error

	// Delete deletes an export record.
	Delete(ctx context.Context, id string) error

	// GetDecisionChain returns the per-decision audit rows (canonical audit_logs
	// decision rows) for an org within an optional date range, in chronological
	// order. A zero from/to is treated as unbounded on that side. One flat row per
	// decision, each carrying its correlation_id; callers reconstruct logical
	// chains via groupDecisionChain (rows sharing a correlation_id → one chain,
	// #2598). See #2588 / #2585.
	GetDecisionChain(ctx context.Context, orgID string, from, to time.Time) ([]DecisionChainRecord, error)

	// GetFullAudit returns the full canonical audit_logs record set (every
	// governed request/response — not just the decision-only subset
	// GetDecisionChain returns) for an org within an optional date range, in
	// chronological order. audit_logs is NOT FORCE-RLS (migration 101); both
	// org_id and tenant_id are matched, mirroring GetDecisionChain. #2610.
	GetFullAudit(ctx context.Context, orgID string, from, to time.Time) ([]AuditLogRecord, error)

	// GetPolicyViolations returns policy_violations rows for an org within an
	// optional date range (org-scoped by explicit org_id filter), oldest first.
	// #2610.
	GetPolicyViolations(ctx context.Context, orgID string, from, to time.Time) ([]PolicyViolationRecord, error)

	// GetHITLApprovalHistory returns hitl_approval_history rows — the immutable
	// human-oversight audit trail (Article 14 / Article 12) — for an org within
	// an optional date range, oldest first. #2610.
	GetHITLApprovalHistory(ctx context.Context, orgID string, from, to time.Time) ([]HITLApprovalRecord, error)

	// GetAccuracyMetrics returns euaiact_accuracy_metrics rows (Article 15) for an
	// org within an optional date range, oldest first. #2610.
	GetAccuracyMetrics(ctx context.Context, orgID string, from, to time.Time) ([]*AccuracyMetric, error)

	// GetConformityAssessments returns euaiact_conformity_assessments rows
	// (Article 43) for an org whose assessment_date falls within an optional date
	// range. #2610.
	GetConformityAssessments(ctx context.Context, orgID string, from, to time.Time) ([]*ConformityAssessment, error)
}

// PostgresExportRepository implements ExportRepository using PostgreSQL.
type PostgresExportRepository struct {
	db *sql.DB
}

// NewPostgresExportRepository creates a new PostgreSQL export repository.
func NewPostgresExportRepository(db *sql.DB) *PostgresExportRepository {
	return &PostgresExportRepository{db: db}
}

// Create creates a new export record.
func (r *PostgresExportRepository) Create(ctx context.Context, export *Export) error {
	query := `
		INSERT INTO euaiact_exports (
			id, org_id, export_type, format, status, progress,
			file_path, file_size, record_count, date_from, date_to,
			model_ids, filters, error, requested_by, created_at,
			started_at, completed_at, download_url, storage_type, storage_key
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)`

	filtersJSON, err := json.Marshal(export.Filters)
	if err != nil {
		return fmt.Errorf("marshal filters: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		export.ID, export.OrgID, export.ExportType, export.Format, export.Status, export.Progress,
		export.FilePath, export.FileSize, export.RecordCount, nullTime(export.DateFrom), nullTime(export.DateTo),
		pq.Array(export.ModelIDs), filtersJSON, export.Error, export.RequestedBy, export.CreatedAt,
		export.StartedAt, export.CompletedAt, nullString(export.DownloadURL), nullString(export.StorageType), nullString(export.StorageKey),
	)
	return err
}

// GetByID retrieves an export by ID.
func (r *PostgresExportRepository) GetByID(ctx context.Context, id string) (*Export, error) {
	query := `
		SELECT id, org_id, export_type, format, status, progress,
			file_path, file_size, record_count, date_from, date_to,
			model_ids, filters, error, requested_by, created_at,
			started_at, completed_at, download_url, storage_type, storage_key
		FROM euaiact_exports
		WHERE id = $1`

	export := &Export{}
	var filtersJSON []byte
	var dateFrom, dateTo sql.NullTime
	var modelIDs pq.StringArray
	var downloadURL, storageType, storageKey sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&export.ID, &export.OrgID, &export.ExportType, &export.Format, &export.Status, &export.Progress,
		&export.FilePath, &export.FileSize, &export.RecordCount, &dateFrom, &dateTo,
		&modelIDs, &filtersJSON, &export.Error, &export.RequestedBy, &export.CreatedAt,
		&export.StartedAt, &export.CompletedAt, &downloadURL, &storageType, &storageKey,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if dateFrom.Valid {
		export.DateFrom = dateFrom.Time
	}
	if dateTo.Valid {
		export.DateTo = dateTo.Time
	}
	export.ModelIDs = modelIDs
	if downloadURL.Valid {
		export.DownloadURL = downloadURL.String
	}
	if storageType.Valid {
		export.StorageType = storageType.String
	}
	if storageKey.Valid {
		export.StorageKey = storageKey.String
	}
	if len(filtersJSON) > 0 {
		if err := json.Unmarshal(filtersJSON, &export.Filters); err != nil {
			return nil, fmt.Errorf("unmarshal filters: %w", err)
		}
	}

	return export, nil
}

// List retrieves exports for an organization.
func (r *PostgresExportRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*Export, int64, error) {
	// Count query
	var total int64
	countQuery := `SELECT COUNT(*) FROM euaiact_exports WHERE org_id = $1`
	if err := r.db.QueryRowContext(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	if limit <= 0 {
		limit = DefaultListLimit
	}
	query := `
		SELECT id, org_id, export_type, format, status, progress,
			file_path, file_size, record_count, date_from, date_to,
			model_ids, filters, error, requested_by, created_at,
			started_at, completed_at, download_url, storage_type, storage_key
		FROM euaiact_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var exports []*Export
	for rows.Next() {
		export := &Export{}
		var filtersJSON []byte
		var dateFrom, dateTo sql.NullTime
		var modelIDs pq.StringArray
		var downloadURL, storageType, storageKey sql.NullString

		if err := rows.Scan(
			&export.ID, &export.OrgID, &export.ExportType, &export.Format, &export.Status, &export.Progress,
			&export.FilePath, &export.FileSize, &export.RecordCount, &dateFrom, &dateTo,
			&modelIDs, &filtersJSON, &export.Error, &export.RequestedBy, &export.CreatedAt,
			&export.StartedAt, &export.CompletedAt, &downloadURL, &storageType, &storageKey,
		); err != nil {
			return nil, 0, err
		}

		if dateFrom.Valid {
			export.DateFrom = dateFrom.Time
		}
		if dateTo.Valid {
			export.DateTo = dateTo.Time
		}
		export.ModelIDs = modelIDs
		if downloadURL.Valid {
			export.DownloadURL = downloadURL.String
		}
		if storageType.Valid {
			export.StorageType = storageType.String
		}
		if storageKey.Valid {
			export.StorageKey = storageKey.String
		}
		if len(filtersJSON) > 0 {
			if err := json.Unmarshal(filtersJSON, &export.Filters); err != nil {
				return nil, 0, fmt.Errorf("unmarshal filters: %w", err)
			}
		}

		exports = append(exports, export)
	}

	return exports, total, rows.Err()
}

// Update updates an export record.
func (r *PostgresExportRepository) Update(ctx context.Context, export *Export) error {
	query := `
		UPDATE euaiact_exports
		SET status = $2, progress = $3, file_path = $4, file_size = $5,
			record_count = $6, error = $7, started_at = $8, completed_at = $9,
			download_url = $10, storage_type = $11, storage_key = $12
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		export.ID, export.Status, export.Progress, export.FilePath, export.FileSize,
		export.RecordCount, export.Error, export.StartedAt, export.CompletedAt,
		export.DownloadURL, export.StorageType, export.StorageKey,
	)
	return err
}

// Delete deletes an export record.
func (r *PostgresExportRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM euaiact_exports WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// GetDecisionChain returns the per-decision audit rows for an org from
// audit_logs decision rows (#2588), in chronological order. The legacy
// decision_chain table had no live writer, so the EU AI Act decision-chain
// export produced an empty file in every deployment. audit_logs is NOT FORCE
// ROW LEVEL SECURITY (migration 101), so this read needs no org-scope GUC.
// org/tenant columns are both matched because the canonical writer
// (writeDecisionAuditLog) populates both.
//
// correlation_id (#2598) is selected — COALESCEd with the dual-written JSONB
// copy — so groupDecisionChain can reconstruct logical chains: every row sharing
// a correlation_id (the W3C trace_id a PEP propagates across its hops) is one
// chain, rows without one are singletons. The flat rows stay ordered by
// (timestamp, id) so both the flat list and each chain read in step order.
func (r *PostgresExportRepository) GetDecisionChain(ctx context.Context, orgID string, from, to time.Time) ([]DecisionChainRecord, error) {
	const q = `
		SELECT id, request_id, timestamp,
		       COALESCE(NULLIF(policy_details->>'stage', ''), request_type) AS decision_type,
		       policy_decision,
		       COALESCE(model, '')                                          AS model_id,
		       COALESCE((policy_details->'policy_ids')::text, '')           AS policies_evaluated,
		       COALESCE(policy_details->'policy_ids'->>0, '')               AS policy_triggered,
		       response_time_ms,
		       COALESCE(correlation_id, policy_details->>'correlation_id', '') AS correlation_id
		FROM audit_logs
		WHERE (org_id = $1 OR tenant_id = $1)
		  AND ($2::timestamp IS NULL OR timestamp >= $2)
		  AND ($3::timestamp IS NULL OR timestamp <= $3)
		  AND policy_details->>'decision_id' IS NOT NULL
		ORDER BY timestamp ASC, id ASC
		LIMIT 100000
	`

	var fromArg, toArg interface{}
	if !from.IsZero() {
		fromArg = from
	}
	if !to.IsZero() {
		toArg = to
	}

	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]DecisionChainRecord, 0, 16)
	for rows.Next() {
		var rec DecisionChainRecord
		var policyDecision, correlationID string
		var processingTimeMs sql.NullInt64

		if err := rows.Scan(
			&rec.ID, &rec.RequestID, &rec.Timestamp, &rec.DecisionType, &policyDecision,
			&rec.ModelID, &rec.PoliciesEvaluated, &rec.PolicyTriggered, &processingTimeMs, &correlationID,
		); err != nil {
			return nil, err
		}

		rec.DecisionOutcome = mapDecisionVerdict(policyDecision)
		rec.RequiresReview = requiresReview(policyDecision)
		if rec.PoliciesEvaluated == "null" {
			rec.PoliciesEvaluated = ""
		}
		if processingTimeMs.Valid {
			v := int(processingTimeMs.Int64)
			rec.ProcessingTimeMs = &v
		}
		rec.CorrelationID = correlationID
		records = append(records, rec)
	}
	return records, rows.Err()
}

// groupDecisionChain reconstructs logical decision chains from the flat,
// chronologically-ordered decision rows (#2598). Rows sharing a non-empty
// correlation_id collapse into one chain in step order; rows without one (legacy
// + single-shot callers) each become a singleton chain. Group order is
// first-appearance, which — because the input is ordered by (timestamp, id) — is
// chronological by each chain's earliest step, preserving the chronological
// behavior for ungrouped rows. Pure function (no I/O) so the grouping is
// unit-testable on its own.
func groupDecisionChain(records []DecisionChainRecord) []DecisionChainGroup {
	if len(records) == 0 {
		return nil
	}
	groups := make([]DecisionChainGroup, 0, len(records))
	indexByCorrelation := make(map[string]int, len(records))
	for _, rec := range records {
		key := rec.CorrelationID
		if key != "" {
			if i, ok := indexByCorrelation[key]; ok {
				g := &groups[i]
				g.Steps = append(g.Steps, rec)
				g.StepCount = len(g.Steps)
				if rec.Timestamp.After(g.EndedAt) {
					g.EndedAt = rec.Timestamp
				}
				if rec.Timestamp.Before(g.StartedAt) {
					g.StartedAt = rec.Timestamp
				}
				continue
			}
			indexByCorrelation[key] = len(groups)
		}
		groups = append(groups, DecisionChainGroup{
			CorrelationID: rec.CorrelationID,
			StepCount:     1,
			StartedAt:     rec.Timestamp,
			EndedAt:       rec.Timestamp,
			Steps:         []DecisionChainRecord{rec},
		})
	}
	return groups
}

// nullableRangeArgs converts a [from, to] window into query args, treating a
// zero time as an unbounded (NULL) bound — mirrors the inline logic in
// GetDecisionChain so the `$N::timestamp IS NULL OR ...` guards behave
// identically across every export query. #2610.
func nullableRangeArgs(from, to time.Time) (interface{}, interface{}) {
	var fromArg, toArg interface{}
	if !from.IsZero() {
		fromArg = from
	}
	if !to.IsZero() {
		toArg = to
	}
	return fromArg, toArg
}

// GetFullAudit returns the full canonical audit_logs record set for an org
// within an optional window. See the interface doc. The raw prompt text
// (audit_logs.query) is intentionally NOT selected — it may carry PII — so the
// regulator-facing export ships the tamper-evident query_hash instead. #2610.
func (r *PostgresExportRepository) GetFullAudit(ctx context.Context, orgID string, from, to time.Time) ([]AuditLogRecord, error) {
	const q = `
		SELECT id, request_id, timestamp,
		       COALESCE(user_email, ''), COALESCE(user_role, ''), COALESCE(client_id, ''),
		       COALESCE(tenant_id, ''), COALESCE(org_id, ''), request_type,
		       COALESCE(query_hash, ''), policy_decision,
		       COALESCE(decision_id, policy_details->>'decision_id', ''),
		       COALESCE(plane, ''), COALESCE(provider, ''), COALESCE(model, ''),
		       response_time_ms, tokens_used, COALESCE(error_message, '')
		FROM audit_logs
		WHERE (org_id = $1 OR tenant_id = $1)
		  AND ($2::timestamp IS NULL OR timestamp >= $2)
		  AND ($3::timestamp IS NULL OR timestamp <= $3)
		ORDER BY timestamp ASC, id ASC
		LIMIT 100000
	`
	fromArg, toArg := nullableRangeArgs(from, to)
	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]AuditLogRecord, 0, 16)
	for rows.Next() {
		var rec AuditLogRecord
		var responseTimeMs, tokensUsed sql.NullInt64
		if err := rows.Scan(
			&rec.ID, &rec.RequestID, &rec.Timestamp,
			&rec.UserEmail, &rec.UserRole, &rec.ClientID,
			&rec.TenantID, &rec.OrgID, &rec.RequestType,
			&rec.QueryHash, &rec.PolicyDecision,
			&rec.DecisionID, &rec.Plane, &rec.Provider, &rec.Model,
			&responseTimeMs, &tokensUsed, &rec.ErrorMessage,
		); err != nil {
			return nil, err
		}
		if responseTimeMs.Valid {
			v := responseTimeMs.Int64
			rec.ResponseTimeMs = &v
		}
		if tokensUsed.Valid {
			v := int(tokensUsed.Int64)
			rec.TokensUsed = &v
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// GetPolicyViolations returns policy_violations rows for an org within an
// optional window. policy_violations has only an org_id tenancy column (no
// tenant_id), so the explicit filter is org_id alone. #2610.
func (r *PostgresExportRepository) GetPolicyViolations(ctx context.Context, orgID string, from, to time.Time) ([]PolicyViolationRecord, error) {
	const q = `
		SELECT id, COALESCE(org_id, ''), COALESCE(violation_type, ''), COALESCE(severity, ''),
		       COALESCE(client_id, ''), COALESCE(user_id, ''), COALESCE(description, ''),
		       COALESCE(details::text, ''), created_at
		FROM policy_violations
		WHERE org_id = $1
		  AND ($2::timestamp IS NULL OR created_at >= $2)
		  AND ($3::timestamp IS NULL OR created_at <= $3)
		ORDER BY created_at ASC, id ASC
		LIMIT 100000
	`
	fromArg, toArg := nullableRangeArgs(from, to)
	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]PolicyViolationRecord, 0, 16)
	for rows.Next() {
		var rec PolicyViolationRecord
		var detailsJSON string
		if err := rows.Scan(
			&rec.ID, &rec.OrgID, &rec.ViolationType, &rec.Severity,
			&rec.ClientID, &rec.UserID, &rec.Description, &detailsJSON, &rec.CreatedAt,
		); err != nil {
			return nil, err
		}
		if detailsJSON != "" {
			if err := json.Unmarshal([]byte(detailsJSON), &rec.Details); err != nil {
				return nil, fmt.Errorf("unmarshal policy_violations.details: %w", err)
			}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// GetHITLApprovalHistory returns hitl_approval_history rows for an org within an
// optional window. request_id is a UUID column, cast to text for the string
// field. Both org_id and tenant_id are matched (the writer populates both).
// #2610.
func (r *PostgresExportRepository) GetHITLApprovalHistory(ctx context.Context, orgID string, from, to time.Time) ([]HITLApprovalRecord, error) {
	const q = `
		SELECT id, request_id::text, COALESCE(org_id, ''), COALESCE(tenant_id, ''), action,
		       COALESCE(actor_id, ''), COALESCE(actor_email, ''), COALESCE(actor_role, ''),
		       COALESCE(comment, ''), COALESCE(justification, ''),
		       COALESCE(previous_status, ''), COALESCE(new_status, ''), created_at
		FROM hitl_approval_history
		WHERE (org_id = $1 OR tenant_id = $1)
		  AND ($2::timestamptz IS NULL OR created_at >= $2)
		  AND ($3::timestamptz IS NULL OR created_at <= $3)
		ORDER BY created_at ASC, id ASC
		LIMIT 100000
	`
	fromArg, toArg := nullableRangeArgs(from, to)
	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]HITLApprovalRecord, 0, 16)
	for rows.Next() {
		var rec HITLApprovalRecord
		if err := rows.Scan(
			&rec.ID, &rec.RequestID, &rec.OrgID, &rec.TenantID, &rec.Action,
			&rec.ActorID, &rec.ActorEmail, &rec.ActorRole,
			&rec.Comment, &rec.Justification,
			&rec.PreviousStatus, &rec.NewStatus, &rec.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// GetAccuracyMetrics returns euaiact_accuracy_metrics rows for an org within an
// optional window. Nullable columns (sample_size, window_start/end) are scanned
// defensively so a NULL never aborts the export. #2610.
func (r *PostgresExportRepository) GetAccuracyMetrics(ctx context.Context, orgID string, from, to time.Time) ([]*AccuracyMetric, error) {
	const q = `
		SELECT id, org_id, model_id, metric_type, value, sample_size,
		       timestamp, window_start, window_end, metadata
		FROM euaiact_accuracy_metrics
		WHERE org_id = $1
		  AND ($2::timestamptz IS NULL OR timestamp >= $2)
		  AND ($3::timestamptz IS NULL OR timestamp <= $3)
		ORDER BY timestamp ASC, id ASC
		LIMIT 100000
	`
	fromArg, toArg := nullableRangeArgs(from, to)
	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	metrics := make([]*AccuracyMetric, 0, 16)
	for rows.Next() {
		metric := &AccuracyMetric{}
		var metadataJSON []byte
		var sampleSize sql.NullInt64
		var windowStart, windowEnd sql.NullTime
		if err := rows.Scan(
			&metric.ID, &metric.OrgID, &metric.ModelID, &metric.MetricType, &metric.Value, &sampleSize,
			&metric.Timestamp, &windowStart, &windowEnd, &metadataJSON,
		); err != nil {
			return nil, err
		}
		if sampleSize.Valid {
			metric.SampleSize = int(sampleSize.Int64)
		}
		if windowStart.Valid {
			metric.WindowStart = windowStart.Time
		}
		if windowEnd.Valid {
			metric.WindowEnd = windowEnd.Time
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &metric.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal accuracy metric metadata: %w", err)
			}
		}
		metrics = append(metrics, metric)
	}
	return metrics, rows.Err()
}

// GetConformityAssessments returns euaiact_conformity_assessments rows for an
// org whose assessment_date falls within an optional window, with their full
// requirements/evidence/findings content. The nullable actor/reason string
// columns are COALESCEd to the empty string so a row that left them NULL (the
// app writes an empty string via Create, but a hand-written or migrated row may
// be NULL) never aborts the regulator-facing export — more defensive than the
// GetByID scan, which assumes the empty string Create writes. #2610.
func (r *PostgresExportRepository) GetConformityAssessments(ctx context.Context, orgID string, from, to time.Time) ([]*ConformityAssessment, error) {
	const q = `
		SELECT id, org_id, system_id, system_name, risk_category, status, version,
		       assessment_date, valid_until, assessors, requirements, evidence,
		       findings, risk_mitigation, recommendations, created_by, created_at,
		       updated_at, submitted_at, COALESCE(submitted_by, ''), approved_at, COALESCE(approved_by, ''),
		       rejected_at, COALESCE(rejected_by, ''), COALESCE(rejection_reason, '')
		FROM euaiact_conformity_assessments
		WHERE org_id = $1
		  AND ($2::timestamptz IS NULL OR assessment_date >= $2)
		  AND ($3::timestamptz IS NULL OR assessment_date <= $3)
		ORDER BY updated_at DESC
		LIMIT 100000
	`
	fromArg, toArg := nullableRangeArgs(from, to)
	rows, err := r.db.QueryContext(ctx, q, orgID, fromArg, toArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	assessments := make([]*ConformityAssessment, 0, 16)
	for rows.Next() {
		assessment := &ConformityAssessment{}
		var assessorsJSON, requirementsJSON, evidenceJSON, findingsJSON, mitigationJSON, recommendationsJSON []byte
		if err := rows.Scan(
			&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.SystemName,
			&assessment.RiskCategory, &assessment.Status, &assessment.Version, &assessment.AssessmentDate,
			&assessment.ValidUntil, &assessorsJSON, &requirementsJSON, &evidenceJSON,
			&findingsJSON, &mitigationJSON, &recommendationsJSON, &assessment.CreatedBy, &assessment.CreatedAt,
			&assessment.UpdatedAt, &assessment.SubmittedAt, &assessment.SubmittedBy, &assessment.ApprovedAt, &assessment.ApprovedBy,
			&assessment.RejectedAt, &assessment.RejectedBy, &assessment.RejectionReason,
		); err != nil {
			return nil, err
		}
		if len(assessorsJSON) > 0 {
			json.Unmarshal(assessorsJSON, &assessment.Assessors)
		}
		if len(requirementsJSON) > 0 {
			json.Unmarshal(requirementsJSON, &assessment.Requirements)
		}
		if len(evidenceJSON) > 0 {
			json.Unmarshal(evidenceJSON, &assessment.Evidence)
		}
		if len(findingsJSON) > 0 {
			json.Unmarshal(findingsJSON, &assessment.Findings)
		}
		if len(mitigationJSON) > 0 {
			json.Unmarshal(mitigationJSON, &assessment.RiskMitigation)
		}
		if len(recommendationsJSON) > 0 {
			json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
		}
		assessments = append(assessments, assessment)
	}
	return assessments, rows.Err()
}

// mapDecisionVerdict translates an audit_logs policy_decision verdict into the
// EU AI Act decision-outcome vocabulary. The raw value is run through the shared
// normalizer (audit.Normalize) FIRST so every writer spelling and era converges
// before mapping — critically, the canonical "allowed"/"blocked" that all
// forward writers now emit map to approved/blocked, where the old present-tense
// switch ("allow"/"deny") let them fall through to the raw value and leak an
// un-mapped "allowed" into a regulator-facing export. needs_approval is flagged
// as requires-review ("pending_review"), never silently downgraded to approved.
func mapDecisionVerdict(verdict string) string {
	switch audit.Normalize(verdict) {
	case audit.DecisionAllowed:
		return "approved"
	case audit.DecisionBlocked:
		return "blocked"
	case audit.DecisionRedacted:
		return "redacted"
	case audit.DecisionNeedsApproval:
		return "pending_review"
	case audit.DecisionError:
		return "error"
	default:
		// Recognized non-verdict marker (override_lifecycle): surface it as-is
		// rather than a distorted decision outcome. Normalize guarantees an
		// unrecognized value can never reach here as "approved".
		return audit.Normalize(verdict)
	}
}

// requiresReview reports whether a raw policy_decision is a human-deferred
// (needs-approval) verdict. It consumes the shared normalizer so it stays in
// lock-step with mapDecisionVerdict — a raw string compare against
// "needs_approval"/"require_approval" would miss legacy/defensive spellings
// (e.g. pending_approval), which mapDecisionVerdict maps to "pending_review"
// while RequiresReview reported false, telling a regulator a human-deferred
// decision needed no review (#2636/#2653).
func requiresReview(policyDecision string) bool {
	return audit.Normalize(policyDecision) == audit.DecisionNeedsApproval
}

// nullTime converts a time.Time to sql.NullTime.
func nullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t, Valid: true}
}

// nullString converts a string to sql.NullString (empty → NULL).
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
