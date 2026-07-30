// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"axonflow/platform/agent/rls"
)

// #3103. Migration 301 switches RLS on for all seven rbi_* tables with a
// `FOR ALL USING (org_id = get_current_org_id())` policy, but this package
// never set app.current_org_id. On an axonflow_app_role pool that made every
// read return SILENT ZERO ROWS and every write fail closed ("new row violates
// row-level security policy" — a FOR ALL USING expression doubles as the
// INSERT/UPDATE WITH CHECK), and on a master/BYPASSRLS pool it left the hand-
// written `WHERE org_id = $n` predicate as the ENTIRE tenant boundary with no
// database backstop underneath — which is why #3099's `?org_id=` override was
// directly exploitable rather than caught one layer down.
//
// Every statement below therefore runs inside rls.WithOrgScope, which opens a
// transaction and SET LOCALs the GUC the policy reads. The SQL org_id
// predicates are KEPT: the wrap is a backstop, not a replacement, and the two
// failing independently is the point.

// ErrAuditExportNotFound is returned when an audit export is not found.
var ErrAuditExportNotFound = errors.New("audit export not found")

// AuditExportRepository provides data access for audit exports.
type AuditExportRepository interface {
	Create(ctx context.Context, export *AuditExport) error
	Get(ctx context.Context, orgID, id string) (*AuditExport, error)
	List(ctx context.Context, orgID string, params *ListAuditExportsParams) ([]*AuditExport, int, error)
	Update(ctx context.Context, export *AuditExport) error
	Delete(ctx context.Context, orgID, id string) error
	GetPending(ctx context.Context) ([]*AuditExport, error)
	GetExpired(ctx context.Context) ([]*AuditExport, error)
}

// ListAuditExportsParams defines filtering parameters for listing audit exports.
type ListAuditExportsParams struct {
	ExportType string
	Status     string
	StartDate  *time.Time
	EndDate    *time.Time
	Limit      int
	Offset     int
}

// PostgresAuditExportRepository implements AuditExportRepository using PostgreSQL.
type PostgresAuditExportRepository struct {
	db *sql.DB
}

// NewPostgresAuditExportRepository creates a new PostgreSQL-backed audit export repository.
func NewPostgresAuditExportRepository(db *sql.DB) *PostgresAuditExportRepository {
	return &PostgresAuditExportRepository{db: db}
}

// Create inserts a new audit export.
func (r *PostgresAuditExportRepository) Create(ctx context.Context, export *AuditExport) error {
	if export.ID == "" {
		export.ID = uuid.New().String()
	}
	export.CreatedAt = time.Now().UTC()
	export.UpdatedAt = export.CreatedAt

	summaryJSON, err := json.Marshal(export.Summary)
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %w", err)
	}

	query := `
		INSERT INTO rbi_audit_exports (
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
		)
	`

	err = rls.WithOrgScope(ctx, r.db, export.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			export.ID,
			export.OrgID,
			string(export.ExportType),
			string(export.Format),
			nullTime(export.StartDate),
			nullTime(export.EndDate),
			pq.Array(export.SystemIDs),
			pq.Array(export.RiskCategories),
			export.IncludeArchived,
			string(export.Status),
			nullString(export.ErrorMessage),
			nullString(export.RequestedBy),
			nullString(export.RequestedByEmail),
			nullString(export.Purpose),
			nullTime(export.StartedAt),
			nullTime(export.CompletedAt),
			nullString(export.FilePath),
			export.FileSizeBytes,
			nullString(export.FileChecksum),
			export.RecordCount,
			summaryJSON,
			nullTime(export.ExpiresAt),
			nullString(export.DownloadURL),
			nullString(export.StorageType),
			nullString(export.StorageKey),
			export.CreatedAt,
			export.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to create audit export: %w", err)
	}

	return nil
}

// Get retrieves an audit export by ID.
func (r *PostgresAuditExportRepository) Get(ctx context.Context, orgID, id string) (*AuditExport, error) {
	query := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`
	var export *AuditExport
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		export, scanErr = r.scanAuditExport(tx.QueryRowContext(ctx, query, id, orgID))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return export, nil
}

// List retrieves audit exports with optional filtering.
func (r *PostgresAuditExportRepository) List(ctx context.Context, orgID string, params *ListAuditExportsParams) ([]*AuditExport, int, error) {
	if params == nil {
		params = &ListAuditExportsParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Build WHERE clause
	conditions := []string{"org_id = $1"}
	args := []interface{}{orgID}
	argIdx := 2

	if params.ExportType != "" {
		conditions = append(conditions, fmt.Sprintf("export_type = $%d", argIdx))
		args = append(args, params.ExportType)
		argIdx++
	}
	if params.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, params.Status)
		argIdx++
	}
	if params.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, *params.StartDate)
		argIdx++
	}
	if params.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, *params.EndDate)
		argIdx++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM rbi_audit_exports WHERE %s", whereClause)

	// Fetch records
	query := fmt.Sprintf(`
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	countArgs := args
	args = append(append([]interface{}{}, args...), params.Limit, params.Offset)

	// One wrap for BOTH statements: the count and the page are separate call
	// sites and each had to be scoped, and sharing the transaction also makes
	// total and rows a consistent snapshot.
	var exports []*AuditExport
	var total int
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return fmt.Errorf("failed to count audit exports: %w", err)
		}

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to list audit exports: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			export, scanErr := r.scanAuditExportRows(rows)
			if scanErr != nil {
				return scanErr
			}
			exports = append(exports, export)
		}
		return rows.Err()
	}); err != nil {
		return nil, 0, err
	}

	return exports, total, nil
}

// Update updates an existing audit export.
func (r *PostgresAuditExportRepository) Update(ctx context.Context, export *AuditExport) error {
	export.UpdatedAt = time.Now().UTC()

	summaryJSON, _ := json.Marshal(export.Summary)

	query := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, export.OrgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query,
			export.ID,
			export.OrgID,
			string(export.Status),
			nullString(export.ErrorMessage),
			nullTime(export.StartedAt),
			nullTime(export.CompletedAt),
			nullString(export.FilePath),
			export.FileSizeBytes,
			nullString(export.FileChecksum),
			export.RecordCount,
			summaryJSON,
			nullTime(export.ExpiresAt),
			nullString(export.DownloadURL),
			nullString(export.StorageType),
			nullString(export.StorageKey),
			export.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to update audit export: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrAuditExportNotFound
	}

	return nil
}

// Delete removes an audit export.
func (r *PostgresAuditExportRepository) Delete(ctx context.Context, orgID, id string) error {
	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx,
			"DELETE FROM rbi_audit_exports WHERE id = $1 AND org_id = $2",
			id, orgID,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to delete audit export: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrAuditExportNotFound
	}

	return nil
}

// GetPending retrieves all pending audit exports for processing.
//
// DELIBERATELY UNWRAPPED, and the only read in this file that is. There is no
// caller org: the statement spans every tenant by design, and rls.WithOrgScope
// rejects an empty orgID precisely so that "scope me to nothing" cannot be
// spelled by accident. Cross-org work belongs on the BYPASSRLS
// axonflow_platform_admin pool (see OpenPlatformAdminConnection), so a
// repository backing this method MUST be constructed with that pool.
//
// On an axonflow_app_role pool this returns zero rows silently. It has no
// production caller today — ProcessPendingExports/CleanupExpiredExports are
// unwired — so no live path is affected, but wiring either one MUST route this
// repository through the admin pool. Allowlisted in rlsReadAllowlist() with
// this reason (#3103).
func (r *PostgresAuditExportRepository) GetPending(ctx context.Context) ([]*AuditExport, error) {
	query := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 10
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending exports: %w", err)
	}
	defer rows.Close()

	var exports []*AuditExport
	for rows.Next() {
		export, err := r.scanAuditExportRows(rows)
		if err != nil {
			return nil, err
		}
		exports = append(exports, export)
	}

	return exports, rows.Err()
}

// GetExpired retrieves all expired audit exports for cleanup.
//
// DELIBERATELY UNWRAPPED for the same reason as GetPending: a retention sweep
// is cross-org by definition and belongs on the axonflow_platform_admin pool.
// Also unwired today. Allowlisted in rlsReadAllowlist() (#3103).
func (r *PostgresAuditExportRepository) GetExpired(ctx context.Context) ([]*AuditExport, error) {
	query := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE expires_at < NOW() AND status = 'completed'
		ORDER BY expires_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get expired exports: %w", err)
	}
	defer rows.Close()

	var exports []*AuditExport
	for rows.Next() {
		export, err := r.scanAuditExportRows(rows)
		if err != nil {
			return nil, err
		}
		exports = append(exports, export)
	}

	return exports, rows.Err()
}

// scanAuditExport scans a single row into an AuditExport.
func (r *PostgresAuditExportRepository) scanAuditExport(row *sql.Row) (*AuditExport, error) {
	var export AuditExport
	var startDate, endDate, startedAt, completedAt, expiresAt sql.NullTime
	var errorMessage, requestedBy, requestedByEmail, purpose sql.NullString
	var filePath, fileChecksum sql.NullString
	var downloadURL, storageType, storageKey sql.NullString
	var summaryJSON []byte

	err := row.Scan(
		&export.ID, &export.OrgID, &export.ExportType, &export.Format,
		&startDate, &endDate,
		pq.Array(&export.SystemIDs), pq.Array(&export.RiskCategories),
		&export.IncludeArchived,
		&export.Status, &errorMessage, &requestedBy, &requestedByEmail, &purpose,
		&startedAt, &completedAt, &filePath, &export.FileSizeBytes, &fileChecksum,
		&export.RecordCount, &summaryJSON, &expiresAt,
		&downloadURL, &storageType, &storageKey,
		&export.CreatedAt, &export.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAuditExportNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit export: %w", err)
	}

	// Handle nullable fields
	if startDate.Valid {
		export.StartDate = &startDate.Time
	}
	if endDate.Valid {
		export.EndDate = &endDate.Time
	}
	if errorMessage.Valid {
		export.ErrorMessage = errorMessage.String
	}
	if requestedBy.Valid {
		export.RequestedBy = requestedBy.String
	}
	if requestedByEmail.Valid {
		export.RequestedByEmail = requestedByEmail.String
	}
	if purpose.Valid {
		export.Purpose = purpose.String
	}
	if startedAt.Valid {
		export.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		export.CompletedAt = &completedAt.Time
	}
	if filePath.Valid {
		export.FilePath = filePath.String
	}
	if fileChecksum.Valid {
		export.FileChecksum = fileChecksum.String
	}
	if expiresAt.Valid {
		export.ExpiresAt = &expiresAt.Time
	}
	if downloadURL.Valid {
		export.DownloadURL = downloadURL.String
	}
	if storageType.Valid {
		export.StorageType = storageType.String
	}
	if storageKey.Valid {
		export.StorageKey = storageKey.String
	}

	if len(summaryJSON) > 0 {
		json.Unmarshal(summaryJSON, &export.Summary)
	}

	return &export, nil
}

// scanAuditExportRows scans a row from rows into an AuditExport.
func (r *PostgresAuditExportRepository) scanAuditExportRows(rows *sql.Rows) (*AuditExport, error) {
	var export AuditExport
	var startDate, endDate, startedAt, completedAt, expiresAt sql.NullTime
	var errorMessage, requestedBy, requestedByEmail, purpose sql.NullString
	var filePath, fileChecksum sql.NullString
	var downloadURL, storageType, storageKey sql.NullString
	var summaryJSON []byte

	err := rows.Scan(
		&export.ID, &export.OrgID, &export.ExportType, &export.Format,
		&startDate, &endDate,
		pq.Array(&export.SystemIDs), pq.Array(&export.RiskCategories),
		&export.IncludeArchived,
		&export.Status, &errorMessage, &requestedBy, &requestedByEmail, &purpose,
		&startedAt, &completedAt, &filePath, &export.FileSizeBytes, &fileChecksum,
		&export.RecordCount, &summaryJSON, &expiresAt,
		&downloadURL, &storageType, &storageKey,
		&export.CreatedAt, &export.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan audit export row: %w", err)
	}

	// Handle nullable fields (same as scanAuditExport)
	if startDate.Valid {
		export.StartDate = &startDate.Time
	}
	if endDate.Valid {
		export.EndDate = &endDate.Time
	}
	if errorMessage.Valid {
		export.ErrorMessage = errorMessage.String
	}
	if requestedBy.Valid {
		export.RequestedBy = requestedBy.String
	}
	if requestedByEmail.Valid {
		export.RequestedByEmail = requestedByEmail.String
	}
	if purpose.Valid {
		export.Purpose = purpose.String
	}
	if startedAt.Valid {
		export.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		export.CompletedAt = &completedAt.Time
	}
	if filePath.Valid {
		export.FilePath = filePath.String
	}
	if fileChecksum.Valid {
		export.FileChecksum = fileChecksum.String
	}
	if expiresAt.Valid {
		export.ExpiresAt = &expiresAt.Time
	}
	if downloadURL.Valid {
		export.DownloadURL = downloadURL.String
	}
	if storageType.Valid {
		export.StorageType = storageType.String
	}
	if storageKey.Valid {
		export.StorageKey = storageKey.String
	}

	if len(summaryJSON) > 0 {
		json.Unmarshal(summaryJSON, &export.Summary)
	}

	return &export, nil
}
