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
