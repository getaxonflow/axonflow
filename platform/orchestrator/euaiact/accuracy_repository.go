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
)

// AccuracyRepository defines the interface for accuracy metrics persistence.
type AccuracyRepository interface {
	// SaveMetric saves an accuracy metric record.
	SaveMetric(ctx context.Context, metric *AccuracyMetric) error

	// GetMetrics retrieves metrics for a model.
	GetMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time, limit, offset int) ([]*AccuracyMetric, int64, error)

	// GetLatestMetric retrieves the latest metric for a model.
	GetLatestMetric(ctx context.Context, orgID, modelID string, metricType MetricType) (*AccuracyMetric, error)

	// AggregateMetrics aggregates metrics for a model.
	AggregateMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time) (*AggregatedMetric, error)

	// SaveBiasRecord saves a bias detection record.
	SaveBiasRecord(ctx context.Context, record *BiasRecord) error

	// GetBiasRecords retrieves bias records for a model.
	GetBiasRecords(ctx context.Context, orgID, modelID string, category BiasCategory, from, to time.Time) ([]*BiasRecord, error)

	// SaveAlert saves an accuracy/bias alert.
	SaveAlert(ctx context.Context, alert *AccuracyAlert) error

	// GetActiveAlerts retrieves active alerts for an org.
	GetActiveAlerts(ctx context.Context, orgID string) ([]*AccuracyAlert, error)

	// GetAlertByID retrieves a specific alert by ID.
	GetAlertByID(ctx context.Context, alertID string) (*AccuracyAlert, error)

	// UpdateAlert updates an alert.
	UpdateAlert(ctx context.Context, alert *AccuracyAlert) error

	// GetDistinctModels returns distinct model IDs for an org.
	GetDistinctModels(ctx context.Context, orgID string) ([]string, error)
}

// PostgresAccuracyRepository implements AccuracyRepository using PostgreSQL.
type PostgresAccuracyRepository struct {
	db *sql.DB
}

// NewPostgresAccuracyRepository creates a new PostgreSQL accuracy repository.
func NewPostgresAccuracyRepository(db *sql.DB) *PostgresAccuracyRepository {
	return &PostgresAccuracyRepository{db: db}
}

// SaveMetric saves an accuracy metric record.
func (r *PostgresAccuracyRepository) SaveMetric(ctx context.Context, metric *AccuracyMetric) error {
	query := `
		INSERT INTO euaiact_accuracy_metrics (
			id, org_id, model_id, metric_type, value, sample_size,
			timestamp, window_start, window_end, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	metadataJSON, err := json.Marshal(metric.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		metric.ID, metric.OrgID, metric.ModelID, metric.MetricType, metric.Value, metric.SampleSize,
		metric.Timestamp, metric.WindowStart, metric.WindowEnd, metadataJSON,
	)
	return err
}

// GetMetrics retrieves metrics for a model.
func (r *PostgresAccuracyRepository) GetMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time, limit, offset int) ([]*AccuracyMetric, int64, error) {
	// Build query with optional filters
	baseQuery := `FROM euaiact_accuracy_metrics WHERE org_id = $1`
	args := []interface{}{orgID}
	argIndex := 2

	if modelID != "" {
		baseQuery += fmt.Sprintf(" AND model_id = $%d", argIndex)
		args = append(args, modelID)
		argIndex++
	}
	if metricType != "" {
		baseQuery += fmt.Sprintf(" AND metric_type = $%d", argIndex)
		args = append(args, metricType)
		argIndex++
	}
	if !from.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, from)
		argIndex++
	}
	if !to.IsZero() {
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, to)
		argIndex++
	}

	// Count query
	var total int64
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	if limit <= 0 {
		limit = DefaultMetricsListLimit
	}
	dataQuery := `SELECT id, org_id, model_id, metric_type, value, sample_size,
		timestamp, window_start, window_end, metadata ` + baseQuery + ` ORDER BY timestamp DESC`
	dataQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var metrics []*AccuracyMetric
	for rows.Next() {
		metric := &AccuracyMetric{}
		var metadataJSON []byte
		if err := rows.Scan(
			&metric.ID, &metric.OrgID, &metric.ModelID, &metric.MetricType, &metric.Value, &metric.SampleSize,
			&metric.Timestamp, &metric.WindowStart, &metric.WindowEnd, &metadataJSON,
		); err != nil {
			return nil, 0, err
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &metric.Metadata); err != nil {
				return nil, 0, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		metrics = append(metrics, metric)
	}

	return metrics, total, rows.Err()
}

// GetLatestMetric retrieves the latest metric for a model.
func (r *PostgresAccuracyRepository) GetLatestMetric(ctx context.Context, orgID, modelID string, metricType MetricType) (*AccuracyMetric, error) {
	query := `
		SELECT id, org_id, model_id, metric_type, value, sample_size,
			timestamp, window_start, window_end, metadata
		FROM euaiact_accuracy_metrics
		WHERE org_id = $1 AND model_id = $2 AND metric_type = $3
		ORDER BY timestamp DESC
		LIMIT 1`

	metric := &AccuracyMetric{}
	var metadataJSON []byte
	err := r.db.QueryRowContext(ctx, query, orgID, modelID, metricType).Scan(
		&metric.ID, &metric.OrgID, &metric.ModelID, &metric.MetricType, &metric.Value, &metric.SampleSize,
		&metric.Timestamp, &metric.WindowStart, &metric.WindowEnd, &metadataJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &metric.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return metric, nil
}

// AggregateMetrics aggregates metrics for a model.
func (r *PostgresAccuracyRepository) AggregateMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time) (*AggregatedMetric, error) {
	query := `
		SELECT
			$3 as metric_type,
			COUNT(*) as count,
			MIN(value) as min,
			MAX(value) as max,
			AVG(value) as avg,
			STDDEV(value) as std_dev,
			PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY value) as p50,
			PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY value) as p95,
			PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY value) as p99
		FROM euaiact_accuracy_metrics
		WHERE org_id = $1 AND model_id = $2 AND metric_type = $3
			AND timestamp BETWEEN $4 AND $5`

	agg := &AggregatedMetric{MetricType: metricType}
	var stdDev sql.NullFloat64
	err := r.db.QueryRowContext(ctx, query, orgID, modelID, metricType, from, to).Scan(
		&agg.MetricType, &agg.Count, &agg.Min, &agg.Max, &agg.Avg,
		&stdDev, &agg.P50, &agg.P95, &agg.P99,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if stdDev.Valid {
		agg.StdDev = stdDev.Float64
	}
	return agg, nil
}

// SaveBiasRecord saves a bias detection record.
func (r *PostgresAccuracyRepository) SaveBiasRecord(ctx context.Context, record *BiasRecord) error {
	query := `
		INSERT INTO euaiact_bias_records (
			id, org_id, model_id, category, score, threshold, is_violation,
			sample_size, group_a, group_b, group_a_rate, group_b_rate,
			timestamp, window_start, window_end, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	metadataJSON, err := json.Marshal(record.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		record.ID, record.OrgID, record.ModelID, record.Category, record.Score, record.Threshold, record.IsViolation,
		record.SampleSize, record.GroupA, record.GroupB, record.GroupARate, record.GroupBRate,
		record.Timestamp, record.WindowStart, record.WindowEnd, metadataJSON,
	)
	return err
}

// GetBiasRecords retrieves bias records for a model.
func (r *PostgresAccuracyRepository) GetBiasRecords(ctx context.Context, orgID, modelID string, category BiasCategory, from, to time.Time) ([]*BiasRecord, error) {
	query := `
		SELECT id, org_id, model_id, category, score, threshold, is_violation,
			sample_size, group_a, group_b, group_a_rate, group_b_rate,
			timestamp, window_start, window_end, metadata
		FROM euaiact_bias_records
		WHERE org_id = $1 AND model_id = $2 AND category = $3
			AND timestamp BETWEEN $4 AND $5
		ORDER BY timestamp DESC
		LIMIT $6`

	rows, err := r.db.QueryContext(ctx, query, orgID, modelID, category, from, to, MaxListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*BiasRecord
	for rows.Next() {
		record := &BiasRecord{}
		var metadataJSON []byte
		if err := rows.Scan(
			&record.ID, &record.OrgID, &record.ModelID, &record.Category, &record.Score, &record.Threshold, &record.IsViolation,
			&record.SampleSize, &record.GroupA, &record.GroupB, &record.GroupARate, &record.GroupBRate,
			&record.Timestamp, &record.WindowStart, &record.WindowEnd, &metadataJSON,
		); err != nil {
			return nil, err
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &record.Metadata); err != nil {
				return nil, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		records = append(records, record)
	}

	return records, rows.Err()
}

// SaveAlert saves an accuracy/bias alert.
func (r *PostgresAccuracyRepository) SaveAlert(ctx context.Context, alert *AccuracyAlert) error {
	query := `
		INSERT INTO euaiact_accuracy_alerts (
			id, org_id, model_id, alert_type, severity, title, description,
			metric_type, bias_category, current_value, threshold, triggered_at,
			acked_at, acked_by, resolved_at, resolved_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`

	_, err := r.db.ExecContext(ctx, query,
		alert.ID, alert.OrgID, alert.ModelID, alert.AlertType, alert.Severity, alert.Title, alert.Description,
		alert.MetricType, alert.BiasCategory, alert.CurrentValue, alert.Threshold, alert.TriggeredAt,
		alert.AckedAt, alert.AckedBy, alert.ResolvedAt, alert.ResolvedBy,
	)
	return err
}

// GetActiveAlerts retrieves active alerts for an org.
func (r *PostgresAccuracyRepository) GetActiveAlerts(ctx context.Context, orgID string) ([]*AccuracyAlert, error) {
	query := `
		SELECT id, org_id, model_id, alert_type, severity, title, description,
			metric_type, bias_category, current_value, threshold, triggered_at,
			acked_at, acked_by, resolved_at, resolved_by
		FROM euaiact_accuracy_alerts
		WHERE org_id = $1 AND resolved_at IS NULL
		ORDER BY triggered_at DESC
		LIMIT $2`

	rows, err := r.db.QueryContext(ctx, query, orgID, DefaultMetricsListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*AccuracyAlert
	for rows.Next() {
		alert := &AccuracyAlert{}
		if err := rows.Scan(
			&alert.ID, &alert.OrgID, &alert.ModelID, &alert.AlertType, &alert.Severity, &alert.Title, &alert.Description,
			&alert.MetricType, &alert.BiasCategory, &alert.CurrentValue, &alert.Threshold, &alert.TriggeredAt,
			&alert.AckedAt, &alert.AckedBy, &alert.ResolvedAt, &alert.ResolvedBy,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, rows.Err()
}

// GetAlertByID retrieves a specific alert by ID.
func (r *PostgresAccuracyRepository) GetAlertByID(ctx context.Context, alertID string) (*AccuracyAlert, error) {
	query := `
		SELECT id, org_id, model_id, alert_type, severity, title, description,
			metric_type, bias_category, current_value, threshold, triggered_at,
			acked_at, acked_by, resolved_at, resolved_by
		FROM euaiact_accuracy_alerts
		WHERE id = $1`

	alert := &AccuracyAlert{}
	err := r.db.QueryRowContext(ctx, query, alertID).Scan(
		&alert.ID, &alert.OrgID, &alert.ModelID, &alert.AlertType, &alert.Severity, &alert.Title, &alert.Description,
		&alert.MetricType, &alert.BiasCategory, &alert.CurrentValue, &alert.Threshold, &alert.TriggeredAt,
		&alert.AckedAt, &alert.AckedBy, &alert.ResolvedAt, &alert.ResolvedBy,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return alert, nil
}

// UpdateAlert updates an alert.
func (r *PostgresAccuracyRepository) UpdateAlert(ctx context.Context, alert *AccuracyAlert) error {
	query := `
		UPDATE euaiact_accuracy_alerts
		SET acked_at = $2, acked_by = $3, resolved_at = $4, resolved_by = $5
		WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		alert.ID, alert.AckedAt, alert.AckedBy, alert.ResolvedAt, alert.ResolvedBy,
	)
	return err
}

// GetDistinctModels returns distinct model IDs for an org.
func (r *PostgresAccuracyRepository) GetDistinctModels(ctx context.Context, orgID string) ([]string, error) {
	query := `SELECT DISTINCT model_id FROM euaiact_accuracy_metrics WHERE org_id = $1 ORDER BY model_id`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models []string
	for rows.Next() {
		var modelID string
		if err := rows.Scan(&modelID); err != nil {
			return nil, err
		}
		models = append(models, modelID)
	}

	return models, rows.Err()
}
