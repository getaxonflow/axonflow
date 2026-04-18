// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var metricColumns = []string{
	"id", "org_id", "model_id", "metric_type", "value", "sample_size",
	"timestamp", "window_start", "window_end", "metadata",
}

var biasColumns = []string{
	"id", "org_id", "model_id", "category", "score", "threshold", "is_violation",
	"sample_size", "group_a", "group_b", "group_a_rate", "group_b_rate",
	"timestamp", "window_start", "window_end", "metadata",
}

var alertColumns = []string{
	"id", "org_id", "model_id", "alert_type", "severity", "title", "description",
	"metric_type", "bias_category", "current_value", "threshold", "triggered_at",
	"acked_at", "acked_by", "resolved_at", "resolved_by",
}

func sampleMetricRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	windowStart := now.Add(-1 * time.Hour)
	windowEnd := now
	return []driver.Value{
		id, orgID, modelID, string(MetricTypeAccuracy), 0.95, 1000,
		now, windowStart, windowEnd, []byte(`{"dataset":"test_v2"}`),
	}
}

func sampleBiasRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	windowStart := now.Add(-1 * time.Hour)
	windowEnd := now
	return []driver.Value{
		id, orgID, modelID, string(BiasCategoryGender), 0.08, 0.10, false,
		5000, "male", "female", 0.82, 0.78,
		now, windowStart, windowEnd, []byte(`{"test":"bias_check"}`),
	}
}

func sampleAlertRow(id, orgID, modelID string) []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		id, orgID, modelID, "accuracy_degradation", string(AlertSeverityCritical),
		"Accuracy below threshold", "Model accuracy dropped to 0.72",
		string(MetricTypeAccuracy), string(BiasCategoryGender), 0.72, 0.80, now,
		nil, "", nil, "",
	}
}

func TestAccuracyRepository_SaveMetric_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	metric := &AccuracyMetric{
		ID:          "metric-001",
		OrgID:       "org-001",
		ModelID:     "model-001",
		MetricType:  MetricTypeAccuracy,
		Value:       0.95,
		SampleSize:  1000,
		Timestamp:   now,
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Metadata:    map[string]interface{}{"dataset": "v2"},
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_accuracy_metrics`)).
		WithArgs(
			metric.ID, metric.OrgID, metric.ModelID, metric.MetricType,
			metric.Value, metric.SampleSize, metric.Timestamp,
			metric.WindowStart, metric.WindowEnd, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.SaveMetric(ctx, metric)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_SaveMetric_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	metric := &AccuracyMetric{
		ID:         "metric-001",
		OrgID:      "org-001",
		ModelID:    "model-001",
		MetricType: MetricTypeAccuracy,
		Value:      0.95,
		SampleSize: 1000,
		Timestamp:  time.Now().UTC(),
		Metadata:   map[string]interface{}{},
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_accuracy_metrics`)).
		WillReturnError(fmt.Errorf("connection refused"))

	err = repo.SaveMetric(ctx, metric)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetMetrics_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	// Count query
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Data query
	dataRows := sqlmock.NewRows(metricColumns).
		AddRow(sampleMetricRow("m-1", "org-001", "model-001")...).
		AddRow(sampleMetricRow("m-2", "org-001", "model-001")...)

	mock.ExpectQuery(`SELECT id, org_id, model_id`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)

	metrics, total, err := repo.GetMetrics(ctx, "org-001", "", "", time.Time{}, time.Time{}, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, metrics, 2)
	assert.Equal(t, "m-1", metrics[0].ID)
	assert.Equal(t, MetricTypeAccuracy, metrics[0].MetricType)
	assert.Equal(t, 0.95, metrics[0].Value)
	assert.NotEmpty(t, metrics[0].Metadata)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetMetrics_WithAllFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy), from, to).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(metricColumns).
		AddRow(sampleMetricRow("m-1", "org-001", "model-001")...)

	mock.ExpectQuery(`SELECT id, org_id, model_id`).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy), from, to, 50, 5).
		WillReturnRows(dataRows)

	metrics, total, err := repo.GetMetrics(ctx, "org-001", "model-001", MetricTypeAccuracy, from, to, 50, 5)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, metrics, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetMetrics_DefaultLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT id, org_id, model_id`).
		WithArgs("org-001", DefaultMetricsListLimit, 0).
		WillReturnRows(sqlmock.NewRows(metricColumns))

	metrics, total, err := repo.GetMetrics(ctx, "org-001", "", "", time.Time{}, time.Time{}, 0, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, metrics)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetMetrics_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table not found"))

	_, _, err = repo.GetMetrics(ctx, "org-001", "", "", time.Time{}, time.Time{}, 10, 0)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetLatestMetric_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(metricColumns).
		AddRow(sampleMetricRow("m-latest", "org-001", "model-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy)).
		WillReturnRows(rows)

	metric, err := repo.GetLatestMetric(ctx, "org-001", "model-001", MetricTypeAccuracy)
	require.NoError(t, err)
	assert.NotNil(t, metric)
	assert.Equal(t, "m-latest", metric.ID)
	assert.Equal(t, 0.95, metric.Value)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetLatestMetric_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "nonexistent", string(MetricTypeAccuracy)).
		WillReturnError(sql.ErrNoRows)

	metric, err := repo.GetLatestMetric(ctx, "org-001", "nonexistent", MetricTypeAccuracy)
	assert.NoError(t, err)
	assert.Nil(t, metric)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetLatestMetric_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy)).
		WillReturnError(fmt.Errorf("connection refused"))

	metric, err := repo.GetLatestMetric(ctx, "org-001", "model-001", MetricTypeAccuracy)
	assert.Nil(t, metric)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_AggregateMetrics_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	rows := sqlmock.NewRows([]string{
		"metric_type", "count", "min", "max", "avg", "std_dev", "p50", "p95", "p99",
	}).AddRow(
		string(MetricTypeAccuracy), int64(100), 0.85, 0.99, 0.94,
		sql.NullFloat64{Float64: 0.03, Valid: true}, 0.95, 0.98, 0.99,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy), from, to).
		WillReturnRows(rows)

	agg, err := repo.AggregateMetrics(ctx, "org-001", "model-001", MetricTypeAccuracy, from, to)
	require.NoError(t, err)
	assert.NotNil(t, agg)
	assert.Equal(t, MetricTypeAccuracy, agg.MetricType)
	assert.Equal(t, int64(100), agg.Count)
	assert.Equal(t, 0.85, agg.Min)
	assert.Equal(t, 0.99, agg.Max)
	assert.Equal(t, 0.94, agg.Avg)
	assert.Equal(t, 0.03, agg.StdDev)
	assert.Equal(t, 0.95, agg.P50)
	assert.Equal(t, 0.98, agg.P95)
	assert.Equal(t, 0.99, agg.P99)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_AggregateMetrics_NullStdDev(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	rows := sqlmock.NewRows([]string{
		"metric_type", "count", "min", "max", "avg", "std_dev", "p50", "p95", "p99",
	}).AddRow(
		string(MetricTypeAccuracy), int64(1), 0.95, 0.95, 0.95,
		sql.NullFloat64{Valid: false}, 0.95, 0.95, 0.95,
	)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy), from, to).
		WillReturnRows(rows)

	agg, err := repo.AggregateMetrics(ctx, "org-001", "model-001", MetricTypeAccuracy, from, to)
	require.NoError(t, err)
	assert.Equal(t, float64(0), agg.StdDev)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_AggregateMetrics_NoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_metrics`)).
		WithArgs("org-001", "model-001", string(MetricTypeAccuracy), from, to).
		WillReturnError(sql.ErrNoRows)

	agg, err := repo.AggregateMetrics(ctx, "org-001", "model-001", MetricTypeAccuracy, from, to)
	assert.NoError(t, err)
	assert.Nil(t, agg)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_SaveBiasRecord_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	record := &BiasRecord{
		ID:          "bias-001",
		OrgID:       "org-001",
		ModelID:     "model-001",
		Category:    BiasCategoryGender,
		Score:       0.08,
		Threshold:   0.10,
		IsViolation: false,
		SampleSize:  5000,
		GroupA:      "male",
		GroupB:      "female",
		GroupARate:  0.82,
		GroupBRate:  0.78,
		Timestamp:   now,
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Metadata:    map[string]interface{}{"test": "bias"},
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_bias_records`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.SaveBiasRecord(ctx, record)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetBiasRecords_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	dataRows := sqlmock.NewRows(biasColumns).
		AddRow(sampleBiasRow("b-1", "org-001", "model-001")...).
		AddRow(sampleBiasRow("b-2", "org-001", "model-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_bias_records`)).
		WithArgs("org-001", "model-001", string(BiasCategoryGender), from, to, MaxListLimit).
		WillReturnRows(dataRows)

	records, err := repo.GetBiasRecords(ctx, "org-001", "model-001", BiasCategoryGender, from, to)
	require.NoError(t, err)
	assert.Len(t, records, 2)
	assert.Equal(t, BiasCategoryGender, records[0].Category)
	assert.Equal(t, 0.08, records[0].Score)
	assert.Equal(t, "male", records[0].GroupA)
	assert.Equal(t, "female", records[0].GroupB)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetBiasRecords_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	from := time.Now().UTC().Add(-24 * time.Hour)
	to := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_bias_records`)).
		WithArgs("org-001", "model-001", string(BiasCategoryAge), from, to, MaxListLimit).
		WillReturnRows(sqlmock.NewRows(biasColumns))

	records, err := repo.GetBiasRecords(ctx, "org-001", "model-001", BiasCategoryAge, from, to)
	require.NoError(t, err)
	assert.Empty(t, records)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_SaveAlert_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	alert := &AccuracyAlert{
		ID:           "alert-001",
		OrgID:        "org-001",
		ModelID:      "model-001",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityCritical,
		Title:        "Accuracy below threshold",
		Description:  "Model accuracy dropped to 0.72",
		MetricType:   MetricTypeAccuracy,
		CurrentValue: 0.72,
		Threshold:    0.80,
		TriggeredAt:  time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_accuracy_alerts`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.SaveAlert(ctx, alert)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetActiveAlerts_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(alertColumns).
		AddRow(sampleAlertRow("alert-1", "org-001", "model-001")...).
		AddRow(sampleAlertRow("alert-2", "org-001", "model-002")...)

	mock.ExpectQuery(regexp.QuoteMeta(`resolved_at IS NULL`)).
		WithArgs("org-001", DefaultMetricsListLimit).
		WillReturnRows(dataRows)

	alerts, err := repo.GetActiveAlerts(ctx, "org-001")
	require.NoError(t, err)
	assert.Len(t, alerts, 2)
	assert.Equal(t, "alert-1", alerts[0].ID)
	assert.Equal(t, AlertSeverityCritical, alerts[0].Severity)
	assert.Nil(t, alerts[0].ResolvedAt)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetActiveAlerts_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`resolved_at IS NULL`)).
		WithArgs("org-001", DefaultMetricsListLimit).
		WillReturnRows(sqlmock.NewRows(alertColumns))

	alerts, err := repo.GetActiveAlerts(ctx, "org-001")
	require.NoError(t, err)
	assert.Empty(t, alerts)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetAlertByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(alertColumns).
		AddRow(sampleAlertRow("alert-001", "org-001", "model-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_alerts WHERE id = $1`)).
		WithArgs("alert-001").
		WillReturnRows(rows)

	alert, err := repo.GetAlertByID(ctx, "alert-001")
	require.NoError(t, err)
	assert.Equal(t, "alert-001", alert.ID)
	assert.Equal(t, "Accuracy below threshold", alert.Title)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetAlertByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_accuracy_alerts WHERE id = $1`)).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	alert, err := repo.GetAlertByID(ctx, "nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, alert)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_UpdateAlert_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	alert := &AccuracyAlert{
		ID:         "alert-001",
		AckedAt:    &now,
		AckedBy:    "admin",
		ResolvedAt: &now,
		ResolvedBy: "admin",
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE euaiact_accuracy_alerts`)).
		WithArgs(alert.ID, alert.AckedAt, alert.AckedBy, alert.ResolvedAt, alert.ResolvedBy).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.UpdateAlert(ctx, alert)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetDistinctModels_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows([]string{"model_id"}).
		AddRow("model-001").
		AddRow("model-002").
		AddRow("model-003")

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT model_id FROM euaiact_accuracy_metrics WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(rows)

	models, err := repo.GetDistinctModels(ctx, "org-001")
	require.NoError(t, err)
	assert.Len(t, models, 3)
	assert.Equal(t, "model-001", models[0])
	assert.Equal(t, "model-002", models[1])
	assert.Equal(t, "model-003", models[2])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetDistinctModels_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT model_id FROM euaiact_accuracy_metrics WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"model_id"}))

	models, err := repo.GetDistinctModels(ctx, "org-001")
	require.NoError(t, err)
	assert.Empty(t, models)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAccuracyRepository_GetDistinctModels_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT DISTINCT model_id`)).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table not found"))

	models, err := repo.GetDistinctModels(ctx, "org-001")
	assert.Nil(t, models)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
