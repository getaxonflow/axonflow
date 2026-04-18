// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for AccuracyRepository
// These tests require DATABASE_URL to be set

func cleanupTestAccuracyData(t *testing.T, db *sql.DB, orgID string) {
	_, err := db.Exec("DELETE FROM euaiact_accuracy_alerts WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup accuracy alerts: %v", err)
	}
	_, err = db.Exec("DELETE FROM euaiact_bias_records WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup bias records: %v", err)
	}
	_, err = db.Exec("DELETE FROM euaiact_accuracy_metrics WHERE org_id = $1", orgID)
	if err != nil {
		t.Logf("Warning: failed to cleanup accuracy metrics: %v", err)
	}
}

func TestAccuracyRepository_Integration_NewPostgresAccuracyRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestAccuracyRepository_Integration_SaveMetric(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-metric-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	metric := &AccuracyMetric{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ModelID:     "model-123",
		MetricType:  MetricTypeAccuracy,
		Value:       0.95,
		SampleSize:  1000,
		Timestamp:   time.Now().UTC(),
		WindowStart: time.Now().UTC().Add(-24 * time.Hour),
		WindowEnd:   time.Now().UTC(),
		Metadata:    map[string]interface{}{"environment": "production", "version": "1.0"},
	}

	err := repo.SaveMetric(ctx, metric)
	if err != nil {
		t.Fatalf("SaveMetric() error = %v", err)
	}

	// Verify by retrieving
	metrics, total, err := repo.GetMetrics(ctx, orgID, "model-123", MetricTypeAccuracy, time.Time{}, time.Time{}, 10, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}

	if total != 1 {
		t.Errorf("Expected total 1, got %d", total)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(metrics))
	}
	if metrics[0].Value != 0.95 {
		t.Errorf("Expected Value 0.95, got %f", metrics[0].Value)
	}
	if metrics[0].SampleSize != 1000 {
		t.Errorf("Expected SampleSize 1000, got %d", metrics[0].SampleSize)
	}
}

func TestAccuracyRepository_Integration_GetMetrics_WithFilters(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-filter-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create metrics for different models and types
	models := []string{"model-A", "model-B"}
	metricTypes := []MetricType{MetricTypeAccuracy, MetricTypePrecision}

	for _, model := range models {
		for _, mt := range metricTypes {
			metric := &AccuracyMetric{
				ID:         uuid.New().String(),
				OrgID:      orgID,
				ModelID:    model,
				MetricType: mt,
				Value:      0.9,
				SampleSize: 500,
				Timestamp:  time.Now().UTC(),
			}
			if err := repo.SaveMetric(ctx, metric); err != nil {
				t.Fatalf("SaveMetric() error = %v", err)
			}
		}
	}

	// Filter by model
	metrics, total, err := repo.GetMetrics(ctx, orgID, "model-A", "", time.Time{}, time.Time{}, 10, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}
	if total != 2 {
		t.Errorf("Expected total 2 for model-A, got %d", total)
	}

	// Filter by metric type
	metrics, total, err = repo.GetMetrics(ctx, orgID, "", MetricTypeAccuracy, time.Time{}, time.Time{}, 10, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}
	if total != 2 {
		t.Errorf("Expected total 2 for accuracy type, got %d", total)
	}

	// Filter by both
	metrics, total, err = repo.GetMetrics(ctx, orgID, "model-A", MetricTypeAccuracy, time.Time{}, time.Time{}, 10, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}
	if total != 1 {
		t.Errorf("Expected total 1 for model-A accuracy, got %d", total)
	}
	if len(metrics) != 1 {
		t.Errorf("Expected 1 metric, got %d", len(metrics))
	}
}

func TestAccuracyRepository_Integration_GetMetrics_TimeRange(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-time-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create metrics at different times
	baseTime := time.Now().UTC()
	times := []time.Time{
		baseTime.Add(-72 * time.Hour), // 3 days ago
		baseTime.Add(-48 * time.Hour), // 2 days ago
		baseTime.Add(-24 * time.Hour), // 1 day ago
		baseTime,                       // now
	}

	for _, ts := range times {
		metric := &AccuracyMetric{
			ID:         uuid.New().String(),
			OrgID:      orgID,
			ModelID:    "model-time",
			MetricType: MetricTypeAccuracy,
			Value:      0.9,
			SampleSize: 100,
			Timestamp:  ts,
		}
		if err := repo.SaveMetric(ctx, metric); err != nil {
			t.Fatalf("SaveMetric() error = %v", err)
		}
	}

	// Query last 2 days
	from := baseTime.Add(-48 * time.Hour)
	to := baseTime.Add(time.Hour)
	metrics, total, err := repo.GetMetrics(ctx, orgID, "model-time", "", from, to, 10, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}

	if total != 3 {
		t.Errorf("Expected total 3 metrics in last 2 days, got %d", total)
	}
	if len(metrics) != 3 {
		t.Errorf("Expected 3 metrics, got %d", len(metrics))
	}
}

func TestAccuracyRepository_Integration_GetLatestMetric(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-latest-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create metrics at different times
	baseTime := time.Now().UTC()
	for i := 0; i < 3; i++ {
		metric := &AccuracyMetric{
			ID:         uuid.New().String(),
			OrgID:      orgID,
			ModelID:    "model-latest",
			MetricType: MetricTypeAccuracy,
			Value:      float64(90+i) / 100,
			SampleSize: 100,
			Timestamp:  baseTime.Add(time.Duration(i) * time.Hour),
		}
		if err := repo.SaveMetric(ctx, metric); err != nil {
			t.Fatalf("SaveMetric() error = %v", err)
		}
	}

	// Get latest
	latest, err := repo.GetLatestMetric(ctx, orgID, "model-latest", MetricTypeAccuracy)
	if err != nil {
		t.Fatalf("GetLatestMetric() error = %v", err)
	}

	if latest == nil {
		t.Fatal("Expected latest metric to be found")
	}
	if latest.Value != 0.92 {
		t.Errorf("Expected latest Value 0.92, got %f", latest.Value)
	}
}

func TestAccuracyRepository_Integration_GetLatestMetric_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-notfound-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	latest, err := repo.GetLatestMetric(ctx, orgID, "non-existent-model", MetricTypeAccuracy)
	if err != nil {
		t.Fatalf("GetLatestMetric() error = %v", err)
	}
	if latest != nil {
		t.Error("Expected nil for non-existent model")
	}
}

func TestAccuracyRepository_Integration_AggregateMetrics(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-acc-agg-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create metrics with known values for aggregation
	values := []float64{0.85, 0.90, 0.92, 0.88, 0.95}
	baseTime := time.Now().UTC()

	for i, val := range values {
		metric := &AccuracyMetric{
			ID:         uuid.New().String(),
			OrgID:      orgID,
			ModelID:    "model-agg",
			MetricType: MetricTypeAccuracy,
			Value:      val,
			SampleSize: 100,
			Timestamp:  baseTime.Add(time.Duration(i) * time.Hour),
		}
		if err := repo.SaveMetric(ctx, metric); err != nil {
			t.Fatalf("SaveMetric() error = %v", err)
		}
	}

	// Aggregate
	from := baseTime.Add(-time.Hour)
	to := baseTime.Add(10 * time.Hour)
	agg, err := repo.AggregateMetrics(ctx, orgID, "model-agg", MetricTypeAccuracy, from, to)
	if err != nil {
		t.Fatalf("AggregateMetrics() error = %v", err)
	}

	if agg == nil {
		t.Fatal("Expected aggregated metrics")
	}
	if agg.Count != 5 {
		t.Errorf("Expected Count 5, got %d", agg.Count)
	}
	if agg.Min != 0.85 {
		t.Errorf("Expected Min 0.85, got %f", agg.Min)
	}
	if agg.Max != 0.95 {
		t.Errorf("Expected Max 0.95, got %f", agg.Max)
	}
	// Average of 0.85, 0.90, 0.92, 0.88, 0.95 = 0.90
	if agg.Avg < 0.89 || agg.Avg > 0.91 {
		t.Errorf("Expected Avg ~0.90, got %f", agg.Avg)
	}
}

func TestAccuracyRepository_Integration_SaveBiasRecord(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-bias-save-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	record := &BiasRecord{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		ModelID:     "model-bias",
		Category:    BiasCategoryGender,
		Score:       0.15,
		Threshold:   0.10,
		IsViolation: true,
		SampleSize:  5000,
		GroupA:      "male",
		GroupB:      "female",
		GroupARate:  0.85,
		GroupBRate:  0.70,
		Timestamp:   time.Now().UTC(),
		Metadata:    map[string]interface{}{"test_id": "bias-001"},
	}

	err := repo.SaveBiasRecord(ctx, record)
	if err != nil {
		t.Fatalf("SaveBiasRecord() error = %v", err)
	}

	// Verify by retrieving
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	records, err := repo.GetBiasRecords(ctx, orgID, "model-bias", BiasCategoryGender, from, to)
	if err != nil {
		t.Fatalf("GetBiasRecords() error = %v", err)
	}

	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}
	if records[0].IsViolation != true {
		t.Error("Expected IsViolation to be true")
	}
	if records[0].GroupA != "male" {
		t.Errorf("Expected GroupA 'male', got %s", records[0].GroupA)
	}
	if records[0].GroupARate != 0.85 {
		t.Errorf("Expected GroupARate 0.85, got %f", records[0].GroupARate)
	}
}

func TestAccuracyRepository_Integration_GetBiasRecords_ByCategory(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-bias-cat-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create records for different categories
	categories := []BiasCategory{BiasCategoryGender, BiasCategoryAge, BiasCategoryEthnicity}
	for _, cat := range categories {
		record := &BiasRecord{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ModelID:     "model-cat",
			Category:    cat,
			Score:       0.08,
			Threshold:   0.10,
			IsViolation: false,
			SampleSize:  1000,
			GroupA:      "group-a",
			GroupB:      "group-b",
			GroupARate:  0.80,
			GroupBRate:  0.78,
			Timestamp:   time.Now().UTC(),
		}
		if err := repo.SaveBiasRecord(ctx, record); err != nil {
			t.Fatalf("SaveBiasRecord() error = %v", err)
		}
	}

	// Query specific category
	from := time.Now().UTC().Add(-time.Hour)
	to := time.Now().UTC().Add(time.Hour)
	records, err := repo.GetBiasRecords(ctx, orgID, "model-cat", BiasCategoryGender, from, to)
	if err != nil {
		t.Fatalf("GetBiasRecords() error = %v", err)
	}

	if len(records) != 1 {
		t.Errorf("Expected 1 record for gender category, got %d", len(records))
	}
	if records[0].Category != BiasCategoryGender {
		t.Errorf("Expected Category gender, got %s", records[0].Category)
	}
}

func TestAccuracyRepository_Integration_SaveAlert(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-alert-save-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	alert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-alert",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityCritical,
		Title:        "Accuracy Below Threshold",
		Description:  "Model accuracy dropped below 90% threshold",
		MetricType:   MetricTypeAccuracy,
		CurrentValue: 0.85,
		Threshold:    0.90,
		TriggeredAt:  time.Now().UTC(),
	}

	err := repo.SaveAlert(ctx, alert)
	if err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	// Verify by retrieving active alerts
	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].AlertType != "accuracy_degradation" {
		t.Errorf("Expected AlertType 'accuracy_degradation', got %s", alerts[0].AlertType)
	}
	if alerts[0].Severity != AlertSeverityCritical {
		t.Errorf("Expected Severity critical, got %s", alerts[0].Severity)
	}
}

func TestAccuracyRepository_Integration_SaveAlert_BiasDetected(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-alert-bias-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	alert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-bias-alert",
		AlertType:    "bias_detected",
		Severity:     AlertSeverityWarning,
		Title:        "Gender Bias Detected",
		Description:  "Disparate impact detected between male and female groups",
		BiasCategory: BiasCategoryGender,
		CurrentValue: 0.15,
		Threshold:    0.10,
		TriggeredAt:  time.Now().UTC(),
	}

	err := repo.SaveAlert(ctx, alert)
	if err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].AlertType != "bias_detected" {
		t.Errorf("Expected AlertType 'bias_detected', got %s", alerts[0].AlertType)
	}
	if alerts[0].BiasCategory != BiasCategoryGender {
		t.Errorf("Expected BiasCategory gender, got %s", alerts[0].BiasCategory)
	}
}

func TestAccuracyRepository_Integration_GetActiveAlerts_OnlyActive(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-alert-active-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create active alert
	activeAlert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-active",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityWarning,
		Title:        "Active Alert",
		Description:  "This alert is active",
		CurrentValue: 0.85,
		Threshold:    0.90,
		TriggeredAt:  time.Now().UTC(),
	}
	if err := repo.SaveAlert(ctx, activeAlert); err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	// Create resolved alert
	resolvedTime := time.Now().UTC()
	resolvedAlert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-resolved",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityWarning,
		Title:        "Resolved Alert",
		Description:  "This alert was resolved",
		CurrentValue: 0.85,
		Threshold:    0.90,
		TriggeredAt:  time.Now().UTC().Add(-time.Hour),
		ResolvedAt:   &resolvedTime,
		ResolvedBy:   "resolver@example.com",
	}
	if err := repo.SaveAlert(ctx, resolvedAlert); err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	// Get active alerts - should only return the active one
	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("Expected 1 active alert, got %d", len(alerts))
	}
	if alerts[0].Title != "Active Alert" {
		t.Errorf("Expected 'Active Alert', got %s", alerts[0].Title)
	}
}

func TestAccuracyRepository_Integration_UpdateAlert_Acknowledge(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-alert-ack-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create alert
	alert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-ack",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityCritical,
		Title:        "Alert to Acknowledge",
		Description:  "This alert needs acknowledgment",
		CurrentValue: 0.80,
		Threshold:    0.90,
		TriggeredAt:  time.Now().UTC(),
	}
	if err := repo.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	// Acknowledge the alert
	ackTime := time.Now().UTC()
	alert.AckedAt = &ackTime
	alert.AckedBy = "operator@example.com"

	err := repo.UpdateAlert(ctx, alert)
	if err != nil {
		t.Fatalf("UpdateAlert() error = %v", err)
	}

	// Verify - alert should still be active (acked but not resolved)
	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].AckedAt == nil {
		t.Error("Expected AckedAt to be set")
	}
	if alerts[0].AckedBy != "operator@example.com" {
		t.Errorf("Expected AckedBy 'operator@example.com', got %s", alerts[0].AckedBy)
	}
}

func TestAccuracyRepository_Integration_UpdateAlert_Resolve(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-alert-resolve-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create and acknowledge alert
	ackTime := time.Now().UTC()
	alert := &AccuracyAlert{
		ID:           uuid.New().String(),
		OrgID:        orgID,
		ModelID:      "model-resolve",
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityCritical,
		Title:        "Alert to Resolve",
		Description:  "This alert needs resolution",
		CurrentValue: 0.80,
		Threshold:    0.90,
		TriggeredAt:  time.Now().UTC().Add(-time.Hour),
		AckedAt:      &ackTime,
		AckedBy:      "operator@example.com",
	}
	if err := repo.SaveAlert(ctx, alert); err != nil {
		t.Fatalf("SaveAlert() error = %v", err)
	}

	// Resolve the alert
	resolveTime := time.Now().UTC()
	alert.ResolvedAt = &resolveTime
	alert.ResolvedBy = "engineer@example.com"

	err := repo.UpdateAlert(ctx, alert)
	if err != nil {
		t.Fatalf("UpdateAlert() error = %v", err)
	}

	// Verify - alert should no longer be in active alerts
	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 0 {
		t.Errorf("Expected 0 active alerts after resolution, got %d", len(alerts))
	}
}

func TestAccuracyRepository_Integration_GetDistinctModels(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-models-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Create metrics for different models
	models := []string{"model-alpha", "model-beta", "model-gamma"}
	for _, model := range models {
		for i := 0; i < 3; i++ { // Multiple metrics per model
			metric := &AccuracyMetric{
				ID:         uuid.New().String(),
				OrgID:      orgID,
				ModelID:    model,
				MetricType: MetricTypeAccuracy,
				Value:      0.9,
				SampleSize: 100,
				Timestamp:  time.Now().UTC(),
			}
			if err := repo.SaveMetric(ctx, metric); err != nil {
				t.Fatalf("SaveMetric() error = %v", err)
			}
		}
	}

	// Get distinct models
	distinctModels, err := repo.GetDistinctModels(ctx, orgID)
	if err != nil {
		t.Fatalf("GetDistinctModels() error = %v", err)
	}

	if len(distinctModels) != 3 {
		t.Errorf("Expected 3 distinct models, got %d", len(distinctModels))
	}

	// Verify alphabetical ordering
	if distinctModels[0] != "model-alpha" {
		t.Errorf("Expected first model to be 'model-alpha', got %s", distinctModels[0])
	}
}

func TestAccuracyRepository_Integration_AllMetricTypes(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-metric-types-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Test all metric types
	metricTypes := []MetricType{
		MetricTypeAccuracy,
		MetricTypePrecision,
		MetricTypeRecall,
		MetricTypeF1Score,
		MetricTypeAUCROC,
		MetricTypeAUCPR,
		MetricTypeMSE,
		MetricTypeMAE,
		MetricTypeCustom,
	}

	for _, mt := range metricTypes {
		metric := &AccuracyMetric{
			ID:         uuid.New().String(),
			OrgID:      orgID,
			ModelID:    "model-types",
			MetricType: mt,
			Value:      0.9,
			SampleSize: 100,
			Timestamp:  time.Now().UTC(),
		}
		if err := repo.SaveMetric(ctx, metric); err != nil {
			t.Fatalf("SaveMetric() error for type %s: %v", mt, err)
		}
	}

	// Verify all were saved
	metrics, total, err := repo.GetMetrics(ctx, orgID, "model-types", "", time.Time{}, time.Time{}, 20, 0)
	if err != nil {
		t.Fatalf("GetMetrics() error = %v", err)
	}

	if total != 9 {
		t.Errorf("Expected total 9 (all metric types), got %d", total)
	}
	if len(metrics) != 9 {
		t.Errorf("Expected 9 metrics, got %d", len(metrics))
	}
}

func TestAccuracyRepository_Integration_AllBiasCategories(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-bias-types-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Test all bias categories
	categories := []BiasCategory{
		BiasCategoryGender,
		BiasCategoryAge,
		BiasCategoryEthnicity,
		BiasCategoryDisability,
		BiasCategoryReligion,
		BiasCategoryNationality,
		BiasCategorySocioeconomic,
		BiasCategoryCustom,
	}

	for _, cat := range categories {
		record := &BiasRecord{
			ID:          uuid.New().String(),
			OrgID:       orgID,
			ModelID:     "model-bias-types",
			Category:    cat,
			Score:       0.05,
			Threshold:   0.10,
			IsViolation: false,
			SampleSize:  1000,
			GroupA:      "group-a",
			GroupB:      "group-b",
			GroupARate:  0.80,
			GroupBRate:  0.78,
			Timestamp:   time.Now().UTC(),
		}
		if err := repo.SaveBiasRecord(ctx, record); err != nil {
			t.Fatalf("SaveBiasRecord() error for category %s: %v", cat, err)
		}

		// Verify each category can be retrieved
		from := time.Now().UTC().Add(-time.Hour)
		to := time.Now().UTC().Add(time.Hour)
		records, err := repo.GetBiasRecords(ctx, orgID, "model-bias-types", cat, from, to)
		if err != nil {
			t.Fatalf("GetBiasRecords() error for category %s: %v", cat, err)
		}
		if len(records) != 1 {
			t.Errorf("Expected 1 record for category %s, got %d", cat, len(records))
		}
	}
}

func TestAccuracyRepository_Integration_AllAlertSeverities(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresAccuracyRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-severity-"+time.Now().Format("20060102150405"))
	defer cleanupTestAccuracyData(t, db, orgID)

	ctx := context.Background()

	// Test all severity levels
	severities := []AlertSeverity{
		AlertSeverityInfo,
		AlertSeverityWarning,
		AlertSeverityCritical,
	}

	for i, sev := range severities {
		alert := &AccuracyAlert{
			ID:           uuid.New().String(),
			OrgID:        orgID,
			ModelID:      "model-severity-" + string(rune('0'+i)),
			AlertType:    "accuracy_degradation",
			Severity:     sev,
			Title:        "Alert with severity " + string(sev),
			Description:  "Testing severity level",
			CurrentValue: 0.80,
			Threshold:    0.90,
			TriggeredAt:  time.Now().UTC(),
		}
		if err := repo.SaveAlert(ctx, alert); err != nil {
			t.Fatalf("SaveAlert() error for severity %s: %v", sev, err)
		}
	}

	// Verify all were saved
	alerts, err := repo.GetActiveAlerts(ctx, orgID)
	if err != nil {
		t.Fatalf("GetActiveAlerts() error = %v", err)
	}

	if len(alerts) != 3 {
		t.Errorf("Expected 3 alerts (all severities), got %d", len(alerts))
	}
}
