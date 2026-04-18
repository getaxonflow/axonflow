// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewAccuracyService(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	if service == nil {
		t.Fatal("Expected non-nil service")
	}
	if service.repo != repo {
		t.Error("Service repo not set correctly")
	}
	// Check defaults
	if service.config.DefaultAccuracyMin != 0.80 {
		t.Errorf("Expected DefaultAccuracyMin 0.80, got %f", service.config.DefaultAccuracyMin)
	}
	if service.config.DefaultBiasMax != 0.10 {
		t.Errorf("Expected DefaultBiasMax 0.10, got %f", service.config.DefaultBiasMax)
	}
	if service.config.AlertCooldownMinutes != 15 {
		t.Errorf("Expected AlertCooldownMinutes 15, got %d", service.config.AlertCooldownMinutes)
	}
}

func TestNewAccuracyService_CustomConfig(t *testing.T) {
	repo := NewMockAccuracyRepository()
	config := AccuracyServiceConfig{
		DefaultAccuracyMin:   0.90,
		DefaultBiasMax:       0.05,
		AlertCooldownMinutes: 30,
	}
	service := NewAccuracyService(repo, config)

	if service.config.DefaultAccuracyMin != 0.90 {
		t.Errorf("Expected DefaultAccuracyMin 0.90, got %f", service.config.DefaultAccuracyMin)
	}
	if service.config.DefaultBiasMax != 0.05 {
		t.Errorf("Expected DefaultBiasMax 0.05, got %f", service.config.DefaultBiasMax)
	}
	if service.config.AlertCooldownMinutes != 30 {
		t.Errorf("Expected AlertCooldownMinutes 30, got %d", service.config.AlertCooldownMinutes)
	}
}

func TestAccuracyService_RecordMetric_EmptyOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordMetricInput{
		OrgID:      "",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.85,
	}

	_, err := service.RecordMetric(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty OrgID")
	}
}

func TestAccuracyService_RecordMetric_EmptyModelID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordMetricInput{
		OrgID:      "test-org",
		ModelID:    "",
		MetricType: MetricTypeAccuracy,
		Value:      0.85,
	}

	_, err := service.RecordMetric(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty ModelID")
	}
}

func TestAccuracyService_RecordMetric_InvalidMetricType(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordMetricInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricType("invalid"),
		Value:      0.85,
	}

	_, err := service.RecordMetric(context.Background(), input)
	if err == nil {
		t.Error("Expected error for invalid MetricType")
	}
}

func TestAccuracyService_RecordMetric_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordMetricInput{
		OrgID:       "test-org",
		ModelID:     "model-1",
		MetricType:  MetricTypeAccuracy,
		Value:       0.85,
		SampleSize:  1000,
		WindowStart: time.Now().Add(-1 * time.Hour),
		WindowEnd:   time.Now(),
		Metadata:    map[string]interface{}{"key": "value"},
	}

	metric, err := service.RecordMetric(context.Background(), input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if metric == nil {
		t.Fatal("Expected non-nil metric")
	}
	if metric.OrgID != "test-org" {
		t.Errorf("Expected OrgID 'test-org', got '%s'", metric.OrgID)
	}
	if metric.ModelID != "model-1" {
		t.Errorf("Expected ModelID 'model-1', got '%s'", metric.ModelID)
	}
	if metric.Value != 0.85 {
		t.Errorf("Expected Value 0.85, got %f", metric.Value)
	}
}

func TestAccuracyService_RecordMetric_AllTypes(t *testing.T) {
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
		t.Run(string(mt), func(t *testing.T) {
			repo := NewMockAccuracyRepository()
			service := NewAccuracyService(repo, AccuracyServiceConfig{})

			input := RecordMetricInput{
				OrgID:      "test-org",
				ModelID:    "model-1",
				MetricType: mt,
				Value:      0.85,
			}

			metric, err := service.RecordMetric(context.Background(), input)
			if err != nil {
				t.Fatalf("Unexpected error for type %s: %v", mt, err)
			}
			if metric.MetricType != mt {
				t.Errorf("Expected MetricType '%s', got '%s'", mt, metric.MetricType)
			}
		})
	}
}

func TestAccuracyService_RecordMetric_RepoError(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.saveErr = errors.New("database error")
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordMetricInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.85,
	}

	_, err := service.RecordMetric(context.Background(), input)
	if err == nil {
		t.Error("Expected error when repo fails")
	}
}

func TestAccuracyService_RecordMetric_LowAccuracyTriggersAlert(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{
		DefaultAccuracyMin: 0.80,
	})

	input := RecordMetricInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.50, // Below threshold
	}

	_, err := service.RecordMetric(context.Background(), input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that an alert was created
	alerts, _ := repo.GetActiveAlerts(context.Background(), "test-org")
	if len(alerts) == 0 {
		t.Error("Expected alert to be created for low accuracy")
	}
}

func TestAccuracyService_RecordBias_EmptyOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordBiasInput{
		OrgID:    "",
		ModelID:  "model-1",
		Category: BiasCategoryGender,
	}

	_, err := service.RecordBias(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty OrgID")
	}
}

func TestAccuracyService_RecordBias_EmptyModelID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordBiasInput{
		OrgID:    "test-org",
		ModelID:  "",
		Category: BiasCategoryGender,
	}

	_, err := service.RecordBias(context.Background(), input)
	if err == nil {
		t.Error("Expected error for empty ModelID")
	}
}

func TestAccuracyService_RecordBias_InvalidCategory(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordBiasInput{
		OrgID:    "test-org",
		ModelID:  "model-1",
		Category: BiasCategory("invalid"),
	}

	_, err := service.RecordBias(context.Background(), input)
	if err == nil {
		t.Error("Expected error for invalid Category")
	}
}

func TestAccuracyService_RecordBias_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordBiasInput{
		OrgID:       "test-org",
		ModelID:     "model-1",
		Category:    BiasCategoryGender,
		GroupA:      "male",
		GroupB:      "female",
		GroupARate:  0.80,
		GroupBRate:  0.75,
		SampleSize:  1000,
		WindowStart: time.Now().Add(-1 * time.Hour),
		WindowEnd:   time.Now(),
		Metadata:    map[string]interface{}{"key": "value"},
	}

	record, err := service.RecordBias(context.Background(), input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if record == nil {
		t.Fatal("Expected non-nil record")
	}
	if record.OrgID != "test-org" {
		t.Errorf("Expected OrgID 'test-org', got '%s'", record.OrgID)
	}
	if record.ModelID != "model-1" {
		t.Errorf("Expected ModelID 'model-1', got '%s'", record.ModelID)
	}
	if record.Category != BiasCategoryGender {
		t.Errorf("Expected Category 'gender', got '%s'", record.Category)
	}
}

func TestAccuracyService_RecordBias_AllCategories(t *testing.T) {
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
		t.Run(string(cat), func(t *testing.T) {
			repo := NewMockAccuracyRepository()
			service := NewAccuracyService(repo, AccuracyServiceConfig{})

			input := RecordBiasInput{
				OrgID:      "test-org",
				ModelID:    "model-1",
				Category:   cat,
				GroupA:     "a",
				GroupB:     "b",
				GroupARate: 0.80,
				GroupBRate: 0.75,
			}

			record, err := service.RecordBias(context.Background(), input)
			if err != nil {
				t.Fatalf("Unexpected error for category %s: %v", cat, err)
			}
			if record.Category != cat {
				t.Errorf("Expected Category '%s', got '%s'", cat, record.Category)
			}
		})
	}
}

func TestAccuracyService_RecordBias_RepoError(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.saveErr = errors.New("database error")
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	input := RecordBiasInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		Category:   BiasCategoryGender,
		GroupARate: 0.80,
		GroupBRate: 0.75,
	}

	_, err := service.RecordBias(context.Background(), input)
	if err == nil {
		t.Error("Expected error when repo fails")
	}
}

func TestAccuracyService_RecordBias_HighBiasTriggersAlert(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{
		DefaultBiasMax: 0.10,
	})

	input := RecordBiasInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		Category:   BiasCategoryGender,
		GroupA:     "male",
		GroupB:     "female",
		GroupARate: 0.80,
		GroupBRate: 0.50, // Large difference = high bias
	}

	record, err := service.RecordBias(context.Background(), input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !record.IsViolation {
		t.Error("Expected IsViolation to be true for high bias")
	}

	// Check that an alert was created
	alerts, _ := repo.GetActiveAlerts(context.Background(), "test-org")
	if len(alerts) == 0 {
		t.Error("Expected alert to be created for high bias")
	}
}

func TestAccuracyService_GetMetrics_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.metrics["m1"] = &AccuracyMetric{
		ID:         "m1",
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.85,
	}
	repo.listTotal = 1

	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	params := AccuracyMetricsParams{
		ModelID: "model-1",
		Limit:   10,
	}

	metrics, total, err := service.GetMetrics(context.Background(), "test-org", params)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(metrics) == 0 {
		t.Error("Expected at least one metric")
	}
	if total != 1 {
		t.Errorf("Expected total 1, got %d", total)
	}
}

func TestAccuracyService_GetMetrics_WithTimeRange(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	params := AccuracyMetricsParams{
		From: "2025-01-01T00:00:00Z",
		To:   "2025-01-02T00:00:00Z",
	}

	_, _, err := service.GetMetrics(context.Background(), "test-org", params)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestAccuracyService_GetMetrics_InvalidFromDate(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	params := AccuracyMetricsParams{
		From: "invalid",
	}

	_, _, err := service.GetMetrics(context.Background(), "test-org", params)
	if err == nil {
		t.Error("Expected error for invalid from date")
	}
}

func TestAccuracyService_GetMetrics_InvalidToDate(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	params := AccuracyMetricsParams{
		To: "invalid",
	}

	_, _, err := service.GetMetrics(context.Background(), "test-org", params)
	if err == nil {
		t.Error("Expected error for invalid to date")
	}
}

func TestAccuracyService_GetAccuracySummary_Empty(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	summary, err := service.GetAccuracySummary(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if summary == nil {
		t.Fatal("Expected non-nil summary")
	}
	if summary.OrgID != "test-org" {
		t.Errorf("Expected OrgID 'test-org', got '%s'", summary.OrgID)
	}
	if summary.TotalModels != 0 {
		t.Errorf("Expected TotalModels 0, got %d", summary.TotalModels)
	}
}

func TestAccuracyService_GetAccuracySummary_WithModels(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.models = []string{"model-1", "model-2"}
	repo.metrics["m1"] = &AccuracyMetric{
		ID:         "m1",
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.85,
		Timestamp:  time.Now(),
	}
	repo.metrics["m2"] = &AccuracyMetric{
		ID:         "m2",
		OrgID:      "test-org",
		ModelID:    "model-2",
		MetricType: MetricTypeAccuracy,
		Value:      0.70,
		Timestamp:  time.Now(),
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{
		DefaultAccuracyMin: 0.80,
	})

	summary, err := service.GetAccuracySummary(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if summary.TotalModels != 2 {
		t.Errorf("Expected TotalModels 2, got %d", summary.TotalModels)
	}
	if summary.ModelsAboveTarget != 1 {
		t.Errorf("Expected ModelsAboveTarget 1, got %d", summary.ModelsAboveTarget)
	}
	if summary.ModelsBelowTarget != 1 {
		t.Errorf("Expected ModelsBelowTarget 1, got %d", summary.ModelsBelowTarget)
	}
}

func TestAccuracyService_GetAccuracySummary_RepoError(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.getErr = errors.New("database error")
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	_, err := service.GetAccuracySummary(context.Background(), "test-org")
	if err == nil {
		t.Error("Expected error when repo fails")
	}
}

func TestAccuracyService_GetActiveAlerts(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-1"] = &AccuracyAlert{
		ID:        "alert-1",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	alerts, err := service.GetActiveAlerts(context.Background(), "test-org")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("Expected 1 alert, got %d", len(alerts))
	}
}

func TestAccuracyService_AcknowledgeAlert_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-123"] = &AccuracyAlert{
		ID:        "alert-123",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	err := service.AcknowledgeAlert(context.Background(), "alert-123", "user-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify alert was updated
	alert := repo.alerts["alert-123"]
	if alert.AckedAt == nil {
		t.Error("Expected AckedAt to be set")
	}
	if alert.AckedBy != "user-1" {
		t.Errorf("Expected AckedBy 'user-1', got '%s'", alert.AckedBy)
	}
}

func TestAccuracyService_AcknowledgeAlert_NotFound(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	err := service.AcknowledgeAlert(context.Background(), "nonexistent", "user-1")
	if err == nil {
		t.Error("Expected error for nonexistent alert")
	}
}

func TestAccuracyService_ResolveAlert_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-123"] = &AccuracyAlert{
		ID:        "alert-123",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	err := service.ResolveAlert(context.Background(), "alert-123", "user-1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify alert was updated
	alert := repo.alerts["alert-123"]
	if alert.ResolvedAt == nil {
		t.Error("Expected ResolvedAt to be set")
	}
	if alert.ResolvedBy != "user-1" {
		t.Errorf("Expected ResolvedBy 'user-1', got '%s'", alert.ResolvedBy)
	}
}

func TestAccuracyService_ResolveAlert_NotFound(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})

	err := service.ResolveAlert(context.Background(), "nonexistent", "user-1")
	if err == nil {
		t.Error("Expected error for nonexistent alert")
	}
}

func TestCalculateBiasScore(t *testing.T) {
	tests := []struct {
		name       string
		groupARate float64
		groupBRate float64
		expected   float64
	}{
		{"equal rates", 0.80, 0.80, 0.0},
		{"group a higher", 0.80, 0.60, 0.25},
		{"group b higher", 0.60, 0.80, 0.25},
		{"both zero", 0.0, 0.0, 0.0},
		{"one zero", 0.0, 0.80, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculateBiasScore(tt.groupARate, tt.groupBRate)
			// Allow small floating point differences
			if diff := score - tt.expected; diff > 0.01 || diff < -0.01 {
				t.Errorf("Expected score %f, got %f", tt.expected, score)
			}
		})
	}
}

func TestGenerateMetricID(t *testing.T) {
	id1 := generateMetricID()
	id2 := generateMetricID()

	if id1 == "" {
		t.Error("Expected non-empty ID")
	}
	if id1 == id2 {
		t.Error("Expected unique IDs")
	}
	if len(id1) < 10 {
		t.Errorf("Expected ID length >= 10, got %d", len(id1))
	}
}

func TestAccuracyService_AlertCooldown(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{
		DefaultAccuracyMin:   0.80,
		AlertCooldownMinutes: 15,
	})

	// First low accuracy metric should create alert
	input := RecordMetricInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		MetricType: MetricTypeAccuracy,
		Value:      0.50,
	}

	_, _ = service.RecordMetric(context.Background(), input)
	alerts1, _ := repo.GetActiveAlerts(context.Background(), "test-org")
	alertCount1 := len(alerts1)

	// Second immediate metric should not create another alert (cooldown)
	_, _ = service.RecordMetric(context.Background(), input)
	alerts2, _ := repo.GetActiveAlerts(context.Background(), "test-org")
	alertCount2 := len(alerts2)

	if alertCount2 > alertCount1 {
		t.Error("Expected cooldown to prevent second alert")
	}
}

func TestAccuracyService_HighBiasCriticalAlert(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{
		DefaultBiasMax: 0.10,
	})

	// Very high bias should create critical alert
	input := RecordBiasInput{
		OrgID:      "test-org",
		ModelID:    "model-1",
		Category:   BiasCategoryGender,
		GroupA:     "male",
		GroupB:     "female",
		GroupARate: 0.90,
		GroupBRate: 0.30, // Very large difference
	}

	_, _ = service.RecordBias(context.Background(), input)

	alerts, _ := repo.GetActiveAlerts(context.Background(), "test-org")
	if len(alerts) == 0 {
		t.Fatal("Expected alert for high bias")
	}

	// Check severity is critical for very high bias
	alert := alerts[0]
	if alert.Severity != AlertSeverityCritical {
		t.Errorf("Expected critical severity for very high bias, got %s", alert.Severity)
	}
}
