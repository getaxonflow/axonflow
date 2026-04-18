// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AccuracyServiceConfig contains configuration for the accuracy service.
type AccuracyServiceConfig struct {
	DefaultAccuracyMin   float64 // Default minimum accuracy threshold (default: 0.80)
	DefaultBiasMax       float64 // Default maximum bias score (default: 0.10)
	AlertCooldownMinutes int     // Minutes between alerts for same metric (default: 15)
}

// AccuracyService provides business logic for accuracy tracking.
type AccuracyService struct {
	mu         sync.RWMutex
	repo       AccuracyRepository
	config     AccuracyServiceConfig
	lastAlert  map[string]time.Time // key -> last alert time for cooldown
}

// NewAccuracyService creates a new accuracy service.
func NewAccuracyService(repo AccuracyRepository, config AccuracyServiceConfig) *AccuracyService {
	if config.DefaultAccuracyMin == 0 {
		config.DefaultAccuracyMin = 0.80
	}
	if config.DefaultBiasMax == 0 {
		config.DefaultBiasMax = 0.10
	}
	if config.AlertCooldownMinutes == 0 {
		config.AlertCooldownMinutes = 15
	}
	return &AccuracyService{
		repo:      repo,
		config:    config,
		lastAlert: make(map[string]time.Time),
	}
}

// RecordMetricInput contains input for recording a metric.
type RecordMetricInput struct {
	OrgID       string
	ModelID     string
	MetricType  MetricType
	Value       float64
	SampleSize  int
	WindowStart time.Time
	WindowEnd   time.Time
	Metadata    map[string]interface{}
}

// RecordMetric records an accuracy metric.
func (s *AccuracyService) RecordMetric(ctx context.Context, input RecordMetricInput) (*AccuracyMetric, error) {
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if input.ModelID == "" {
		return nil, fmt.Errorf("model_id is required")
	}
	if !input.MetricType.Valid() {
		return nil, fmt.Errorf("invalid metric_type: %s", input.MetricType)
	}

	metric := &AccuracyMetric{
		ID:          generateMetricID(),
		OrgID:       input.OrgID,
		ModelID:     input.ModelID,
		MetricType:  input.MetricType,
		Value:       input.Value,
		SampleSize:  input.SampleSize,
		Timestamp:   time.Now().UTC(),
		WindowStart: input.WindowStart,
		WindowEnd:   input.WindowEnd,
		Metadata:    input.Metadata,
	}

	if err := s.repo.SaveMetric(ctx, metric); err != nil {
		return nil, fmt.Errorf("save metric: %w", err)
	}

	// Check for threshold violations
	s.checkMetricThresholds(ctx, metric)

	return metric, nil
}

// RecordBiasInput contains input for recording a bias measurement.
type RecordBiasInput struct {
	OrgID       string
	ModelID     string
	Category    BiasCategory
	GroupA      string
	GroupB      string
	GroupARate  float64
	GroupBRate  float64
	SampleSize  int
	WindowStart time.Time
	WindowEnd   time.Time
	Metadata    map[string]interface{}
}

// RecordBias records a bias detection result.
func (s *AccuracyService) RecordBias(ctx context.Context, input RecordBiasInput) (*BiasRecord, error) {
	if input.OrgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	if input.ModelID == "" {
		return nil, fmt.Errorf("model_id is required")
	}
	if !input.Category.Valid() {
		return nil, fmt.Errorf("invalid category: %s", input.Category)
	}

	// Calculate bias score using demographic parity
	biasScore := calculateBiasScore(input.GroupARate, input.GroupBRate)
	isViolation := biasScore > s.config.DefaultBiasMax

	record := &BiasRecord{
		ID:          generateMetricID(),
		OrgID:       input.OrgID,
		ModelID:     input.ModelID,
		Category:    input.Category,
		Score:       biasScore,
		Threshold:   s.config.DefaultBiasMax,
		IsViolation: isViolation,
		SampleSize:  input.SampleSize,
		GroupA:      input.GroupA,
		GroupB:      input.GroupB,
		GroupARate:  input.GroupARate,
		GroupBRate:  input.GroupBRate,
		Timestamp:   time.Now().UTC(),
		WindowStart: input.WindowStart,
		WindowEnd:   input.WindowEnd,
		Metadata:    input.Metadata,
	}

	if err := s.repo.SaveBiasRecord(ctx, record); err != nil {
		return nil, fmt.Errorf("save bias record: %w", err)
	}

	// Create alert if violation
	if isViolation {
		s.createBiasAlert(ctx, record)
	}

	return record, nil
}

// GetMetrics retrieves metrics for a model.
func (s *AccuracyService) GetMetrics(ctx context.Context, orgID string, params AccuracyMetricsParams) ([]*AccuracyMetric, int64, error) {
	var from, to time.Time
	if params.From != "" {
		var err error
		from, err = time.Parse(time.RFC3339, params.From)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid from date: %w", err)
		}
	}
	if params.To != "" {
		var err error
		to, err = time.Parse(time.RFC3339, params.To)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid to date: %w", err)
		}
	}

	return s.repo.GetMetrics(ctx, orgID, params.ModelID, MetricType(params.MetricType), from, to, params.Limit, params.Offset)
}

// GetAccuracySummary returns a summary of accuracy status for an org.
func (s *AccuracyService) GetAccuracySummary(ctx context.Context, orgID string) (*AccuracySummary, error) {
	models, err := s.repo.GetDistinctModels(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("get models: %w", err)
	}

	summary := &AccuracySummary{
		OrgID:          orgID,
		TotalModels:    len(models),
		LastUpdated:    time.Now().UTC(),
		MetricsByModel: make(map[string]interface{}),
	}

	var totalAccuracy float64
	var accuracyCount int

	for _, modelID := range models {
		// Get latest accuracy metric
		metric, err := s.repo.GetLatestMetric(ctx, orgID, modelID, MetricTypeAccuracy)
		if err != nil {
			continue
		}
		if metric != nil {
			totalAccuracy += metric.Value
			accuracyCount++

			if metric.Value >= s.config.DefaultAccuracyMin {
				summary.ModelsAboveTarget++
			} else {
				summary.ModelsBelowTarget++
			}

			summary.MetricsByModel[modelID] = map[string]interface{}{
				"accuracy":   metric.Value,
				"updated_at": metric.Timestamp,
			}
		}
	}

	if accuracyCount > 0 {
		summary.AverageAccuracy = totalAccuracy / float64(accuracyCount)
	}

	// Get active alerts count
	alerts, err := s.repo.GetActiveAlerts(ctx, orgID)
	if err == nil {
		summary.ActiveAlerts = len(alerts)
	}

	return summary, nil
}

// GetActiveAlerts retrieves active alerts for an org.
func (s *AccuracyService) GetActiveAlerts(ctx context.Context, orgID string) ([]*AccuracyAlert, error) {
	return s.repo.GetActiveAlerts(ctx, orgID)
}

// AcknowledgeAlert acknowledges an alert.
func (s *AccuracyService) AcknowledgeAlert(ctx context.Context, alertID, userID string) error {
	alert, err := s.repo.GetAlertByID(ctx, alertID)
	if err != nil {
		return fmt.Errorf("get alert: %w", err)
	}
	if alert == nil {
		return fmt.Errorf("alert not found")
	}

	now := time.Now().UTC()
	alert.AckedAt = &now
	alert.AckedBy = userID
	return s.repo.UpdateAlert(ctx, alert)
}

// ResolveAlert resolves an alert.
func (s *AccuracyService) ResolveAlert(ctx context.Context, alertID, userID string) error {
	alert, err := s.repo.GetAlertByID(ctx, alertID)
	if err != nil {
		return fmt.Errorf("get alert: %w", err)
	}
	if alert == nil {
		return fmt.Errorf("alert not found")
	}

	now := time.Now().UTC()
	alert.ResolvedAt = &now
	alert.ResolvedBy = userID
	return s.repo.UpdateAlert(ctx, alert)
}

// checkMetricThresholds checks if a metric violates thresholds.
func (s *AccuracyService) checkMetricThresholds(ctx context.Context, metric *AccuracyMetric) {
	switch metric.MetricType {
	case MetricTypeAccuracy, MetricTypePrecision, MetricTypeRecall, MetricTypeF1Score:
		if metric.Value < s.config.DefaultAccuracyMin {
			s.createAccuracyAlert(ctx, metric)
		}
	}
}

// createAccuracyAlert creates an alert for accuracy degradation.
func (s *AccuracyService) createAccuracyAlert(ctx context.Context, metric *AccuracyMetric) {
	key := fmt.Sprintf("%s:%s:%s", metric.OrgID, metric.ModelID, metric.MetricType)

	if !s.shouldAlert(key) {
		return
	}

	alert := &AccuracyAlert{
		ID:           generateMetricID(),
		OrgID:        metric.OrgID,
		ModelID:      metric.ModelID,
		AlertType:    "accuracy_degradation",
		Severity:     AlertSeverityWarning,
		Title:        "Accuracy Below Threshold",
		Description:  fmt.Sprintf("Model %s %s is %.2f%%, below the minimum threshold of %.2f%%", metric.ModelID, metric.MetricType, metric.Value*100, s.config.DefaultAccuracyMin*100),
		MetricType:   metric.MetricType,
		CurrentValue: metric.Value,
		Threshold:    s.config.DefaultAccuracyMin,
		TriggeredAt:  time.Now().UTC(),
	}

	if err := s.repo.SaveAlert(ctx, alert); err != nil {
		log.Printf("Failed to save accuracy alert for model %s: %v", metric.ModelID, err)
	}
}

// createBiasAlert creates an alert for bias detection.
func (s *AccuracyService) createBiasAlert(ctx context.Context, record *BiasRecord) {
	key := fmt.Sprintf("%s:%s:%s", record.OrgID, record.ModelID, record.Category)

	if !s.shouldAlert(key) {
		return
	}

	severity := AlertSeverityWarning
	if record.Score > 0.20 {
		severity = AlertSeverityCritical
	}

	alert := &AccuracyAlert{
		ID:           generateMetricID(),
		OrgID:        record.OrgID,
		ModelID:      record.ModelID,
		AlertType:    "bias_detected",
		Severity:     severity,
		Title:        "Bias Detected",
		Description:  fmt.Sprintf("Bias detected in category %s for model %s. Bias score: %.2f%% (threshold: %.2f%%). Group '%s' rate: %.2f%%, Group '%s' rate: %.2f%%", record.Category, record.ModelID, record.Score*100, record.Threshold*100, record.GroupA, record.GroupARate*100, record.GroupB, record.GroupBRate*100),
		BiasCategory: record.Category,
		CurrentValue: record.Score,
		Threshold:    record.Threshold,
		TriggeredAt:  time.Now().UTC(),
	}

	if err := s.repo.SaveAlert(ctx, alert); err != nil {
		log.Printf("Failed to save bias alert for model %s: %v", record.ModelID, err)
	}
}

// shouldAlert checks if we should create an alert (cooldown check).
func (s *AccuracyService) shouldAlert(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	cooldown := time.Duration(s.config.AlertCooldownMinutes) * time.Minute
	lastTime, exists := s.lastAlert[key]
	if exists && time.Since(lastTime) < cooldown {
		return false
	}

	s.lastAlert[key] = time.Now()
	return true
}

// calculateBiasScore calculates bias score using demographic parity.
func calculateBiasScore(groupARate, groupBRate float64) float64 {
	if groupARate == 0 && groupBRate == 0 {
		return 0
	}

	diff := math.Abs(groupARate - groupBRate)
	maxRate := math.Max(groupARate, groupBRate)

	if maxRate == 0 {
		return 0
	}

	return diff / maxRate
}

// generateMetricID generates a unique ID for a metric.
func generateMetricID() string {
	return "metric-" + uuid.New().String()[:8]
}
