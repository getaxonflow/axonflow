// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockAccuracyRepository implements AccuracyRepository for testing.
type MockAccuracyRepository struct {
	metrics    map[string]*AccuracyMetric
	biasRecs   map[string]*BiasRecord
	alerts     map[string]*AccuracyAlert
	models     []string
	saveErr    error
	getErr     error
	listTotal  int64
}

func NewMockAccuracyRepository() *MockAccuracyRepository {
	return &MockAccuracyRepository{
		metrics:  make(map[string]*AccuracyMetric),
		biasRecs: make(map[string]*BiasRecord),
		alerts:   make(map[string]*AccuracyAlert),
		models:   []string{},
	}
}

func (m *MockAccuracyRepository) SaveMetric(ctx context.Context, metric *AccuracyMetric) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.metrics[metric.ID] = metric
	return nil
}

func (m *MockAccuracyRepository) GetMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time, limit, offset int) ([]*AccuracyMetric, int64, error) {
	if m.getErr != nil {
		return nil, 0, m.getErr
	}
	var metrics []*AccuracyMetric
	for _, metric := range m.metrics {
		if metric.OrgID == orgID {
			if modelID == "" || metric.ModelID == modelID {
				if metricType == "" || metric.MetricType == metricType {
					metrics = append(metrics, metric)
				}
			}
		}
	}
	return metrics, m.listTotal, nil
}

func (m *MockAccuracyRepository) GetLatestMetric(ctx context.Context, orgID, modelID string, metricType MetricType) (*AccuracyMetric, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	var latest *AccuracyMetric
	for _, metric := range m.metrics {
		if metric.OrgID == orgID && metric.ModelID == modelID && metric.MetricType == metricType {
			if latest == nil || metric.Timestamp.After(latest.Timestamp) {
				latest = metric
			}
		}
	}
	return latest, nil
}

func (m *MockAccuracyRepository) AggregateMetrics(ctx context.Context, orgID, modelID string, metricType MetricType, from, to time.Time) (*AggregatedMetric, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return &AggregatedMetric{
		MetricType: metricType,
		Count:      10,
		Min:        0.80,
		Max:        0.90,
		Avg:        0.85,
	}, nil
}

func (m *MockAccuracyRepository) SaveBiasRecord(ctx context.Context, record *BiasRecord) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.biasRecs[record.ID] = record
	return nil
}

func (m *MockAccuracyRepository) GetBiasRecords(ctx context.Context, orgID, modelID string, category BiasCategory, from, to time.Time) ([]*BiasRecord, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	var records []*BiasRecord
	for _, rec := range m.biasRecs {
		if rec.OrgID == orgID {
			if modelID == "" || rec.ModelID == modelID {
				if category == "" || rec.Category == category {
					records = append(records, rec)
				}
			}
		}
	}
	return records, nil
}

func (m *MockAccuracyRepository) SaveAlert(ctx context.Context, alert *AccuracyAlert) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.alerts[alert.ID] = alert
	return nil
}

func (m *MockAccuracyRepository) GetActiveAlerts(ctx context.Context, orgID string) ([]*AccuracyAlert, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	var alerts []*AccuracyAlert
	for _, alert := range m.alerts {
		if alert.ResolvedAt == nil {
			if orgID == "" || alert.OrgID == orgID {
				alerts = append(alerts, alert)
			}
		}
	}
	return alerts, nil
}

func (m *MockAccuracyRepository) GetAlertByID(ctx context.Context, alertID string) (*AccuracyAlert, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	alert, exists := m.alerts[alertID]
	if !exists {
		return nil, nil
	}
	return alert, nil
}

func (m *MockAccuracyRepository) UpdateAlert(ctx context.Context, alert *AccuracyAlert) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.alerts[alert.ID] = alert
	return nil
}

func (m *MockAccuracyRepository) GetDistinctModels(ctx context.Context, orgID string) ([]string, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.models, nil
}

func TestNewAccuracyHandler(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestAccuracyHandler_RegisterRoutes(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test that routes are registered by making requests
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Should get 200 OK (not 404)
	if rr.Code == http.StatusNotFound {
		t.Error("Route not registered")
	}
}

func TestAccuracyHandler_HandleAccuracy_MissingOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy", nil)
	rr := httptest.NewRecorder()

	handler.handleAccuracy(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracy_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy", nil)
	rr := httptest.NewRecorder()

	handler.handleAccuracy(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracy_Success(t *testing.T) {
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

	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleAccuracy(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleRecordMetric_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/record", nil)
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordMetric_MissingOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", nil)
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordMetric_InvalidJSON(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordMetric_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "metric_type": "accuracy", "value": 0.85, "sample_size": 1000}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleRecordMetric_WithDates(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "metric_type": "accuracy", "value": 0.85, "sample_size": 1000, "window_start": "2025-01-01T00:00:00Z", "window_end": "2025-01-02T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleRecordMetric_InvalidWindowStart(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "metric_type": "accuracy", "value": 0.85, "window_start": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordMetric_InvalidWindowEnd(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "metric_type": "accuracy", "value": 0.85, "window_end": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/record", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordMetric(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/bias", nil)
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_MissingOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", nil)
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_InvalidJSON(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "category": "gender", "group_a": "male", "group_b": "female", "group_a_rate": 0.8, "group_b_rate": 0.75, "sample_size": 1000}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleRecordBias_WithDates(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "category": "gender", "group_a": "male", "group_b": "female", "group_a_rate": 0.8, "group_b_rate": 0.75, "window_start": "2025-01-01T00:00:00Z", "window_end": "2025-01-02T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_InvalidWindowStart(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "category": "gender", "window_start": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleRecordBias_InvalidWindowEnd(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	body := `{"model_id": "model-1", "category": "gender", "window_end": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/bias", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleRecordBias(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracyHistory_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/history", nil)
	rr := httptest.NewRecorder()

	handler.handleAccuracyHistory(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracyHistory_MissingOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/history", nil)
	rr := httptest.NewRecorder()

	handler.handleAccuracyHistory(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracyHistory_Success(t *testing.T) {
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
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/history?model_id=model-1&metric_type=accuracy", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleAccuracyHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleAccuracyHistory_WithPagination(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/history?limit=20&offset=10", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleAccuracyHistory(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestAccuracyHandler_HandleAccuracyHistory_InvalidLimit(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/history?limit=invalid", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleAccuracyHistory(rr, req)

	// Should still succeed with default limit
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlerts_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts", nil)
	rr := httptest.NewRecorder()

	handler.handleAlerts(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlerts_MissingOrgID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/alerts", nil)
	rr := httptest.NewRecorder()

	handler.handleAlerts(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlerts_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-1"] = &AccuracyAlert{
		ID:        "alert-1",
		OrgID:     "test-org",
		ModelID:   "model-1",
		AlertType: "accuracy_degradation",
		Severity:  AlertSeverityWarning,
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/alerts", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleAlerts(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleAlertByID_MissingID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/", nil)
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlertByID_MethodNotAllowed(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/accuracy/alerts/alert-123/acknowledge", nil)
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlertByID_InvalidAction(t *testing.T) {
	repo := NewMockAccuracyRepository()
	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/alert-123/invalid", nil)
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAccuracyHandler_HandleAlertByID_Acknowledge_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-123"] = &AccuracyAlert{
		ID:        "alert-123",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/alert-123/acknowledge", nil)
	req.Header.Set("X-User-ID", "user-1")
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleAlertByID_Resolve_Success(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-123"] = &AccuracyAlert{
		ID:        "alert-123",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/alert-123/resolve", nil)
	req.Header.Set("X-User-ID", "user-1")
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestAccuracyHandler_HandleAlertByID_DefaultUserID(t *testing.T) {
	repo := NewMockAccuracyRepository()
	repo.alerts["alert-123"] = &AccuracyAlert{
		ID:        "alert-123",
		OrgID:     "test-org",
		AlertType: "accuracy_degradation",
	}

	service := NewAccuracyService(repo, AccuracyServiceConfig{})
	handler := NewAccuracyHandler(service)

	// No X-User-ID header - should default to "system"
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/alert-123/acknowledge", nil)
	rr := httptest.NewRecorder()

	handler.handleAlertByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}
