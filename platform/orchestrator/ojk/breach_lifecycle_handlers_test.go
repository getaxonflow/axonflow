//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ackRequest(id string) *http.Request {
	body, _ := json.Marshal(map[string]string{"id": id})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/acknowledge", bytes.NewBuffer(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandleBreachAcknowledge_POST(t *testing.T) {
	svc := &mockOJKService{}
	h := NewOJKAuditExportHandler(svc)
	w := httptest.NewRecorder()

	h.handleBreachAcknowledge(w, ackRequest("breach-1"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if !svc.ackCalled {
		t.Error("AcknowledgeBreachNotification not called")
	}
	var got OJKBreachNotification
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Status != string(BreachStatusAcknowledged) {
		t.Errorf("status = %q, want acknowledged", got.Status)
	}
}

func TestHandleBreachAcknowledge_NotFound(t *testing.T) {
	svc := &mockOJKService{ackErr: fmt.Errorf("%w: %q", ErrBreachNotFound, "x")}
	h := NewOJKAuditExportHandler(svc)
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, ackRequest("missing"))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestHandleBreachAcknowledge_InvalidTransition(t *testing.T) {
	svc := &mockOJKService{ackErr: fmt.Errorf("from draft: %w", ErrInvalidBreachTransition)}
	h := NewOJKAuditExportHandler(svc)
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, ackRequest("draft-1"))
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestHandleBreachAcknowledge_InternalError(t *testing.T) {
	svc := &mockOJKService{ackErr: fmt.Errorf("db down")}
	h := NewOJKAuditExportHandler(svc)
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, ackRequest("any"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleBreachAcknowledge_MissingID(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, ackRequest("   "))
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for blank id", w.Code)
	}
}

func TestHandleBreachAcknowledge_MissingTenant(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	body, _ := json.Marshal(map[string]string{"id": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/acknowledge", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for missing tenant", w.Code)
	}
}

func TestHandleBreachAcknowledge_InvalidBody(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/acknowledge", bytes.NewBufferString("{not json"))
	req.Header.Set("X-Tenant-ID", "t")
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid body", w.Code)
	}
}

func TestHandleBreachAcknowledge_InvalidMethod(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/breach/acknowledge", nil)
	req.Header.Set("X-Tenant-ID", "t")
	w := httptest.NewRecorder()
	h.handleBreachAcknowledge(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleBreachEvaluateDeadlines_POST(t *testing.T) {
	svc := &mockOJKService{evalFlipped: 3}
	h := NewOJKAuditExportHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/evaluate-deadlines", nil)
	req.Header.Set("X-Tenant-ID", "t")
	w := httptest.NewRecorder()
	h.handleBreachEvaluateDeadlines(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
	}
	if !svc.evalCalled {
		t.Error("EvaluateBreachDeadlines not called")
	}
	var got map[string]int
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["flipped_overdue"] != 3 {
		t.Errorf("flipped_overdue = %d, want 3", got["flipped_overdue"])
	}
}

func TestHandleBreachEvaluateDeadlines_Error(t *testing.T) {
	svc := &mockOJKService{evalErr: fmt.Errorf("db down")}
	h := NewOJKAuditExportHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/evaluate-deadlines", nil)
	req.Header.Set("X-Tenant-ID", "t")
	w := httptest.NewRecorder()
	h.handleBreachEvaluateDeadlines(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestHandleBreachEvaluateDeadlines_MissingTenant(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/evaluate-deadlines", nil)
	w := httptest.NewRecorder()
	h.handleBreachEvaluateDeadlines(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleBreachEvaluateDeadlines_InvalidMethod(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/breach/evaluate-deadlines", nil)
	req.Header.Set("X-Tenant-ID", "t")
	w := httptest.NewRecorder()
	h.handleBreachEvaluateDeadlines(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestBreachLifecycleRoutesRegistered(t *testing.T) {
	h := NewOJKAuditExportHandler(&mockOJKService{})
	sm := http.NewServeMux()
	h.RegisterRoutes(sm)
	for _, path := range []string{
		"/api/v1/ojk/breach/acknowledge",
		"/api/v1/ojk/breach/evaluate-deadlines",
	} {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(`{"id":"x"}`))
		req.Header.Set("X-Tenant-ID", "t")
		_, pattern := sm.Handler(req)
		if pattern == "" {
			t.Errorf("route %s not registered on ServeMux", path)
		}
	}
}
