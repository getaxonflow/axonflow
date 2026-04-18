// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaterialityClassification_Valid(t *testing.T) {
	tests := []struct {
		classification MaterialityClassification
		want           bool
	}{
		{MaterialityHigh, true},
		{MaterialityMedium, true},
		{MaterialityLow, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.classification), func(t *testing.T) {
			if got := tt.classification.Valid(); got != tt.want {
				t.Errorf("MaterialityClassification.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSystemStatus_Valid(t *testing.T) {
	tests := []struct {
		status SystemStatus
		want   bool
	}{
		{SystemStatusDraft, true},
		{SystemStatusActive, true},
		{SystemStatusSuspended, true},
		{SystemStatusRetired, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("SystemStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEATAssessmentStatus_Valid(t *testing.T) {
	tests := []struct {
		status FEATAssessmentStatus
		want   bool
	}{
		{FEATStatusPending, true},
		{FEATStatusInProgress, true},
		{FEATStatusCompleted, true},
		{FEATStatusApproved, true},
		{FEATStatusRejected, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("FEATAssessmentStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKillSwitchStatus_Valid(t *testing.T) {
	tests := []struct {
		status KillSwitchStatus
		want   bool
	}{
		{KillSwitchEnabled, true},
		{KillSwitchDisabled, true},
		{KillSwitchTriggered, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("KillSwitchStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEATPillar_Valid(t *testing.T) {
	tests := []struct {
		pillar FEATPillar
		want   bool
	}{
		{PillarFairness, true},
		{PillarEthics, true},
		{PillarAccountability, true},
		{PillarTransparency, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.pillar), func(t *testing.T) {
			if got := tt.pillar.Valid(); got != tt.want {
				t.Errorf("FEATPillar.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAISystemUseCase_Valid(t *testing.T) {
	tests := []struct {
		useCase AISystemUseCase
		want    bool
	}{
		{UseCaseCreditScoring, true},
		{UseCaseRoboAdvisory, true},
		{UseCaseInsuranceUnderwriting, true},
		{UseCaseTradingAlgorithm, true},
		{UseCaseAMLCFT, true},
		{UseCaseCustomerService, true},
		{UseCaseFraudDetection, true},
		{UseCaseOther, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.useCase), func(t *testing.T) {
			if got := tt.useCase.Valid(); got != tt.want {
				t.Errorf("AISystemUseCase.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExportFormat_Valid(t *testing.T) {
	tests := []struct {
		format ExportFormat
		want   bool
	}{
		{ExportFormatJSON, true},
		{ExportFormatCSV, true},
		{ExportFormatXML, true},
		{ExportFormatPDF, true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			if got := tt.format.Valid(); got != tt.want {
				t.Errorf("ExportFormat.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateMateriality(t *testing.T) {
	tests := []struct {
		name       string
		impact     int
		complexity int
		reliance   int
		want       MaterialityClassification
	}{
		{"High - sum >= 12", 5, 4, 4, MaterialityHigh},
		{"High - sum = 12", 4, 4, 4, MaterialityHigh},
		{"Medium - sum >= 8", 3, 3, 3, MaterialityMedium},
		{"Medium - sum = 8", 3, 3, 2, MaterialityMedium},
		{"Low - sum < 8", 2, 2, 2, MaterialityLow},
		{"Low - minimum", 1, 1, 1, MaterialityLow},
		{"High - maximum", 5, 5, 5, MaterialityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateMateriality(tt.impact, tt.complexity, tt.reliance); got != tt.want {
				t.Errorf("calculateMateriality(%d, %d, %d) = %v, want %v",
					tt.impact, tt.complexity, tt.reliance, got, tt.want)
			}
		})
	}
}

func TestGetOrgIDFromRequest(t *testing.T) {
	tests := []struct {
		name      string
		headers   map[string]string
		wantOrgID string
	}{
		{
			name:      "X-Org-ID header",
			headers:   map[string]string{"X-Org-ID": "org-123"},
			wantOrgID: "org-123",
		},
		{
			name:      "X-Tenant-ID header fallback",
			headers:   map[string]string{"X-Tenant-ID": "tenant-456"},
			wantOrgID: "tenant-456",
		},
		{
			name:      "X-Org-ID takes precedence",
			headers:   map[string]string{"X-Org-ID": "org-123", "X-Tenant-ID": "tenant-456"},
			wantOrgID: "org-123",
		},
		{
			name:      "No headers",
			headers:   map[string]string{},
			wantOrgID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := getOrgIDFromRequest(req); got != tt.wantOrgID {
				t.Errorf("getOrgIDFromRequest() = %v, want %v", got, tt.wantOrgID)
			}
		})
	}
}

func TestGetUserFromRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		wantUser string
	}{
		{
			name:     "X-User-ID header",
			headers:  map[string]string{"X-User-ID": "user-123"},
			wantUser: "user-123",
		},
		{
			name:     "X-User-Email header fallback",
			headers:  map[string]string{"X-User-Email": "user@example.com"},
			wantUser: "user@example.com",
		},
		{
			name:     "X-User-ID takes precedence",
			headers:  map[string]string{"X-User-ID": "user-123", "X-User-Email": "user@example.com"},
			wantUser: "user-123",
		},
		{
			name:     "No headers",
			headers:  map[string]string{},
			wantUser: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := getUserFromRequest(req); got != tt.wantUser {
				t.Errorf("getUserFromRequest() = %v, want %v", got, tt.wantUser)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		data       interface{}
		wantStatus int
		wantBody   string
	}{
		{
			name:       "Simple object",
			status:     http.StatusOK,
			data:       map[string]string{"key": "value"},
			wantStatus: http.StatusOK,
			wantBody:   `{"key":"value"}`,
		},
		{
			name:       "Created status",
			status:     http.StatusCreated,
			data:       map[string]int{"count": 42},
			wantStatus: http.StatusCreated,
			wantBody:   `{"count":42}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeJSON(w, tt.status, tt.data)

			if w.Code != tt.wantStatus {
				t.Errorf("writeJSON() status = %v, want %v", w.Code, tt.wantStatus)
			}
			if w.Body.String() != tt.wantBody {
				t.Errorf("writeJSON() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("writeJSON() Content-Type = %v, want application/json", ct)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "test error")

	if w.Code != http.StatusBadRequest {
		t.Errorf("writeError() status = %v, want %v", w.Code, http.StatusBadRequest)
	}
	want := `{"error":"test error"}`
	if w.Body.String() != want {
		t.Errorf("writeError() body = %v, want %v", w.Body.String(), want)
	}
}
