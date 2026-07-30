// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuditExportHandler_Create(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		name       string
		body       CreateAuditExportRequest
		wantStatus int
	}{
		{
			name: "valid full export",
			body: CreateAuditExportRequest{
				ExportType:  AuditExportTypeFull,
				Format:      AuditExportFormatJSON,
				RequestedBy: "user-1",
				Purpose:     "RBI Compliance Audit",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "valid systems export",
			body: CreateAuditExportRequest{
				ExportType: AuditExportTypeSystems,
				Format:     AuditExportFormatCSV,
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "export with filters",
			body: CreateAuditExportRequest{
				ExportType:      AuditExportTypeIncidents,
				Format:          AuditExportFormatJSON,
				SystemIDs:       []string{"sys-1", "sys-2"},
				RiskCategories:  []string{"high", "critical"},
				IncludeArchived: true,
			},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/rbi/audit-exports", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Org-ID", "org-1")
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}

			if tt.wantStatus == http.StatusCreated {
				var resp AuditExportResponse
				json.NewDecoder(rr.Body).Decode(&resp)
				if resp.Export == nil {
					t.Error("expected export in response")
				}
				if resp.Export.ID == "" {
					t.Error("expected export ID")
				}
				if resp.Export.Status != AuditExportStatusPending {
					t.Errorf("expected status pending, got %s", resp.Export.Status)
				}
			}
		})
	}
}

func TestAuditExportHandler_List(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	ctx := context.Background()

	// Pre-populate some exports
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})
	service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeSystems,
		Format:     AuditExportFormatCSV,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/rbi/audit-exports", nil)
	req.Header.Set("X-Org-ID", "org-1")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
	}

	var resp ListAuditExportsResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Total != 2 {
		t.Errorf("expected 2 exports, got %d", resp.Total)
	}
}

func TestAuditExportHandler_Get(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	ctx := context.Background()

	// Create an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		name       string
		orgID      string
		id         string
		wantStatus int
	}{
		{
			name:       "existing export",
			orgID:      "org-1",
			id:         export.ID,
			wantStatus: http.StatusOK,
		},
		{
			name:       "non-existent export",
			orgID:      "org-1",
			id:         "non-existent",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "wrong org",
			orgID:      "org-2",
			id:         export.ID,
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/rbi/audit-exports/"+tt.id, nil)
			req.Header.Set("X-Org-ID", tt.orgID)
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestAuditExportHandler_Delete(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	ctx := context.Background()

	// Create an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		name       string
		orgID      string
		id         string
		wantStatus int
	}{
		{
			name:       "existing export",
			orgID:      "org-1",
			id:         export.ID,
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "non-existent export",
			orgID:      "org-1",
			id:         "non-existent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("DELETE", "/api/v1/rbi/audit-exports/"+tt.id, nil)
			req.Header.Set("X-Org-ID", tt.orgID)
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestAuditExportHandler_Process(t *testing.T) {
	tmpDir := t.TempDir()

	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, tmpDir, nil)
	handler := NewAuditExportHandler(service)

	ctx := context.Background()

	// Create an export
	export, _ := service.CreateExport(ctx, &CreateExportRequest{
		OrgID:      "org-1",
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	})

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		name       string
		orgID      string
		id         string
		wantStatus int
	}{
		{
			name:       "process pending export",
			orgID:      "org-1",
			id:         export.ID,
			wantStatus: http.StatusOK,
		},
		{
			name:       "non-existent export",
			orgID:      "org-1",
			id:         "non-existent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/rbi/audit-exports/"+tt.id+"/process", nil)
			req.Header.Set("X-Org-ID", tt.orgID)
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}

			if tt.wantStatus == http.StatusOK {
				var resp AuditExportResponse
				json.NewDecoder(rr.Body).Decode(&resp)
				if resp.Export.Status != AuditExportStatusCompleted {
					t.Errorf("expected status completed, got %s", resp.Export.Status)
				}
			}
		})
	}
}

func TestAuditExportHandler_NoAuthenticatedOrg(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test various endpoints with no authenticated org. #3066 C3-3: the response
	// is 401 (no authenticated identity), not 400 — and, critically, `?org_id=`
	// is no longer one of the ways to supply one.
	endpoints := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/rbi/audit-exports"},
		{"GET", "/api/v1/rbi/audit-exports"},
		{"GET", "/api/v1/rbi/audit-exports/test-id"},
		{"DELETE", "/api/v1/rbi/audit-exports/test-id"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			var req *http.Request
			if ep.method == "POST" {
				body := []byte(`{"export_type":"full","format":"json"}`)
				req = httptest.NewRequest(ep.method, ep.path, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(ep.method, ep.path, nil)
			}
			rr := httptest.NewRecorder()

			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
			}
		})
	}
}

func TestAuditExportHandler_InvalidJSON(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/rbi/audit-exports", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAuditExportHandler_XOrgIDHeader(t *testing.T) {
	repo := NewMockAuditExportRepository()
	service := NewAuditExportService(repo, nil, nil, nil, nil, nil, "/tmp/test-exports", nil)
	handler := NewAuditExportHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// The gateway-stamped X-Org-ID header is the ONLY source of scope (#3066 C3-3).
	body := CreateAuditExportRequest{
		ExportType: AuditExportTypeFull,
		Format:     AuditExportFormatJSON,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/rbi/audit-exports", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}
