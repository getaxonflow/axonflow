// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockTemplateService implements TemplateServicer for testing
type mockTemplateService struct {
	getTemplateFunc   func(ctx context.Context, templateID string) (*PolicyTemplate, error)
	listTemplatesFunc func(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error)
	applyTemplateFunc func(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error)
	getCategoriesFunc func(ctx context.Context) ([]string, error)
	getUsageStatsFunc func(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error)
}

func (m *mockTemplateService) GetTemplate(ctx context.Context, templateID string) (*PolicyTemplate, error) {
	if m.getTemplateFunc != nil {
		return m.getTemplateFunc(ctx, templateID)
	}
	return nil, nil
}

func (m *mockTemplateService) ListTemplates(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error) {
	if m.listTemplatesFunc != nil {
		return m.listTemplatesFunc(ctx, params)
	}
	return nil, nil
}

func (m *mockTemplateService) ApplyTemplate(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error) {
	if m.applyTemplateFunc != nil {
		return m.applyTemplateFunc(ctx, tenantID, templateID, req, userID)
	}
	return nil, nil
}

func (m *mockTemplateService) GetCategories(ctx context.Context) ([]string, error) {
	if m.getCategoriesFunc != nil {
		return m.getCategoriesFunc(ctx)
	}
	return nil, nil
}

func (m *mockTemplateService) GetUsageStats(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error) {
	if m.getUsageStatsFunc != nil {
		return m.getUsageStatsFunc(ctx, tenantID)
	}
	return nil, nil
}

func testPolicyTemplate() *PolicyTemplate {
	return &PolicyTemplate{
		ID:          "template-123",
		Name:        "rate_limiting_basic",
		DisplayName: "Basic Rate Limiting",
		Description: "A basic rate limiting template",
		Category:    "rate_limiting",
		Template: map[string]interface{}{
			"type": "rate_limit",
		},
		Variables: []TemplateVariable{
			{Name: "threshold", Type: "number", Required: true, Default: 100},
		},
		IsBuiltin: true,
		IsActive:  true,
		Version:   "1.0",
		Tags:      []string{"rate-limiting", "security"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestNewTemplateAPIHandler(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != mock {
		t.Error("Expected handler to have the provided service")
	}
}

func TestTemplateAPIHandler_HandleListTemplates(t *testing.T) {
	templates := []PolicyTemplate{*testPolicyTemplate()}
	mock := &mockTemplateService{
		listTemplatesFunc: func(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error) {
			return &TemplatesListResponse{
				Templates: templates,
				Pagination: TemplatePaginationMeta{
					Page:       1,
					PageSize:   20,
					TotalItems: 1,
					TotalPages: 1,
				},
			}, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates?page=1&page_size=20&category=security&active=true&builtin=true", nil)
	w := httptest.NewRecorder()

	handler.HandleListTemplates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp TemplatesListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(resp.Templates) != 1 {
		t.Errorf("Expected 1 template, got %d", len(resp.Templates))
	}
}

func TestTemplateAPIHandler_HandleListTemplates_Options(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/templates", nil)
	w := httptest.NewRecorder()

	handler.HandleListTemplates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleListTemplates_MethodNotAllowed(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", nil)
	w := httptest.NewRecorder()

	handler.HandleListTemplates(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestTemplateAPIHandler_HandleListTemplates_Error(t *testing.T) {
	mock := &mockTemplateService{
		listTemplatesFunc: func(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
	w := httptest.NewRecorder()

	handler.HandleListTemplates(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestTemplateAPIHandler_HandleListTemplates_QueryParams(t *testing.T) {
	var capturedParams ListTemplatesParams
	mock := &mockTemplateService{
		listTemplatesFunc: func(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error) {
			capturedParams = params
			return &TemplatesListResponse{
				Templates:  []PolicyTemplate{},
				Pagination: TemplatePaginationMeta{Page: params.Page, PageSize: params.PageSize},
			}, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates?page=3&page_size=50&category=security&search=test&tags=tag1,tag2&active=false&builtin=true", nil)
	w := httptest.NewRecorder()

	handler.HandleListTemplates(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	if capturedParams.Page != 3 {
		t.Errorf("Expected page 3, got %d", capturedParams.Page)
	}
	if capturedParams.PageSize != 50 {
		t.Errorf("Expected page_size 50, got %d", capturedParams.PageSize)
	}
	if capturedParams.Category != "security" {
		t.Errorf("Expected category 'security', got '%s'", capturedParams.Category)
	}
	if capturedParams.Search != "test" {
		t.Errorf("Expected search 'test', got '%s'", capturedParams.Search)
	}
}

func TestTemplateAPIHandler_HandleGetTemplate(t *testing.T) {
	template := testPolicyTemplate()
	mock := &mockTemplateService{
		getTemplateFunc: func(ctx context.Context, templateID string) (*PolicyTemplate, error) {
			return template, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/template-123", nil)
	w := httptest.NewRecorder()

	handler.HandleGetTemplate(w, req, "template-123")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp TemplateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Template.ID != template.ID {
		t.Errorf("Expected template ID %s, got %s", template.ID, resp.Template.ID)
	}
}

func TestTemplateAPIHandler_HandleGetTemplate_Options(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/templates/template-123", nil)
	w := httptest.NewRecorder()

	handler.HandleGetTemplate(w, req, "template-123")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetTemplate_MethodNotAllowed(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123", nil)
	w := httptest.NewRecorder()

	handler.HandleGetTemplate(w, req, "template-123")

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetTemplate_NotFound(t *testing.T) {
	mock := &mockTemplateService{
		getTemplateFunc: func(ctx context.Context, templateID string) (*PolicyTemplate, error) {
			return nil, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/not-found", nil)
	w := httptest.NewRecorder()

	handler.HandleGetTemplate(w, req, "not-found")

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetTemplate_Error(t *testing.T) {
	mock := &mockTemplateService{
		getTemplateFunc: func(ctx context.Context, templateID string) (*PolicyTemplate, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/template-123", nil)
	w := httptest.NewRecorder()

	handler.HandleGetTemplate(w, req, "template-123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate(t *testing.T) {
	mock := &mockTemplateService{
		applyTemplateFunc: func(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error) {
			return &ApplyTemplateResponse{
				Success: true,
				UsageID: "usage-123",
				Message: "Policy created successfully",
			}, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	body := `{"variables": {"threshold": 100}, "policy_name": "My Policy", "enabled": true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("X-User-ID", "user-1")
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp ApplyTemplateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Error("Expected success=true")
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_Options(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/templates/template-123/apply", nil)
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_MethodNotAllowed(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/template-123/apply", nil)
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_NoTenantID(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	body := `{"variables": {}, "policy_name": "Test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_InvalidJSON(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader("invalid"))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_ValidationError(t *testing.T) {
	mock := &mockTemplateService{
		applyTemplateFunc: func(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error) {
			return nil, &TemplateValidationError{
				Errors: []TemplateFieldError{
					{Field: "policy_name", Message: "Policy name is required"},
				},
			}
		},
	}
	handler := NewTemplateAPIHandler(mock)

	body := `{"variables": {}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_NotFound(t *testing.T) {
	mock := &mockTemplateService{
		applyTemplateFunc: func(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error) {
			return nil, errors.New("template not found")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	body := `{"variables": {}, "policy_name": "Test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestTemplateAPIHandler_HandleApplyTemplate_Error(t *testing.T) {
	mock := &mockTemplateService{
		applyTemplateFunc: func(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error) {
			return nil, errors.New("some other error")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	body := `{"variables": {}, "policy_name": "Test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleApplyTemplate(w, req, "template-123")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetCategories(t *testing.T) {
	mock := &mockTemplateService{
		getCategoriesFunc: func(ctx context.Context) ([]string, error) {
			return []string{"security", "compliance", "rate_limiting"}, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/categories", nil)
	w := httptest.NewRecorder()

	handler.HandleGetCategories(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetCategories_Options(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/templates/categories", nil)
	w := httptest.NewRecorder()

	handler.HandleGetCategories(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetCategories_MethodNotAllowed(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/categories", nil)
	w := httptest.NewRecorder()

	handler.HandleGetCategories(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetCategories_Error(t *testing.T) {
	mock := &mockTemplateService{
		getCategoriesFunc: func(ctx context.Context) ([]string, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/categories", nil)
	w := httptest.NewRecorder()

	handler.HandleGetCategories(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetUsageStats(t *testing.T) {
	mock := &mockTemplateService{
		getUsageStatsFunc: func(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error) {
			return []TemplateUsageStatsResponse{
				{TemplateID: "template-1", TemplateName: "Rate Limit", UsageCount: 5},
			}, nil
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/stats", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleGetUsageStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetUsageStats_Options(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/templates/stats", nil)
	w := httptest.NewRecorder()

	handler.HandleGetUsageStats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetUsageStats_MethodNotAllowed(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/stats", nil)
	w := httptest.NewRecorder()

	handler.HandleGetUsageStats(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetUsageStats_NoTenantID(t *testing.T) {
	mock := &mockTemplateService{}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/stats", nil)
	w := httptest.NewRecorder()

	handler.HandleGetUsageStats(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestTemplateAPIHandler_HandleGetUsageStats_Error(t *testing.T) {
	mock := &mockTemplateService{
		getUsageStatsFunc: func(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewTemplateAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/stats", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.HandleGetUsageStats(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestTemplateAPIHandler_CORSHeaders(t *testing.T) {
	handler := &TemplateAPIHandler{}

	w := httptest.NewRecorder()
	handler.handleCORS(w)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	expectedHeaders := []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
	}

	for _, header := range expectedHeaders {
		if w.Header().Get(header) == "" {
			t.Errorf("Expected %s header to be set", header)
		}
	}
}

func TestTemplateAPIHandler_ErrorResponses(t *testing.T) {
	handler := &TemplateAPIHandler{}

	tests := []struct {
		name    string
		code    string
		message string
		status  int
	}{
		{
			name:    "not found",
			code:    "NOT_FOUND",
			message: "Template not found",
			status:  http.StatusNotFound,
		},
		{
			name:    "unauthorized",
			code:    "UNAUTHORIZED",
			message: "Missing tenant ID",
			status:  http.StatusUnauthorized,
		},
		{
			name:    "internal error",
			code:    "INTERNAL_ERROR",
			message: "Database error",
			status:  http.StatusInternalServerError,
		},
		{
			name:    "method not allowed",
			code:    "METHOD_NOT_ALLOWED",
			message: "Method not allowed",
			status:  http.StatusMethodNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.writeError(w, tt.status, tt.code, tt.message)

			if w.Code != tt.status {
				t.Errorf("Expected status %d, got %d", tt.status, w.Code)
			}

			var resp TemplateAPIError
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if resp.Error.Code != tt.code {
				t.Errorf("Expected code %s, got %s", tt.code, resp.Error.Code)
			}

			if resp.Error.Message != tt.message {
				t.Errorf("Expected message %s, got %s", tt.message, resp.Error.Message)
			}
		})
	}
}

func TestTemplateAPIHandler_ValidationErrorResponse(t *testing.T) {
	handler := &TemplateAPIHandler{}

	fieldErrors := []TemplateFieldError{
		{Field: "policy_name", Message: "Policy name is required"},
		{Field: "variables.threshold", Message: "Threshold must be a number"},
	}

	w := httptest.NewRecorder()
	handler.writeValidationError(w, fieldErrors)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp TemplateAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("Expected code VALIDATION_ERROR, got %s", resp.Error.Code)
	}

	if len(resp.Error.Details) != 2 {
		t.Errorf("Expected 2 field errors, got %d", len(resp.Error.Details))
	}
}

func TestTemplateAPIHandler_JSONResponse(t *testing.T) {
	handler := &TemplateAPIHandler{}

	w := httptest.NewRecorder()
	data := map[string]interface{}{
		"success": true,
		"count":   42,
	}
	handler.writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("Expected success=true, got %v", resp["success"])
	}

	if resp["count"] != float64(42) {
		t.Errorf("Expected count=42, got %v", resp["count"])
	}
}

func TestTemplateAPIHandler_GetTenantID(t *testing.T) {
	handler := &TemplateAPIHandler{}

	tests := []struct {
		name           string
		headerTenantID string
		expected       string
	}{
		{
			name:           "tenant from header",
			headerTenantID: "tenant-123",
			expected:       "tenant-123",
		},
		{
			name:           "no tenant",
			headerTenantID: "",
			expected:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
			if tt.headerTenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.headerTenantID)
			}

			got := handler.getTenantID(req)
			if got != tt.expected {
				t.Errorf("getTenantID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTemplateAPIHandler_GetUserID(t *testing.T) {
	handler := &TemplateAPIHandler{}

	tests := []struct {
		name         string
		headerUserID string
		expected     string
	}{
		{
			name:         "user from header",
			headerUserID: "user-456",
			expected:     "user-456",
		},
		{
			name:         "no user - defaults to system",
			headerUserID: "",
			expected:     "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/templates", nil)
			if tt.headerUserID != "" {
				req.Header.Set("X-User-ID", tt.headerUserID)
			}

			got := handler.getUserID(req)
			if got != tt.expected {
				t.Errorf("getUserID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestApplyTemplateRequest_JSON(t *testing.T) {
	jsonData := `{
		"variables": {
			"threshold": 100,
			"window_seconds": 60,
			"blocked_keywords": ["spam", "hack"]
		},
		"policy_name": "My Rate Limit Policy",
		"description": "Custom rate limiting policy",
		"enabled": true,
		"priority": 50
	}`

	var req ApplyTemplateRequest
	if err := json.NewDecoder(bytes.NewBufferString(jsonData)).Decode(&req); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if req.PolicyName != "My Rate Limit Policy" {
		t.Errorf("Expected policy_name 'My Rate Limit Policy', got '%s'", req.PolicyName)
	}

	if req.Description != "Custom rate limiting policy" {
		t.Errorf("Expected description 'Custom rate limiting policy', got '%s'", req.Description)
	}

	if !req.Enabled {
		t.Error("Expected enabled=true")
	}

	if req.Priority == nil || *req.Priority != 50 {
		t.Errorf("Expected priority=50, got %v", req.Priority)
	}

	if len(req.Variables) != 3 {
		t.Errorf("Expected 3 variables, got %d", len(req.Variables))
	}

	if threshold, ok := req.Variables["threshold"].(float64); !ok || threshold != 100 {
		t.Errorf("Expected threshold=100, got %v", req.Variables["threshold"])
	}
}

func TestListTemplatesParams_Defaults(t *testing.T) {
	params := ListTemplatesParams{}

	// Check zero values
	if params.Page != 0 {
		t.Errorf("Expected default page=0, got %d", params.Page)
	}

	if params.PageSize != 0 {
		t.Errorf("Expected default page_size=0, got %d", params.PageSize)
	}

	if params.Category != "" {
		t.Errorf("Expected empty category, got '%s'", params.Category)
	}

	if params.Search != "" {
		t.Errorf("Expected empty search, got '%s'", params.Search)
	}
}

func TestPolicyTemplate_JSON(t *testing.T) {
	jsonData := `{
		"id": "template-123",
		"name": "rate_limiting_basic",
		"display_name": "Basic Rate Limiting",
		"description": "A basic rate limiting template",
		"category": "rate_limiting",
		"subcategory": "basic",
		"template": {
			"type": "rate_limit",
			"conditions": [{"field": "requests", "operator": "gt", "value": "{{threshold}}"}],
			"actions": [{"type": "rate_limit", "config": {"limit": "{{threshold}}", "window": "{{window_seconds}}"}}]
		},
		"variables": [
			{"name": "threshold", "type": "number", "required": true, "default": 100},
			{"name": "window_seconds", "type": "number", "required": false, "default": 60}
		],
		"is_builtin": true,
		"is_active": true,
		"version": "1.0",
		"tags": ["rate-limiting", "security"]
	}`

	var template PolicyTemplate
	if err := json.NewDecoder(bytes.NewBufferString(jsonData)).Decode(&template); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"ID", template.ID, "template-123"},
		{"Name", template.Name, "rate_limiting_basic"},
		{"DisplayName", template.DisplayName, "Basic Rate Limiting"},
		{"Category", template.Category, "rate_limiting"},
		{"IsBuiltin", template.IsBuiltin, true},
		{"IsActive", template.IsActive, true},
		{"Version", template.Version, "1.0"},
		{"TagsLen", len(template.Tags), 2},
		{"VariablesLen", len(template.Variables), 2},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.expected, tt.got)
		}
	}
}

func TestTemplateVariable_Validation(t *testing.T) {
	jsonData := `{
		"name": "email_pattern",
		"type": "string",
		"required": true,
		"default": ".*@example.com",
		"description": "Email pattern to match",
		"validation": "^[a-zA-Z0-9@.]+$"
	}`

	var variable TemplateVariable
	if err := json.NewDecoder(bytes.NewBufferString(jsonData)).Decode(&variable); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	if variable.Name != "email_pattern" {
		t.Errorf("Expected name 'email_pattern', got '%s'", variable.Name)
	}

	if variable.Type != "string" {
		t.Errorf("Expected type 'string', got '%s'", variable.Type)
	}

	if !variable.Required {
		t.Error("Expected required=true")
	}

	if variable.Validation != "^[a-zA-Z0-9@.]+$" {
		t.Errorf("Expected validation pattern, got '%s'", variable.Validation)
	}
}

func TestValidTemplateCategories(t *testing.T) {
	expectedCategories := []string{
		"general",
		"security",
		"compliance",
		"content_safety",
		"rate_limiting",
		"access_control",
		"data_protection",
		"custom",
	}

	if len(ValidTemplateCategories) != len(expectedCategories) {
		t.Errorf("Expected %d categories, got %d", len(expectedCategories), len(ValidTemplateCategories))
	}

	for i, expected := range expectedCategories {
		if ValidTemplateCategories[i] != expected {
			t.Errorf("Category at index %d: expected '%s', got '%s'", i, expected, ValidTemplateCategories[i])
		}
	}
}
