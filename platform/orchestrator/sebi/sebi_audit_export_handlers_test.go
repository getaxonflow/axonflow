// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build enterprise

package sebi

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Mock Service for Testing
// =============================================================================

type mockSEBIAuditExportService struct {
	exportAuditDataFunc             func(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error)
	getRetentionStatusFunc          func(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error)
	getExportStatusFunc             func(ctx context.Context, tenantID string, exportID string) (*SEBIAuditExportResponse, error)
	validateComplianceReadinessFunc func(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error)
}

func (m *mockSEBIAuditExportService) ExportAuditData(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error) {
	if m.exportAuditDataFunc != nil {
		return m.exportAuditDataFunc(ctx, tenantID, req)
	}
	return &SEBIAuditExportResponse{
		ExportID:   "exp_123_test",
		Status:     "completed",
		Framework:  SEBIFrameworkAIML,
		ExportedAt: time.Now().UTC(),
		Summary: &SEBIAuditExportSummary{
			TotalRecords:  100,
			RecordsByType: map[SEBIAuditDataType]int{SEBIDataTypePolicyViolations: 50, SEBIDataTypeLLMCalls: 50},
		},
		Metadata: &SEBIExportMetadata{
			ExportVersion:       "1.0.0",
			GeneratedBy:         "AxonFlow Enterprise",
			GeneratedAt:         time.Now().UTC(),
			TenantID:            tenantID,
			ComplianceFramework: SEBIFrameworkAIML,
		},
	}, nil
}

func (m *mockSEBIAuditExportService) GetRetentionStatus(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error) {
	if m.getRetentionStatusFunc != nil {
		return m.getRetentionStatusFunc(ctx, tenantID, req)
	}
	return &SEBIRetentionStatusResponse{
		TenantID:         tenantID,
		Framework:        SEBIFrameworkAIML,
		ComplianceStatus: "COMPLIANT",
		Status: []SEBIDataTypeRetentionStatus{
			{DataType: SEBIDataTypePolicyViolations, RetentionDays: 1825, ComplianceStatus: "COMPLIANT"},
		},
	}, nil
}


func (m *mockSEBIAuditExportService) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error) {
	if m.validateComplianceReadinessFunc != nil {
		return m.validateComplianceReadinessFunc(ctx, tenantID)
	}
	return &SEBIComplianceReadinessResponse{
		Ready: true,
		Score: 100,
		Checks: []SEBIComplianceCheck{
			{Name: "Retention Configuration", Status: "pass"},
			{Name: "PII Detection Policies", Status: "pass"},
		},
	}, nil
}

// =============================================================================
// Handler Tests
// =============================================================================

func TestSEBIAuditExportHandler_ExportAuditData(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		requestBody    string
		expectedStatus int
		expectedError  string
	}{
		{
			name:     "successful export with all defaults",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-12-31T23:59:59Z"
			}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:     "successful export with specific data types",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-12-31T23:59:59Z",
				"data_types": ["policy_violations", "llm_calls"],
				"format": "json",
				"framework": "SEBI_AI_ML"
			}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:     "successful export with PII redaction",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-06-30T23:59:59Z",
				"redact_pii": true
			}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing tenant ID",
			tenantID:       "",
			requestBody:    `{"start_date": "2024-01-01T00:00:00Z", "end_date": "2024-12-31T23:59:59Z"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "UNAUTHORIZED",
		},
		{
			name:           "missing start date",
			tenantID:       "travel-us",
			requestBody:    `{"end_date": "2024-12-31T23:59:59Z"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:           "missing end date",
			tenantID:       "travel-us",
			requestBody:    `{"start_date": "2024-01-01T00:00:00Z"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:     "end date before start date",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-12-31T00:00:00Z",
				"end_date": "2024-01-01T00:00:00Z"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:     "date range exceeds 5 years",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2018-01-01T00:00:00Z",
				"end_date": "2024-12-31T00:00:00Z"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:     "invalid format",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-12-31T23:59:59Z",
				"format": "pdf"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:     "invalid framework",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-12-31T23:59:59Z",
				"framework": "INVALID"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:     "invalid data type",
			tenantID: "travel-us",
			requestBody: `{
				"start_date": "2024-01-01T00:00:00Z",
				"end_date": "2024-12-31T23:59:59Z",
				"data_types": ["invalid_type"]
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "VALIDATION_ERROR",
		},
		{
			name:           "invalid JSON",
			tenantID:       "travel-us",
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "INVALID_JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockSEBIAuditExportService{}
			handler := NewSEBIAuditExportHandler(mockService)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/audit/export", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}

			rr := httptest.NewRecorder()
			handler.handleExport(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedError != "" {
				var errResp SEBIAPIError
				if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}
				if errResp.Error.Code != tt.expectedError {
					t.Errorf("expected error code %s, got %s", tt.expectedError, errResp.Error.Code)
				}
			}

			if tt.expectedStatus == http.StatusOK {
				var resp SEBIAuditExportResponse
				if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.ExportID == "" {
					t.Error("expected non-empty export ID")
				}
				if resp.Status != "completed" {
					t.Errorf("expected status 'completed', got '%s'", resp.Status)
				}
			}
		})
	}
}


func TestSEBIAuditExportHandler_GetRetentionStatus(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		queryParams    string
		expectedStatus int
	}{
		{
			name:           "successful retention check - all types",
			tenantID:       "travel-us",
			queryParams:    "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "successful retention check - specific types",
			tenantID:       "travel-us",
			queryParams:    "?data_types=policy_violations,llm_calls",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing tenant ID",
			tenantID:       "",
			queryParams:    "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockSEBIAuditExportService{}
			handler := NewSEBIAuditExportHandler(mockService)

			url := "/api/v1/sebi/audit/retention" + tt.queryParams
			req := httptest.NewRequest(http.MethodGet, url, nil)
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}

			rr := httptest.NewRecorder()
			handler.handleRetentionStatus(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}

func TestSEBIAuditExportHandler_GetComplianceReadiness(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		expectedStatus int
		expectedReady  bool
	}{
		{
			name:           "fully compliant tenant",
			tenantID:       "travel-us",
			expectedStatus: http.StatusOK,
			expectedReady:  true,
		},
		{
			name:           "missing tenant ID",
			tenantID:       "",
			expectedStatus: http.StatusUnauthorized,
			expectedReady:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockSEBIAuditExportService{}
			handler := NewSEBIAuditExportHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}

			rr := httptest.NewRecorder()
			handler.handleComplianceReadiness(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var resp SEBIComplianceReadinessResponse
				if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if resp.Ready != tt.expectedReady {
					t.Errorf("expected ready=%v, got %v", tt.expectedReady, resp.Ready)
				}
			}
		})
	}
}

func TestSEBIAuditExportHandler_CORS(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	tests := []struct {
		name           string
		endpoint       string
		origin         string
		expectedStatus int
	}{
		{
			name:           "export endpoint with allowed origin",
			endpoint:       "/api/v1/sebi/audit/export",
			origin:         "https://customer.getaxonflow.com",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "retention endpoint with allowed origin",
			endpoint:       "/api/v1/sebi/audit/retention",
			origin:         "https://app.getaxonflow.com",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, tt.endpoint, nil)
			req.Header.Set("Origin", tt.origin)

			rr := httptest.NewRecorder()
			handler.handleExport(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if origin := rr.Header().Get("Access-Control-Allow-Origin"); origin != tt.origin {
				t.Errorf("expected origin %s, got %s", tt.origin, origin)
			}
		})
	}
}

func TestSEBIAuditExportHandler_MethodNotAllowed(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	tests := []struct {
		name     string
		method   string
		endpoint string
		handler  func(http.ResponseWriter, *http.Request)
	}{
		{"export - DELETE not allowed", http.MethodDelete, "/api/v1/sebi/audit/export", handler.handleExport},
		{"export - PUT not allowed", http.MethodPut, "/api/v1/sebi/audit/export", handler.handleExport},
		{"retention - POST not allowed", http.MethodPost, "/api/v1/sebi/audit/retention", handler.handleRetentionStatus},
		{"readiness - POST not allowed", http.MethodPost, "/api/v1/sebi/audit/readiness", handler.handleComplianceReadiness},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.endpoint, nil)
			req.Header.Set("X-Tenant-ID", "travel-us")

			rr := httptest.NewRecorder()
			tt.handler(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
			}
		})
	}
}

// =============================================================================
// Validation Tests
// =============================================================================

func TestValidateExportRequest(t *testing.T) {
	handler := NewSEBIAuditExportHandler(nil)

	tests := []struct {
		name        string
		request     *SEBIAuditExportRequest
		expectError bool
		errorField  string
	}{
		{
			name: "valid request - all fields",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				DataTypes: []SEBIAuditDataType{SEBIDataTypePolicyViolations},
				Format:    SEBIFormatJSON,
				Framework: SEBIFrameworkAIML,
			},
			expectError: false,
		},
		{
			name: "valid request - CSV format",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				Format:    SEBIFormatCSV,
			},
			expectError: false,
		},
		{
			name: "valid request - XML format",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				Format:    SEBIFormatXML,
			},
			expectError: false,
		},
		{
			name: "valid request - DPDP framework",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				Framework: SEBIFrameworkDPDP,
			},
			expectError: false,
		},
		{
			name: "valid request - combined framework",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				Framework: SEBIFrameworkCombined,
			},
			expectError: false,
		},
		{
			name: "valid request - all data types",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
				DataTypes: []SEBIAuditDataType{
					SEBIDataTypePolicyViolations,
					SEBIDataTypeLLMCalls,
					SEBIDataTypeDecisionChain,
					SEBIDataTypeHITLOversight,
					SEBIDataTypePIIRedactions,
				},
			},
			expectError: false,
		},
		{
			name: "missing start date",
			request: &SEBIAuditExportRequest{
				EndDate: time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			},
			expectError: true,
			errorField:  "start_date",
		},
		{
			name: "missing end date",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			expectError: true,
			errorField:  "end_date",
		},
		{
			name: "end before start",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2024, 12, 31, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			expectError: true,
			errorField:  "end_date",
		},
		{
			name: "range exceeds 5 years",
			request: &SEBIAuditExportRequest{
				StartDate: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
				EndDate:   time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			expectError: true,
			errorField:  "date_range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateExportRequest(tt.request)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if validationErr, ok := err.(*ValidationError); ok {
					if len(validationErr.Errors) > 0 && validationErr.Errors[0].Field != tt.errorField {
						t.Errorf("expected error field %s, got %s", tt.errorField, validationErr.Errors[0].Field)
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// Types Tests
// =============================================================================

func TestSEBIAuditDataType_Values(t *testing.T) {
	// Verify all data type constants have expected values
	expectedDataTypes := map[SEBIAuditDataType]string{
		SEBIDataTypePolicyViolations: "policy_violations",
		SEBIDataTypeLLMCalls:         "llm_calls",
		SEBIDataTypeDecisionChain:    "decision_chain",
		SEBIDataTypeHITLOversight:    "hitl_oversight",
		SEBIDataTypePIIRedactions:    "pii_redactions",
		SEBIDataTypeAll:              "all",
	}

	for dataType, expected := range expectedDataTypes {
		if string(dataType) != expected {
			t.Errorf("expected %s, got %s", expected, string(dataType))
		}
	}
}

func TestSEBIExportFormat_Values(t *testing.T) {
	// Verify all format constants have expected values
	expectedFormats := map[SEBIExportFormat]string{
		SEBIFormatJSON: "json",
		SEBIFormatCSV:  "csv",
		SEBIFormatXML:  "xml",
	}

	for format, expected := range expectedFormats {
		if string(format) != expected {
			t.Errorf("expected %s, got %s", expected, string(format))
		}
	}
}

func TestSEBIComplianceFramework_Values(t *testing.T) {
	// Verify all framework constants have expected values
	expectedFrameworks := map[SEBIComplianceFramework]string{
		SEBIFrameworkAIML:     "SEBI_AI_ML",
		SEBIFrameworkDPDP:     "DPDP_ACT_2023",
		SEBIFrameworkCombined: "SEBI_DPDP_COMBINED",
	}

	for framework, expected := range expectedFrameworks {
		if string(framework) != expected {
			t.Errorf("expected %s, got %s", expected, string(framework))
		}
	}
}

// =============================================================================
// Integration-style Tests (with mock service)
// =============================================================================

func TestSEBIAuditExportHandler_FullWorkflow(t *testing.T) {
	// Simulate a full export workflow: request export -> check status -> verify data

	exportID := "exp_workflow_test"

	mockService := &mockSEBIAuditExportService{
		exportAuditDataFunc: func(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error) {
			return &SEBIAuditExportResponse{
				ExportID:   exportID,
				Status:     "completed",
				Framework:  req.Framework,
				ExportedAt: time.Now().UTC(),
				Summary: &SEBIAuditExportSummary{
					TotalRecords: 250,
					RecordsByType: map[SEBIAuditDataType]int{
						SEBIDataTypePolicyViolations: 100,
						SEBIDataTypeLLMCalls:         150,
					},
					ComplianceScore: 92.5,
				},
				Data: &SEBIAuditExportData{
					PolicyViolations: []SEBIPolicyViolationRecord{
						{ID: "pv_1", ViolationType: "pii_detected", Severity: "critical"},
					},
					LLMCalls: []SEBILLMCallRecord{
						{ID: "llm_1", Provider: "openai", Model: "gpt-4", PolicyDecision: "allowed"},
					},
				},
				Metadata: &SEBIExportMetadata{
					ExportVersion:       "1.0.0",
					GeneratedBy:         "AxonFlow Enterprise",
					GeneratedAt:         time.Now().UTC(),
					TenantID:            tenantID,
					ComplianceFramework: req.Framework,
				},
			}, nil
		},
	}

	handler := NewSEBIAuditExportHandler(mockService)

	// Step 1: Request export
	exportReq := `{
		"start_date": "2024-01-01T00:00:00Z",
		"end_date": "2024-12-31T23:59:59Z",
		"data_types": ["policy_violations", "llm_calls"],
		"format": "json",
		"framework": "SEBI_AI_ML"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/audit/export", bytes.NewBufferString(exportReq))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "travel-us")

	rr := httptest.NewRecorder()
	handler.handleExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp SEBIAuditExportResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify response
	if resp.ExportID != exportID {
		t.Errorf("expected export ID %s, got %s", exportID, resp.ExportID)
	}
	if resp.Status != "completed" {
		t.Errorf("expected status 'completed', got '%s'", resp.Status)
	}
	if resp.Summary.TotalRecords != 250 {
		t.Errorf("expected 250 total records, got %d", resp.Summary.TotalRecords)
	}
	if resp.Summary.ComplianceScore != 92.5 {
		t.Errorf("expected compliance score 92.5, got %f", resp.Summary.ComplianceScore)
	}
	if len(resp.Data.PolicyViolations) != 1 {
		t.Errorf("expected 1 policy violation, got %d", len(resp.Data.PolicyViolations))
	}
	if len(resp.Data.LLMCalls) != 1 {
		t.Errorf("expected 1 LLM call, got %d", len(resp.Data.LLMCalls))
	}
}

func TestSEBIAuditExportHandler_RegisterRoutes(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	serveMux := http.NewServeMux()
	handler.RegisterRoutes(serveMux)

	// Test that routes are registered by making requests
	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/sebi/audit/export"},
		{"GET", "/api/v1/sebi/audit/export/test-id"},
		{"GET", "/api/v1/sebi/audit/retention"},
		{"GET", "/api/v1/sebi/audit/readiness"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-Tenant-ID", "travel-us")
			rr := httptest.NewRecorder()
			serveMux.ServeHTTP(rr, req)

			// Should not get 404 (route should be registered)
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s not found", tt.method, tt.path)
			}
		})
	}
}

func TestSEBIAuditExportHandler_GetTenantID_FromContext(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	// Test with tenant_id in context (string value)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
	ctx := context.WithValue(req.Context(), "tenant_id", "banking-india")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.handleComplianceReadiness(rr, req)

	// Should get 200 OK because tenant ID was found in context
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_GetTenantID_FromContextOrgIDFallback(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	// Test with org_id string in context (legacy fallback)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
	ctx := context.WithValue(req.Context(), "org_id", "legacy-456")
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	handler.handleComplianceReadiness(rr, req)

	// Should get 200 OK because org_id string was found in context (fallback)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_GetTenantID_StringHeader(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	// Test with string tenant ID - any non-empty string is valid
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleComplianceReadiness(rr, req)

	// Should get 200 OK because any non-empty string tenant ID is valid
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_GetTenantID_LegacyOrgIDHeader(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	// Test with X-Org-ID header (legacy fallback) - string value
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
	req.Header.Set("X-Org-ID", "legacy-123")
	rr := httptest.NewRecorder()

	handler.handleComplianceReadiness(rr, req)

	// Should get 200 OK because X-Org-ID is accepted as fallback
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_GetUserID(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	tests := []struct {
		name       string
		setupReq   func(*http.Request) *http.Request
		wantUserID string
	}{
		{
			name: "from header",
			setupReq: func(r *http.Request) *http.Request {
				r.Header.Set("X-User-ID", "test-user-123")
				return r
			},
			wantUserID: "test-user-123",
		},
		{
			name: "from context",
			setupReq: func(r *http.Request) *http.Request {
				ctx := context.WithValue(r.Context(), "user_id", "context-user-456")
				return r.WithContext(ctx)
			},
			wantUserID: "context-user-456",
		},
		{
			name: "default system",
			setupReq: func(r *http.Request) *http.Request {
				// No user ID set
				return r
			},
			wantUserID: "system",
		},
		{
			name: "header takes precedence over context",
			setupReq: func(r *http.Request) *http.Request {
				r.Header.Set("X-User-ID", "header-user")
				ctx := context.WithValue(r.Context(), "user_id", "context-user")
				return r.WithContext(ctx)
			},
			wantUserID: "header-user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req = tt.setupReq(req)

			got := handler.getUserID(req)
			if got != tt.wantUserID {
				t.Errorf("getUserID() = %s, want %s", got, tt.wantUserID)
			}
		})
	}
}

func TestSEBIAuditExportHandler_HandleExportByID_CORS(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sebi/audit/export/test-id", nil)
	req.Header.Set("Origin", "https://app.getaxonflow.com")
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_HandleExportByID_MethodNotAllowed(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/sebi/audit/export/test-id", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ValidationError
		expected string
	}{
		{
			name: "with errors",
			err: &ValidationError{
				Errors: []PolicyFieldError{{Field: "test", Message: "test error"}},
			},
			expected: "test error",
		},
		{
			name:     "empty errors",
			err:      &ValidationError{Errors: []PolicyFieldError{}},
			expected: "validation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestSEBIAuditExportHandler_ExportServiceError(t *testing.T) {
	mockService := &mockSEBIAuditExportService{
		exportAuditDataFunc: func(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error) {
			return nil, fmt.Errorf("database error")
		},
	}
	handler := NewSEBIAuditExportHandler(mockService)

	requestBody := `{
		"start_date": "2024-01-01T00:00:00Z",
		"end_date": "2024-12-31T23:59:59Z"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/audit/export", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}

	var errResp SEBIAPIError
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp.Error.Code != "EXPORT_FAILED" {
		t.Errorf("Expected error code EXPORT_FAILED, got %s", errResp.Error.Code)
	}
}



func TestSEBIAuditExportHandler_RetentionStatus_ServiceError(t *testing.T) {
	mockService := &mockSEBIAuditExportService{
		getRetentionStatusFunc: func(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error) {
			return nil, fmt.Errorf("service error")
		},
	}
	handler := NewSEBIAuditExportHandler(mockService)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/retention", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleRetentionStatus(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}
}

func TestSEBIAuditExportHandler_ComplianceReadiness_ServiceError(t *testing.T) {
	mockService := &mockSEBIAuditExportService{
		validateComplianceReadinessFunc: func(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error) {
			return nil, fmt.Errorf("service error")
		},
	}
	handler := NewSEBIAuditExportHandler(mockService)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleComplianceReadiness(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rr.Code)
	}
}

// TestSEBIAuditExportHandler_ExportCSVFormat asserts the response BODY parses
// as CSV, not merely that a CSV Content-Disposition header was set (#3241).
//
// The version this replaces checked the header only, and carried the comment
// "writeJSON always sets application/json, overwriting format-specific headers"
// - it DOCUMENTED the defect and passed anyway. A header assertion cannot tell
// a CSV file from a JSON body wearing a CSV filename, which is exactly what
// this endpoint returned.
func TestSEBIAuditExportHandler_ExportCSVFormat(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	requestBody := `{
		"start_date": "2024-01-01T00:00:00Z",
		"end_date": "2024-12-31T23:59:59Z",
		"format": "csv"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/audit/export", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Expected a text/csv Content-Type, got %q", ct)
	}
	if disposition := rr.Header().Get("Content-Disposition"); disposition != "attachment; filename=sebi-audit-export.csv" {
		t.Errorf("Expected CSV Content-Disposition, got %s", disposition)
	}

	body := rr.Body.String()
	// A JSON body starts with '{'. Nothing else in this assertion set catches
	// the original defect as directly.
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Fatalf("CSV export returned a JSON body under a text/csv header: %s", body)
	}
	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("CSV export body does not parse as CSV: %v\nbody=%s", err, body)
	}
	if len(records) == 0 {
		t.Fatal("CSV export body parsed to zero records")
	}
	if !strings.Contains(records[0][0], "AxonFlow Compliance Report") {
		t.Errorf("CSV export is missing its title row; first record = %q", records[0])
	}
}

// TestSEBIAuditExportHandler_ExportXMLFormat asserts the XML format returns an
// honest 501 (#3241).
//
// BEHAVIOR CHANGE, deliberate: this used to be a 200 carrying a JSON body under
// an application/xml header. The version of this test it replaces asserted only
// the Content-Disposition filename, so it passed on the mislabelled response.
// Nothing could have consumed that response as XML - it never was XML.
func TestSEBIAuditExportHandler_ExportXMLFormat(t *testing.T) {
	mockService := &mockSEBIAuditExportService{}
	handler := NewSEBIAuditExportHandler(mockService)

	requestBody := `{
		"start_date": "2024-01-01T00:00:00Z",
		"end_date": "2024-12-31T23:59:59Z",
		"format": "xml"
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/audit/export", bytes.NewBufferString(requestBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("Expected status 501 for the unimplemented XML format, got %d. body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "XML_NOT_IMPLEMENTED") {
		t.Errorf("Expected the XML_NOT_IMPLEMENTED error code, got %s", rr.Body.String())
	}
	// The refusal must not carry a filename that suggests a downloadable file.
	if disposition := rr.Header().Get("Content-Disposition"); disposition != "" {
		t.Errorf("A 501 must not advertise an attachment; got Content-Disposition %q", disposition)
	}
}

func TestSEBIAuditExportHandler_ComplianceReadinessChecks(t *testing.T) {
	tests := []struct {
		name            string
		ready           bool
		score           int
		failedChecks    []string
		recommendations []string
	}{
		{
			name:  "fully compliant",
			ready: true,
			score: 100,
		},
		{
			name:            "missing retention config",
			ready:           false,
			score:           75,
			failedChecks:    []string{"Retention Configuration"},
			recommendations: []string{"Update retention configuration to meet 5-year SEBI requirement"},
		},
		{
			name:            "missing PII policies",
			ready:           false,
			score:           75,
			failedChecks:    []string{"PII Detection Policies"},
			recommendations: []string{"Enable PAN and Aadhaar detection policies for DPDP Act compliance"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockService := &mockSEBIAuditExportService{
				validateComplianceReadinessFunc: func(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error) {
					checks := []SEBIComplianceCheck{
						{Name: "Retention Configuration", Status: "pass"},
						{Name: "PII Detection Policies", Status: "pass"},
						{Name: "Human Oversight", Status: "pass"},
						{Name: "Audit Logging", Status: "pass"},
						{Name: "Decision Chain Tracing", Status: "pass"},
					}

					// Mark failed checks
					for i := range checks {
						for _, failed := range tt.failedChecks {
							if checks[i].Name == failed {
								checks[i].Status = "fail"
							}
						}
					}

					return &SEBIComplianceReadinessResponse{
						Ready:           tt.ready,
						Score:           tt.score,
						Checks:          checks,
						Recommendations: tt.recommendations,
					}, nil
				},
			}

			handler := NewSEBIAuditExportHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/readiness", nil)
			req.Header.Set("X-Tenant-ID", "travel-us")

			rr := httptest.NewRecorder()
			handler.handleComplianceReadiness(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rr.Code)
			}

			var resp SEBIComplianceReadinessResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Ready != tt.ready {
				t.Errorf("expected ready=%v, got %v", tt.ready, resp.Ready)
			}
			if resp.Score != tt.score {
				t.Errorf("expected score=%d, got %d", tt.score, resp.Score)
			}
			if len(resp.Recommendations) != len(tt.recommendations) {
				t.Errorf("expected %d recommendations, got %d", len(tt.recommendations), len(resp.Recommendations))
			}
		})
	}
}
