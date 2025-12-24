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

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// Test timestamp for consistent mock data
var testTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func TestNewStaticPolicyAPIHandler(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	handler := NewStaticPolicyAPIHandler(db)
	if handler == nil {
		t.Fatal("expected handler, got nil")
	}
	if handler.db != db {
		t.Error("expected db to be set")
	}
	if handler.policyRepo == nil {
		t.Error("expected policyRepo to be set")
	}
	if handler.overrideRepo == nil {
		t.Error("expected overrideRepo to be set")
	}
}

func TestHandleListStaticPolicies(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		tenantID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
		expectedCount  int
	}{
		{
			name:        "success - list all policies",
			queryParams: "",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Count query
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				// Main query
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "tier", "pattern",
					"severity", "description", "action", "priority", "enabled",
					"organization_id", "tenant_id", "org_id", "tags", "metadata",
					"version", "created_at", "updated_at", "created_by", "updated_by",
				}).
					AddRow(
						"uuid-1", "sql_injection_union", "SQL Injection UNION", "security-sqli", "system", "union\\s+select",
						"critical", "Blocks UNION-based SQL injection", "block", 100, true,
						nil, "global", "", "[]", "{}",
						1, testTime, testTime, "system", "system",
					).
					AddRow(
						"uuid-2", "pii_ssn", "PII SSN Detection", "pii-us", "tenant", "\\d{3}-\\d{2}-\\d{4}",
						"high", "Detects SSN patterns", "redact", 50, true,
						nil, "test-tenant", "", "[]", "{}",
						1, testTime, testTime, "user", "user",
					)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "success - empty result",
			queryParams: "?category=nonexistent",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "tier", "pattern",
						"severity", "description", "action", "priority", "enabled",
						"organization_id", "tenant_id", "org_id", "tags", "metadata",
						"version", "created_at", "updated_at", "created_by", "updated_by",
					}))
			},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("GET", "/api/v1/static-policies"+tt.queryParams, nil)
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleListStaticPolicies(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var response StaticPoliciesListResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if len(response.Policies) != tt.expectedCount {
					t.Errorf("expected %d policies, got %d", tt.expectedCount, len(response.Policies))
				}
			}
		})
	}
}

func TestHandleGetStaticPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "success - get by policy_id",
			policyID: "sql_injection_union",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "tier", "pattern",
					"severity", "description", "action", "priority", "enabled",
					"organization_id", "tenant_id", "org_id", "tags", "metadata",
					"version", "created_at", "updated_at", "created_by", "updated_by", "deleted_at",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "security-sqli", "system", "union\\s+select",
					"critical", "Blocks UNION-based SQL injection", "block", 100, true,
					nil, "global", "", "[]", "{}",
					1, testTime, testTime, "system", "system", nil,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("sql_injection_union").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "not found",
			policyID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("nonexistent").
					WillReturnRows(sqlmock.NewRows([]string{}))
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("GET", "/api/v1/static-policies/"+tt.policyID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			rr := httptest.NewRecorder()

			handler.HandleGetStaticPolicy(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var policy StaticPolicy
				if err := json.Unmarshal(rr.Body.Bytes(), &policy); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if policy.PolicyID == "" {
					t.Error("expected policy_id to be set")
				}
			}
		})
	}
}

func TestHandleCreateStaticPolicy(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		requestBody    CreateStaticPolicyRequest
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "missing tenant ID",
			tenantID: "",
			requestBody: CreateStaticPolicyRequest{
				Name:     "Test Policy",
				Pattern:  "test.*pattern",
				Category: "pii-global",
				Action:   "block",
				Tier:     TierTenant,
			},
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "missing name",
			tenantID: "test-tenant",
			requestBody: CreateStaticPolicyRequest{
				Pattern:  "test.*pattern",
				Category: "pii-global",
				Action:   "block",
				Tier:     TierTenant,
			},
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "missing pattern",
			tenantID: "test-tenant",
			requestBody: CreateStaticPolicyRequest{
				Name:     "Test Policy",
				Category: "pii-global",
				Action:   "block",
				Tier:     TierTenant,
			},
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/api/v1/static-policies", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleCreateStaticPolicy(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleDeleteStaticPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "not found",
			policyID: "nonexistent",
			setupMock: func(mock sqlmock.Sqlmock) {
				// First query to get the policy
				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("nonexistent").
					WillReturnRows(sqlmock.NewRows([]string{}))
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("DELETE", "/api/v1/static-policies/"+tt.policyID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			req.Header.Set("X-User-ID", "test-user")
			rr := httptest.NewRecorder()

			handler.HandleDeleteStaticPolicy(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleTogglePolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		enabled        bool
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "not found",
			policyID: "nonexistent",
			enabled:  true,
			setupMock: func(mock sqlmock.Sqlmock) {
				// First query to get the policy for toggle
				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("nonexistent").
					WillReturnRows(sqlmock.NewRows([]string{}))
			},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			body, _ := json.Marshal(map[string]bool{"enabled": tt.enabled})
			req := httptest.NewRequest("PATCH", "/api/v1/static-policies/"+tt.policyID, bytes.NewReader(body))
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-User-ID", "test-user")
			rr := httptest.NewRecorder()

			handler.HandleTogglePolicy(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleGetEffectivePolicies(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:           "missing tenant ID",
			tenantID:       "",
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:     "success",
			tenantID: "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				// Main policies query
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "tier", "pattern",
					"severity", "description", "action", "priority", "enabled",
					"organization_id", "tenant_id", "org_id", "tags", "metadata",
					"version", "created_at", "updated_at", "created_by", "updated_by",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "security-sqli", "system", "union\\s+select",
					"critical", "Blocks UNION-based SQL injection", "block", 100, true,
					nil, "global", "", "[]", "{}",
					1, testTime, testTime, "system", "system",
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WillReturnRows(rows)

				// Overrides query
				mock.ExpectQuery(`SELECT.*FROM policy_overrides`).
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "policy_type", "organization_id", "tenant_id",
						"action_override", "enabled_override", "override_reason", "expires_at",
						"created_by", "created_at", "updated_by", "updated_at",
					}))
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("GET", "/api/v1/static-policies/effective", nil)
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleGetEffectivePolicies(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var response EffectivePolicies
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if response.TenantID != tt.tenantID {
					t.Errorf("expected tenant_id %s, got %s", tt.tenantID, response.TenantID)
				}
			}
		})
	}
}

func TestHandleTestPattern(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(t *testing.T, response *PatternTestResult)
	}{
		{
			name:           "missing pattern",
			requestBody:    map[string]interface{}{"inputs": []string{"test"}},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "valid pattern with matches",
			requestBody: map[string]interface{}{
				"pattern": "\\d{3}-\\d{2}-\\d{4}",
				"inputs":  []string{"123-45-6789", "no match here"},
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response *PatternTestResult) {
				if !response.Valid {
					t.Error("expected pattern to be valid")
				}
				if len(response.Matches) != 2 {
					t.Errorf("expected 2 matches, got %d", len(response.Matches))
				}
			},
		},
		{
			name: "invalid pattern",
			requestBody: map[string]interface{}{
				"pattern": "[invalid(pattern",
				"inputs":  []string{"test"},
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response *PatternTestResult) {
				if response.Valid {
					t.Error("expected pattern to be invalid")
				}
				if response.Error == "" {
					t.Error("expected error message")
				}
			},
		},
		{
			name: "backward compatible single input",
			requestBody: map[string]interface{}{
				"pattern": "test",
				"input":   "this is a test",
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response *PatternTestResult) {
				if !response.Valid {
					t.Error("expected pattern to be valid")
				}
				if len(response.Matches) != 1 {
					t.Errorf("expected 1 match, got %d", len(response.Matches))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			handler := NewStaticPolicyAPIHandler(db)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/api/v1/static-policies/test", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.HandleTestPattern(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK && tt.checkResponse != nil {
				var response PatternTestResult
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				tt.checkResponse(t, &response)
			}
		})
	}
}

func TestHandleGetVersionHistory(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		tenantID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "success",
			policyID: "test-policy",
			tenantID: "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				// First the license check query
				mock.ExpectQuery(`SELECT license_tier FROM clients`).
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("enterprise"))

				// Then the versions query
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "version", "snapshot", "change_type", "change_summary", "changed_by", "changed_at",
				}).AddRow(
					"version-1", "test-policy", 1, []byte("{}"), "create", "Policy created", "user", testTime,
				).AddRow(
					"version-2", "test-policy", 2, []byte("{}"), "update", "Policy updated", "user", testTime,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policy_versions WHERE`).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("GET", "/api/v1/static-policies/"+tt.policyID+"/versions", nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleGetVersionHistory(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}

				if response["policy_id"] != tt.policyID {
					t.Errorf("expected policy_id %s, got %v", tt.policyID, response["policy_id"])
				}
			}
		})
	}
}

func TestHandleCreateOverride(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		tenantID       string
		requestBody    CreateOverrideRequest
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "missing tenant ID",
			policyID: "test-policy",
			tenantID: "",
			requestBody: CreateOverrideRequest{
				OverrideReason: "Testing",
			},
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/api/v1/static-policies/"+tt.policyID+"/override", bytes.NewReader(body))
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			req.Header.Set("Content-Type", "application/json")
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleCreateOverride(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleDeleteOverride(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		tenantID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:           "missing tenant ID",
			policyID:       "test-policy",
			tenantID:       "",
			setupMock:      func(mock sqlmock.Sqlmock) {},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock db: %v", err)
			}
			defer db.Close()

			tt.setupMock(mock)

			handler := NewStaticPolicyAPIHandler(db)

			req := httptest.NewRequest("DELETE", "/api/v1/static-policies/"+tt.policyID+"/override", nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
			rr := httptest.NewRecorder()

			handler.HandleDeleteOverride(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d: %s", tt.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestWriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"test": "value"}

	writeJSONResponse(rr, data, http.StatusOK)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response["test"] != "value" {
		t.Errorf("expected test=value, got %s", response["test"])
	}
}

func TestWriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()

	writeJSONError(rr, "test error", http.StatusBadRequest)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj, ok := response["error"].(map[string]interface{})
	if !ok {
		t.Fatal("expected error object in response")
	}

	if errObj["message"] != "test error" {
		t.Errorf("expected message 'test error', got %v", errObj["message"])
	}
}

func TestPaginationMeta(t *testing.T) {
	tests := []struct {
		name          string
		totalItems    int
		pageSize      int
		page          int
		expectedPages int
	}{
		{
			name:          "exact division",
			totalItems:    100,
			pageSize:      20,
			page:          1,
			expectedPages: 5,
		},
		{
			name:          "with remainder",
			totalItems:    101,
			pageSize:      20,
			page:          1,
			expectedPages: 6,
		},
		{
			name:          "single page",
			totalItems:    5,
			pageSize:      20,
			page:          1,
			expectedPages: 1,
		},
		{
			name:          "empty",
			totalItems:    0,
			pageSize:      20,
			page:          1,
			expectedPages: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			totalPages := (tt.totalItems + tt.pageSize - 1) / tt.pageSize
			if tt.totalItems == 0 {
				totalPages = 0
			}

			if totalPages != tt.expectedPages {
				t.Errorf("expected %d pages, got %d", tt.expectedPages, totalPages)
			}
		})
	}
}

func TestRegisterStaticPolicyHandlers(t *testing.T) {
	t.Run("registers handlers with database", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("failed to create mock db: %v", err)
		}
		defer db.Close()

		router := mux.NewRouter()
		RegisterStaticPolicyHandlers(router, db)

		// Verify that routes were registered by checking that they exist
		routes := []struct {
			path   string
			method string
		}{
			{"/api/v1/static-policies", "GET"},
			{"/api/v1/static-policies", "POST"},
			{"/api/v1/static-policies/effective", "GET"},
			{"/api/v1/static-policies/test", "POST"},
			{"/api/v1/static-policies/{id}", "GET"},
			{"/api/v1/static-policies/{id}", "PUT"},
			{"/api/v1/static-policies/{id}", "DELETE"},
			{"/api/v1/static-policies/{id}", "PATCH"},
			{"/api/v1/static-policies/{id}/versions", "GET"},
			{"/api/v1/static-policies/{id}/override", "POST"},
			{"/api/v1/static-policies/{id}/override", "DELETE"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("expected route %s %s to be registered", route.method, route.path)
			}
		}
	})

	t.Run("skips registration without database", func(t *testing.T) {
		router := mux.NewRouter()
		RegisterStaticPolicyHandlers(router, nil)

		// With nil db, no routes should be registered
		req := httptest.NewRequest("GET", "/api/v1/static-policies", nil)
		match := &mux.RouteMatch{}
		if router.Match(req, match) {
			t.Error("expected no routes to be registered with nil db")
		}
	})
}
