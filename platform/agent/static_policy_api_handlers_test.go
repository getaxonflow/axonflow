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

package agent

import (
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
					WithArgs("test-tenant").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

				// Main query
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).
					AddRow(
						"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
						"Blocks UNION-based SQL injection", "block", true, "global",
						"{}", testTime, testTime, 1,
					).
					AddRow(
						"uuid-2", "pii_ssn", "PII SSN Detection", "pii_detection", "\\d{3}-\\d{2}-\\d{4}", "high",
						"Detects SSN patterns", "redact", true, "test-tenant",
						"{}", testTime, testTime, 1,
					)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "success - filter by category",
			queryParams: "?category=sql_injection",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant", "sql_injection").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", "sql_injection", 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "success - filter by severity",
			queryParams: "?severity=critical",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant", "critical").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", "critical", 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "success - filter by enabled",
			queryParams: "?enabled=true",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant", true).
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", true, 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "success - pagination",
			queryParams: "?page=2&page_size=5",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "policy-6", "Policy 6", "sql_injection", "pattern", "high",
					"Description", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", 5, 5). // page_size=5, offset=5 (page 2)
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "success - empty result",
			queryParams: "?category=nonexistent",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant", "nonexistent").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				})

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", "nonexistent", 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name:        "success - without tenant ID (global policies only)",
			queryParams: "",
			tenantID:    "",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("", 20, 0).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "success - page size capped at 100",
			queryParams: "?page_size=200",
			tenantID:    "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
					WithArgs("test-tenant").
					WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

				mock.ExpectQuery(`SELECT.*FROM static_policies`).
					WithArgs("test-tenant", 100, 0). // page_size capped at 100
					WillReturnRows(sqlmock.NewRows([]string{
						"id", "policy_id", "name", "category", "pattern", "severity",
						"description", "action", "enabled", "tenant_id",
						"metadata", "created_at", "updated_at", "version",
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

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestHandleGetStaticPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policyID       string
		tenantID       string
		setupMock      func(sqlmock.Sqlmock)
		expectedStatus int
	}{
		{
			name:     "success - get by policy_id",
			policyID: "sql_injection_union",
			tenantID: "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("sql_injection_union", "test-tenant").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "success - get by UUID",
			policyID: "uuid-1",
			tenantID: "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("uuid-1", "test-tenant").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:     "not found",
			policyID: "nonexistent",
			tenantID: "test-tenant",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("nonexistent", "test-tenant").
					WillReturnRows(sqlmock.NewRows([]string{}))
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:     "success - global policy without tenant ID",
			policyID: "sql_injection_union",
			tenantID: "",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "policy_id", "name", "category", "pattern", "severity",
					"description", "action", "enabled", "tenant_id",
					"metadata", "created_at", "updated_at", "version",
				}).AddRow(
					"uuid-1", "sql_injection_union", "SQL Injection UNION", "sql_injection", "union\\s+select", "critical",
					"Blocks UNION-based SQL injection", "block", true, "global",
					"{}", testTime, testTime, 1,
				)

				mock.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
					WithArgs("sql_injection_union", "").
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

			req := httptest.NewRequest("GET", "/api/v1/static-policies/"+tt.policyID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.policyID})
			if tt.tenantID != "" {
				req.Header.Set("X-Tenant-ID", tt.tenantID)
			}
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

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestBuildListQuery(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	handler := NewStaticPolicyAPIHandler(db)

	tests := []struct {
		name         string
		tenantID     string
		category     string
		severity     string
		enabled      string
		page         int
		pageSize     int
		expectedArgs int // Number of expected arguments
	}{
		{
			name:         "no filters",
			tenantID:     "test",
			page:         1,
			pageSize:     20,
			expectedArgs: 3, // tenantID, pageSize, offset
		},
		{
			name:         "category filter",
			tenantID:     "test",
			category:     "sql_injection",
			page:         1,
			pageSize:     20,
			expectedArgs: 4, // tenantID, category, pageSize, offset
		},
		{
			name:         "all filters",
			tenantID:     "test",
			category:     "sql_injection",
			severity:     "critical",
			enabled:      "true",
			page:         1,
			pageSize:     20,
			expectedArgs: 6, // tenantID, category, severity, enabled, pageSize, offset
		},
		{
			name:         "pagination",
			tenantID:     "test",
			page:         3,
			pageSize:     10,
			expectedArgs: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, countQuery, args := handler.buildListQuery(
				tt.tenantID, tt.category, tt.severity, tt.enabled, tt.page, tt.pageSize,
			)

			if query == "" {
				t.Error("expected query to be non-empty")
			}
			if countQuery == "" {
				t.Error("expected count query to be non-empty")
			}
			if len(args) != tt.expectedArgs {
				t.Errorf("expected %d args, got %d", tt.expectedArgs, len(args))
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
		name           string
		totalItems     int
		pageSize       int
		page           int
		expectedPages  int
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

			if totalPages != tt.expectedPages {
				t.Errorf("expected %d pages, got %d", tt.expectedPages, totalPages)
			}
		})
	}
}
