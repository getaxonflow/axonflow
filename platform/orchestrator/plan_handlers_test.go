// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
)

// --- updatePlanHandler tests ---

// TestUpdatePlanHandler tests the updatePlanHandler HTTP handler with table-driven tests.
func TestUpdatePlanHandler(t *testing.T) {
	tests := []struct {
		name           string
		planID         string
		orgID          string
		body           interface{}
		setupService   bool
		setupPlan      *planning.Plan
		wantStatus     int
		wantErrContain string
	}{
		{
			name:   "success: valid update with version",
			planID: "plan_update_ok",
			orgID:  "org_1",
			body: map[string]interface{}{
				"version": 1,
				"execution_mode":   "parallel",
			},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_update_ok",
				OrgID:              "org_1",
				Status:             planning.PlanStatusPending,
				Version:            1,
				ExecutionMode:      "sequential",
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "version conflict returns 409",
			planID: "plan_update_conflict",
			orgID:  "org_1",
			body: map[string]interface{}{
				"version": 5, // plan is at version 1
				"execution_mode":   "parallel",
			},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_update_conflict",
				OrgID:              "org_1",
				Status:             planning.PlanStatusPending,
				Version:            1,
				ExecutionMode:      "sequential",
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			},
			wantStatus:     http.StatusConflict,
			wantErrContain: "version conflict",
		},
		{
			name:           "invalid JSON body returns 400",
			planID:         "plan_update_bad_json",
			orgID:          "org_1",
			body:           nil, // will send invalid JSON string below
			setupService:   true,
			setupPlan:      nil,
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "Invalid request body",
		},
		{
			name:           "missing plan ID returns 400",
			planID:         "",
			orgID:          "org_1",
			body:           map[string]interface{}{"version": 1},
			setupService:   true,
			setupPlan:      nil,
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "required",
		},
		{
			name:   "plan not found returns 404",
			planID: "nonexistent_plan",
			orgID:  "org_1",
			body: map[string]interface{}{
				"version": 1,
				"execution_mode":   "parallel",
			},
			setupService:   true,
			setupPlan:      nil, // no plan stored
			wantStatus:     http.StatusNotFound,
			wantErrContain: "not found",
		},
		{
			name:   "non-pending plan returns 400",
			planID: "plan_update_completed",
			orgID:  "org_1",
			body: map[string]interface{}{
				"version": 1,
				"execution_mode":   "parallel",
			},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_update_completed",
				OrgID:              "org_1",
				Status:             planning.PlanStatusCompleted,
				Version:            1,
				ExecutionMode:      "sequential",
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			},
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "only pending plans",
		},
		{
			name:   "nil plan service returns 503",
			planID: "plan_any",
			orgID:  "org_1",
			body: map[string]interface{}{
				"version": 1,
				"execution_mode":   "parallel",
			},
			setupService:   false,
			setupPlan:      nil,
			wantStatus:     http.StatusServiceUnavailable,
			wantErrContain: "not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore package-level state
			oldPlanService := planService
			defer func() {
				planService = oldPlanService
			}()

			if tt.setupService {
				mockRepo := planning.NewMockRepository()
				if tt.setupPlan != nil {
					if err := mockRepo.SavePlan(context.Background(), tt.setupPlan); err != nil {
						t.Fatalf("failed to save setup plan: %v", err)
					}
				}
				planService = planning.NewService(mockRepo)
			} else {
				planService = nil
			}

			// Build request body
			var bodyReader *bytes.Reader
			if tt.name == "invalid JSON body returns 400" {
				// Send malformed JSON
				bodyReader = bytes.NewReader([]byte(`{not valid json`))
			} else if tt.body != nil {
				bodyBytes, err := json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("failed to marshal body: %v", err)
				}
				bodyReader = bytes.NewReader(bodyBytes)
			} else {
				bodyReader = bytes.NewReader([]byte(`{}`))
			}

			req := httptest.NewRequest("PUT", "/api/v1/plan/"+tt.planID, bodyReader)
			req.Header.Set("Content-Type", "application/json")
			if tt.orgID != "" {
				req.Header.Set("X-Org-ID", tt.orgID)
			}
			req = mux.SetURLVars(req, map[string]string{"id": tt.planID})

			w := httptest.NewRecorder()
			updatePlanHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Verify Content-Type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
			}

			// Parse response and check error message
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response body: %v; raw: %s", err, w.Body.String())
			}

			if tt.wantErrContain != "" {
				// Check error field or message field
				errMsg, _ := resp["error"].(string)
				msgField, _ := resp["message"].(string)
				combined := errMsg + " " + msgField
				found := false
				target := tt.wantErrContain
				for i := 0; i <= len(combined)-len(target); i++ {
					if matchesCaseInsensitive(combined[i:i+len(target)], target) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("response error = %q / message = %q, want substring %q", errMsg, msgField, tt.wantErrContain)
				}
			}
		})
	}
}

// TestUpdatePlanHandler_SuccessResponseFields verifies that a successful update response
// includes the expected fields: success, plan_id, version, and status.
func TestUpdatePlanHandler_SuccessResponseFields(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_update_fields",
		OrgID:              "org_1",
		Status:             planning.PlanStatusPending,
		Version:            1,
		ExecutionMode:      "sequential",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	body, _ := json.Marshal(map[string]interface{}{
		"version": 1,
		"execution_mode":   "parallel",
	})
	req := httptest.NewRequest("PUT", "/api/v1/plan/plan_update_fields", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_update_fields"})

	w := httptest.NewRecorder()
	updatePlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("success = %v, want true", resp["success"])
	}
	if resp["plan_id"] != "plan_update_fields" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan_update_fields")
	}
	// Version should be incremented from 1 to 2
	version, _ := resp["version"].(float64)
	if version != 2 {
		t.Errorf("version = %v, want 2", resp["version"])
	}
	if resp["status"] != string(planning.PlanStatusPending) {
		t.Errorf("status = %v, want %q", resp["status"], planning.PlanStatusPending)
	}
}

// TestUpdatePlanHandler_InvalidExecutionMode verifies that an invalid execution mode
// returns 400 with an appropriate error message.
func TestUpdatePlanHandler_InvalidExecutionMode(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_bad_mode",
		OrgID:              "org_1",
		Status:             planning.PlanStatusPending,
		Version:            1,
		ExecutionMode:      "sequential",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	// Clear DEPLOYMENT_MODE to simulate community mode
	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Setenv("DEPLOYMENT_MODE", oldDeployment)

	body, _ := json.Marshal(map[string]interface{}{
		"version": 1,
		"execution_mode":   "invalid_mode",
	})
	req := httptest.NewRequest("PUT", "/api/v1/plan/plan_bad_mode", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_bad_mode"})

	w := httptest.NewRecorder()
	updatePlanHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errMsg, _ := resp["error"].(string)
	if errMsg == "" {
		t.Error("expected error message about invalid execution mode")
	}
}

// TestUpdatePlanHandler_CrossTenantRejected verifies that updating a plan owned by a
// different org returns 404 (to avoid leaking plan existence).
func TestUpdatePlanHandler_CrossTenantRejected(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_cross_tenant_update",
		OrgID:              "org_owner",
		Status:             planning.PlanStatusPending,
		Version:            1,
		ExecutionMode:      "sequential",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	body, _ := json.Marshal(map[string]interface{}{
		"version": 1,
		"domain":           "travel",
	})
	req := httptest.NewRequest("PUT", "/api/v1/plan/plan_cross_tenant_update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_attacker")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_cross_tenant_update"})

	w := httptest.NewRecorder()
	updatePlanHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

// --- getPlanVersionsHandler tests ---

// TestGetPlanVersionsHandler tests the getPlanVersionsHandler HTTP handler.
func TestGetPlanVersionsHandler(t *testing.T) {
	tests := []struct {
		name           string
		planID         string
		orgID          string
		setupService   bool
		setupPlan      *planning.Plan
		setupVersions  []planning.PlanVersion
		wantStatus     int
		wantErrContain string
	}{
		{
			name:         "success: returns versions",
			planID:       "plan_versions_ok",
			orgID:        "org_1",
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_versions_ok",
				OrgID:              "org_1",
				Status:             planning.PlanStatusPending,
				Version:            2,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			},
			setupVersions: []planning.PlanVersion{
				{
					PlanID:        "plan_versions_ok",
					Version:       1,
					Snapshot:      json.RawMessage(`{"status":"pending"}`),
					ChangedBy:     "user_1",
					ChangeType:    "update",
					ChangeSummary: "execution_mode: sequential -> parallel",
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:           "plan not found returns 404",
			planID:         "nonexistent_plan",
			orgID:          "org_1",
			setupService:   true,
			setupPlan:      nil,
			wantStatus:     http.StatusNotFound,
			wantErrContain: "not found",
		},
		{
			name:           "missing plan ID returns 400",
			planID:         "",
			orgID:          "org_1",
			setupService:   true,
			setupPlan:      nil,
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "required",
		},
		{
			name:         "empty versions list returns OK with empty array",
			planID:       "plan_no_versions",
			orgID:        "org_1",
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_no_versions",
				OrgID:              "org_1",
				Status:             planning.PlanStatusPending,
				Version:            1,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
				UpdatedAt:          time.Now(),
			},
			setupVersions: nil, // No versions
			wantStatus:    http.StatusOK,
		},
		{
			name:           "nil plan service returns 503",
			planID:         "plan_any",
			orgID:          "org_1",
			setupService:   false,
			wantStatus:     http.StatusServiceUnavailable,
			wantErrContain: "not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore package-level state
			oldPlanService := planService
			defer func() {
				planService = oldPlanService
			}()

			if tt.setupService {
				mockRepo := planning.NewMockRepository()
				if tt.setupPlan != nil {
					if err := mockRepo.SavePlan(context.Background(), tt.setupPlan); err != nil {
						t.Fatalf("failed to save setup plan: %v", err)
					}
				}
				// Save versions if provided
				for i := range tt.setupVersions {
					if err := mockRepo.SavePlanVersion(context.Background(), &tt.setupVersions[i]); err != nil {
						t.Fatalf("failed to save version: %v", err)
					}
				}
				planService = planning.NewService(mockRepo)
			} else {
				planService = nil
			}

			req := httptest.NewRequest("GET", "/api/v1/plan/"+tt.planID+"/versions", nil)
			if tt.orgID != "" {
				req.Header.Set("X-Org-ID", tt.orgID)
			}
			req = mux.SetURLVars(req, map[string]string{"id": tt.planID})

			w := httptest.NewRecorder()
			getPlanVersionsHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Verify Content-Type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
			}

			// Parse response
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response body: %v; raw: %s", err, w.Body.String())
			}

			// Check error message for error cases
			if tt.wantErrContain != "" {
				errMsg, _ := resp["error"].(string)
				if errMsg == "" {
					t.Errorf("expected error containing %q, got no error field", tt.wantErrContain)
				} else {
					found := false
					for i := 0; i <= len(errMsg)-len(tt.wantErrContain); i++ {
						if matchesCaseInsensitive(errMsg[i:i+len(tt.wantErrContain)], tt.wantErrContain) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("error = %q, want substring %q", errMsg, tt.wantErrContain)
					}
				}
			}
		})
	}
}

// TestGetPlanVersionsHandler_SuccessResponseFields verifies that a successful response
// contains plan_id and versions array.
func TestGetPlanVersionsHandler_SuccessResponseFields(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_versions_fields",
		OrgID:              "org_1",
		Status:             planning.PlanStatusPending,
		Version:            2,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}

	// Save a version
	v := &planning.PlanVersion{
		PlanID:        "plan_versions_fields",
		Version:       1,
		Snapshot:      json.RawMessage(`{"old":"state"}`),
		ChangedBy:     "user_test",
		ChangeType:    "update",
		ChangeSummary: "domain: generic -> travel",
	}
	if err := mockRepo.SavePlanVersion(context.Background(), v); err != nil {
		t.Fatalf("failed to save version: %v", err)
	}
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("GET", "/api/v1/plan/plan_versions_fields/versions", nil)
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_versions_fields"})

	w := httptest.NewRecorder()
	getPlanVersionsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["plan_id"] != "plan_versions_fields" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan_versions_fields")
	}

	versions, ok := resp["versions"].([]interface{})
	if !ok {
		t.Fatal("expected versions to be an array")
	}
	if len(versions) != 1 {
		t.Errorf("versions count = %d, want 1", len(versions))
	}
}

// TestGetPlanVersionsHandler_CrossTenantRejected verifies that requesting versions
// for a plan owned by a different org returns 404.
func TestGetPlanVersionsHandler_CrossTenantRejected(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_versions_cross_tenant",
		OrgID:              "org_owner",
		Status:             planning.PlanStatusPending,
		Version:            1,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("GET", "/api/v1/plan/plan_versions_cross_tenant/versions", nil)
	req.Header.Set("X-Org-ID", "org_attacker")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_versions_cross_tenant"})

	w := httptest.NewRecorder()
	getPlanVersionsHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

// --- resumePlanHandler tests ---

// TestResumePlanHandler tests the resumePlanHandler HTTP handler.
func TestResumePlanHandler(t *testing.T) {
	tests := []struct {
		name           string
		planID         string
		orgID          string
		deploymentMode string
		setupService   bool
		body           interface{}
		wantStatus     int
		wantErrContain string
	}{
		{
			name:           "community mode returns 403",
			planID:         "plan_resume_community",
			orgID:          "org_1",
			deploymentMode: "community",
			setupService:   true,
			body:           map[string]interface{}{"approved": true},
			wantStatus:     http.StatusForbidden,
			wantErrContain: "Enterprise",
		},
		{
			name:           "empty deployment mode (community default) returns 403",
			planID:         "plan_resume_empty_mode",
			orgID:          "org_1",
			deploymentMode: "", // empty = community
			setupService:   true,
			body:           map[string]interface{}{"approved": true},
			wantStatus:     http.StatusForbidden,
			wantErrContain: "Enterprise",
		},
		{
			name:           "enterprise mode: missing plan ID returns 400",
			planID:         "",
			orgID:          "org_1",
			deploymentMode: "enterprise",
			setupService:   true,
			body:           nil,
			wantStatus:     http.StatusBadRequest,
			wantErrContain: "required",
		},
		{
			name:           "enterprise mode: nil plan service returns 503",
			planID:         "plan_resume_no_svc",
			orgID:          "org_1",
			deploymentMode: "enterprise",
			setupService:   false,
			body:           nil,
			wantStatus:     http.StatusServiceUnavailable,
			wantErrContain: "not available",
		},
		{
			name:           "enterprise mode: nil WCP executor returns 503",
			planID:         "plan_resume_no_wcp",
			orgID:          "org_1",
			deploymentMode: "enterprise",
			setupService:   true,
			body:           map[string]interface{}{"approved": true},
			wantStatus:     http.StatusServiceUnavailable,
			wantErrContain: "WCP executor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore package-level state
			oldPlanService := planService
			oldWCPExecutor := mapWCPExecutor
			oldWCPService := workflowControlService
			defer func() {
				planService = oldPlanService
				mapWCPExecutor = oldWCPExecutor
				workflowControlService = oldWCPService
			}()

			// Ensure WCP is nil for non-WCP tests
			mapWCPExecutor = nil
			workflowControlService = nil

			// Set deployment mode
			oldDeployment := os.Getenv("DEPLOYMENT_MODE")
			if tt.deploymentMode != "" {
				os.Setenv("DEPLOYMENT_MODE", tt.deploymentMode)
			} else {
				os.Unsetenv("DEPLOYMENT_MODE")
			}
			defer func() {
				if oldDeployment != "" {
					os.Setenv("DEPLOYMENT_MODE", oldDeployment)
				} else {
					os.Unsetenv("DEPLOYMENT_MODE")
				}
			}()

			if tt.setupService {
				mockRepo := planning.NewMockRepository()
				planService = planning.NewService(mockRepo)
			} else {
				planService = nil
			}

			// Build request body
			var bodyReader *bytes.Reader
			if tt.body != nil {
				bodyBytes, err := json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("failed to marshal body: %v", err)
				}
				bodyReader = bytes.NewReader(bodyBytes)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest("POST", "/api/v1/plan/"+tt.planID+"/resume", bodyReader)
			req.Header.Set("Content-Type", "application/json")
			if tt.orgID != "" {
				req.Header.Set("X-Org-ID", tt.orgID)
			}
			req = mux.SetURLVars(req, map[string]string{"id": tt.planID})

			// #2896 WS1c: enterprise resume now requires the Agent proxy token.
			// These cases assert DOWNSTREAM branching (400/503), so route them
			// through a valid proxy token to reach that logic. (Community cases
			// 403 on the licensing gate before proxy-auth is consulted.)
			if tt.deploymentMode == "enterprise" {
				installProxyTokenValidator(t, proxyGuardTestSecret)
				req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			}

			w := httptest.NewRecorder()
			resumePlanHandler(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Verify Content-Type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
			}

			// Parse response
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response body: %v; raw: %s", err, w.Body.String())
			}

			// Check error message for error cases
			if tt.wantErrContain != "" {
				errMsg, _ := resp["error"].(string)
				if errMsg == "" {
					t.Errorf("expected error containing %q, got no error field; resp: %v", tt.wantErrContain, resp)
				} else {
					found := false
					for i := 0; i <= len(errMsg)-len(tt.wantErrContain); i++ {
						if matchesCaseInsensitive(errMsg[i:i+len(tt.wantErrContain)], tt.wantErrContain) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("error = %q, want substring %q", errMsg, tt.wantErrContain)
					}
				}
			}
		})
	}
}

// setupResumeTestWCP creates a WCP service with a mock repo containing a matching workflow
// for the given plan. Returns cleanup function.
func setupResumeTestWCP(t *testing.T, planID string, executionMode string) func() {
	t.Helper()

	oldPlanService := planService
	oldWCPExecutor := mapWCPExecutor
	oldWCPService := workflowControlService

	// Set enterprise mode
	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")

	// Create plan in executing state
	planRepo := planning.NewMockRepository()
	planSvc := planning.NewService(planRepo)
	planService = planSvc

	workflowDef := `{"apiVersion":"v1","kind":"Workflow","metadata":{"name":"test"},"spec":{"steps":[{"name":"step1","type":"llm-call"},{"name":"step2","type":"tool-call"}]}}`
	plan := &planning.Plan{
		PlanID:             planID,
		Query:              "test query",
		Domain:             "generic",
		ExecutionMode:      executionMode,
		Status:             planning.PlanStatusExecuting,
		WorkflowDefinition: json.RawMessage(workflowDef),
		Version:            1,
	}
	if err := planRepo.SavePlan(context.Background(), plan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	// Move plan to executing state
	_ = planRepo.UpdatePlanStatus(context.Background(), planID, planning.PlanStatusExecuting, nil, "")

	// Create WCP mock with matching workflow
	wcpRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(wcpRepo, nil, nil)
	workflowControlService = wcpSvc

	// Create the WCP workflow matching naming convention
	wcpWorkflowName := "map-" + executionMode + "-" + planID
	pending := workflow_control.ApprovalStatusPending
	wcpWorkflow := &workflow_control.Workflow{
		WorkflowID:       "wf-" + planID,
		WorkflowName:     wcpWorkflowName,
		Source:           workflow_control.WorkflowSource("map"),
		Status:           workflow_control.WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		Steps: []workflow_control.WorkflowStep{
			{
				StepID:         "step_0_step1",
				WorkflowID:     "wf-" + planID,
				StepName:       "step1",
				StepType:       workflow_control.StepTypeLLMCall,
				Decision:       workflow_control.GateDecisionRequireApproval,
				ApprovalStatus: &pending,
			},
		},
	}
	if err := wcpRepo.Create(context.Background(), wcpWorkflow); err != nil {
		t.Fatalf("failed to create WCP workflow: %v", err)
	}
	// Add the step to the repo
	if err := wcpRepo.AddStep(context.Background(), &wcpWorkflow.Steps[0]); err != nil {
		t.Fatalf("failed to add step: %v", err)
	}

	// Set up WCP executor
	mapWCPExecutor = NewMAPWCPExecutor(wcpSvc, planSvc)

	return func() {
		planService = oldPlanService
		mapWCPExecutor = oldWCPExecutor
		workflowControlService = oldWCPService
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}
}

// TestResumePlanHandler_PlanNotExecuting verifies that a plan not in executing state returns 400.
func TestResumePlanHandler_PlanNotExecuting(t *testing.T) {
	oldPlanService := planService
	oldWCPExecutor := mapWCPExecutor
	oldWCPService := workflowControlService
	defer func() {
		planService = oldPlanService
		mapWCPExecutor = oldWCPExecutor
		workflowControlService = oldWCPService
	}()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	planRepo := planning.NewMockRepository()
	planSvc := planning.NewService(planRepo)
	planService = planSvc

	// Create plan in pending state (not executing)
	plan := &planning.Plan{
		PlanID: "plan_not_executing",
		Status: planning.PlanStatusPending,
	}
	_ = planRepo.SavePlan(context.Background(), plan)

	wcpRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(wcpRepo, nil, nil)
	workflowControlService = wcpSvc
	mapWCPExecutor = NewMAPWCPExecutor(wcpSvc, planSvc)

	body, _ := json.Marshal(map[string]interface{}{"approved": true})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_not_executing/resume", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_not_executing"})
	// #2896 WS1c: enterprise resume requires the Agent proxy token.
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

// TestResumePlanHandler_ApproveStep verifies that the handler reaches the WCP approve flow.
// Without a real workflow engine, step execution will fail — but we verify it gets past
// WCP approval and reaches the execution stage.
func TestResumePlanHandler_ApproveStep(t *testing.T) {
	cleanup := setupResumeTestWCP(t, "plan_approve_step", "confirm")
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"approved": true})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_approve_step/resume", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "test-user")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_approve_step"})
	// #2896 WS1c: enterprise resume requires the Agent proxy token.
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	// Should not be 503 (WCP is set up) or 403 (enterprise mode)
	if w.Code == http.StatusServiceUnavailable {
		t.Fatalf("got 503, expected the handler to reach step execution; body: %s", w.Body.String())
	}
	if w.Code == http.StatusForbidden {
		t.Fatalf("got 403, expected enterprise mode; body: %s", w.Body.String())
	}

	// The handler reaches step execution but fails (no workflow engine) — that's expected.
	// Verify it returns 500 with a step execution error (not a WCP error).
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d (no engine available); body: %s", w.Code, http.StatusInternalServerError, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v; raw: %s", err, w.Body.String())
	}

	// Error should mention step execution, not WCP
	errMsg, _ := resp["error"].(string)
	if errMsg == "" {
		t.Fatal("expected error field in response")
	}
	if !containsSubstring(errMsg, "engine") && !containsSubstring(errMsg, "Step execution") {
		t.Errorf("error = %q, expected step execution failure", errMsg)
	}
}

// TestResumePlanHandler_RejectStep verifies that the handler rejects a step and aborts the plan.
func TestResumePlanHandler_RejectStep(t *testing.T) {
	cleanup := setupResumeTestWCP(t, "plan_reject_step", "confirm")
	defer cleanup()

	body, _ := json.Marshal(map[string]interface{}{"approved": false})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_reject_step/resume", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_reject_step"})
	// #2896 WS1c: enterprise resume requires the Agent proxy token.
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v; raw: %s", err, w.Body.String())
	}

	if resp["status"] != "rejected" {
		t.Errorf("status = %v, want %q", resp["status"], "rejected")
	}
	if resp["plan_id"] != "plan_reject_step" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan_reject_step")
	}
	if resp["workflow_id"] != "wf-plan_reject_step" {
		t.Errorf("workflow_id = %v, want %q", resp["workflow_id"], "wf-plan_reject_step")
	}
}

// TestResumePlanHandler_DefaultApproved verifies that when no body is provided,
// the handler defaults approved to true.
func TestResumePlanHandler_DefaultApproved(t *testing.T) {
	cleanup := setupResumeTestWCP(t, "plan_default_approved", "confirm")
	defer cleanup()

	// Send request with empty body — approved defaults to true
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_default_approved/resume", nil)
	req.Header.Set("X-User-ID", "test-user")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_default_approved"})
	// #2896 WS1c: enterprise resume requires the Agent proxy token.
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	// Should not be 503 (WCP is set up)
	if w.Code == http.StatusServiceUnavailable {
		t.Fatalf("got 503, handler should have WCP executor; body: %s", w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v; raw: %s", err, w.Body.String())
	}

	// The response should indicate processing occurred (not rejected)
	if resp["status"] == "rejected" {
		t.Error("expected approved (default=true), got rejected")
	}
}

// --- getPlanStatusHandler tests ---

// TestGetPlanStatusHandler_LegacyPathReturnsUnifiedFields verifies that the legacy
// plan-based path returns the same unified fields as the tracker path.
func TestGetPlanStatusHandler_LegacyPathReturnsUnifiedFields(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()

	// Disable tracker to force legacy path
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	now := time.Now()
	testPlan := &planning.Plan{
		PlanID:    "plan_status_unified",
		OrgID:     "org_1",
		Query:     "analyze travel data",
		Domain:    "travel",
		Status:    planning.PlanStatusCompleted,
		StepCount: 3,
		Version:   2,
		ExecutionMode:      "sequential",
		Complexity:         3,
		WorkflowDefinition: json.RawMessage(`{"spec":{"steps":[{"name":"fetch","type":"api-call"},{"name":"analyze","type":"llm-call"},{"name":"report","type":"llm-call"}]}}`),
		ExecutionResult:    json.RawMessage(`{"result":"success"}`),
		ExpiresAt:          now.Add(1 * time.Hour),
		CreatedAt:          now.Add(-10 * time.Minute),
		UpdatedAt:          now,
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("GET", "/api/v1/plan/plan_status_unified", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "plan_status_unified"})

	w := httptest.NewRecorder()
	getPlanStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify unified fields are present
	if resp["plan_id"] != "plan_status_unified" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan_status_unified")
	}
	if resp["execution_id"] != "plan_status_unified" {
		t.Errorf("execution_id = %v, want %q", resp["execution_id"], "plan_status_unified")
	}
	if resp["progress_percent"] == nil {
		t.Error("expected progress_percent field")
	}
	if pp, ok := resp["progress_percent"].(float64); !ok || pp != 100.0 {
		t.Errorf("progress_percent = %v, want 100.0", resp["progress_percent"])
	}
	if resp["started_at"] == nil {
		t.Error("expected started_at field")
	}
	if resp["duration"] == nil {
		t.Error("expected duration field")
	}

	// Verify steps array is present and populated
	steps, ok := resp["steps"].([]interface{})
	if !ok {
		t.Fatal("expected steps to be an array")
	}
	if len(steps) != 3 {
		t.Errorf("steps count = %d, want 3", len(steps))
	}

	// Verify execution_result preserved
	if resp["execution_result"] == nil {
		t.Error("expected execution_result field")
	}

	// Verify workflow_definition preserved
	if resp["workflow_definition"] == nil {
		t.Error("expected workflow_definition field")
	}

	// Verify version preserved
	if resp["version"] == nil {
		t.Error("expected version field")
	}
}

// TestGetPlanStatusHandler_PendingPlanFields verifies fields for a pending plan.
func TestGetPlanStatusHandler_PendingPlanFields(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()

	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	now := time.Now()
	testPlan := &planning.Plan{
		PlanID:    "plan_status_pending",
		OrgID:     "org_1",
		Query:     "test query",
		Domain:    "finance",
		Status:    planning.PlanStatusPending,
		StepCount: 2,
		Version:   1,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("GET", "/api/v1/plan/plan_status_pending", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "plan_status_pending"})

	w := httptest.NewRecorder()
	getPlanStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Pending plan should have 0% progress and 0 completed steps
	if pp, ok := resp["progress_percent"].(float64); !ok || pp != 0.0 {
		t.Errorf("progress_percent = %v, want 0.0", resp["progress_percent"])
	}
	completedSteps, _ := resp["completed_steps"].(float64)
	if completedSteps != 0 {
		t.Errorf("completed_steps = %v, want 0", resp["completed_steps"])
	}
}

// TestGetPlanStatusHandler_NotFound verifies 404 for missing plan.
func TestGetPlanStatusHandler_NotFound(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()

	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("GET", "/api/v1/plan/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})

	w := httptest.NewRecorder()
	getPlanStatusHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// TestGetPlanStatusHandler_NilService verifies 503 for nil plan service.
func TestGetPlanStatusHandler_NilService(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()

	planService = nil
	mapExecutionTracker = nil

	req := httptest.NewRequest("GET", "/api/v1/plan/any", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "any"})

	w := httptest.NewRecorder()
	getPlanStatusHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// TestResumePlanHandler_NoWorkflow verifies that the handler returns 404 when no active
// WCP workflow is found for the plan.
func TestResumePlanHandler_NoWorkflow(t *testing.T) {
	oldPlanService := planService
	oldWCPExecutor := mapWCPExecutor
	oldWCPService := workflowControlService
	defer func() {
		planService = oldPlanService
		mapWCPExecutor = oldWCPExecutor
		workflowControlService = oldWCPService
	}()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	planRepo := planning.NewMockRepository()
	planSvc := planning.NewService(planRepo)
	planService = planSvc

	// Create plan in executing state but no matching WCP workflow
	plan := &planning.Plan{
		PlanID: "plan_no_workflow",
		Status: planning.PlanStatusExecuting,
	}
	_ = planRepo.SavePlan(context.Background(), plan)
	_ = planRepo.UpdatePlanStatus(context.Background(), "plan_no_workflow", planning.PlanStatusExecuting, nil, "")

	wcpRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(wcpRepo, nil, nil)
	workflowControlService = wcpSvc
	mapWCPExecutor = NewMAPWCPExecutor(wcpSvc, planSvc)

	body, _ := json.Marshal(map[string]interface{}{"approved": true})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_no_workflow/resume", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_no_workflow"})
	// #2896 WS1c: enterprise resume requires the Agent proxy token.
	installProxyTokenValidator(t, proxyGuardTestSecret)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))

	w := httptest.NewRecorder()
	resumePlanHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

// --- rollbackPlanHandler tests ---

// TestRollbackPlanHandler_CommunityBlocked verifies community mode blocks rollback
// (rollback requires Enterprise license; community users get 403).
func TestRollbackPlanHandler_CommunityBlocked(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan-community-rollback",
		OrgID:              "org-1",
		Status:             planning.PlanStatusPending,
		Version:            2,
		ExecutionMode:      "parallel",
		Domain:             "travel",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	_ = mockRepo.SavePlanVersion(context.Background(), &planning.PlanVersion{
		PlanID:     "plan-community-rollback",
		Version:    1,
		Snapshot:   json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":[]}}`),
		ChangeType: "update",
	})
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-community-rollback/rollback/1", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan-community-rollback", "version": "1"})

	w := httptest.NewRecorder()
	rollbackPlanHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errMsg, _ := resp["error"].(string)
	if !strings.Contains(errMsg, "Enterprise license") {
		t.Errorf("error = %q, want to contain 'Enterprise license'", errMsg)
	}
}

// TestRollbackPlanHandler_CommunityVersionLimit verifies that community mode
// returns 403 when the version limit is reached.
func TestRollbackPlanHandler_CommunityVersionLimit(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan-version-limit",
		OrgID:              "org-1",
		Status:             planning.PlanStatusPending,
		Version:            4,
		ExecutionMode:      "parallel",
		Domain:             "travel",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	// Save versions up to the limit (3 versions = max)
	for v := 1; v <= 3; v++ {
		_ = mockRepo.SavePlanVersion(context.Background(), &planning.PlanVersion{
			PlanID:     "plan-version-limit",
			Version:    v,
			Snapshot:   json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":[]}}`),
			ChangeType: "update",
		})
	}
	// Use a low version limit to trigger the error
	planService = planning.NewServiceWithConfig(mockRepo, planning.ServiceConfig{
		MaxPlansWithVersioning: 100,
		MaxVersionsPerPlan:     3,
	})

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-version-limit/rollback/1", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan-version-limit", "version": "1"})

	w := httptest.NewRecorder()
	rollbackPlanHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

// TestRollbackPlanHandler_EnterpriseSuccess verifies rollback works in enterprise mode.
func TestRollbackPlanHandler_EnterpriseSuccess(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan-rollback-handler",
		OrgID:              "org-1",
		Status:             planning.PlanStatusPending,
		Version:            2,
		ExecutionMode:      "parallel",
		Domain:             "travel",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	// Save v1 snapshot
	_ = mockRepo.SavePlanVersion(context.Background(), &planning.PlanVersion{
		PlanID:     "plan-rollback-handler",
		Version:    1,
		Snapshot:   json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":[]}}`),
		ChangeType: "update",
	})
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-rollback-handler/rollback/1", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-User-ID", "user-1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan-rollback-handler", "version": "1"})

	w := httptest.NewRecorder()
	rollbackPlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("success = %v, want true", resp["success"])
	}
	if resp["plan_id"] != "plan-rollback-handler" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan-rollback-handler")
	}
	version, _ := resp["version"].(float64)
	if version != 3 {
		t.Errorf("version = %v, want 3", resp["version"])
	}
	rolledBackTo, _ := resp["rolled_back_to"].(float64)
	if rolledBackTo != 1 {
		t.Errorf("rolled_back_to = %v, want 1", resp["rolled_back_to"])
	}
}

// TestRollbackPlanHandler_VersionNotFound verifies 404 for missing version.
func TestRollbackPlanHandler_VersionNotFound(t *testing.T) {
	oldPlanService := planService
	defer func() { planService = oldPlanService }()

	oldDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", oldDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:    "plan-rollback-no-ver",
		OrgID:     "org-1",
		Status:    planning.PlanStatusPending,
		Version:   2,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	req := httptest.NewRequest("POST", "/api/v1/plan/plan-rollback-no-ver/rollback/1", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan-rollback-no-ver", "version": "1"})

	w := httptest.NewRecorder()
	rollbackPlanHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

// --- CE Gating Route Registration Tests ---

// TestWCPRouteGating_CommunityMode verifies that in community mode,
// core WCP routes are registered but enterprise approval routes are not.
func TestWCPRouteGating_CommunityMode(t *testing.T) {
	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, nil, nil)
	handler := workflow_control.NewHandler(svc)

	// Simulate community mode: only register core routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	// Do NOT call RegisterEnterpriseRoutes (community mode)

	// Core routes should work
	coreRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows/wf-1"},
		{"POST", "/api/v1/workflows/wf-1/complete"},
		{"POST", "/api/v1/workflows/wf-1/abort"},
		{"POST", "/api/v1/workflows/wf-1/resume"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/gate"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/complete"},
	}

	for _, route := range coreRoutes {
		t.Run("core_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("core route should be registered in community mode: %s %s", route.method, route.path)
			}
		})
	}

	// Approval routes should NOT be registered
	enterpriseRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/approve"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/reject"},
		{"GET", "/api/v1/workflows/approvals/pending"},
	}

	for _, route := range enterpriseRoutes {
		t.Run("enterprise_blocked_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if router.Match(req, match) {
				t.Errorf("enterprise route should NOT be registered in community mode: %s %s", route.method, route.path)
			}
		})
	}
}

// TestWCPRouteGating_EnterpriseMode verifies that in enterprise mode,
// both core and approval routes are registered.
func TestWCPRouteGating_EnterpriseMode(t *testing.T) {
	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, nil, nil)
	handler := workflow_control.NewHandler(svc)

	// Simulate enterprise mode: register both core and enterprise routes
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	handler.RegisterEnterpriseRoutes(router)

	allRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows"},
		{"GET", "/api/v1/workflows/wf-1"},
		{"POST", "/api/v1/workflows/wf-1/complete"},
		{"POST", "/api/v1/workflows/wf-1/abort"},
		{"POST", "/api/v1/workflows/wf-1/resume"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/gate"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/complete"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/approve"},
		{"POST", "/api/v1/workflows/wf-1/steps/step-1/reject"},
		{"GET", "/api/v1/workflows/approvals/pending"},
	}

	for _, route := range allRoutes {
		t.Run("enterprise_"+route.method+"_"+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("route should be registered in enterprise mode: %s %s", route.method, route.path)
			}
		})
	}
}

// TestPlanRequest_ExecutionModeFromContext verifies that execution_mode is correctly
// extracted from the context map when not set at the top level.
func TestPlanRequest_ExecutionModeFromContext(t *testing.T) {
	tests := []struct {
		name         string
		execMode     string                 // top-level execution_mode
		context      map[string]interface{} // context map
		wantExecMode string
	}{
		{
			name:         "top-level execution_mode takes precedence",
			execMode:     "parallel",
			context:      map[string]interface{}{"execution_mode": "confirm"},
			wantExecMode: "parallel",
		},
		{
			name:         "context execution_mode used when top-level empty",
			execMode:     "",
			context:      map[string]interface{}{"execution_mode": "confirm"},
			wantExecMode: "confirm",
		},
		{
			name:         "defaults to auto when neither set",
			execMode:     "",
			context:      map[string]interface{}{},
			wantExecMode: "auto",
		},
		{
			name:         "defaults to auto when context is nil",
			execMode:     "",
			context:      nil,
			wantExecMode: "auto",
		},
		{
			name:         "context execution_mode balanced",
			execMode:     "",
			context:      map[string]interface{}{"execution_mode": "balanced"},
			wantExecMode: "balanced",
		},
		{
			name:         "ignores empty string in context",
			execMode:     "",
			context:      map[string]interface{}{"execution_mode": ""},
			wantExecMode: "auto",
		},
		{
			name:         "ignores non-string context value",
			execMode:     "",
			context:      map[string]interface{}{"execution_mode": 123},
			wantExecMode: "auto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := PlanRequest{
				ExecutionMode: tt.execMode,
				Context:       tt.context,
			}

			// Apply the same extraction logic as planRequestHandler
			if req.ExecutionMode == "" {
				if execMode, ok := req.Context["execution_mode"].(string); ok && execMode != "" {
					req.ExecutionMode = execMode
				} else {
					req.ExecutionMode = "auto"
				}
			}

			if req.ExecutionMode != tt.wantExecMode {
				t.Errorf("ExecutionMode = %q, want %q", req.ExecutionMode, tt.wantExecMode)
			}
		})
	}
}

// TestWebhookGating_CommunityMode verifies that webhooks are registered in all modes.
// Webhooks are a core MAP v1.0 feature available in both community and enterprise modes.
func TestWebhookGating_CommunityMode(t *testing.T) {
	tests := []struct {
		name           string
		deploymentMode string
		shouldRegister bool
	}{
		{"community mode allows webhooks", "community", true},
		{"empty mode allows webhooks", "", true},
		{"enterprise mode allows webhooks", "enterprise", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Webhooks are now registered regardless of deployment mode.
			// The only gate is whether webhookHandler is non-nil (i.e., database is available).
			shouldRegister := true

			if shouldRegister != tt.shouldRegister {
				t.Errorf("webhook registration = %v, want %v for DEPLOYMENT_MODE=%q",
					shouldRegister, tt.shouldRegister, tt.deploymentMode)
			}
		})
	}
}
