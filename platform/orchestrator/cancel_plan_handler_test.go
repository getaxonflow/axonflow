// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/planning"
)

// TestCancelPlanHandler tests the cancelPlanHandler HTTP handler with table-driven tests.
// The handler is a package-level function that depends on the package-level planService variable.
func TestCancelPlanHandler(t *testing.T) {
	tests := []struct {
		name           string
		planID         string
		orgID          string
		body           interface{}
		setupService   bool
		setupPlan      *planning.Plan
		wantStatus     int
		wantSuccess    bool
		wantErrContain string
	}{
		{
			name:         "cancel pending plan with reason",
			planID:       "plan_cancel_pending",
			orgID:        "org_1",
			body:         map[string]string{"reason": "no longer needed"},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_pending",
				OrgID:              "org_1",
				Status:             planning.PlanStatusPending,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:  http.StatusOK,
			wantSuccess: true,
		},
		{
			name:         "cancel executing plan",
			planID:       "plan_cancel_executing",
			orgID:        "org_1",
			body:         map[string]string{"reason": "timeout"},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_executing",
				OrgID:              "org_1",
				Status:             planning.PlanStatusExecuting,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:  http.StatusOK,
			wantSuccess: true,
		},
		{
			name:         "cancel with no body defaults reason",
			planID:       "plan_cancel_no_body",
			orgID:        "",
			body:         nil,
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_no_body",
				OrgID:              "",
				Status:             planning.PlanStatusPending,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:  http.StatusOK,
			wantSuccess: true,
		},
		{
			name:         "cancel with empty reason defaults to API message",
			planID:       "plan_cancel_empty_reason",
			orgID:        "",
			body:         map[string]string{"reason": ""},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_empty_reason",
				OrgID:              "",
				Status:             planning.PlanStatusPending,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:  http.StatusOK,
			wantSuccess: true,
		},
		{
			// The handler uses errors.Is to match wrapped ErrPlanNotFound from the service.
			name:           "cancel nonexistent plan returns 404",
			planID:         "nonexistent_plan",
			orgID:          "org_1",
			body:           map[string]string{"reason": "cleanup"},
			setupService:   true,
			setupPlan:      nil, // No plan stored
			wantStatus:     http.StatusNotFound,
			wantSuccess:    false,
			wantErrContain: "plan not found",
		},
		{
			name:         "cancel completed plan returns 409",
			planID:       "plan_cancel_completed",
			orgID:        "org_1",
			body:         map[string]string{"reason": "too late"},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_completed",
				OrgID:              "org_1",
				Status:             planning.PlanStatusCompleted,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:     http.StatusConflict,
			wantSuccess:    false,
			wantErrContain: "cannot cancel",
		},
		{
			name:         "cancel failed plan returns 409",
			planID:       "plan_cancel_failed",
			orgID:        "org_1",
			body:         map[string]string{"reason": "retry"},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cancel_failed",
				OrgID:              "org_1",
				Status:             planning.PlanStatusFailed,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:     http.StatusConflict,
			wantSuccess:    false,
			wantErrContain: "cannot cancel",
		},
		{
			name:         "cross-tenant cancel rejected as 404",
			planID:       "plan_cross_tenant",
			orgID:        "org_attacker",
			body:         map[string]string{"reason": "steal data"},
			setupService: true,
			setupPlan: &planning.Plan{
				PlanID:             "plan_cross_tenant",
				OrgID:              "org_owner",
				Status:             planning.PlanStatusPending,
				WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
				CreatedAt:          time.Now(),
			},
			wantStatus:     http.StatusNotFound,
			wantSuccess:    false,
			wantErrContain: "not found",
		},
		{
			name:           "nil plan service returns 503",
			planID:         "plan_any",
			orgID:          "",
			body:           nil,
			setupService:   false,
			setupPlan:      nil,
			wantStatus:     http.StatusServiceUnavailable,
			wantSuccess:    false,
			wantErrContain: "not available",
		},
		{
			name:           "empty plan ID returns 400",
			planID:         "", // mux.Vars returns empty for missing key
			orgID:          "org_1",
			body:           nil,
			setupService:   true,
			setupPlan:      nil,
			wantStatus:     http.StatusBadRequest,
			wantSuccess:    false,
			wantErrContain: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore package-level state
			oldPlanService := planService
			oldTracker := mapExecutionTracker
			defer func() {
				planService = oldPlanService
				mapExecutionTracker = oldTracker
			}()

			// Leave mapExecutionTracker nil so the handler skips the sync call
			mapExecutionTracker = nil

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
			if tt.body != nil {
				bodyBytes, err := json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("failed to marshal body: %v", err)
				}
				bodyReader = bytes.NewReader(bodyBytes)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest("POST", "/api/v1/plan/"+tt.planID+"/cancel", bodyReader)
			req.Header.Set("Content-Type", "application/json")
			if tt.orgID != "" {
				req.Header.Set("X-Org-ID", tt.orgID)
			}

			// Set mux URL vars (gorilla/mux pattern)
			req = mux.SetURLVars(req, map[string]string{"id": tt.planID})

			w := httptest.NewRecorder()
			cancelPlanHandler(w, req)

			// Verify status code
			if w.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}

			// Parse response
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response body: %v; raw: %s", err, w.Body.String())
			}

			// Verify success field
			gotSuccess, _ := resp["success"].(bool)
			if gotSuccess != tt.wantSuccess {
				t.Errorf("success = %v, want %v", gotSuccess, tt.wantSuccess)
			}

			// Verify error message for error cases
			if tt.wantErrContain != "" {
				errMsg, _ := resp["error"].(string)
				if errMsg == "" {
					t.Errorf("expected error containing %q, got no error field", tt.wantErrContain)
				} else {
					found := false
					// Case-insensitive substring check
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

			// Verify Content-Type header
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
			}
		})
	}
}

// TestCancelPlanHandler_SuccessResponseFields verifies that a successful cancel response
// includes the expected fields: success, plan_id, status, and reason.
func TestCancelPlanHandler_SuccessResponseFields(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_fields_test",
		OrgID:              "org_1",
		Status:             planning.PlanStatusPending,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	body, _ := json.Marshal(map[string]string{"reason": "user cancelled"})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_fields_test/cancel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_fields_test"})

	w := httptest.NewRecorder()
	cancelPlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Check all expected fields
	if resp["success"] != true {
		t.Errorf("success = %v, want true", resp["success"])
	}
	if resp["plan_id"] != "plan_fields_test" {
		t.Errorf("plan_id = %v, want %q", resp["plan_id"], "plan_fields_test")
	}
	if resp["status"] != "cancelled" {
		t.Errorf("status = %v, want %q", resp["status"], "cancelled")
	}
	if resp["reason"] != "user cancelled" {
		t.Errorf("reason = %v, want %q", resp["reason"], "user cancelled")
	}
}

// TestCancelPlanHandler_DefaultReason verifies that when no reason is provided,
// the handler defaults to "cancelled via API".
func TestCancelPlanHandler_DefaultReason(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_default_reason",
		Status:             planning.PlanStatusPending,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	// Send request with no body
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_default_reason/cancel", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "plan_default_reason"})

	w := httptest.NewRecorder()
	cancelPlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	reason, _ := resp["reason"].(string)
	if reason != "cancelled via API" {
		t.Errorf("reason = %q, want %q", reason, "cancelled via API")
	}
}

// TestCancelPlanHandler_PlanStateAfterCancel verifies that the underlying plan's status
// is updated to cancelled in the repository after a successful cancel request.
func TestCancelPlanHandler_PlanStateAfterCancel(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_state_check",
		OrgID:              "org_1",
		Status:             planning.PlanStatusPending,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	body, _ := json.Marshal(map[string]string{"reason": "state check test"})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_state_check/cancel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_state_check"})

	w := httptest.NewRecorder()
	cancelPlanHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", w.Code, http.StatusOK)
	}

	// Verify plan state in repository
	updatedPlan, err := mockRepo.GetPlan(context.Background(), "plan_state_check")
	if err != nil {
		t.Fatalf("failed to get plan from repo: %v", err)
	}
	if updatedPlan.Status != planning.PlanStatusCancelled {
		t.Errorf("plan status = %s, want %s", updatedPlan.Status, planning.PlanStatusCancelled)
	}
	if updatedPlan.ErrorMessage != "state check test" {
		t.Errorf("plan error message = %q, want %q", updatedPlan.ErrorMessage, "state check test")
	}
}

// TestCancelPlanHandler_CancelAlreadyCancelledPlan verifies that cancelling an
// already cancelled plan returns a conflict error.
func TestCancelPlanHandler_CancelAlreadyCancelledPlan(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_already_cancelled",
		OrgID:              "org_1",
		Status:             planning.PlanStatusCancelled,
		ErrorMessage:       "previously cancelled",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	body, _ := json.Marshal(map[string]string{"reason": "cancel again"})
	req := httptest.NewRequest("POST", "/api/v1/plan/plan_already_cancelled/cancel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req = mux.SetURLVars(req, map[string]string{"id": "plan_already_cancelled"})

	w := httptest.NewRecorder()
	cancelPlanHandler(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusConflict, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["success"] != false {
		t.Errorf("success = %v, want false", resp["success"])
	}
}

// TestCancelPlanHandler_OrgIDFromHeader verifies that the handler reads X-Org-ID
// from the request header and uses it for authorization.
func TestCancelPlanHandler_OrgIDFromHeader(t *testing.T) {
	oldPlanService := planService
	oldTracker := mapExecutionTracker
	defer func() {
		planService = oldPlanService
		mapExecutionTracker = oldTracker
	}()
	mapExecutionTracker = nil

	mockRepo := planning.NewMockRepository()
	testPlan := &planning.Plan{
		PlanID:             "plan_org_header",
		OrgID:              "org_correct",
		Status:             planning.PlanStatusPending,
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}
	if err := mockRepo.SavePlan(context.Background(), testPlan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	planService = planning.NewService(mockRepo)

	// Correct org should succeed
	t.Run("correct org succeeds", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"reason": "org test"})
		req := httptest.NewRequest("POST", "/api/v1/plan/plan_org_header/cancel", bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org_correct")
		req = mux.SetURLVars(req, map[string]string{"id": "plan_org_header"})

		w := httptest.NewRecorder()
		cancelPlanHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})

	// Reset plan state for next sub-test (re-save as pending since cancel changed it)
	testPlan.Status = planning.PlanStatusPending
	testPlan.ErrorMessage = ""
	_ = mockRepo.SavePlan(context.Background(), testPlan)

	// Wrong org should be rejected
	t.Run("wrong org rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"reason": "org test"})
		req := httptest.NewRequest("POST", "/api/v1/plan/plan_org_header/cancel", bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org_wrong")
		req = mux.SetURLVars(req, map[string]string{"id": "plan_org_header"})

		w := httptest.NewRecorder()
		cancelPlanHandler(w, req)

		// Cross-tenant returns 404 (not 403) to avoid leaking plan existence
		if w.Code != http.StatusNotFound {
			t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusNotFound, w.Body.String())
		}
	})

	// No org header should succeed (community mode)
	testPlan.Status = planning.PlanStatusPending
	testPlan.ErrorMessage = ""
	_ = mockRepo.SavePlan(context.Background(), testPlan)

	t.Run("no org header passes (community mode)", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"reason": "community"})
		req := httptest.NewRequest("POST", "/api/v1/plan/plan_org_header/cancel", bytes.NewReader(body))
		// No X-Org-ID header set
		req = mux.SetURLVars(req, map[string]string{"id": "plan_org_header"})

		w := httptest.NewRecorder()
		cancelPlanHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status code = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
		}
	})
}

// matchesCaseInsensitive checks if two equal-length strings match case-insensitively.
func matchesCaseInsensitive(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
