// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func setupTestHandler() (*Handler, *Service, *MockRepository) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	handler := NewHandler(svc)
	return handler, svc, repo
}

func TestHandlerCreateWorkflow(t *testing.T) {
	handler, _, _ := setupTestHandler()

	tests := []struct {
		name       string
		body       CreateWorkflowRequest
		wantStatus int
	}{
		{
			name: "create workflow successfully",
			body: CreateWorkflowRequest{
				WorkflowName: "test-workflow",
				Source:       WorkflowSourceLangGraph,
			},
			wantStatus: http.StatusCreated,
		},
		{
			name: "create workflow without name fails",
			body: CreateWorkflowRequest{
				WorkflowName: "",
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tenant-ID", "tenant-1")

			rr := httptest.NewRecorder()
			handler.CreateWorkflow(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantStatus == http.StatusCreated {
				var response CreateWorkflowResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if response.WorkflowID == "" {
					t.Error("workflow_id should not be empty")
				}
			}
		})
	}
}

func TestHandlerGetWorkflow(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow first
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	tests := []struct {
		name       string
		workflowID string
		wantStatus int
	}{
		{
			name:       "get existing workflow",
			workflowID: workflow.WorkflowID,
			wantStatus: http.StatusOK,
		},
		{
			name:       "get non-existent workflow",
			workflowID: "non-existent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/"+tt.workflowID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.workflowID})

			rr := httptest.NewRecorder()
			handler.GetWorkflow(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandlerListWorkflows(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create some workflows
	for i := 0; i < 5; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows?limit=10", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.ListWorkflows(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response ListWorkflowsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Total != 5 {
		t.Errorf("total = %d, want 5", response.Total)
	}
}

func TestHandlerStepGate(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow first
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	tests := []struct {
		name       string
		workflowID string
		stepID     string
		body       StepGateRequest
		wantStatus int
		wantDecision GateDecision
	}{
		{
			name:       "step gate allow",
			workflowID: workflow.WorkflowID,
			stepID:     "step-1",
			body: StepGateRequest{
				StepName: "generate-code",
				StepType: StepTypeLLMCall,
				Model:    "gpt-4",
				Provider: "openai",
			},
			wantStatus:   http.StatusOK,
			wantDecision: GateDecisionAllow,
		},
		{
			name:       "step gate missing step type",
			workflowID: workflow.WorkflowID,
			stepID:     "step-2",
			body: StepGateRequest{
				StepName: "generate-code",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "step gate non-existent workflow",
			workflowID: "non-existent",
			stepID:     "step-1",
			body: StepGateRequest{
				StepName: "generate-code",
				StepType: StepTypeLLMCall,
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+tt.workflowID+"/steps/"+tt.stepID+"/gate", bytes.NewReader(body))
			req = mux.SetURLVars(req, map[string]string{"id": tt.workflowID, "step_id": tt.stepID})
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tenant-ID", "tenant-1")

			rr := httptest.NewRecorder()
			handler.StepGate(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body: %s", rr.Code, tt.wantStatus, rr.Body.String())
			}

			if tt.wantStatus == http.StatusOK {
				var response StepGateResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if response.Decision != tt.wantDecision {
					t.Errorf("decision = %s, want %s", response.Decision, tt.wantDecision)
				}
			}
		})
	}
}

func TestHandlerCompleteWorkflow(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow first
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.CompleteWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Try to complete again (should fail with conflict)
	rr = httptest.NewRecorder()
	handler.CompleteWorkflow(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerAbortWorkflow(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow first
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	abortReq := AbortWorkflowRequest{
		Reason: "Testing abort",
	}
	body, _ := json.Marshal(abortReq)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/abort", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.AbortWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify the workflow was aborted
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "", "")
	if updated.Status != WorkflowStatusAborted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusAborted)
	}
}

func TestHandlerResumeWorkflow(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow first
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandlerMarkStepCompleted(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create a workflow and step
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step via gate
	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.MarkStepCompleted(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestHandlerMarkStepCompletedWithMetrics(t *testing.T) {
	handler, svc, repo := setupTestHandler()
	ctx := context.Background()

	// Create a workflow and step
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step via gate
	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	// Send step complete with metrics body
	metricsBody := StepCompleteRequest{
		Output:    map[string]interface{}{"code": "def hello(): pass"},
		TokensIn:  intPtr(150),
		TokensOut: intPtr(45),
		CostUSD:   float64Ptr(0.0023),
	}
	body, _ := json.Marshal(metricsBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/complete", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.MarkStepCompleted(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	// Verify metrics were stored
	step, _ := repo.GetStep(ctx, workflow.WorkflowID, "step-1")
	if step.TokensIn == nil || *step.TokensIn != 150 {
		t.Errorf("tokens_in = %v, want 150", step.TokensIn)
	}
	if step.TokensOut == nil || *step.TokensOut != 45 {
		t.Errorf("tokens_out = %v, want 45", step.TokensOut)
	}
	if step.CostUSD == nil || *step.CostUSD != 0.0023 {
		t.Errorf("cost_usd = %v, want 0.0023", step.CostUSD)
	}
}

func float64Ptr(f float64) *float64 { return &f }

func TestHandlerApproveStep(t *testing.T) {
	// Setup with approval policy evaluator
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	// Create a workflow and step requiring approval
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"comment": "Reviewed and approved for production"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "approver@example.com")

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestHandlerApproveStepMissingComment(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	// No body — should be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "approver@example.com")

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestHandlerApproveStepShortComment(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	// Too short — should be rejected
	body := strings.NewReader(`{"comment": "ok"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "approver@example.com")

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestHandlerRejectStep(t *testing.T) {
	// Setup with approval policy evaluator
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	// Create a workflow and step requiring approval
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"reason": "Contains prohibited content, rejecting"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/reject", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "rejecter@example.com")

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Verify workflow was aborted
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "", "")
	if updated.Status != WorkflowStatusAborted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusAborted)
	}
}

func TestHandlerGetPendingApprovals(t *testing.T) {
	// Setup with approval policy evaluator
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	// Create workflows with pending approvals
	for i := 0; i < 3; i++ {
		workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")

		gateReq := &StepGateRequest{
			StepName: "step-1",
			StepType: StepTypeLLMCall,
		}
		svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending?limit=10", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.GetPendingApprovals(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	count := int(response["count"].(float64))
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
}

func TestHandlerCORS(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workflows", nil)
	req.Header.Set("Origin", "http://localhost:3000")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "http://localhost:3000" {
		t.Errorf("Access-Control-Allow-Origin = %s, want http://localhost:3000", allowOrigin)
	}
}

func TestHandlerRouteRegistration(t *testing.T) {
	handler, _, _ := setupTestHandler()
	router := mux.NewRouter()

	handler.RegisterRoutes(router)
	handler.RegisterEnterpriseRoutes(router)

	// Test that routes are registered
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/workflows"},
		{http.MethodGet, "/api/v1/workflows"},
		{http.MethodGet, "/api/v1/workflows/{id}"},
		{http.MethodPost, "/api/v1/workflows/{id}/complete"},
		{http.MethodPost, "/api/v1/workflows/{id}/abort"},
		{http.MethodPost, "/api/v1/workflows/{id}/resume"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/gate"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/complete"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/approve"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/reject"},
		{http.MethodGet, "/api/v1/workflows/approvals/pending"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("route not registered: %s %s", route.method, route.path)
			}
		})
	}
}

func TestHandlerCoreRouteRegistration(t *testing.T) {
	handler, _, _ := setupTestHandler()
	router := mux.NewRouter()

	// Only register core routes (no enterprise routes)
	handler.RegisterRoutes(router)

	coreRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/workflows"},
		{http.MethodGet, "/api/v1/workflows"},
		{http.MethodGet, "/api/v1/workflows/{id}"},
		{http.MethodPost, "/api/v1/workflows/{id}/complete"},
		{http.MethodPost, "/api/v1/workflows/{id}/abort"},
		{http.MethodPost, "/api/v1/workflows/{id}/resume"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/gate"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/complete"},
	}

	for _, route := range coreRoutes {
		t.Run("core_"+route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("core route not registered: %s %s", route.method, route.path)
			}
		})
	}

	// Enterprise approval routes should NOT be registered
	enterpriseRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/workflows/test-id/steps/step-1/approve"},
		{http.MethodPost, "/api/v1/workflows/test-id/steps/step-1/reject"},
		{http.MethodGet, "/api/v1/workflows/approvals/pending"},
	}

	for _, route := range enterpriseRoutes {
		t.Run("enterprise_not_registered_"+route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if router.Match(req, match) {
				t.Errorf("enterprise route should NOT be registered in community mode: %s %s", route.method, route.path)
			}
		})
	}
}

func TestHandlerEnterpriseRouteRegistration(t *testing.T) {
	handler, _, _ := setupTestHandler()
	router := mux.NewRouter()

	handler.RegisterRoutes(router)
	handler.RegisterEnterpriseRoutes(router)

	// All enterprise approval routes should be registered
	enterpriseRoutes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/approve"},
		{http.MethodPost, "/api/v1/workflows/{id}/steps/{step_id}/reject"},
		{http.MethodGet, "/api/v1/workflows/approvals/pending"},
	}

	for _, route := range enterpriseRoutes {
		t.Run("enterprise_"+route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Errorf("enterprise route not registered: %s %s", route.method, route.path)
			}
		})
	}
}

func TestNewHandlerWithLogger(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)

	// Test with nil logger (should use default)
	handler := NewHandlerWithLogger(svc, nil)
	if handler == nil {
		t.Error("handler should not be nil")
	}

	// Test with custom logger
	customLogger := log.New(bytes.NewBuffer(nil), "TEST: ", log.LstdFlags)
	handler = NewHandlerWithLogger(svc, customLogger)
	if handler == nil {
		t.Error("handler should not be nil")
	}
}

func TestHandlerCreateWorkflowInvalidJSON(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerGetWorkflowMissingID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})

	rr := httptest.NewRecorder()
	handler.GetWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerListWorkflowsWithFilters(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create workflows with different statuses
	for i := 0; i < 3; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
			Source:       WorkflowSourceLangGraph,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	// Test with status filter
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows?status=in_progress&source=langgraph&offset=0", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-1")

	rr := httptest.NewRecorder()
	handler.ListWorkflows(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandlerStepGateMissingWorkflowID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	body, _ := json.Marshal(StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//steps/step-1/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": "", "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerStepGateMissingStepID(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	body, _ := json.Marshal(StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps//gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": ""})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerStepGateInvalidJSON(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/gate", bytes.NewReader([]byte("invalid json")))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerStepGateTerminalWorkflow(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Complete the workflow first
	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "", "")

	body, _ := json.Marshal(StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerStepGatePendingApproval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Try to add another step while approval is pending
	body, _ := json.Marshal(StepGateRequest{
		StepName: "test2",
		StepType: StepTypeLLMCall,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-2/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-2"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerMarkStepCompletedMissingIDs(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//steps//complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "step_id": ""})

	rr := httptest.NewRecorder()
	handler.MarkStepCompleted(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerMarkStepCompletedNotFound(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/non-existent/complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.MarkStepCompleted(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerMarkStepCompletedMalformedBody(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	gateReq := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", gateReq, "tenant-1", "org-1", "user-1", "client-1")

	// Send malformed JSON body
	body := bytes.NewReader([]byte(`{invalid json`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/complete", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.MarkStepCompleted(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for malformed body", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerCompleteWorkflowMissingID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})

	rr := httptest.NewRecorder()
	handler.CompleteWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerCompleteWorkflowNotFound(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/non-existent/complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.CompleteWorkflow(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerCompleteWorkflowWithPendingApproval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/complete", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.CompleteWorkflow(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerAbortWorkflowMissingID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//abort", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})

	rr := httptest.NewRecorder()
	handler.AbortWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerAbortWorkflowNotFound(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/non-existent/abort", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.AbortWorkflow(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerAbortWorkflowEmptyBody(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Empty body should use default reason
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/abort", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.AbortWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandlerAbortWorkflowTerminal(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Complete the workflow
	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "", "")

	body, _ := json.Marshal(AbortWorkflowRequest{Reason: "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/abort", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.AbortWorkflow(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerResumeWorkflowMissingID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerResumeWorkflowNotFound(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/non-existent/resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerResumeWorkflowTerminal(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Complete the workflow
	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerResumeWorkflowWithPendingApproval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerResumeWorkflowRejected(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create new workflow to test rejected case since reject aborts the workflow
	workflow2, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow-2",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow2.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.RejectStep(ctx, workflow2.WorkflowID, "step-1", "", "", "user@test.com", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow2.WorkflowID+"/resume", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow2.WorkflowID})

	rr := httptest.NewRecorder()
	handler.ResumeWorkflow(rr, req)

	// Should return conflict since workflow is aborted (terminal state)
	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerApproveStepMissingIDs(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//steps//approve", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "step_id": ""})

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerApproveStepNotFound(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"comment": "Reviewed and approved for production"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/non-existent/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerApproveStepNoApprovalNeeded(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step that doesn't require approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"comment": "Reviewed and approved for production"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerApproveStepNotPending(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Approve the step first (via service directly, bypasses handler validation)
	svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "", "", "approver@test.com", "Initial approval for testing")

	// Try to approve again via handler
	body := strings.NewReader(`{"comment": "Attempting second approval"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerRejectStepMissingReason(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// No body — should be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/reject", nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "rejecter@example.com")

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestHandlerRejectStepShortReason(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Too short — should be rejected
	body := strings.NewReader(`{"reason": "no"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/reject", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "rejecter@example.com")

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}
}

func TestHandlerRejectStepMissingIDs(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows//steps//reject", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "", "step_id": ""})

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerRejectStepNotFound(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"reason": "Rejecting due to policy violation"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/non-existent/reject", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "non-existent"})

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandlerRejectStepNoApprovalNeeded(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step that doesn't require approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	body := strings.NewReader(`{"reason": "Rejecting due to policy violation"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/reject", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandlerGetPendingApprovalsMissingTenant(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending", nil)
	// No X-Tenant-ID header

	rr := httptest.NewRecorder()
	handler.GetPendingApprovals(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandlerGetPendingApprovalsWithLimit(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	handler := NewHandler(svc)
	ctx := context.Background()

	// Create workflows with pending approvals
	for i := 0; i < 5; i++ {
		workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")

		svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
			StepName: "test",
			StepType: StepTypeLLMCall,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending?limit=2", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.GetPendingApprovals(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &response)

	// count is the total number of pending approvals (5), not limited
	count := int(response["count"].(float64))
	if count != 5 {
		t.Errorf("count = %d, want 5 (total pending)", count)
	}

	// pending_approvals should be limited to 2 items
	approvals := response["pending_approvals"].([]interface{})
	if len(approvals) > 2 {
		t.Errorf("pending_approvals len = %d, should be <= 2 with limit", len(approvals))
	}
}

func TestHandlerContextExtraction(t *testing.T) {
	handler, _, _ := setupTestHandler()
	ctx := context.Background()

	// Test with context values instead of headers
	ctx = context.WithValue(ctx, "tenant_id", "ctx-tenant")
	ctx = context.WithValue(ctx, "org_id", "ctx-org")
	ctx = context.WithValue(ctx, "user_id", "ctx-user")
	ctx = context.WithValue(ctx, "client_id", "ctx-client")

	body, _ := json.Marshal(CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

func TestHandlerCORSDisallowedOrigin(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/workflows", nil)
	req.Header.Set("Origin", "http://malicious.com")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should not set the disallowed origin
	allowOrigin := rr.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin == "http://malicious.com" {
		t.Error("should not allow malicious origin")
	}
}

// --- Tests for trace_id (#1259) ---

func TestHandlerCreateWorkflowWithTraceID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	body, _ := json.Marshal(CreateWorkflowRequest{
		WorkflowName: "traced-workflow",
		Source:       WorkflowSourceLangGraph,
		TraceID:      "langsmith-trace-abc123",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var response CreateWorkflowResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.TraceID != "langsmith-trace-abc123" {
		t.Errorf("trace_id = %q, want %q", response.TraceID, "langsmith-trace-abc123")
	}
}

func TestHandlerGetWorkflowReturnsTraceID(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create workflow with trace_id
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "traced-workflow",
		TraceID:      "datadog-trace-xyz789",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/"+workflow.WorkflowID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID})

	rr := httptest.NewRecorder()
	handler.GetWorkflow(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response WorkflowStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.TraceID != "datadog-trace-xyz789" {
		t.Errorf("trace_id = %q, want %q", response.TraceID, "datadog-trace-xyz789")
	}
}

func TestHandlerListWorkflowsTraceIDFilter(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	// Create workflows: 2 with same trace_id, 1 without
	svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "traced-1",
		TraceID:      "shared-trace-001",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "traced-2",
		TraceID:      "shared-trace-001",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "untraced",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows?trace_id=shared-trace-001", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.ListWorkflows(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	var response ListWorkflowsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Total != 2 {
		t.Errorf("total = %d, want 2 (filtered by trace_id)", response.Total)
	}

	for _, w := range response.Workflows {
		if w.TraceID != "shared-trace-001" {
			t.Errorf("workflow %s has trace_id=%q, want %q", w.WorkflowID, w.TraceID, "shared-trace-001")
		}
	}
}

func TestHandlerCreateWorkflowWithoutTraceID(t *testing.T) {
	handler, _, _ := setupTestHandler()

	body, _ := json.Marshal(CreateWorkflowRequest{
		WorkflowName: "no-trace-workflow",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var response CreateWorkflowResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// trace_id should be empty (omitted from JSON via omitempty)
	if response.TraceID != "" {
		t.Errorf("trace_id = %q, want empty when not provided", response.TraceID)
	}
}

func TestServiceCreateWorkflowTraceIDTooLong(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	longTraceID := make([]byte, 256)
	for i := range longTraceID {
		longTraceID[i] = 'x'
	}

	_, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "long-trace",
		TraceID:      string(longTraceID),
	}, "tenant-1", "org-1", "user-1", "client-1")

	if err == nil {
		t.Error("expected error for trace_id exceeding 255 chars")
	}
}

func TestTraceIDJSONSerialization(t *testing.T) {
	// Verify trace_id uses omitempty — empty trace_id should not appear in JSON
	resp := CreateWorkflowResponse{
		WorkflowID:   "wf_123",
		WorkflowName: "test",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if _, exists := raw["trace_id"]; exists {
		t.Error("trace_id should be omitted from JSON when empty")
	}

	// With trace_id set, it should appear
	resp.TraceID = "my-trace"
	data, _ = json.Marshal(resp)
	json.Unmarshal(data, &raw)

	if raw["trace_id"] != "my-trace" {
		t.Errorf("trace_id = %v, want 'my-trace'", raw["trace_id"])
	}
}

// --- P2: Handler-level test for trace_id too long (#1281) ---

func TestHandlerCreateWorkflowTraceIDTooLong(t *testing.T) {
	handler, _, _ := setupTestHandler()

	longTraceID := make([]byte, 256)
	for i := range longTraceID {
		longTraceID[i] = 'x'
	}

	body, _ := json.Marshal(CreateWorkflowRequest{
		WorkflowName: "long-trace-workflow",
		TraceID:      string(longTraceID),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.CreateWorkflow(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response["code"] != "INVALID_TRACE_ID" {
		t.Errorf("code = %v, want INVALID_TRACE_ID", response["code"])
	}
}

// --- P2: Handler-level tests for ToolContext (#1282) ---

func TestHandlerStepGateWithToolContext(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "tool-context-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	body, _ := json.Marshal(StepGateRequest{
		StepName: "tool-step",
		StepType: StepTypeToolCall,
		ToolContext: &ToolContext{
			ToolName: "search_database",
			ToolType: "function",
			ToolInput: map[string]interface{}{
				"query": "SELECT * FROM users",
			},
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestHandlerStepGateToolContextEmptyToolName(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "tool-context-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	body, _ := json.Marshal(StepGateRequest{
		StepName: "tool-step",
		StepType: StepTypeToolCall,
		ToolContext: &ToolContext{
			ToolName: "",
			ToolType: "function",
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", rr.Code, http.StatusBadRequest, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response["code"] != "INVALID_TOOL_CONTEXT" {
		t.Errorf("code = %v, want INVALID_TOOL_CONTEXT", response["code"])
	}
}

// TestHandlerGetPendingApprovalsEmptyListSerialisesAsArray asserts that when
// no pending approvals exist the WCP listing returns `pending_approvals: []`
// rather than `pending_approvals: null`. Reviewer UIs rely on the array
// shape; returning null forces defensive client code in every consumer.
// Regression guard for the fix that aligns WCP with the MAP plane-scoped
// listing (Issue #1680).
func TestHandlerGetPendingApprovalsEmptyListSerialisesAsArray(t *testing.T) {
	handler, _, _ := setupTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending", nil)
	req.Header.Set("X-Tenant-ID", "tenant-empty")
	rr := httptest.NewRecorder()
	handler.GetPendingApprovals(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"pending_approvals":[]`) {
		t.Errorf("empty result must serialise as [], not null; body = %s", body)
	}
}
