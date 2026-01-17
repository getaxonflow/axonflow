// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
	"time"
)

func TestCreateWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	tests := []struct {
		name        string
		req         *CreateWorkflowRequest
		tenantID    string
		wantErr     bool
		wantSource  WorkflowSource
		wantStatus  WorkflowStatus
	}{
		{
			name: "create basic workflow",
			req: &CreateWorkflowRequest{
				WorkflowName: "test-workflow",
			},
			tenantID:   "tenant-1",
			wantErr:    false,
			wantSource: WorkflowSourceExternal,
			wantStatus: WorkflowStatusInProgress,
		},
		{
			name: "create langgraph workflow",
			req: &CreateWorkflowRequest{
				WorkflowName: "langgraph-workflow",
				Source:       WorkflowSourceLangGraph,
			},
			tenantID:   "tenant-1",
			wantErr:    false,
			wantSource: WorkflowSourceLangGraph,
			wantStatus: WorkflowStatusInProgress,
		},
		{
			name: "create workflow with total steps",
			req: &CreateWorkflowRequest{
				WorkflowName: "multi-step-workflow",
				TotalSteps:   intPtr(5),
			},
			tenantID:   "tenant-1",
			wantErr:    false,
			wantSource: WorkflowSourceExternal,
			wantStatus: WorkflowStatusInProgress,
		},
		{
			name: "create workflow without name fails",
			req: &CreateWorkflowRequest{
				WorkflowName: "",
			},
			tenantID: "tenant-1",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow, err := svc.CreateWorkflow(ctx, tt.req, tt.tenantID, "org-1", "user-1", "client-1")

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if workflow.WorkflowName != tt.req.WorkflowName {
				t.Errorf("workflow name = %s, want %s", workflow.WorkflowName, tt.req.WorkflowName)
			}
			if workflow.Source != tt.wantSource {
				t.Errorf("source = %s, want %s", workflow.Source, tt.wantSource)
			}
			if workflow.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s", workflow.Status, tt.wantStatus)
			}
			if workflow.TenantID != tt.tenantID {
				t.Errorf("tenant_id = %s, want %s", workflow.TenantID, tt.tenantID)
			}
			if workflow.WorkflowID == "" {
				t.Error("workflow_id should not be empty")
			}
		})
	}
}

func TestGetWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow first
	workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}

	// Test get existing workflow
	t.Run("get existing workflow", func(t *testing.T) {
		got, err := svc.GetWorkflow(ctx, workflow.WorkflowID)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if got.WorkflowID != workflow.WorkflowID {
			t.Errorf("workflow_id = %s, want %s", got.WorkflowID, workflow.WorkflowID)
		}
	})

	// Test get non-existent workflow
	t.Run("get non-existent workflow", func(t *testing.T) {
		_, err := svc.GetWorkflow(ctx, "non-existent")
		if err == nil {
			t.Error("expected error for non-existent workflow")
		}
	})
}

func TestStepGate_Allow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil) // Default evaluator allows all
	ctx := context.Background()

	// Create a workflow
	workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}

	// Check step gate
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
		Model:    "gpt-4",
		Provider: "openai",
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionAllow {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionAllow)
	}
}

func TestStepGate_TerminalWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create and complete a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.CompleteWorkflow(ctx, workflow.WorkflowID)

	// Try to check step gate on completed workflow
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}

	_, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err == nil {
		t.Error("expected error for terminal workflow")
	}
}

func TestCompleteWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Complete workflow
	err := svc.CompleteWorkflow(ctx, workflow.WorkflowID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID)
	if updated.Status != WorkflowStatusCompleted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusCompleted)
	}

	// Try to complete again (should fail)
	err = svc.CompleteWorkflow(ctx, workflow.WorkflowID)
	if err == nil {
		t.Error("expected error when completing already completed workflow")
	}
}

func TestAbortWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Abort workflow
	err := svc.AbortWorkflow(ctx, workflow.WorkflowID, "test abort")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID)
	if updated.Status != WorkflowStatusAborted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusAborted)
	}
}

func TestFailWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Fail workflow
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "test failure")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID)
	if updated.Status != WorkflowStatusFailed {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusFailed)
	}
}

func TestListWorkflows(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create multiple workflows
	for i := 0; i < 5; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
			Source:       WorkflowSourceLangGraph,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}
	for i := 0; i < 3; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
			Source:       WorkflowSourceCrewAI,
		}, "tenant-2", "org-1", "user-1", "client-1")
	}

	// Test listing with filters
	t.Run("list all", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Limit: 100})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if response.Total != 8 {
			t.Errorf("total = %d, want 8", response.Total)
		}
	})

	t.Run("list by tenant", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", Limit: 100})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if response.Total != 5 {
			t.Errorf("total = %d, want 5", response.Total)
		}
	})

	t.Run("list by source", func(t *testing.T) {
		source := WorkflowSourceLangGraph
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Source: &source, Limit: 100})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if response.Total != 5 {
			t.Errorf("total = %d, want 5", response.Total)
		}
	})

	t.Run("list with pagination", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Limit: 3, Offset: 0})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if len(response.Workflows) != 3 {
			t.Errorf("workflows count = %d, want 3", len(response.Workflows))
		}
		if !response.HasMore {
			t.Error("has_more should be true")
		}
	})
}

func TestResumeWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Resume should work on in-progress workflow
	err := svc.ResumeWorkflow(ctx, workflow.WorkflowID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Complete and try to resume (should fail)
	svc.CompleteWorkflow(ctx, workflow.WorkflowID)
	err = svc.ResumeWorkflow(ctx, workflow.WorkflowID)
	if err == nil {
		t.Error("expected error when resuming completed workflow")
	}
}

func TestMarkStepCompleted(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow and add a step
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Check step gate first (creates the step)
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")

	// Mark step completed
	err := svc.MarkStepCompleted(ctx, workflow.WorkflowID, "step-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Try to mark non-existent step completed
	err = svc.MarkStepCompleted(ctx, workflow.WorkflowID, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent step")
	}
}

// MockBlockingPolicyEvaluator always blocks steps
type MockBlockingPolicyEvaluator struct{}

func (m *MockBlockingPolicyEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:  GateDecisionBlock,
		Reason:    "Policy blocked this step",
		PolicyIDs: []string{"policy-1"},
	}
}

func TestStepGate_Block(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockBlockingPolicyEvaluator{}, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Check step gate
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionBlock {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionBlock)
	}
	if response.Reason != "Policy blocked this step" {
		t.Errorf("reason = %s, want 'Policy blocked this step'", response.Reason)
	}
}

// MockApprovalPolicyEvaluator requires approval for steps
type MockApprovalPolicyEvaluator struct{}

func (m *MockApprovalPolicyEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:  GateDecisionRequireApproval,
		Reason:    "Human approval required",
		PolicyIDs: []string{"policy-approval-1"},
	}
}

func TestStepGate_RequireApproval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, &ServiceConfig{
		BaseURL: "https://portal.getaxonflow.com",
	})
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Check step gate
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionRequireApproval {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionRequireApproval)
	}
	if response.ApprovalURL == "" {
		t.Error("approval_url should not be empty")
	}
}

func TestApproveStep(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step that requires approval
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")

	// Approve the step
	err := svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "approver@example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Try to approve again (should fail)
	err = svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "approver@example.com")
	if err == nil {
		t.Error("expected error when approving already approved step")
	}
}

func TestRejectStep(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step that requires approval
	req := &StepGateRequest{
		StepName: "step-1",
		StepType: StepTypeLLMCall,
	}
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")

	// Reject the step
	err := svc.RejectStep(ctx, workflow.WorkflowID, "step-1", "rejecter@example.com")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify workflow was aborted
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID)
	if updated.Status != WorkflowStatusAborted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusAborted)
	}
}

func TestGetPendingApprovals(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	// Create workflows and steps requiring approval
	for i := 0; i < 3; i++ {
		workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")

		req := &StepGateRequest{
			StepName: "step-1",
			StepType: StepTypeLLMCall,
		}
		svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	}

	// Get pending approvals
	pending, err := svc.GetPendingApprovals(ctx, "tenant-1", 10)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(pending) != 3 {
		t.Errorf("pending count = %d, want 3", len(pending))
	}
}

// Helper function
func intPtr(i int) *int {
	return &i
}

func TestNewServiceWithLogger(t *testing.T) {
	repo := NewMockRepository()

	// Test with nil logger (should use default)
	svc := NewServiceWithLogger(repo, nil, nil, nil)
	if svc == nil {
		t.Error("service should not be nil")
	}

	// Test with custom logger
	customLogger := log.New(bytes.NewBuffer(nil), "TEST: ", log.LstdFlags)
	svc = NewServiceWithLogger(repo, nil, nil, customLogger)
	if svc == nil {
		t.Error("service should not be nil")
	}
}

func TestCleanupStaleWorkflows(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// This is a placeholder implementation that returns 0, nil
	count, err := svc.CleanupStaleWorkflows(ctx, 24*time.Hour)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestCreateWorkflowWithMetadata(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	metadata := map[string]interface{}{
		"environment": "production",
		"team":        "engineering",
	}

	workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
		Metadata:     metadata,
	}, "tenant-1", "org-1", "user-1", "client-1")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if workflow.Metadata == nil {
		t.Error("metadata should not be nil")
	}
}

func TestStepGateWithStepInput(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	stepInput := map[string]interface{}{
		"query": "SELECT * FROM users",
	}

	req := &StepGateRequest{
		StepName:  "query-step",
		StepType:  StepTypeToolCall,
		StepInput: stepInput,
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if response.StepID != "step-1" {
		t.Errorf("step_id = %s, want step-1", response.StepID)
	}
}

func TestStepGateNonExistentWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	req := &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}

	_, err := svc.StepGate(ctx, "non-existent", "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestServiceWithBaseURL(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, &ServiceConfig{
		BaseURL: "https://portal.example.com",
	})
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}

	response, _ := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")

	if response.ApprovalURL == "" {
		t.Error("approval_url should be set when baseURL is configured")
	}
	if !strings.Contains(response.ApprovalURL, "portal.example.com") {
		t.Error("approval_url should contain the base URL")
	}
}

func TestApproveStepNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	err := svc.ApproveStep(ctx, workflow.WorkflowID, "non-existent", "approver@test.com")
	if err == nil {
		t.Error("expected error for non-existent step")
	}
}

func TestRejectStepNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	err := svc.RejectStep(ctx, workflow.WorkflowID, "non-existent", "rejector@test.com")
	if err == nil {
		t.Error("expected error for non-existent step")
	}
}

func TestAbortWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.AbortWorkflow(ctx, "non-existent", "test reason")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestCompleteWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.CompleteWorkflow(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestFailWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.FailWorkflow(ctx, "non-existent", "test reason")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestResumeWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.ResumeWorkflow(ctx, "non-existent")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestListWorkflowsDefaultLimit(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create some workflows
	for i := 0; i < 5; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	// List with no limit (should default to 20)
	response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Limit: 0})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if response.Limit != 20 {
		t.Errorf("limit = %d, want 20 (default)", response.Limit)
	}
}

func TestListWorkflowsByStatus(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create and complete some workflows
	workflow1, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow-1",
	}, "tenant-1", "org-1", "user-1", "client-1")
	svc.CompleteWorkflow(ctx, workflow1.WorkflowID)

	svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow-2",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// List only completed workflows
	status := WorkflowStatusCompleted
	response, _ := svc.ListWorkflows(ctx, ListWorkflowsOptions{Status: &status, Limit: 100})

	if response.Total != 1 {
		t.Errorf("total = %d, want 1 completed workflow", response.Total)
	}
}
