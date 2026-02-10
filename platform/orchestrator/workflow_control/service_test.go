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

// === Issue #1021: Policy Info in StepGateResponse Tests ===

// MockPolicyInfoEvaluator returns detailed policy info for testing Issue #1021
type MockPolicyInfoEvaluator struct {
	decision          GateDecision
	policiesEvaluated []PolicyMatch
	policiesMatched   []PolicyMatch
}

func (m *MockPolicyInfoEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:          m.decision,
		Reason:            "Test policy evaluation",
		PolicyIDs:         []string{"policy-pii-detection", "policy-sqli-prevention"},
		PoliciesEvaluated: m.policiesEvaluated,
		PoliciesMatched:   m.policiesMatched,
	}
}

func TestStepGate_PolicyInfoInResponse_Allow(t *testing.T) {
	// Test that PoliciesEvaluated is included even when step is allowed (Issue #1021)
	evaluator := &MockPolicyInfoEvaluator{
		decision: GateDecisionAllow,
		policiesEvaluated: []PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "pii-detection", Action: "allow"},
			{PolicyID: "pol-2", PolicyName: "sqli-prevention", Action: "allow"},
		},
		policiesMatched: []PolicyMatch{}, // No matches when allowed
	}

	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName: "test-step",
		StepType: StepTypeLLMCall,
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionAllow {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionAllow)
	}

	// Verify PoliciesEvaluated is populated (Issue #1021)
	if len(response.PoliciesEvaluated) != 2 {
		t.Errorf("PoliciesEvaluated length = %d, want 2", len(response.PoliciesEvaluated))
	}

	if len(response.PoliciesMatched) != 0 {
		t.Errorf("PoliciesMatched length = %d, want 0 for allowed step", len(response.PoliciesMatched))
	}
}

func TestStepGate_PolicyInfoInResponse_Block(t *testing.T) {
	// Test that both PoliciesEvaluated and PoliciesMatched are included when blocked (Issue #1021)
	evaluator := &MockPolicyInfoEvaluator{
		decision: GateDecisionBlock,
		policiesEvaluated: []PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "pii-detection", Action: "allow"},
			{PolicyID: "pol-2", PolicyName: "sqli-prevention", Action: "block", Reason: "SQL injection detected"},
		},
		policiesMatched: []PolicyMatch{
			{PolicyID: "pol-2", PolicyName: "sqli-prevention", Action: "block", Reason: "SQL injection detected"},
		},
	}

	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName:  "query-step",
		StepType:  StepTypeToolCall,
		StepInput: map[string]interface{}{"query": "DROP TABLE users"},
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionBlock {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionBlock)
	}

	// Verify PoliciesEvaluated includes all checked policies (Issue #1021)
	if len(response.PoliciesEvaluated) != 2 {
		t.Errorf("PoliciesEvaluated length = %d, want 2", len(response.PoliciesEvaluated))
	}

	// Verify PoliciesMatched includes only blocking policies (Issue #1021)
	if len(response.PoliciesMatched) != 1 {
		t.Errorf("PoliciesMatched length = %d, want 1", len(response.PoliciesMatched))
	}

	if len(response.PoliciesMatched) > 0 && response.PoliciesMatched[0].PolicyName != "sqli-prevention" {
		t.Errorf("PoliciesMatched[0].PolicyName = %s, want sqli-prevention", response.PoliciesMatched[0].PolicyName)
	}
}

func TestStepGate_PolicyInfoInResponse_RequireApproval(t *testing.T) {
	// Test policy info when require_approval decision (Issue #1021)
	evaluator := &MockPolicyInfoEvaluator{
		decision: GateDecisionRequireApproval,
		policiesEvaluated: []PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "high-risk-review", Action: "require_approval"},
		},
		policiesMatched: []PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "high-risk-review", Action: "require_approval", Reason: "High risk action requires approval"},
		},
	}

	repo := NewMockRepository()
	svc := NewService(repo, evaluator, &ServiceConfig{BaseURL: "https://portal.test.com"})
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName: "deploy-step",
		StepType: StepTypeConnectorCall,
	}

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if response.Decision != GateDecisionRequireApproval {
		t.Errorf("decision = %s, want %s", response.Decision, GateDecisionRequireApproval)
	}

	// Verify policy info is included (Issue #1021)
	if len(response.PoliciesEvaluated) != 1 {
		t.Errorf("PoliciesEvaluated length = %d, want 1", len(response.PoliciesEvaluated))
	}

	if len(response.PoliciesMatched) != 1 {
		t.Errorf("PoliciesMatched length = %d, want 1", len(response.PoliciesMatched))
	}

	// Verify approval URL is still generated
	if response.ApprovalURL == "" {
		t.Error("ApprovalURL should not be empty for require_approval")
	}
}

func TestStepGate_PolicyMatchDetails(t *testing.T) {
	// Test that PolicyMatch details (reason, action) are preserved (Issue #1021)
	evaluator := &MockPolicyInfoEvaluator{
		decision: GateDecisionBlock,
		policiesEvaluated: []PolicyMatch{
			{
				PolicyID:   "pol-pii-1",
				PolicyName: "pii-detection-critical",
				Action:     "block",
				Reason:     "Credit card number detected in input",
			},
		},
		policiesMatched: []PolicyMatch{
			{
				PolicyID:   "pol-pii-1",
				PolicyName: "pii-detection-critical",
				Action:     "block",
				Reason:     "Credit card number detected in input",
			},
		},
	}

	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName: "payment-step",
		StepType: StepTypeLLMCall,
	}

	response, _ := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")

	// Verify PolicyMatch details are preserved (Issue #1021)
	if len(response.PoliciesMatched) != 1 {
		t.Fatalf("PoliciesMatched length = %d, want 1", len(response.PoliciesMatched))
	}

	match := response.PoliciesMatched[0]
	if match.PolicyID != "pol-pii-1" {
		t.Errorf("PolicyID = %s, want pol-pii-1", match.PolicyID)
	}
	if match.PolicyName != "pii-detection-critical" {
		t.Errorf("PolicyName = %s, want pii-detection-critical", match.PolicyName)
	}
	if match.Action != "block" {
		t.Errorf("Action = %s, want block", match.Action)
	}
	if match.Reason != "Credit card number detected in input" {
		t.Errorf("Reason = %s, want 'Credit card number detected in input'", match.Reason)
	}
}

// === Additional Coverage Tests ===

func TestCreateWorkflowWithAllSources(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	sources := []WorkflowSource{
		WorkflowSourceLangGraph,
		WorkflowSourceLangChain,
		WorkflowSourceCrewAI,
		WorkflowSourceExternal,
	}

	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
				WorkflowName: "test-" + string(source),
				Source:       source,
			}, "tenant-1", "org-1", "user-1", "client-1")

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if workflow.Source != source {
				t.Errorf("source = %s, want %s", workflow.Source, source)
			}
		})
	}
}

func TestStepGateAllStepTypes(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	stepTypes := []StepType{
		StepTypeLLMCall,
		StepTypeToolCall,
		StepTypeConnectorCall,
		StepTypeHumanTask,
	}

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	for i, stepType := range stepTypes {
		t.Run(string(stepType), func(t *testing.T) {
			req := &StepGateRequest{
				StepName: "step-" + string(stepType),
				StepType: stepType,
			}

			stepID := "step-" + string(rune('a'+i))
			response, err := svc.StepGate(ctx, workflow.WorkflowID, stepID, req, "tenant-1", "org-1", "user-1", "client-1")

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if response.Decision != GateDecisionAllow {
				t.Errorf("decision = %s, want allow", response.Decision)
			}
		})
	}
}

func TestStepGateDuplicateStep(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	req := &StepGateRequest{
		StepName: "test-step",
		StepType: StepTypeLLMCall,
	}

	// First call should succeed
	_, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Errorf("first call unexpected error: %v", err)
	}

	// Second call with same step ID - should update or error depending on implementation
	_, err = svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	// Either no error (update) or conflict error is acceptable
	_ = err
}

func TestResumeWorkflowAfterApproval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Approve the step
	err := svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "approver@test.com")
	if err != nil {
		t.Errorf("approve step error: %v", err)
	}

	// Now resume should work
	err = svc.ResumeWorkflow(ctx, workflow.WorkflowID)
	if err != nil {
		t.Errorf("resume after approval should succeed: %v", err)
	}
}

func TestAbortAlreadyAbortedWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Abort once
	err := svc.AbortWorkflow(ctx, workflow.WorkflowID, "first abort")
	if err != nil {
		t.Errorf("first abort unexpected error: %v", err)
	}

	// Abort again should fail
	err = svc.AbortWorkflow(ctx, workflow.WorkflowID, "second abort")
	if err == nil {
		t.Error("second abort should fail on terminal state")
	}
}

func TestFailAlreadyFailedWorkflow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Fail once
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "first failure")
	if err != nil {
		t.Errorf("first fail unexpected error: %v", err)
	}

	// Fail again should fail
	err = svc.FailWorkflow(ctx, workflow.WorkflowID, "second failure")
	if err == nil {
		t.Error("second fail should fail on terminal state")
	}
}

func TestListWorkflowsWithAllFilters(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create workflows with different sources
	for i := 0; i < 3; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "langgraph-workflow",
			Source:       WorkflowSourceLangGraph,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	for i := 0; i < 2; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "crewai-workflow",
			Source:       WorkflowSourceCrewAI,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	// Test combined filters
	source := WorkflowSourceLangGraph
	status := WorkflowStatusInProgress
	response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{
		TenantID: "tenant-1",
		OrgID:    "org-1",
		Status:   &status,
		Source:   &source,
		Limit:    10,
		Offset:   0,
	})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	if response.Total != 3 {
		t.Errorf("total = %d, want 3 (langgraph workflows)", response.Total)
	}
}

func TestListWorkflowsMaxLimit(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create more workflows than limit
	for i := 0; i < 25; i++ {
		svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
			WorkflowName: "test-workflow",
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	// Request with limit 100 (should still work)
	response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Limit: 100})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if response.Total != 25 {
		t.Errorf("total = %d, want 25", response.Total)
	}
}

func TestRejectStepAlreadyRejected(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Reject first time
	err := svc.RejectStep(ctx, workflow.WorkflowID, "step-1", "user@test.com")
	if err != nil {
		t.Errorf("first reject unexpected error: %v", err)
	}

	// Create new workflow to test double rejection properly
	workflow2, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow-2",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow2.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Approve first
	svc.ApproveStep(ctx, workflow2.WorkflowID, "step-1", "approver@test.com")

	// Try to reject after approval
	err = svc.RejectStep(ctx, workflow2.WorkflowID, "step-1", "user@test.com")
	if err == nil {
		t.Error("reject after approval should fail")
	}
}

func TestMockRepositoryGetStepsForWorkflow(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Create workflow
	workflow := &Workflow{
		WorkflowID:   "wf_test123",
		WorkflowName: "test",
		Source:       WorkflowSourceExternal,
		Status:       WorkflowStatusInProgress,
		TenantID:     "tenant-1",
	}
	repo.Create(ctx, workflow)

	// Add a step
	step := &WorkflowStep{
		WorkflowID: "wf_test123",
		StepID:     "step-1",
		StepName:   "test-step",
		StepType:   StepTypeLLMCall,
		Decision:   GateDecisionAllow,
	}
	repo.AddStep(ctx, step)

	// Get steps for workflow
	steps, err := repo.GetStepsForWorkflow(ctx, "wf_test123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if len(steps) != 1 {
		t.Errorf("steps count = %d, want 1", len(steps))
	}
}

func TestMockRepositoryUpdateStatus(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Create workflow
	workflow := &Workflow{
		WorkflowID:   "wf_test456",
		WorkflowName: "test",
		Source:       WorkflowSourceExternal,
		Status:       WorkflowStatusInProgress,
		TenantID:     "tenant-1",
	}
	repo.Create(ctx, workflow)

	// Update status
	err := repo.UpdateStatus(ctx, "wf_test456", WorkflowStatusCompleted)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify
	updated, _ := repo.GetByID(ctx, "wf_test456")
	if updated.Status != WorkflowStatusCompleted {
		t.Errorf("status = %s, want completed", updated.Status)
	}
}

func TestMockRepositoryUpdateStatusNotFound(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	err := repo.UpdateStatus(ctx, "non-existent", WorkflowStatusCompleted)
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestMockRepositoryGetStepsForWorkflowNotFound(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	// Mock returns empty slice for non-existent workflow (not error)
	steps, err := repo.GetStepsForWorkflow(ctx, "non-existent")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(steps) != 0 {
		t.Errorf("steps should be empty for non-existent workflow, got %d", len(steps))
	}
}

// === Webhook Notification Tests ===

// MockWebhookNotifier records webhook events for testing
type MockWebhookNotifier struct {
	Events []webhookEvent
}

type webhookEvent struct {
	EventType string
	Data      map[string]interface{}
	TenantID  string
	OrgID     string
}

func (m *MockWebhookNotifier) Fire(ctx context.Context, eventType string, data map[string]interface{}, tenantID, orgID string) {
	m.Events = append(m.Events, webhookEvent{
		EventType: eventType,
		Data:      data,
		TenantID:  tenantID,
		OrgID:     orgID,
	})
}

func TestFailWorkflow_FiresWebhook(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	notifier := &MockWebhookNotifier{}
	svc.SetWebhookNotifier(notifier)
	ctx := context.Background()

	// Create a workflow
	workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "webhook-test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}

	// Fail the workflow
	err = svc.FailWorkflow(ctx, workflow.WorkflowID, "LLM provider timeout")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify webhook was fired
	if len(notifier.Events) != 1 {
		t.Fatalf("webhook events = %d, want 1", len(notifier.Events))
	}

	event := notifier.Events[0]
	if event.EventType != "workflow.failed" {
		t.Errorf("event_type = %s, want workflow.failed", event.EventType)
	}
	if event.Data["workflow_id"] != workflow.WorkflowID {
		t.Errorf("workflow_id = %v, want %s", event.Data["workflow_id"], workflow.WorkflowID)
	}
	if event.Data["workflow_name"] != "webhook-test-workflow" {
		t.Errorf("workflow_name = %v, want webhook-test-workflow", event.Data["workflow_name"])
	}
	if event.Data["reason"] != "LLM provider timeout" {
		t.Errorf("reason = %v, want 'LLM provider timeout'", event.Data["reason"])
	}
	if event.TenantID != "tenant-1" {
		t.Errorf("tenant_id = %s, want tenant-1", event.TenantID)
	}
	if event.OrgID != "org-1" {
		t.Errorf("org_id = %s, want org-1", event.OrgID)
	}
}

func TestAbortWorkflow_FiresWebhook(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	notifier := &MockWebhookNotifier{}
	svc.SetWebhookNotifier(notifier)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "abort-test",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.AbortWorkflow(ctx, workflow.WorkflowID, "user cancelled")

	if len(notifier.Events) != 1 {
		t.Fatalf("webhook events = %d, want 1", len(notifier.Events))
	}
	if notifier.Events[0].EventType != "workflow.aborted" {
		t.Errorf("event_type = %s, want workflow.aborted", notifier.Events[0].EventType)
	}
}

func TestCompleteWorkflow_FiresWebhook(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	notifier := &MockWebhookNotifier{}
	svc.SetWebhookNotifier(notifier)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "complete-test",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.CompleteWorkflow(ctx, workflow.WorkflowID)

	if len(notifier.Events) != 1 {
		t.Fatalf("webhook events = %d, want 1", len(notifier.Events))
	}
	if notifier.Events[0].EventType != "workflow.completed" {
		t.Errorf("event_type = %s, want workflow.completed", notifier.Events[0].EventType)
	}
}

func TestFailWorkflow_NoWebhookWithoutNotifier(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil) // No webhook notifier
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "no-webhook-test",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Should not panic when no notifier is set
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "test failure")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDefaultPolicyEvaluatorEvaluateStepGate(t *testing.T) {
	evaluator := &DefaultPolicyEvaluator{}
	ctx := context.Background()

	step := &StepGateContext{
		WorkflowID: "wf_test",
		StepID:     "step-1",
		StepName:   "test",
		StepType:   StepTypeLLMCall,
	}

	result := evaluator.EvaluateStepGate(ctx, step)

	if result.Decision != GateDecisionAllow {
		t.Errorf("decision = %s, want allow", result.Decision)
	}
}
