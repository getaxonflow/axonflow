// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		name       string
		req        *CreateWorkflowRequest
		tenantID   string
		wantErr    bool
		wantSource WorkflowSource
		wantStatus WorkflowStatus
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
		got, err := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
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
		_, err := svc.GetWorkflow(ctx, "non-existent", "tenant-1", "org-1")
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

	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")

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
	err := svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.Status != WorkflowStatusCompleted {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusCompleted)
	}

	// Try to complete again (should fail)
	err = svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
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
	err := svc.AbortWorkflow(ctx, workflow.WorkflowID, "test abort", "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
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
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "test failure", "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify status
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.Status != WorkflowStatusFailed {
		t.Errorf("status = %s, want %s", updated.Status, WorkflowStatusFailed)
	}
}

// TestCompleteWorkflow_FinalizesTotalSteps verifies that completing an open-ended workflow
// (one where total_steps was not declared upfront) sets total_steps to the actual step count.
func TestCompleteWorkflow_FinalizesTotalSteps(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create workflow without declaring total_steps
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "open-ended-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	if workflow.TotalSteps != nil {
		t.Fatalf("TotalSteps should be nil for open-ended workflow, got %d", *workflow.TotalSteps)
	}

	// Add 3 steps via gate checks
	for i, name := range []string{"agent", "tools", "agent"} {
		stepID := fmt.Sprintf("step-%d", i+1)
		svc.StepGate(ctx, workflow.WorkflowID, stepID, &StepGateRequest{
			StepName: name,
			StepType: StepTypeLLMCall,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	// Complete the workflow
	if err := svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1"); err != nil {
		t.Fatalf("CompleteWorkflow() error = %v", err)
	}

	// TotalSteps should now equal the number of steps that ran
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.TotalSteps == nil {
		t.Fatal("TotalSteps should be set after completion")
	}
	if *updated.TotalSteps != updated.CurrentStepIndex {
		t.Errorf("TotalSteps = %d, want %d (CurrentStepIndex)", *updated.TotalSteps, updated.CurrentStepIndex)
	}
}

// TestCompleteWorkflow_PreservesDeclaredTotalSteps verifies that a workflow with a declared
// total_steps is not overwritten on completion (COALESCE leaves it unchanged).
func TestCompleteWorkflow_PreservesDeclaredTotalSteps(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	declared := 5
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "declared-steps-workflow",
		TotalSteps:   &declared,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Add only 2 of the 5 declared steps
	for i, name := range []string{"step-a", "step-b"} {
		svc.StepGate(ctx, workflow.WorkflowID, fmt.Sprintf("step-%d", i+1), &StepGateRequest{
			StepName: name,
			StepType: StepTypeLLMCall,
		}, "tenant-1", "org-1", "user-1", "client-1")
	}

	if err := svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1"); err != nil {
		t.Fatalf("CompleteWorkflow() error = %v", err)
	}

	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.TotalSteps == nil || *updated.TotalSteps != declared {
		t.Errorf("TotalSteps = %v, want %d (declared value must not be overwritten)", updated.TotalSteps, declared)
	}
}

// TestAbortWorkflow_FinalizesTotalSteps verifies the same finalization for aborted workflows.
func TestAbortWorkflow_FinalizesTotalSteps(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "open-ended-aborted",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "agent",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	if err := svc.AbortWorkflow(ctx, workflow.WorkflowID, "user cancelled", "tenant-1", "org-1"); err != nil {
		t.Fatalf("AbortWorkflow() error = %v", err)
	}

	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.TotalSteps == nil {
		t.Fatal("TotalSteps should be set after abort")
	}
	if *updated.TotalSteps != updated.CurrentStepIndex {
		t.Errorf("TotalSteps = %d, want %d", *updated.TotalSteps, updated.CurrentStepIndex)
	}
}

// TestFailWorkflow_FinalizesTotalSteps verifies the same finalization for failed workflows.
func TestFailWorkflow_FinalizesTotalSteps(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "open-ended-failed",
	}, "tenant-1", "org-1", "user-1", "client-1")

	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "agent",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	svc.StepGate(ctx, workflow.WorkflowID, "step-2", &StepGateRequest{
		StepName: "tools",
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	if err := svc.FailWorkflow(ctx, workflow.WorkflowID, "llm error", "tenant-1", "org-1"); err != nil {
		t.Fatalf("FailWorkflow() error = %v", err)
	}

	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if updated.TotalSteps == nil {
		t.Fatal("TotalSteps should be set after failure")
	}
	if *updated.TotalSteps != updated.CurrentStepIndex {
		t.Errorf("TotalSteps = %d, want %d", *updated.TotalSteps, updated.CurrentStepIndex)
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

	// #3065: "list all" is no longer a thing. The listing scope is mandatory,
	// so the widest a caller can see is its own tenancy — the 8 rows below
	// span two tenants and no single caller may see both.
	t.Run("unscoped listing is denied", func(t *testing.T) {
		if _, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{Limit: 100}); err == nil {
			t.Error("an unscoped list must be refused, not silently widened to every tenant")
		}
	})

	t.Run("a tenant never sees another tenant's rows", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Limit: 100})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Assert on IDENTIFIERS, not just the count: every returned workflow
		// id must be one tenant-1 owns.
		for _, wf := range response.Workflows {
			owned, err := svc.GetWorkflow(ctx, wf.WorkflowID, "tenant-1", "org-1")
			if err != nil || owned == nil {
				t.Errorf("listing returned %s, which tenant-1 cannot fetch — a cross-tenant row leaked into the list", wf.WorkflowID)
			}
		}
		if response.Total != 5 {
			t.Errorf("total = %d, want 5 (tenant-1's own rows only)", response.Total)
		}
	})

	t.Run("list by tenant", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Limit: 100})
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
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Source: &source, Limit: 100})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if response.Total != 5 {
			t.Errorf("total = %d, want 5", response.Total)
		}
	})

	t.Run("list with pagination", func(t *testing.T) {
		response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Limit: 3, Offset: 0})
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
	err := svc.ResumeWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Complete and try to resume (should fail)
	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	err = svc.ResumeWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
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

	// Mark step completed (nil request — backward compatible)
	err := svc.MarkStepCompleted(ctx, workflow.WorkflowID, "step-1", nil, "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Try to mark non-existent step completed
	err = svc.MarkStepCompleted(ctx, workflow.WorkflowID, "non-existent", nil, "tenant-1", "org-1")
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

// MockApprovalPolicyEvaluatorWithApprovalID simulates the HITL-integrated adapter
// that populates ApprovalID alongside the require_approval decision.
type MockApprovalPolicyEvaluatorWithApprovalID struct {
	ApprovalID string
}

func (m *MockApprovalPolicyEvaluatorWithApprovalID) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:   GateDecisionRequireApproval,
		Reason:     "Human approval required",
		PolicyIDs:  []string{"policy-approval-1"},
		ApprovalID: m.ApprovalID,
	}
}

func TestStepGate_RequireApproval_SurfacesApprovalID(t *testing.T) {
	// Regression: StepGateResponse previously dropped the ApprovalID populated
	// by the HITL adapter, so SDK clients saw approval_id: null even though the
	// HITL queue entry existed. Caught in banking-demo VC demo verification
	// 2026-04-21.
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluatorWithApprovalID{
		ApprovalID: "approval-uuid-1234",
	}, &ServiceConfig{BaseURL: "https://portal.getaxonflow.com"})
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "payment-processing",
	}, "tenant-1", "org-1", "user-1", "client-1")

	response, err := svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "Initiate Wire",
		StepType: StepTypeToolCall,
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Decision != GateDecisionRequireApproval {
		t.Fatalf("decision = %s, want require_approval", response.Decision)
	}
	if response.ApprovalID != "approval-uuid-1234" {
		t.Errorf("approval_id = %q, want approval-uuid-1234", response.ApprovalID)
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
	err := svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "tenant-1", "org-1", "approver@example.com", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Try to approve again (should fail)
	err = svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "tenant-1", "org-1", "approver@example.com", "")
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
	err := svc.RejectStep(ctx, workflow.WorkflowID, "step-1", "tenant-1", "org-1", "rejecter@example.com", "")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify workflow was aborted
	updated, _ := svc.GetWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
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

	err := svc.ApproveStep(ctx, workflow.WorkflowID, "non-existent", "tenant-1", "org-1", "approver@test.com", "")
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

	err := svc.RejectStep(ctx, workflow.WorkflowID, "non-existent", "tenant-1", "org-1", "rejector@test.com", "")
	if err == nil {
		t.Error("expected error for non-existent step")
	}
}

func TestAbortWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.AbortWorkflow(ctx, "non-existent", "test reason", "tenant-1", "org-1")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestCompleteWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.CompleteWorkflow(ctx, "non-existent", "tenant-1", "org-1")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestFailWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.FailWorkflow(ctx, "non-existent", "test reason", "tenant-1", "org-1")
	if err == nil {
		t.Error("expected error for non-existent workflow")
	}
}

func TestResumeWorkflowNonExistent(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	err := svc.ResumeWorkflow(ctx, "non-existent", "tenant-1", "org-1")
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
	response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Limit: 0})
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
	svc.CompleteWorkflow(ctx, workflow1.WorkflowID, "tenant-1", "org-1")

	svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow-2",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// List only completed workflows
	status := WorkflowStatusCompleted
	response, _ := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Status: &status, Limit: 100})

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
	err := svc.ApproveStep(ctx, workflow.WorkflowID, "step-1", "tenant-1", "org-1", "approver@test.com", "")
	if err != nil {
		t.Errorf("approve step error: %v", err)
	}

	// Now resume should work
	err = svc.ResumeWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if err != nil {
		t.Errorf("resume after approval should succeed: %v", err)
	}
}

// TestResumeWorkflowAfterExpiry covers the #2654 branch: a workflow whose last
// require_approval step auto-expired (timed out) must NOT resume, and the error
// must say "expired" — distinct from the "was rejected" human-reject path.
func TestResumeWorkflowAfterExpiry(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	ctx := context.Background()

	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "test-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Create step requiring approval.
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "test",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Simulate the auto-timeout path setting the step to 'expired'.
	if err := repo.UpdateStepApproval(ctx, workflow.WorkflowID, "step-1", ApprovalStatusExpired, "system:auto-expired", "approval timed out"); err != nil {
		t.Fatalf("set step expired: %v", err)
	}

	err := svc.ResumeWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")
	if err == nil {
		t.Fatal("resume after expiry should fail")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("resume error = %q, want it to mention 'expired'", err.Error())
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
	err := svc.AbortWorkflow(ctx, workflow.WorkflowID, "first abort", "tenant-1", "org-1")
	if err != nil {
		t.Errorf("first abort unexpected error: %v", err)
	}

	// Abort again should fail
	err = svc.AbortWorkflow(ctx, workflow.WorkflowID, "second abort", "tenant-1", "org-1")
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
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "first failure", "tenant-1", "org-1")
	if err != nil {
		t.Errorf("first fail unexpected error: %v", err)
	}

	// Fail again should fail
	err = svc.FailWorkflow(ctx, workflow.WorkflowID, "second failure", "tenant-1", "org-1")
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
	response, err := svc.ListWorkflows(ctx, ListWorkflowsOptions{TenantID: "tenant-1", OrgID: "org-1", Limit: 100})
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
	err := svc.RejectStep(ctx, workflow.WorkflowID, "step-1", "tenant-1", "org-1", "user@test.com", "")
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
	svc.ApproveStep(ctx, workflow2.WorkflowID, "step-1", "tenant-1", "org-1", "approver@test.com", "")

	// Try to reject after approval
	err = svc.RejectStep(ctx, workflow2.WorkflowID, "step-1", "tenant-1", "org-1", "user@test.com", "")
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
	err = svc.FailWorkflow(ctx, workflow.WorkflowID, "LLM provider timeout", "tenant-1", "org-1")
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

	svc.AbortWorkflow(ctx, workflow.WorkflowID, "user cancelled", "tenant-1", "org-1")

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

	svc.CompleteWorkflow(ctx, workflow.WorkflowID, "tenant-1", "org-1")

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
	err := svc.FailWorkflow(ctx, workflow.WorkflowID, "test failure", "tenant-1", "org-1")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// === Bug A: Sentinel Error Wrapping Tests ===

func TestMockRepository_SentinelErrors(t *testing.T) {
	repo := NewMockRepository()
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"UpdateStatus", func() error {
			return repo.UpdateStatus(ctx, "non-existent", WorkflowStatusCompleted)
		}},
		{"Complete", func() error {
			return repo.Complete(ctx, "non-existent")
		}},
		{"Abort", func() error {
			return repo.Abort(ctx, "non-existent", "reason")
		}},
		{"Fail", func() error {
			return repo.Fail(ctx, "non-existent", "reason")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrWorkflowNotFound) {
				t.Errorf("errors.Is(err, ErrWorkflowNotFound) = false, want true; err = %v", err)
			}
		})
	}
}

func TestMarkStepCompletedWithMetrics(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow and add a step
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "metrics-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Gate check (creates the step)
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName: "generate-code",
		StepType: StepTypeLLMCall,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Mark step completed with post-execution metrics
	tokensIn := 150
	tokensOut := 45
	costUSD := 0.0023
	req := &StepCompleteRequest{
		Output:    map[string]interface{}{"code": "def sort(items): return sorted(items)"},
		TokensIn:  &tokensIn,
		TokensOut: &tokensOut,
		CostUSD:   &costUSD,
	}

	err := svc.MarkStepCompleted(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify metrics were applied
	step, err := repo.GetStep(ctx, workflow.WorkflowID, "step-1")
	if err != nil {
		t.Fatalf("failed to get step: %v", err)
	}
	if step.TokensIn == nil || *step.TokensIn != 150 {
		t.Errorf("tokens_in = %v, want 150", step.TokensIn)
	}
	if step.TokensOut == nil || *step.TokensOut != 45 {
		t.Errorf("tokens_out = %v, want 45", step.TokensOut)
	}
	if step.CostUSD == nil || *step.CostUSD != 0.0023 {
		t.Errorf("cost_usd = %v, want 0.0023", step.CostUSD)
	}
	if step.StepCompletedAt == nil {
		t.Error("step_completed_at should not be nil")
	}
	// Verify output was stored
	if step.StepOutput == nil {
		t.Fatal("step_output should not be nil")
	}
	if string(step.StepOutput) != `{"code":"def sort(items): return sorted(items)"}` {
		t.Errorf("step_output = %s, want JSON with code field", string(step.StepOutput))
	}
}

func TestMarkStepCompletedOverridesGateMetrics(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, nil, nil)
	ctx := context.Background()

	// Create a workflow
	workflow, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "override-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Gate check with estimated tokens
	gateTokensIn := 100
	gateTokensOut := 30
	svc.StepGate(ctx, workflow.WorkflowID, "step-1", &StepGateRequest{
		StepName:  "generate",
		StepType:  StepTypeLLMCall,
		TokensIn:  &gateTokensIn,
		TokensOut: &gateTokensOut,
	}, "tenant-1", "org-1", "user-1", "client-1")

	// Mark step completed with actual (different) metrics
	actualTokensIn := 200
	actualTokensOut := 60
	actualCost := 0.005
	err := svc.MarkStepCompleted(ctx, workflow.WorkflowID, "step-1", &StepCompleteRequest{
		TokensIn:  &actualTokensIn,
		TokensOut: &actualTokensOut,
		CostUSD:   &actualCost,
	}, "tenant-1", "org-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify completion-time values override gate-time values
	step, _ := repo.GetStep(ctx, workflow.WorkflowID, "step-1")
	if step.TokensIn == nil || *step.TokensIn != 200 {
		t.Errorf("tokens_in = %v, want 200 (should override gate value of 100)", step.TokensIn)
	}
	if step.TokensOut == nil || *step.TokensOut != 60 {
		t.Errorf("tokens_out = %v, want 60 (should override gate value of 30)", step.TokensOut)
	}
	if step.CostUSD == nil || *step.CostUSD != 0.005 {
		t.Errorf("cost_usd = %v, want 0.005", step.CostUSD)
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

// --- P2: Service-level test for ToolContext propagation (#1282) ---

// MockCapturingPolicyEvaluator captures the StepGateContext passed to EvaluateStepGate
type MockCapturingPolicyEvaluator struct {
	capturedContext *StepGateContext
}

func (m *MockCapturingPolicyEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	m.capturedContext = step
	return &StepGateEvaluation{
		Decision:          GateDecisionAllow,
		Reason:            "Allowed for test",
		PolicyIDs:         []string{},
		PoliciesEvaluated: []PolicyMatch{},
		PoliciesMatched:   []PolicyMatch{},
	}
}

func TestStepGateToolContextPropagation(t *testing.T) {
	evaluator := &MockCapturingPolicyEvaluator{}
	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	ctx := context.Background()

	workflow, err := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{
		WorkflowName: "tool-context-workflow",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("failed to create workflow: %v", err)
	}

	req := &StepGateRequest{
		StepName: "tool-step",
		StepType: StepTypeToolCall,
		ToolContext: &ToolContext{
			ToolName: "search_database",
			ToolType: "function",
			ToolInput: map[string]interface{}{
				"query": "SELECT * FROM users",
			},
		},
	}

	_, err = svc.StepGate(ctx, workflow.WorkflowID, "step-1", req, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify ToolContext was propagated to the policy evaluator
	if evaluator.capturedContext == nil {
		t.Fatal("policy evaluator was not called")
	}

	if evaluator.capturedContext.ToolContext == nil {
		t.Fatal("ToolContext was not propagated to StepGateContext")
	}

	if evaluator.capturedContext.ToolContext.ToolName != "search_database" {
		t.Errorf("tool_name = %q, want %q", evaluator.capturedContext.ToolContext.ToolName, "search_database")
	}

	if evaluator.capturedContext.ToolContext.ToolType != "function" {
		t.Errorf("tool_type = %q, want %q", evaluator.capturedContext.ToolContext.ToolType, "function")
	}

	if evaluator.capturedContext.ToolContext.ToolInput["query"] != "SELECT * FROM users" {
		t.Errorf("tool_input[query] = %v, want 'SELECT * FROM users'", evaluator.capturedContext.ToolContext.ToolInput["query"])
	}
}
