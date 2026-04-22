// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// Integration tests for PostgresRepository
// Uses testcontainers if DATABASE_URL is not set

func getTestDB(t *testing.T) *sql.DB {
	t.Helper()

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("Failed to open database: %v", err)
		}
		if err := db.Ping(); err != nil {
			t.Fatalf("Failed to ping database: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}

	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, workflowControlSchema())
	return pg.DB
}

// workflowControlSchema returns the schema needed for workflow control tests.
func workflowControlSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS workflows (
			workflow_id VARCHAR(255) PRIMARY KEY,
			workflow_name VARCHAR(255) NOT NULL,
			source VARCHAR(100) NOT NULL DEFAULT 'external',
			status VARCHAR(50) NOT NULL DEFAULT 'in_progress',
			current_step_index INTEGER DEFAULT 0,
			total_steps INTEGER,
			org_id VARCHAR(255),
			tenant_id VARCHAR(255),
			user_id VARCHAR(255),
			client_id VARCHAR(255),
			trace_id VARCHAR(255),
			metadata JSONB DEFAULT '{}',
			started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS workflow_steps (
			id SERIAL PRIMARY KEY,
			workflow_id VARCHAR(255) NOT NULL REFERENCES workflows(workflow_id) ON DELETE CASCADE,
			step_id VARCHAR(255) NOT NULL,
			step_index INTEGER NOT NULL,
			step_name VARCHAR(255),
			step_type VARCHAR(100),
			decision VARCHAR(50) NOT NULL,
			decision_reason TEXT,
			policies_evaluated JSONB DEFAULT '[]',
			policies_matched JSONB DEFAULT '[]',
			approval_status VARCHAR(50),
			approved_by VARCHAR(255),
			approved_at TIMESTAMP WITH TIME ZONE,
			step_input JSONB,
			model VARCHAR(100),
			provider VARCHAR(100),
			tokens_in INTEGER,
			tokens_out INTEGER,
			cost_usd DOUBLE PRECISION,
			step_output JSONB,
			approval_comment TEXT,
			gate_checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			step_completed_at TIMESTAMP WITH TIME ZONE,
			-- Issue #1673 Phase 1 (migration 071)
			gate_count INTEGER NOT NULL DEFAULT 0,
			completion_count INTEGER NOT NULL DEFAULT 0,
			last_decision VARCHAR(50),
			first_attempt_at TIMESTAMP WITH TIME ZONE,
			-- Issue #1673 Phase 2 (migration 072)
			idempotency_key VARCHAR(255),
			UNIQUE(workflow_id, step_id)
		);

		CREATE INDEX IF NOT EXISTS idx_workflow_steps_idempotency_key
			ON workflow_steps(idempotency_key)
			WHERE idempotency_key IS NOT NULL;
	`
}

func cleanupTestWorkflows(t *testing.T, db *sql.DB, tenantID string) {
	// Clean up workflow steps first (foreign key)
	_, err := db.Exec("DELETE FROM workflow_steps WHERE workflow_id IN (SELECT workflow_id FROM workflows WHERE tenant_id = $1)", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup workflow_steps: %v", err)
	}
	// Then clean up workflows
	_, err = db.Exec("DELETE FROM workflows WHERE tenant_id = $1", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup workflows: %v", err)
	}
}

func intPtr(i int) *int {
	return &i
}

// === Create Tests ===

func TestPostgresRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-create-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	t.Run("create workflow successfully", func(t *testing.T) {
		metadata, _ := json.Marshal(map[string]interface{}{"test": "value"})
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_%d", time.Now().UnixNano()),
			WorkflowName: "Integration Test Workflow",
			Source:       WorkflowSourceLangGraph,
			Status:       WorkflowStatusInProgress,
			TotalSteps:   intPtr(5),
			TenantID:     tenantID,
			OrgID:        "org-123",
			UserID:       "user-456",
			ClientID:     "client-789",
			Metadata:     metadata,
		}

		err := repo.Create(ctx, workflow)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		// Verify by reading back
		retrieved, err := repo.GetByID(ctx, workflow.WorkflowID)
		if err != nil {
			t.Fatalf("GetByID() error = %v", err)
		}

		if retrieved.WorkflowName != workflow.WorkflowName {
			t.Errorf("WorkflowName = %s, want %s", retrieved.WorkflowName, workflow.WorkflowName)
		}
		if retrieved.Source != workflow.Source {
			t.Errorf("Source = %s, want %s", retrieved.Source, workflow.Source)
		}
		if retrieved.TotalSteps == nil || *retrieved.TotalSteps != 5 {
			t.Errorf("TotalSteps = %v, want 5", retrieved.TotalSteps)
		}
	})

	t.Run("create with all sources", func(t *testing.T) {
		sources := []WorkflowSource{
			WorkflowSourceLangGraph,
			WorkflowSourceLangChain,
			WorkflowSourceCrewAI,
			WorkflowSourceExternal,
		}

		for _, source := range sources {
			workflow := &Workflow{
				WorkflowID:   fmt.Sprintf("wf_%s_%d", source, time.Now().UnixNano()),
				WorkflowName: fmt.Sprintf("Test %s Workflow", source),
				Source:       source,
				Status:       WorkflowStatusInProgress,
				TenantID:     tenantID,
			}

			err := repo.Create(ctx, workflow)
			if err != nil {
				t.Errorf("Create() for source %s error = %v", source, err)
			}
		}
	})
}

// === GetByID Tests ===

func TestPostgresRepository_Integration_GetByID(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-getbyid-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create test workflow
	workflow := &Workflow{
		WorkflowID:   fmt.Sprintf("wf_%d", time.Now().UnixNano()),
		WorkflowName: "Get By ID Test",
		Source:       WorkflowSourceExternal,
		Status:       WorkflowStatusInProgress,
		TenantID:     tenantID,
	}
	repo.Create(ctx, workflow)

	t.Run("get existing workflow", func(t *testing.T) {
		retrieved, err := repo.GetByID(ctx, workflow.WorkflowID)
		if err != nil {
			t.Fatalf("GetByID() error = %v", err)
		}
		if retrieved.WorkflowID != workflow.WorkflowID {
			t.Errorf("WorkflowID = %s, want %s", retrieved.WorkflowID, workflow.WorkflowID)
		}
	})

	t.Run("get non-existent workflow", func(t *testing.T) {
		_, err := repo.GetByID(ctx, "non-existent-workflow")
		if err == nil {
			t.Error("Expected error for non-existent workflow")
		}
	})
}

// === List Tests ===

func TestPostgresRepository_Integration_List(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-list-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create test workflows with different statuses and sources
	for i := 0; i < 5; i++ {
		status := WorkflowStatusInProgress
		if i >= 3 {
			status = WorkflowStatusCompleted
		}
		source := WorkflowSourceLangGraph
		if i%2 == 0 {
			source = WorkflowSourceCrewAI
		}

		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_list_%d_%d", time.Now().UnixNano(), i),
			WorkflowName: fmt.Sprintf("List Test %d", i),
			Source:       source,
			Status:       status,
			TenantID:     tenantID,
			OrgID:        "org-123",
		}
		repo.Create(ctx, workflow)
	}

	t.Run("list all for tenant", func(t *testing.T) {
		opts := ListWorkflowsOptions{
			TenantID: tenantID,
			Limit:    50,
		}
		workflows, total, err := repo.List(ctx, opts)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if total != 5 {
			t.Errorf("Total = %d, want 5", total)
		}
		if len(workflows) != 5 {
			t.Errorf("Workflows count = %d, want 5", len(workflows))
		}
	})

	t.Run("list with status filter", func(t *testing.T) {
		status := WorkflowStatusInProgress
		opts := ListWorkflowsOptions{
			TenantID: tenantID,
			Status:   &status,
			Limit:    50,
		}
		workflows, total, err := repo.List(ctx, opts)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Total in_progress = %d, want 3", total)
		}
		if len(workflows) != 3 {
			t.Errorf("Workflows count = %d, want 3", len(workflows))
		}
	})

	t.Run("list with source filter", func(t *testing.T) {
		source := WorkflowSourceCrewAI
		opts := ListWorkflowsOptions{
			TenantID: tenantID,
			Source:   &source,
			Limit:    50,
		}
		workflows, total, err := repo.List(ctx, opts)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Total crewai = %d, want 3", total)
		}
		if len(workflows) != 3 {
			t.Errorf("Workflows count = %d, want 3", len(workflows))
		}
	})

	t.Run("list with pagination", func(t *testing.T) {
		opts := ListWorkflowsOptions{
			TenantID: tenantID,
			Limit:    2,
			Offset:   0,
		}
		workflows, total, err := repo.List(ctx, opts)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if total != 5 {
			t.Errorf("Total = %d, want 5", total)
		}
		if len(workflows) != 2 {
			t.Errorf("Workflows count = %d, want 2 (limited)", len(workflows))
		}
	})
}

// === Status Update Tests ===

func TestPostgresRepository_Integration_StatusUpdates(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-status-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	t.Run("complete workflow", func(t *testing.T) {
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_complete_%d", time.Now().UnixNano()),
			WorkflowName: "Complete Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
		}
		repo.Create(ctx, workflow)

		err := repo.Complete(ctx, workflow.WorkflowID)
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.Status != WorkflowStatusCompleted {
			t.Errorf("Status = %s, want completed", retrieved.Status)
		}
		if retrieved.CompletedAt == nil {
			t.Error("CompletedAt should be set")
		}
	})

	t.Run("abort workflow", func(t *testing.T) {
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_abort_%d", time.Now().UnixNano()),
			WorkflowName: "Abort Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
		}
		repo.Create(ctx, workflow)

		err := repo.Abort(ctx, workflow.WorkflowID, "Test abort reason")
		if err != nil {
			t.Fatalf("Abort() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.Status != WorkflowStatusAborted {
			t.Errorf("Status = %s, want aborted", retrieved.Status)
		}
	})

	t.Run("fail workflow", func(t *testing.T) {
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_fail_%d", time.Now().UnixNano()),
			WorkflowName: "Fail Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
		}
		repo.Create(ctx, workflow)

		err := repo.Fail(ctx, workflow.WorkflowID, "Test failure reason")
		if err != nil {
			t.Fatalf("Fail() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.Status != WorkflowStatusFailed {
			t.Errorf("Status = %s, want failed", retrieved.Status)
		}
	})

	t.Run("complete finalises total_steps when not declared", func(t *testing.T) {
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_finalise_%d", time.Now().UnixNano()),
			WorkflowName: "Finalise TotalSteps Test",
			Source:       WorkflowSourceLangGraph,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
			// TotalSteps intentionally omitted
		}
		repo.Create(ctx, workflow)

		// Add two steps so current_step_index advances
		for i := 0; i < 2; i++ {
			repo.AddStep(ctx, &WorkflowStep{
				WorkflowID: workflow.WorkflowID,
				StepID:     fmt.Sprintf("step-%d", i+1),
				StepIndex:  i + 1,
				StepName:   "agent",
				StepType:   StepTypeLLMCall,
				Decision:   GateDecisionAllow,
			})
		}

		if err := repo.Complete(ctx, workflow.WorkflowID); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.TotalSteps == nil {
			t.Fatal("TotalSteps should be set after completion of open-ended workflow")
		}
		if *retrieved.TotalSteps != retrieved.CurrentStepIndex {
			t.Errorf("TotalSteps = %d, want %d (CurrentStepIndex)", *retrieved.TotalSteps, retrieved.CurrentStepIndex)
		}
	})

	t.Run("complete preserves declared total_steps", func(t *testing.T) {
		declared := 10
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_preserve_%d", time.Now().UnixNano()),
			WorkflowName: "Preserve TotalSteps Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
			TotalSteps:   &declared,
		}
		repo.Create(ctx, workflow)

		if err := repo.Complete(ctx, workflow.WorkflowID); err != nil {
			t.Fatalf("Complete() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.TotalSteps == nil || *retrieved.TotalSteps != declared {
			t.Errorf("TotalSteps = %v, want %d (declared value must not change)", retrieved.TotalSteps, declared)
		}
	})

	t.Run("update status directly", func(t *testing.T) {
		workflow := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_updatestatus_%d", time.Now().UnixNano()),
			WorkflowName: "Update Status Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
		}
		repo.Create(ctx, workflow)

		err := repo.UpdateStatus(ctx, workflow.WorkflowID, WorkflowStatusCompleted)
		if err != nil {
			t.Fatalf("UpdateStatus() error = %v", err)
		}

		retrieved, _ := repo.GetByID(ctx, workflow.WorkflowID)
		if retrieved.Status != WorkflowStatusCompleted {
			t.Errorf("Status = %s, want completed", retrieved.Status)
		}
	})
}

// === Step Tests ===

func TestPostgresRepository_Integration_Steps(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-steps-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create workflow for step tests
	workflow := &Workflow{
		WorkflowID:   fmt.Sprintf("wf_steps_%d", time.Now().UnixNano()),
		WorkflowName: "Steps Test",
		Source:       WorkflowSourceLangGraph,
		Status:       WorkflowStatusInProgress,
		TotalSteps:   intPtr(3),
		TenantID:     tenantID,
	}
	repo.Create(ctx, workflow)

	t.Run("add step with allow decision", func(t *testing.T) {
		policiesEvaluated, _ := json.Marshal([]PolicyMatch{})
		policiesMatched, _ := json.Marshal([]PolicyMatch{})
		stepInput, _ := json.Marshal(map[string]interface{}{"prompt": "test"})

		step := &WorkflowStep{
			WorkflowID:        workflow.WorkflowID,
			StepID:            "step-1",
			StepIndex:         0,
			StepName:          "Analyze Data",
			StepType:          StepTypeLLMCall,
			Decision:          GateDecisionAllow,
			DecisionReason:    "No policies configured",
			PoliciesEvaluated: policiesEvaluated,
			PoliciesMatched:   policiesMatched,
			Model:             "gpt-4",
			Provider:          "openai",
			StepInput:         stepInput,
		}

		err := repo.AddStep(ctx, step)
		if err != nil {
			t.Fatalf("AddStep() error = %v", err)
		}

		// Verify step was added
		retrieved, err := repo.GetStep(ctx, workflow.WorkflowID, "step-1")
		if err != nil {
			t.Fatalf("GetStep() error = %v", err)
		}
		if retrieved.Decision != GateDecisionAllow {
			t.Errorf("Decision = %s, want allow", retrieved.Decision)
		}
		if retrieved.Model != "gpt-4" {
			t.Errorf("Model = %s, want gpt-4", retrieved.Model)
		}
	})

	t.Run("add step with block decision and policy matches", func(t *testing.T) {
		policiesEvaluated, _ := json.Marshal([]PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "PII Detection", Action: "block", Reason: "Credit card detected"},
		})
		policiesMatched, _ := json.Marshal([]PolicyMatch{
			{PolicyID: "pol-1", PolicyName: "PII Detection", Action: "block", Reason: "Credit card detected"},
		})

		step := &WorkflowStep{
			WorkflowID:        workflow.WorkflowID,
			StepID:            "step-2",
			StepIndex:         1,
			StepName:          "Process Payment",
			StepType:          StepTypeToolCall,
			Decision:          GateDecisionBlock,
			DecisionReason:    "PII detected in input",
			PoliciesEvaluated: policiesEvaluated,
			PoliciesMatched:   policiesMatched,
		}

		err := repo.AddStep(ctx, step)
		if err != nil {
			t.Fatalf("AddStep() error = %v", err)
		}

		retrieved, _ := repo.GetStep(ctx, workflow.WorkflowID, "step-2")
		if retrieved.Decision != GateDecisionBlock {
			t.Errorf("Decision = %s, want block", retrieved.Decision)
		}

		// Verify policies were stored
		var policies []PolicyMatch
		json.Unmarshal(retrieved.PoliciesMatched, &policies)
		if len(policies) != 1 {
			t.Errorf("PoliciesMatched count = %d, want 1", len(policies))
		}
	})

	t.Run("add step with require_approval", func(t *testing.T) {
		pending := ApprovalStatusPending
		step := &WorkflowStep{
			WorkflowID:     workflow.WorkflowID,
			StepID:         "step-3",
			StepIndex:      2,
			StepName:       "Deploy to Production",
			StepType:       StepTypeConnectorCall,
			Decision:       GateDecisionRequireApproval,
			DecisionReason: "Production deployment requires approval",
			ApprovalStatus: &pending,
		}

		err := repo.AddStep(ctx, step)
		if err != nil {
			t.Fatalf("AddStep() error = %v", err)
		}

		retrieved, _ := repo.GetStep(ctx, workflow.WorkflowID, "step-3")
		if retrieved.Decision != GateDecisionRequireApproval {
			t.Errorf("Decision = %s, want require_approval", retrieved.Decision)
		}
		if retrieved.ApprovalStatus == nil || *retrieved.ApprovalStatus != ApprovalStatusPending {
			t.Error("ApprovalStatus should be pending")
		}
	})

	t.Run("get steps for workflow", func(t *testing.T) {
		steps, err := repo.GetStepsForWorkflow(ctx, workflow.WorkflowID)
		if err != nil {
			t.Fatalf("GetStepsForWorkflow() error = %v", err)
		}
		if len(steps) != 3 {
			t.Errorf("Steps count = %d, want 3", len(steps))
		}
	})

	t.Run("mark step completed", func(t *testing.T) {
		err := repo.MarkStepCompleted(ctx, workflow.WorkflowID, "step-1", nil)
		if err != nil {
			t.Fatalf("MarkStepCompleted() error = %v", err)
		}

		retrieved, _ := repo.GetStep(ctx, workflow.WorkflowID, "step-1")
		if retrieved.StepCompletedAt == nil {
			t.Error("StepCompletedAt should be set")
		}
	})
}

// === Approval Tests ===

func TestPostgresRepository_Integration_Approvals(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-approvals-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create workflow with approval step
	workflow := &Workflow{
		WorkflowID:   fmt.Sprintf("wf_approvals_%d", time.Now().UnixNano()),
		WorkflowName: "Approvals Test",
		Source:       WorkflowSourceExternal,
		Status:       WorkflowStatusInProgress,
		TenantID:     tenantID,
	}
	repo.Create(ctx, workflow)

	pending := ApprovalStatusPending
	step := &WorkflowStep{
		WorkflowID:     workflow.WorkflowID,
		StepID:         "approval-step",
		StepIndex:      0,
		StepName:       "Needs Approval",
		StepType:       StepTypeLLMCall,
		Decision:       GateDecisionRequireApproval,
		ApprovalStatus: &pending,
	}
	repo.AddStep(ctx, step)

	t.Run("approve step", func(t *testing.T) {
		err := repo.UpdateStepApproval(ctx, workflow.WorkflowID, "approval-step", ApprovalStatusApproved, "approver@test.com", "")
		if err != nil {
			t.Fatalf("UpdateStepApproval() error = %v", err)
		}

		retrieved, _ := repo.GetStep(ctx, workflow.WorkflowID, "approval-step")
		if retrieved.ApprovalStatus == nil || *retrieved.ApprovalStatus != ApprovalStatusApproved {
			t.Error("ApprovalStatus should be approved")
		}
		if retrieved.ApprovedBy != "approver@test.com" {
			t.Errorf("ApprovedBy = %s, want approver@test.com", retrieved.ApprovedBy)
		}
		if retrieved.ApprovedAt == nil {
			t.Error("ApprovedAt should be set")
		}
	})

	t.Run("get pending approvals", func(t *testing.T) {
		// Create another workflow with pending approval
		workflow2 := &Workflow{
			WorkflowID:   fmt.Sprintf("wf_pending_%d", time.Now().UnixNano()),
			WorkflowName: "Pending Approvals Test",
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenantID,
		}
		repo.Create(ctx, workflow2)

		pendingStep := &WorkflowStep{
			WorkflowID:     workflow2.WorkflowID,
			StepID:         "pending-step",
			StepIndex:      0,
			StepName:       "Pending",
			StepType:       StepTypeLLMCall,
			Decision:       GateDecisionRequireApproval,
			ApprovalStatus: &pending,
		}
		repo.AddStep(ctx, pendingStep)

		approvals, err := repo.GetPendingApprovals(ctx, tenantID, 10)
		if err != nil {
			t.Fatalf("GetPendingApprovals() error = %v", err)
		}
		if len(approvals) < 1 {
			t.Errorf("Expected at least 1 pending approval, got %d", len(approvals))
		}

		// Verify workflow_name is populated
		found := false
		for _, a := range approvals {
			if a.WorkflowName == "Pending Approvals Test" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected pending approval with workflow_name='Pending Approvals Test'")
		}

		// Verify CountPendingApprovals
		count, countErr := repo.CountPendingApprovals(ctx, tenantID)
		if countErr != nil {
			t.Fatalf("CountPendingApprovals() error = %v", countErr)
		}
		if count < 1 {
			t.Errorf("CountPendingApprovals = %d, want >= 1", count)
		}
	})
}

// === Workflow with Steps Tests ===

func TestPostgresRepository_Integration_GetByIDWithSteps(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-withsteps-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create workflow
	workflow := &Workflow{
		WorkflowID:   fmt.Sprintf("wf_withsteps_%d", time.Now().UnixNano()),
		WorkflowName: "With Steps Test",
		Source:       WorkflowSourceLangChain,
		Status:       WorkflowStatusInProgress,
		TotalSteps:   intPtr(2),
		TenantID:     tenantID,
	}
	repo.Create(ctx, workflow)

	// Add steps
	for i := 0; i < 2; i++ {
		step := &WorkflowStep{
			WorkflowID: workflow.WorkflowID,
			StepID:     fmt.Sprintf("step-%d", i),
			StepIndex:  i,
			StepName:   fmt.Sprintf("Step %d", i),
			StepType:   StepTypeLLMCall,
			Decision:   GateDecisionAllow,
		}
		repo.AddStep(ctx, step)
	}

	t.Run("get workflow with steps included", func(t *testing.T) {
		retrieved, err := repo.GetByID(ctx, workflow.WorkflowID)
		if err != nil {
			t.Fatalf("GetByID() error = %v", err)
		}
		if len(retrieved.Steps) != 2 {
			t.Errorf("Steps count = %d, want 2", len(retrieved.Steps))
		}
	})
}

// === Concurrency Test ===

func TestPostgresRepository_Integration_Concurrency(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-concurrent-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)

	ctx := context.Background()

	// Create workflows concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			workflow := &Workflow{
				WorkflowID:   fmt.Sprintf("wf_concurrent_%d_%d", time.Now().UnixNano(), idx),
				WorkflowName: fmt.Sprintf("Concurrent Test %d", idx),
				Source:       WorkflowSourceExternal,
				Status:       WorkflowStatusInProgress,
				TenantID:     tenantID,
			}
			err := repo.Create(ctx, workflow)
			if err != nil {
				t.Errorf("Concurrent Create() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all workflows were created
	workflows, total, err := repo.List(ctx, ListWorkflowsOptions{TenantID: tenantID, Limit: 50})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 10 {
		t.Errorf("Total = %d, want 10", total)
	}
	if len(workflows) != 10 {
		t.Errorf("Workflows count = %d, want 10", len(workflows))
	}
}

// === Plan-Plane Pending Approvals (Issue #1680) ===

// TestPostgresRepository_Integration_PlanApprovals exercises the real
// `metadata->>'plan_id'` JSONB filter against Postgres. Mocking this path
// silently hides Postgres-specific behavior (index usage, sql.NullString
// wiring, NULL vs empty-string handling), so the DB is the only honest test.
func TestPostgresRepository_Integration_PlanApprovals(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-planapprovals-%d", time.Now().UnixNano())
	otherTenantID := fmt.Sprintf("test-tenant-other-%d", time.Now().UnixNano())
	defer cleanupTestWorkflows(t, db, tenantID)
	defer cleanupTestWorkflows(t, db, otherTenantID)

	ctx := context.Background()

	mkPending := func(workflowID, workflowName, planID, stepID string, tenant string) {
		t.Helper()
		var meta json.RawMessage
		if planID != "" {
			meta, _ = json.Marshal(map[string]interface{}{
				"plan_id":        planID,
				"execution_mode": "confirm",
			})
		} else {
			meta = json.RawMessage("{}")
		}
		wf := &Workflow{
			WorkflowID:   workflowID,
			WorkflowName: workflowName,
			Source:       WorkflowSourceExternal,
			Status:       WorkflowStatusInProgress,
			TenantID:     tenant,
			Metadata:     meta,
		}
		if err := repo.Create(ctx, wf); err != nil {
			t.Fatalf("Create(%s): %v", workflowID, err)
		}
		pending := ApprovalStatusPending
		step := &WorkflowStep{
			WorkflowID:     workflowID,
			StepID:         stepID,
			StepIndex:      0,
			StepName:       "step-" + stepID,
			StepType:       StepTypeToolCall,
			Decision:       GateDecisionRequireApproval,
			ApprovalStatus: &pending,
		}
		if err := repo.AddStep(ctx, step); err != nil {
			t.Fatalf("AddStep(%s/%s): %v", workflowID, stepID, err)
		}
	}

	// Two MAP-backed workflows on the target tenant (both have plan_id)
	mkPending(fmt.Sprintf("wf_map_a_%d", time.Now().UnixNano()), "map-confirm-plan-a", "plan-a", "step_0_a", tenantID)
	// Small gap so the DESC ordering is deterministic and tests can inspect it
	time.Sleep(2 * time.Millisecond)
	mkPending(fmt.Sprintf("wf_map_b_%d", time.Now().UnixNano()), "map-confirm-plan-b", "plan-b", "step_0_b", tenantID)
	// Native WCP workflow on the target tenant (no plan_id)
	mkPending(fmt.Sprintf("wf_wcp_c_%d", time.Now().UnixNano()), "wcp-native", "", "step_0_c", tenantID)
	// A MAP-backed workflow on a different tenant — must never appear in the target tenant's list
	mkPending(fmt.Sprintf("wf_other_%d", time.Now().UnixNano()), "other-tenant-plan", "plan-other", "step_0_other", otherTenantID)

	t.Run("filters to MAP-backed only and populates plan_id", func(t *testing.T) {
		got, err := repo.GetPendingPlanApprovals(ctx, tenantID, "", 10)
		if err != nil {
			t.Fatalf("GetPendingPlanApprovals: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("want 2 MAP-backed rows, got %d: %+v", len(got), got)
		}
		seen := map[string]bool{}
		for _, row := range got {
			if row.PlanID == "" {
				t.Errorf("plan_id unpopulated on MAP-backed row: %+v", row)
			}
			if row.WorkflowName == "" {
				t.Errorf("workflow_name unpopulated on MAP-backed row: %+v", row)
			}
			if row.ApprovalStatus == nil || *row.ApprovalStatus != ApprovalStatusPending {
				t.Errorf("approval_status wrong on MAP-backed row: %+v", row)
			}
			seen[row.PlanID] = true
		}
		if !seen["plan-a"] || !seen["plan-b"] {
			t.Errorf("expected plan-a and plan-b in results; got %+v", seen)
		}
		if seen[""] {
			t.Errorf("native WCP workflow leaked through MAP-plane filter")
		}
	})

	t.Run("plan_id filter scopes to one plan", func(t *testing.T) {
		got, err := repo.GetPendingPlanApprovals(ctx, tenantID, "plan-a", 10)
		if err != nil {
			t.Fatalf("GetPendingPlanApprovals: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("filter=plan-a: want 1, got %d", len(got))
		}
		if got[0].PlanID != "plan-a" {
			t.Errorf("plan_id = %q, want plan-a", got[0].PlanID)
		}
	})

	t.Run("tenant isolation blocks other-tenant MAP workflows", func(t *testing.T) {
		got, err := repo.GetPendingPlanApprovals(ctx, tenantID, "", 10)
		if err != nil {
			t.Fatalf("GetPendingPlanApprovals: %v", err)
		}
		for _, row := range got {
			if row.PlanID == "plan-other" {
				t.Errorf("leaked other-tenant row: %+v", row)
			}
		}
	})

	t.Run("CountPendingPlanApprovals matches filter semantics", func(t *testing.T) {
		all, err := repo.CountPendingPlanApprovals(ctx, tenantID, "")
		if err != nil {
			t.Fatalf("CountPendingPlanApprovals: %v", err)
		}
		if all != 2 {
			t.Errorf("unfiltered count: want 2, got %d", all)
		}
		scoped, err := repo.CountPendingPlanApprovals(ctx, tenantID, "plan-a")
		if err != nil {
			t.Fatalf("CountPendingPlanApprovals filter: %v", err)
		}
		if scoped != 1 {
			t.Errorf("filter=plan-a count: want 1, got %d", scoped)
		}
		missing, err := repo.CountPendingPlanApprovals(ctx, tenantID, "plan-does-not-exist")
		if err != nil {
			t.Fatalf("CountPendingPlanApprovals missing: %v", err)
		}
		if missing != 0 {
			t.Errorf("missing-plan count: want 0, got %d", missing)
		}
	})

	t.Run("resolved approvals do not surface", func(t *testing.T) {
		// Approve one of the MAP rows and assert the list shrinks by 1.
		before, _ := repo.CountPendingPlanApprovals(ctx, tenantID, "")
		rows, _ := repo.GetPendingPlanApprovals(ctx, tenantID, "plan-a", 1)
		if len(rows) != 1 {
			t.Fatalf("pre-approve fixture broken")
		}
		if err := repo.UpdateStepApproval(ctx, rows[0].WorkflowID, rows[0].StepID, ApprovalStatusApproved, "approver@example.com", "Approved for integration test"); err != nil {
			t.Fatalf("UpdateStepApproval: %v", err)
		}
		after, _ := repo.CountPendingPlanApprovals(ctx, tenantID, "")
		if after != before-1 {
			t.Errorf("count after approve: want %d, got %d", before-1, after)
		}
	})
}
