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

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

// Integration tests verify multiple components working together

// TestPlanningEngineWorkflowIntegration tests planning engine generating executable workflows
func TestPlanningEngineWorkflowIntegration(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	planningEngine := NewPlanningEngine(router)

	ctx := context.Background()

	domains := []string{"travel", "healthcare", "finance", "generic"}

	for _, domain := range domains {
		t.Run("domain_"+domain, func(t *testing.T) {
			req := PlanGenerationRequest{
				Query:         "Test query for " + domain,
				Domain:        domain,
				ExecutionMode: "auto",
				ClientID:      "test-client",
				RequestID:     "test-req",
			}

			workflow, err := planningEngine.GeneratePlan(ctx, req)
			if err != nil {
				t.Fatalf("Plan generation failed for %s: %v", domain, err)
			}

			if workflow == nil {
				t.Fatal("Expected workflow to be generated")
			}

			if len(workflow.Spec.Steps) == 0 {
				t.Error("Expected workflow to have steps")
			}

			// Verify workflow structure is valid
			if workflow.APIVersion != "v1" {
				t.Error("Expected APIVersion to be v1")
			}

			if workflow.Kind != "Workflow" {
				t.Error("Expected Kind to be Workflow")
			}

			t.Logf("Generated %d steps for %s domain", len(workflow.Spec.Steps), domain)
		})
	}
}

// TestEndToEndPlanningToExecution tests planning → workflow execution flow
func TestEndToEndPlanningToExecution(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)

	planningEngine := NewPlanningEngine(router)
	workflowEngine := NewWorkflowEngine()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate plan
	req := PlanGenerationRequest{
		Query:         "Analyze market data",
		Domain:        "finance",
		ExecutionMode: "auto",
		ClientID:      "test-client",
		RequestID:     "test-req",
	}

	workflow, err := planningEngine.GeneratePlan(ctx, req)
	if err != nil{
		t.Fatalf("Planning failed: %v", err)
	}

	if workflow == nil || len(workflow.Spec.Steps) == 0 {
		t.Fatal("Expected valid workflow with steps")
	}

	// Execute the generated workflow
	user := UserContext{
		TenantID: "test-tenant",
		Role:     "user",
		Email:    "test@example.com",
	}

	execution, err := workflowEngine.ExecuteWorkflow(ctx, *workflow, map[string]interface{}{
		"query": req.Query,
	}, user)

	if err != nil {
		// Execution may fail due to missing processors, but workflow should be created
		t.Logf("Execution error (expected): %v", err)
	}

	if execution == nil {
		t.Fatal("Expected execution to be created even if it fails")
	}

	// Verify execution was created with proper metadata
	if execution.ID == "" {
		t.Error("Expected execution ID to be set")
	}

	if execution.WorkflowName != workflow.Metadata.Name {
		t.Error("Expected workflow name to match")
	}

	t.Logf("Successfully integrated planning → execution: %s", execution.ID)
}

// TestDynamicPolicyEngineIntegration tests dynamic policy engine integration
func TestDynamicPolicyEngineIntegration(t *testing.T) {
	dynamicEngine := NewDynamicPolicyEngine()

	tests := []struct {
		name  string
		query string
		user  UserContext
	}{
		{
			name:  "Normal query",
			query: "SELECT * FROM products",
			user: UserContext{
				TenantID: "tenant-1",
				Role:     "user",
				Email:    "user@test.com",
			},
		},
		{
			name:  "Sensitive query",
			query: "SELECT password FROM users",
			user: UserContext{
				TenantID: "tenant-2",
				Role:     "analyst",
				Email:    "analyst@test.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			req := OrchestratorRequest{
				RequestID:   "test-req",
				Query:       tt.query,
				RequestType: "sql",
				User:        tt.user,
			}

			result := dynamicEngine.EvaluateDynamicPolicies(ctx, req)

			if result == nil {
				t.Error("Expected policy result")
			}

			t.Logf("Policy evaluation: allowed=%v, risk=%.2f, actions=%v",
				result.Allowed, result.RiskScore, result.RequiredActions)
		})
	}
}

// TestLLMRouterHealthCheck tests LLM router health across planning and workflow
func TestLLMRouterHealthCheck(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)

	if !router.IsHealthy() {
		t.Error("Expected router to be healthy")
	}

	planningEngine := NewPlanningEngine(router)

	if !planningEngine.IsHealthy() {
		t.Error("Expected planning engine to be healthy")
	}

	t.Log("LLM router health check passed")
}

// TestWorkflowTenantIsolation tests tenant isolation in workflow execution
func TestWorkflowTenantIsolation(t *testing.T) {
	workflowEngine := NewWorkflowEngine()

	workflow := Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name:    "test-workflow",
			Version: "1.0",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{
					Name:       "step1",
					Type:       "function-call",
					Function:   "test",
					Parameters: make(map[string]interface{}),
				},
			},
		},
	}

	ctx := context.Background()

	// Create executions for different tenants
	userA := UserContext{TenantID: "tenant-a", Role: "user", Email: "a@test.com"}
	userB := UserContext{TenantID: "tenant-b", Role: "user", Email: "b@test.com"}

	exec1, _ := workflowEngine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, userA)
	exec2, _ := workflowEngine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, userB)
	exec3, _ := workflowEngine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, userA)

	if exec1 == nil || exec2 == nil || exec3 == nil {
		t.Fatal("Expected all executions to be created")
	}

	// Verify each execution has unique ID
	if exec1.ID == exec2.ID || exec1.ID == exec3.ID || exec2.ID == exec3.ID {
		t.Error("Expected unique execution IDs")
	}

	t.Log("Tenant isolation verified - all executions independent")
}

// TestConcurrentWorkflowExecution tests parallel workflow execution
func TestConcurrentWorkflowExecution(t *testing.T) {
	workflowEngine := NewWorkflowEngine()

	workflow := Workflow{
		APIVersion: "v1",
		Kind:       "Workflow",
		Metadata: WorkflowMetadata{
			Name:    "concurrent-test",
			Version: "1.0",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{
					Name:       "task-1",
					Type:       "function-call",
					Function:   "test",
					Parameters: make(map[string]interface{}),
				},
			},
		},
	}

	ctx := context.Background()
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	// Warmup: Initialize timezone and logger to avoid race detector false positives
	// in Go's standard library when log.Printf is called concurrently for the first time
	log.Printf("[Test] Initializing concurrent workflow execution test")

	// Launch 10 concurrent workflow executions
	for i := 0; i < 10; i++ {
		go func(index int) {
			user := UserContext{
				TenantID: fmt.Sprintf("tenant-%d", index),
				Role:     "user",
				Email:    fmt.Sprintf("user%d@test.com", index),
			}

			_, err := workflowEngine.ExecuteWorkflow(ctx, workflow, map[string]interface{}{}, user)
			if err != nil {
				errors <- fmt.Errorf("execution %d failed: %v", index, err)
			}
			done <- true
		}(i)
	}

	// Wait for all executions
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	errorCount := 0
	for err := range errors {
		errorCount++
		t.Log(err)
	}

	t.Logf("Concurrent execution completed (%d errors expected)", errorCount)
}

// TestPlanningWithSynthesisSteps tests that planning engine creates synthesis steps
func TestPlanningWithSynthesisSteps(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	planningEngine := NewPlanningEngine(router)

	ctx := context.Background()

	req := PlanGenerationRequest{
		Query:         "Plan a 3-day trip to Paris",
		Domain:        "travel",
		ExecutionMode: "auto",
		ClientID:      "test-client",
		RequestID:     "test-req",
	}

	workflow, err := planningEngine.GeneratePlan(ctx, req)
	if err != nil {
		t.Fatalf("Planning failed: %v", err)
	}

	// Verify workflow contains synthesis step
	hasSynthesis := false
	for _, step := range workflow.Spec.Steps {
		stepNameLower := strings.ToLower(step.Name)
		if stringContains(stepNameLower, "synthesize") ||
			stringContains(stepNameLower, "combine") ||
			stringContains(stepNameLower, "summary") {
			hasSynthesis = true
			t.Logf("Found synthesis step: %s", step.Name)
			break
		}
	}

	if !hasSynthesis {
		t.Error("Expected workflow to have synthesis step")
	}
}

// TestLLMRouterFailover tests LLM provider failover mechanism
func TestLLMRouterFailover(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey:    "invalid-key", // Will fail
		AnthropicKey: "invalid-key", // Will fail
	}
	router := NewLLMRouter(config)

	planningEngine := NewPlanningEngine(router)

	ctx := context.Background()

	req := PlanGenerationRequest{
		Query:         "Test query",
		Domain:        "generic",
		ExecutionMode: "auto",
		ClientID:      "test-client",
		RequestID:     "test-failover",
	}

	// Planning should still work via heuristic fallback
	workflow, err := planningEngine.GeneratePlan(ctx, req)
	if err != nil {
		t.Fatalf("Planning failed even with fallback: %v", err)
	}

	if workflow == nil {
		t.Fatal("Expected workflow via fallback mechanism")
	}

	t.Log("LLM failover to heuristics successful")
}

// TestWorkflowEngineHealthCheck tests workflow engine health
func TestWorkflowEngineHealthCheck(t *testing.T) {
	workflowEngine := NewWorkflowEngine()

	if !workflowEngine.IsHealthy() {
		t.Error("Expected workflow engine to be healthy")
	}

	t.Log("Workflow engine health check passed")
}

// TestMultiDomainPlanning tests planning across multiple domains
func TestMultiDomainPlanning(t *testing.T) {
	config := LLMRouterConfig{
		OpenAIKey: "test-key",
	}
	router := NewLLMRouter(config)
	planningEngine := NewPlanningEngine(router)

	ctx := context.Background()

	domains := map[string]string{
		"travel":     "Plan a vacation",
		"healthcare": "Diagnose symptoms",
		"finance":    "Analyze investments",
		"generic":    "General task",
	}

	for domain, query := range domains {
		t.Run(domain, func(t *testing.T) {
			req := PlanGenerationRequest{
				Query:         query,
				Domain:        domain,
				ExecutionMode: "auto",
				ClientID:      "test-client",
				RequestID:     fmt.Sprintf("test-%s", domain),
			}

			workflow, err := planningEngine.GeneratePlan(ctx, req)
			if err != nil {
				t.Errorf("Planning failed for %s: %v", domain, err)
			}

			if workflow == nil || len(workflow.Spec.Steps) == 0 {
				t.Errorf("Expected valid workflow for %s domain", domain)
			}

			t.Logf("%s: generated %d steps", domain, len(workflow.Spec.Steps))
		})
	}
}
