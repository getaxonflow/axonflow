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
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// init initializes the logger and timezone to avoid race conditions
// during concurrent workflow execution. This resolves the Go stdlib
// race condition where multiple goroutines simultaneously initialize
// the timezone when log.Printf formats timestamps for the first time.
func init() {
	// Warm up the logger and timezone by calling log.Printf once
	// This ensures timezone is initialized before any concurrent operations
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	_ = time.Now() // Initialize timezone
}

// WorkflowEngine handles basic 2-3 step workflow execution
type WorkflowEngine struct {
	stepProcessors map[string]StepProcessor
	storage        WorkflowStorage
}

// Workflow represents a workflow definition
type Workflow struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   WorkflowMetadata  `json:"metadata"`
	Spec       WorkflowSpec      `json:"spec"`
}

type WorkflowMetadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
}

type WorkflowSpec struct {
	Timeout string                 `json:"timeout"`
	Retries int                   `json:"retries"`
	Input   InputSchema           `json:"input"`
	Steps   []WorkflowStep        `json:"steps"`
	Output  map[string]string     `json:"output"`
}

type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

type WorkflowStep struct {
	Name       string                  `json:"name"`
	Type       string                  `json:"type"`       // "llm-call", "connector-call", "conditional", etc.
	Provider   string                  `json:"provider,omitempty"`
	Model      string                  `json:"model,omitempty"`
	Prompt     string                  `json:"prompt,omitempty"`
	Function   string                  `json:"function,omitempty"`
	Condition  string                  `json:"condition,omitempty"`
	IfTrue     []WorkflowStep          `json:"if_true,omitempty"`
	IfFalse    []WorkflowStep          `json:"if_false,omitempty"`
	Timeout    string                  `json:"timeout,omitempty"`
	MaxTokens  int                     `json:"max_tokens,omitempty"`
	Branches   map[string]WorkflowStep `json:"branches,omitempty"`
	Output     map[string]interface{}  `json:"output_schema,omitempty"`

	// MCP Connector fields (for type="connector-call")
	Connector  string                 `json:"connector,omitempty"`  // Name of registered connector
	Operation  string                 `json:"operation,omitempty"`  // "query" or "execute"
	Statement  string                 `json:"statement,omitempty"`  // Query/command statement
	Action     string                 `json:"action,omitempty"`     // For execute: POST, PUT, DELETE, etc.
	Parameters map[string]interface{} `json:"parameters,omitempty"` // Query/command parameters
}

// WorkflowExecution represents a running workflow instance
type WorkflowExecution struct {
	ID           string                 `json:"id"`
	WorkflowName string                 `json:"workflow_name"`
	Status       string                 `json:"status"` // pending, running, completed, failed
	Input        map[string]interface{} `json:"input"`
	Output       map[string]interface{} `json:"output"`
	Steps        []StepExecution        `json:"steps"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	UserContext  UserContext           `json:"user_context"`
	Error        string                 `json:"error,omitempty"`
}

type StepExecution struct {
	Name        string                 `json:"name"`
	Status      string                 `json:"status"` // pending, running, completed, failed, skipped
	Input       map[string]interface{} `json:"input"`
	Output      map[string]interface{} `json:"output"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ProcessTime string                 `json:"process_time"`
}

// StepProcessor interface for different step types
type StepProcessor interface {
	ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error)
}

// WorkflowStorage interface for persisting workflow state
type WorkflowStorage interface {
	SaveExecution(execution *WorkflowExecution) error
	GetExecution(id string) (*WorkflowExecution, error)
	UpdateExecution(execution *WorkflowExecution) error
}

// Simple in-memory storage implementation with thread-safe access
type InMemoryWorkflowStorage struct {
	mu         sync.RWMutex
	executions map[string]*WorkflowExecution
}

func NewInMemoryWorkflowStorage() *InMemoryWorkflowStorage {
	return &InMemoryWorkflowStorage{
		executions: make(map[string]*WorkflowExecution),
	}
}

func (s *InMemoryWorkflowStorage) SaveExecution(execution *WorkflowExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executions[execution.ID] = execution
	return nil
}

func (s *InMemoryWorkflowStorage) GetExecution(id string) (*WorkflowExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	execution, exists := s.executions[id]
	if !exists {
		return nil, fmt.Errorf("execution not found: %s", id)
	}
	return execution, nil
}

func (s *InMemoryWorkflowStorage) UpdateExecution(execution *WorkflowExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executions[execution.ID] = execution
	return nil
}

// LLM Call Step Processor
type LLMCallProcessor struct {
	llmRouter *LLMRouter
}

func NewLLMCallProcessor(router *LLMRouter) *LLMCallProcessor {
	return &LLMCallProcessor{llmRouter: router}
}

func (p *LLMCallProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	log.Printf("[LLM] Executing step '%s' for workflow %s", step.Name, execution.ID)

	// Replace template variables in prompt
	prompt := p.replaceTemplateVars(step.Prompt, input, execution)
	log.Printf("[LLM] Step '%s': Prompt length = %d chars", step.Name, len(prompt))

	// For synthesis steps, automatically inject previous step outputs
	if p.isSynthesisStep(step.Name) {
		log.Printf("[LLM] Step '%s' is a synthesis step - injecting previous outputs", step.Name)

		// Log what task outputs are being synthesized
		log.Printf("[Synthesis Debug] Task outputs being synthesized:")
		for _, stepExec := range execution.Steps {
			if stepExec.Status == "completed" && stepExec.Output != nil {
				if response, ok := stepExec.Output["response"].(string); ok && response != "" {
					// Log first 200 chars of each step output
					preview := response
					if len(preview) > 200 {
						preview = preview[:200] + "..."
					}
					log.Printf("[Synthesis Debug]   - %s: %s", stepExec.Name, preview)
				}
			}
		}

		previousOutputs := p.buildPreviousOutputsContext(execution)
		if previousOutputs != "" {
			log.Printf("[LLM] Step '%s': Injected %d chars of previous outputs", step.Name, len(previousOutputs))
			prompt = prompt + "\n\n" + previousOutputs
		} else {
			log.Printf("[LLM] Step '%s': WARNING - No previous outputs to inject!", step.Name)
		}
	}

	// Create orchestrator request for LLM
	req := OrchestratorRequest{
		RequestID:   fmt.Sprintf("%s-%s", execution.ID, step.Name),
		Query:       prompt,
		RequestType: "llm-call",
		User:        execution.UserContext,
		Context: map[string]interface{}{
			"workflow_id": execution.ID,
			"step_name":   step.Name,
			"provider":    step.Provider,
			"model":       step.Model,
			"max_tokens":  step.MaxTokens, // Pass through max_tokens if specified
		},
	}

	log.Printf("[LLM] Step '%s': Routing to provider=%s, model=%s, max_tokens=%d",
		step.Name, step.Provider, step.Model, step.MaxTokens)

	// Route to LLM
	response, providerInfo, err := p.llmRouter.RouteRequest(ctx, req)
	if err != nil {
		log.Printf("[LLM] Step '%s': LLM call FAILED - %v", step.Name, err)
		return nil, fmt.Errorf("LLM call failed: %v", err)
	}

	log.Printf("[LLM] Step '%s': Response received - length=%d chars, provider=%s, model=%s, tokens=%d, time=%dms",
		step.Name, len(response.Content), providerInfo.Provider, providerInfo.Model,
		providerInfo.TokensUsed, providerInfo.ResponseTimeMs)

	// CRITICAL: Check for empty or insufficient response
	if response.Content == "" {
		log.Printf("[LLM] Step '%s': CRITICAL - Empty response from LLM (provider=%s, model=%s)",
			step.Name, providerInfo.Provider, providerInfo.Model)
		return nil, fmt.Errorf("LLM returned empty response for step '%s'", step.Name)
	}

	if len(response.Content) < 50 && p.isSynthesisStep(step.Name) {
		log.Printf("[LLM] Step '%s': WARNING - Synthesis response very short (%d chars): %s",
			step.Name, len(response.Content), response.Content)
	}

	// Enhanced validation for synthesis steps - detect empty structured responses
	if p.isSynthesisStep(step.Name) {
		log.Printf("[Synthesis Debug] Validating synthesis response for step '%s'", step.Name)
		log.Printf("[Synthesis Debug] Response length: %d chars", len(response.Content))

		// Generic validation: response should have meaningful content (>100 chars)
		if len(strings.TrimSpace(response.Content)) < 100 {
			log.Printf("[Synthesis] Response too short (%d chars), marking as failed", len(response.Content))
			return nil, fmt.Errorf("synthesis response validation failed - response too short")
		}

		log.Printf("[Synthesis Debug] Validation passed - response contains content")
	}

	// Process response based on expected output schema
	output := map[string]interface{}{
		"response":     response.Content,
		"provider":     providerInfo.Provider,
		"model":        providerInfo.Model,
		"tokens_used":  providerInfo.TokensUsed,
		"response_time": providerInfo.ResponseTimeMs,
	}

	// Try to parse JSON if output schema expects structured data
	if step.Output != nil {
		if parsedResponse, err := p.parseStructuredResponse(response.Content); err == nil {
			output["parsed"] = parsedResponse
			log.Printf("[LLM] Step '%s': Successfully parsed structured response", step.Name)
		} else {
			log.Printf("[LLM] Step '%s': Could not parse as structured JSON: %v", step.Name, err)
		}
	}

	log.Printf("[LLM] Step '%s': Completed successfully", step.Name)
	return output, nil
}

func (p *LLMCallProcessor) replaceTemplateVars(template string, stepInput map[string]interface{}, execution *WorkflowExecution) string {
	result := template
	
	// Replace {{input.key}} variables
	for key, value := range stepInput {
		placeholder := fmt.Sprintf("{{input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}
	
	// Replace {{steps.stepname.output.key}} variables
	for _, stepExec := range execution.Steps {
		if stepExec.Status == "completed" {
			for key, value := range stepExec.Output {
				placeholder := fmt.Sprintf("{{steps.%s.output.%s}}", stepExec.Name, key)
				if str, ok := value.(string); ok {
					result = strings.ReplaceAll(result, placeholder, str)
				}
			}
		}
	}

	return result
}

// isSynthesisStep checks if this is a synthesis/final step
func (p *LLMCallProcessor) isSynthesisStep(stepName string) bool {
	stepNameLower := strings.ToLower(stepName)
	return strings.Contains(stepNameLower, "synthesize") ||
		strings.Contains(stepNameLower, "combine") ||
		strings.Contains(stepNameLower, "final") ||
		strings.Contains(stepNameLower, "summary") ||
		strings.Contains(stepNameLower, "aggregate") ||
		strings.Contains(stepNameLower, "merge")
}

// buildPreviousOutputsContext creates a formatted string of all previous step outputs
func (p *LLMCallProcessor) buildPreviousOutputsContext(execution *WorkflowExecution) string {
	var builder strings.Builder
	builder.WriteString("===== PREVIOUS STEP RESULTS =====\n\n")
	builder.WriteString("Use the following real data from previous steps to create your response:\n\n")

	for _, stepExec := range execution.Steps {
		if stepExec.Status == "completed" {
			// Skip if this is the current synthesis step
			if p.isSynthesisStep(stepExec.Name) {
				continue
			}

			builder.WriteString(fmt.Sprintf("## Step: %s\n", stepExec.Name))

			// Include the formatted response if available (for connectors)
			if response, ok := stepExec.Output["response"].(string); ok && response != "" {
				builder.WriteString(response)
				builder.WriteString("\n\n")
			} else {
				// Fallback: show raw output
				if len(stepExec.Output) > 0 {
					for key, value := range stepExec.Output {
						// Skip internal fields
						if key == "provider" || key == "model" || key == "tokens_used" || key == "response_time" || key == "duration" || key == "cached" || key == "connector" {
							continue
						}
						builder.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
					}
					builder.WriteString("\n")
				}
			}
		}
	}

	builder.WriteString("===== END OF PREVIOUS RESULTS =====\n")
	builder.WriteString("IMPORTANT: Use the above real data (especially flight prices, times, and details) in your response. Do NOT make up generic information.\n")

	return builder.String()
}

func (p *LLMCallProcessor) parseStructuredResponse(response interface{}) (map[string]interface{}, error) {
	if str, ok := response.(string); ok {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(str), &parsed); err == nil {
			return parsed, nil
		}
	}
	return nil, fmt.Errorf("could not parse structured response")
}

// Conditional Step Processor
type ConditionalProcessor struct{}

func NewConditionalProcessor() *ConditionalProcessor {
	return &ConditionalProcessor{}
}

func (p *ConditionalProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	// Evaluate condition
	conditionResult := p.evaluateCondition(step.Condition, execution)
	
	output := map[string]interface{}{
		"condition_evaluated": step.Condition,
		"condition_result":    conditionResult,
		"branch_taken":        "",
	}
	
	// Execute appropriate branch
	var stepsToExecute []WorkflowStep
	if conditionResult {
		stepsToExecute = step.IfTrue
		output["branch_taken"] = "if_true"
	} else {
		stepsToExecute = step.IfFalse
		output["branch_taken"] = "if_false"
	}
	
	// Note: In a full implementation, we would execute the branch steps
	// For this basic demo, we just record which branch would be taken
	output["steps_to_execute"] = len(stepsToExecute)
	
	return output, nil
}

func (p *ConditionalProcessor) evaluateCondition(condition string, execution *WorkflowExecution) bool {
	// Simple condition evaluation - in production this would be more sophisticated
	// Example: "{{steps.initial-analysis.output.escalation_required == true}}"
	
	// For demo, parse basic equality conditions
	if strings.Contains(condition, "==") {
		parts := strings.Split(condition, "==")
		if len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			
			// Extract value from execution state
			leftValue := p.extractValue(left, execution)
			
			// Compare with expected value
			return fmt.Sprintf("%v", leftValue) == strings.Trim(right, " \"'")
		}
	}
	
	// Default to false for safety
	return false
}

func (p *ConditionalProcessor) extractValue(path string, execution *WorkflowExecution) interface{} {
	// Extract value from execution state using path like "steps.step-name.output.key"
	if strings.HasPrefix(path, "{{") && strings.HasSuffix(path, "}}") {
		path = strings.Trim(path, "{}")
	}
	
	parts := strings.Split(path, ".")
	if len(parts) >= 4 && parts[0] == "steps" {
		stepName := parts[1]
		outputKey := parts[3]
		
		for _, stepExec := range execution.Steps {
			if stepExec.Name == stepName && stepExec.Status == "completed" {
				if value, exists := stepExec.Output[outputKey]; exists {
					return value
				}
			}
		}
	}
	
	return nil
}

// Function Call Processor
type FunctionCallProcessor struct{}

func NewFunctionCallProcessor() *FunctionCallProcessor {
	return &FunctionCallProcessor{}
}

func (p *FunctionCallProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	// For demo purposes, simulate function execution
	output := map[string]interface{}{
		"function":    step.Function,
		"executed_at": time.Now().UTC(),
		"status":      "simulated",
	}
	
	// Add simulated function-specific outputs
	switch step.Function {
	case "data-validator":
		output["validation_score"] = 0.95
		output["compliance_checks"] = []string{"gdpr", "ccpa"}
		output["status"] = "valid"
		
	case "risk-calculator":
		output["final_risk_score"] = 25
		output["recommendation"] = "auto-approve"
		
	case "auto-moderate":
		output["action"] = "approved"
		output["reason"] = "low risk score"
		
	default:
		output["result"] = "function executed successfully"
	}
	
	return output, nil
}

// Main Workflow Engine
func NewWorkflowEngine() *WorkflowEngine {
	engine := &WorkflowEngine{
		stepProcessors: make(map[string]StepProcessor),
		storage:        NewInMemoryWorkflowStorage(),
	}
	
	// Note: Step processors that need llmRouter will be registered after initialization
	// For now, register only the processors that don't need external dependencies
	engine.stepProcessors["conditional"] = NewConditionalProcessor()
	engine.stepProcessors["function-call"] = NewFunctionCallProcessor()
	
	return engine
}

// InitializeWithDependencies sets up processors that need external dependencies
func (e *WorkflowEngine) InitializeWithDependencies(router *LLMRouter, amadeusClient *AmadeusClient) {
	if router != nil {
		e.stepProcessors["llm-call"] = NewLLMCallProcessor(router)
	}
	// Register API call processor (supports Amadeus and future APIs)
	e.stepProcessors["api-call"] = NewAPICallProcessor(amadeusClient)

	// Register MCP Connector processor (MCP v0.2)
	// Note: Removed business logic fallback - clients handle their own fallbacks
	mcpProcessor := NewMCPConnectorProcessor()
	e.stepProcessors["connector-call"] = mcpProcessor
}

// Execute a workflow
func (e *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error) {
	// Create execution instance
	execution := &WorkflowExecution{
		ID:           fmt.Sprintf("wf_%d_%s", time.Now().Unix(), generateRandomString(8)),
		WorkflowName: workflow.Metadata.Name,
		Status:       "running",
		Input:        input,
		Output:       make(map[string]interface{}),
		Steps:        make([]StepExecution, 0),
		StartTime:    time.Now(),
		UserContext:  user,
	}
	
	// Save initial state
	if err := e.storage.SaveExecution(execution); err != nil {
		return nil, fmt.Errorf("failed to save execution: %v", err)
	}
	
	log.Printf("Starting workflow execution: %s (%s)", execution.ID, workflow.Metadata.Name)
	
	// Execute steps sequentially (basic implementation)
	for _, step := range workflow.Spec.Steps {
		stepExecution := StepExecution{
			Name:      step.Name,
			Status:    "running",
			StartTime: time.Now(),
			Input:     input, // Pass current input to step
		}
		
		execution.Steps = append(execution.Steps, stepExecution)
		
		// Get step processor
		processor, exists := e.stepProcessors[step.Type]
		if !exists {
			err := fmt.Errorf("unknown step type: %s", step.Type)
			stepExecution.Status = "failed"
			stepExecution.Error = err.Error()
			execution.Status = "failed"
			execution.Error = err.Error()
			_ = e.storage.UpdateExecution(execution)
			return execution, err
		}
		
		// Execute step
		stepOutput, err := processor.ExecuteStep(ctx, step, input, execution)
		now := time.Now()
		stepExecution.EndTime = &now
		stepExecution.ProcessTime = now.Sub(stepExecution.StartTime).String()
		
		if err != nil {
			stepExecution.Status = "failed"
			stepExecution.Error = err.Error()
			execution.Status = "failed"
			execution.Error = fmt.Sprintf("Step %s failed: %v", step.Name, err)

			// Update execution state
			execution.Steps[len(execution.Steps)-1] = stepExecution
			_ = e.storage.UpdateExecution(execution)
			return execution, err
		}
		
		stepExecution.Status = "completed"
		stepExecution.Output = stepOutput
		
		// Update execution state
		execution.Steps[len(execution.Steps)-1] = stepExecution
		
		// Update input for next step (pass output of current step)
		if stepOutput != nil {
			// Merge step output into available context for template replacement
			for key, value := range stepOutput {
				input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
			}
		}
		
		log.Printf("Completed step: %s in %s", step.Name, stepExecution.ProcessTime)
	}
	
	// Mark workflow as completed
	execution.Status = "completed"
	now := time.Now()
	execution.EndTime = &now
	
	// Generate final output based on workflow output specification
	for key, template := range workflow.Spec.Output {
		execution.Output[key] = e.resolveOutputTemplate(template, execution)
	}

	_ = e.storage.UpdateExecution(execution)

	log.Printf("Workflow execution completed: %s in %s", execution.ID, now.Sub(execution.StartTime).String())
	return execution, nil
}

func (e *WorkflowEngine) resolveOutputTemplate(template string, execution *WorkflowExecution) interface{} {
	// Simple template resolution for output
	result := template

	log.Printf("[OutputTemplate] Resolving template: %s", template)
	log.Printf("[OutputTemplate] Execution has %d steps", len(execution.Steps))

	// Replace step output references
	for _, stepExec := range execution.Steps {
		log.Printf("[OutputTemplate] Step '%s' status=%s, output keys=%v", stepExec.Name, stepExec.Status, getKeys(stepExec.Output))
		if stepExec.Status == "completed" {
			for key, value := range stepExec.Output {
				placeholder := fmt.Sprintf("{{steps.%s.output.%s}}", stepExec.Name, key)
				log.Printf("[OutputTemplate] Checking placeholder: %s, value type: %T", placeholder, value)
				if str, ok := value.(string); ok {
					log.Printf("[OutputTemplate] Replacing %s with string (len=%d)", placeholder, len(str))
					result = strings.ReplaceAll(result, placeholder, str)
				} else if llmResp, ok := value.(*LLMResponse); ok {
					// Handle LLMResponse objects - extract Content field
					log.Printf("[OutputTemplate] Replacing %s with LLMResponse.Content (len=%d)", placeholder, len(llmResp.Content))
					result = strings.ReplaceAll(result, placeholder, llmResp.Content)
				} else {
					log.Printf("[OutputTemplate] WARNING: Value type %T not handled for key %s", value, key)
				}
			}
		}
	}

	log.Printf("[OutputTemplate] Final result type: %T", result)
	if len(result) > 0 {
		log.Printf("[OutputTemplate] Final result preview: %s", truncateString(result, 200))
	}

	return result
}

// Helper to get map keys for logging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Helper to truncate strings for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Get workflow execution status
func (e *WorkflowEngine) GetExecution(id string) (*WorkflowExecution, error) {
	return e.storage.GetExecution(id)
}

// List recent executions (for demo purposes)
func (e *WorkflowEngine) ListRecentExecutions(limit int) ([]*WorkflowExecution, error) {
	// In a real implementation, this would query the storage
	// For demo, return empty list
	return []*WorkflowExecution{}, nil
}

// Health check for workflow engine
func (e *WorkflowEngine) IsHealthy() bool {
	return e.storage != nil && len(e.stepProcessors) > 0
}

// isSynthesisStep checks if a step name indicates a synthesis/final step
func (e *WorkflowEngine) isSynthesisStep(stepName string) bool {
	stepNameLower := strings.ToLower(stepName)
	return strings.Contains(stepNameLower, "synthesize") ||
		strings.Contains(stepNameLower, "combine") ||
		strings.Contains(stepNameLower, "final") ||
		strings.Contains(stepNameLower, "summary") ||
		strings.Contains(stepNameLower, "aggregate") ||
		strings.Contains(stepNameLower, "merge")
}

// Note: Business logic fallbacks removed - clients handle their own fallback logic
// Orchestrator is infrastructure layer, not application layer

// GetExecutionsByTenant returns workflow executions for a specific tenant
func (e *WorkflowEngine) GetExecutionsByTenant(tenantID string) ([]*WorkflowExecution, error) {
	var tenantExecutions []*WorkflowExecution

	// Get all executions from storage (would be optimized with proper database query)
	allExecutions := e.storage.(*InMemoryWorkflowStorage).executions

	for _, execution := range allExecutions {
		if execution.UserContext.TenantID == tenantID {
			tenantExecutions = append(tenantExecutions, execution)
		}
	}

	return tenantExecutions, nil
}

// === Parallel Execution Support (Multi-Agent Planning v0.1) ===

// StepResult holds the result of a single step execution
type StepResult struct {
	StepIndex int
	Step      WorkflowStep
	Execution StepExecution
	Error     error
}

// ExecuteWorkflowWithParallelSupport executes a workflow with parallel step support
// This is the enhanced version used by Multi-Agent Planning
func (e *WorkflowEngine) ExecuteWorkflowWithParallelSupport(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext, enableParallel bool) (*WorkflowExecution, error) {
	// Initialize input map if nil
	if input == nil {
		input = make(map[string]interface{})
	}

	// Create execution instance
	execution := &WorkflowExecution{
		ID:           fmt.Sprintf("wf_%d_%s", time.Now().Unix(), generateRandomString(8)),
		WorkflowName: workflow.Metadata.Name,
		Status:       "running",
		Input:        input,
		Output:       make(map[string]interface{}),
		Steps:        make([]StepExecution, 0),
		StartTime:    time.Now(),
		UserContext:  user,
	}

	// Save initial state
	if err := e.storage.SaveExecution(execution); err != nil {
		return nil, fmt.Errorf("failed to save execution: %v", err)
	}

	log.Printf("Starting workflow execution: %s (%s), parallel=%v", execution.ID, workflow.Metadata.Name, enableParallel)

	// Group steps by parallelizability
	stepGroups := e.groupStepsForExecution(workflow.Spec.Steps, enableParallel)

	// Execute step groups
	for groupIdx, group := range stepGroups {
		log.Printf("[Workflow] Executing step group %d/%d with %d steps (parallel=%v)",
			groupIdx+1, len(stepGroups), len(group.Steps), group.IsParallel)

		if group.IsParallel && len(group.Steps) > 1 {
			// Execute steps in parallel
			groupResults, err := e.executeStepsParallel(ctx, group.Steps, input, execution)
			if err != nil {
				log.Printf("[Workflow] Step group %d FAILED: %v", groupIdx+1, err)
				execution.Status = "failed"
				execution.Error = err.Error()
				_ = e.storage.UpdateExecution(execution)
				return execution, err
			}

			// Add results to execution
			execution.Steps = append(execution.Steps, groupResults...)
			log.Printf("[Workflow] Step group %d completed - %d parallel steps succeeded", groupIdx+1, len(groupResults))

			// Merge outputs for next group
			mergedCount := 0
			for _, result := range groupResults {
				if result.Output != nil {
					for key, value := range result.Output {
						input[fmt.Sprintf("step_%s_%s", result.Name, key)] = value
						mergedCount++
					}
				}
			}
			log.Printf("[Workflow] Merged %d outputs from group %d into input context", mergedCount, groupIdx+1)
		} else {
			// Execute steps sequentially
			log.Printf("[Workflow] Executing %d steps sequentially in group %d", len(group.Steps), groupIdx+1)
			for _, step := range group.Steps {
				stepResult, err := e.executeSingleStep(ctx, step, input, execution)
				if err != nil {
					log.Printf("[Workflow] Sequential step '%s' FAILED in group %d: %v", step.Name, groupIdx+1, err)
					// Note: Clients handle their own fallback logic - orchestrator returns errors
					execution.Status = "failed"
					execution.Error = fmt.Sprintf("Step %s failed: %v", step.Name, err)
					_ = e.storage.UpdateExecution(execution)
					return execution, err
				}

				execution.Steps = append(execution.Steps, stepResult)
				log.Printf("[Workflow] Sequential step '%s' in group %d completed", step.Name, groupIdx+1)

				// Merge output for next step
				mergedCount := 0
				if stepResult.Output != nil {
					for key, value := range stepResult.Output {
						input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
						mergedCount++
					}
				}
				log.Printf("[Workflow] Merged %d outputs from step '%s' into input context", mergedCount, step.Name)
			}
		}
	}

	// Mark workflow as completed
	log.Printf("[Workflow] All step groups completed - marking workflow %s as completed", execution.ID)
	execution.Status = "completed"
	now := time.Now()
	execution.EndTime = &now

	// Generate final output
	for key, template := range workflow.Spec.Output {
		execution.Output[key] = e.resolveOutputTemplate(template, execution)
	}

	_ = e.storage.UpdateExecution(execution)

	log.Printf("Workflow execution completed: %s in %s", execution.ID, now.Sub(execution.StartTime).String())
	return execution, nil
}

// StepGroup represents a group of steps that can be executed together
type StepGroup struct {
	IsParallel bool
	Steps      []WorkflowStep
}

// Group steps for execution (parallel vs sequential)
func (e *WorkflowEngine) groupStepsForExecution(steps []WorkflowStep, enableParallel bool) []StepGroup {
	if !enableParallel || len(steps) <= 1 {
		// All steps sequential
		return []StepGroup{{IsParallel: false, Steps: steps}}
	}

	// Simple heuristic: Last step is usually synthesis (sequential)
	// All others can be parallel if they don't have dependencies
	groups := []StepGroup{}

	if len(steps) > 1 {
		// First N-1 steps parallel
		parallelSteps := steps[:len(steps)-1]
		groups = append(groups, StepGroup{
			IsParallel: true,
			Steps:      parallelSteps,
		})

		// Last step sequential (synthesis)
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      []WorkflowStep{steps[len(steps)-1]},
		})
	} else {
		// Single step
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      steps,
		})
	}

	return groups
}

// Execute steps in parallel using goroutines
func (e *WorkflowEngine) executeStepsParallel(ctx context.Context, steps []WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) ([]StepExecution, error) {
	numSteps := len(steps)
	results := make([]StepExecution, numSteps)
	errors := make([]error, numSteps)

	var wg sync.WaitGroup

	for i, step := range steps {
		wg.Add(1)
		go func(idx int, s WorkflowStep) {
			defer wg.Done()

			log.Printf("[Parallel] Starting step %d/%d: %s", idx+1, numSteps, s.Name)

			stepResult, err := e.executeSingleStep(ctx, s, input, execution)
			results[idx] = stepResult
			errors[idx] = err

			if err != nil {
				log.Printf("[Parallel] Step %s failed: %v", s.Name, err)
			} else {
				log.Printf("[Parallel] Step %s completed in %s", s.Name, stepResult.ProcessTime)
			}
		}(i, step)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Check for errors - Allow workflow to continue with partial results for trip planning
	// Only fail if ALL critical steps failed (flights/hotels)
	failedSteps := []string{}
	criticalStepsFailed := 0
	totalSteps := 0

	for i, err := range errors {
		if err != nil {
			failedSteps = append(failedSteps, steps[i].Name)
			log.Printf("[Parallel] Step %s failed: %v", steps[i].Name, err)

			// Check if this is a critical step (flights or hotels for trip planning)
			if steps[i].Name == "flight-search" || steps[i].Name == "hotel-search" {
				criticalStepsFailed++
			}
		}
		totalSteps++
	}

	// If some steps succeeded, continue with partial results (synthesis can use fallback)
	if len(failedSteps) > 0 && len(failedSteps) < totalSteps {
		log.Printf("[Parallel] %d/%d steps failed (%v), but continuing with partial results for synthesis fallback",
			len(failedSteps), totalSteps, failedSteps)
		// Return results without error - synthesis step will handle partial data
		return results, nil
	}

	// Only fail if ALL steps failed or all critical steps failed
	if len(failedSteps) == totalSteps {
		return results, fmt.Errorf("all parallel steps failed: %v", failedSteps)
	}

	if criticalStepsFailed > 0 && criticalStepsFailed == 2 {
		return results, fmt.Errorf("critical steps (flights and hotels) failed")
	}

	return results, nil
}

// Execute a single step (helper for both sequential and parallel execution)
func (e *WorkflowEngine) executeSingleStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (StepExecution, error) {
	log.Printf("[Step] Executing step '%s' (type=%s)", step.Name, step.Type)

	stepExecution := StepExecution{
		Name:      step.Name,
		Status:    "running",
		StartTime: time.Now(),
		Input:     input,
	}

	// Get step processor
	processor, exists := e.stepProcessors[step.Type]
	if !exists {
		err := fmt.Errorf("unknown step type: %s", step.Type)
		log.Printf("[Step] ERROR: Unknown step type '%s' for step '%s'", step.Type, step.Name)
		stepExecution.Status = "failed"
		stepExecution.Error = err.Error()
		now := time.Now()
		stepExecution.EndTime = &now
		stepExecution.ProcessTime = "0ms"
		return stepExecution, err
	}

	// Execute step
	log.Printf("[Step] Invoking processor for step '%s'", step.Name)
	stepOutput, err := processor.ExecuteStep(ctx, step, input, execution)
	now := time.Now()
	stepExecution.EndTime = &now
	stepExecution.ProcessTime = now.Sub(stepExecution.StartTime).String()

	if err != nil {
		log.Printf("[Step] Step '%s' FAILED after %s: %v", step.Name, stepExecution.ProcessTime, err)
		stepExecution.Status = "failed"
		stepExecution.Error = err.Error()
		return stepExecution, err
	}

	// Log output details
	outputSize := 0
	if stepOutput != nil {
		if respStr, ok := stepOutput["response"].(string); ok {
			outputSize = len(respStr)
		}
		log.Printf("[Step] Step '%s' completed in %s - output fields: %d, response size: %d chars",
			step.Name, stepExecution.ProcessTime, len(stepOutput), outputSize)
	} else {
		log.Printf("[Step] Step '%s' completed in %s - WARNING: nil output!", step.Name, stepExecution.ProcessTime)
	}

	stepExecution.Status = "completed"
	stepExecution.Output = stepOutput

	return stepExecution, nil
}