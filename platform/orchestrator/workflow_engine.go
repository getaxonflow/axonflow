// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"log"
	"sort"
	"strconv"
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

// ReplayRecorder interface for execution snapshot recording
type ReplayRecorder interface {
	StartExecution(ctx context.Context, requestID, workflowName string, totalSteps int, orgID, tenantID, userID string) error
	RecordStep(ctx context.Context, snapshot *ReplaySnapshotInput) error
	CompleteExecution(ctx context.Context, requestID string, outputSummary json.RawMessage) error
	FailExecution(ctx context.Context, requestID string, errorMessage string) error
}

// ReplaySnapshotInput captures step execution state for recording
// This is the input type passed to the ReplayRecorder interface
type ReplaySnapshotInput struct {
	RequestID   string
	StepIndex   int
	StepName    string
	Status      string
	StartedAt   time.Time
	CompletedAt *time.Time
	DurationMs  *int
	Input       json.RawMessage
	Output      json.RawMessage
	Provider    string
	Model       string
	TokensIn    int
	TokensOut   int
	CostUSD     float64
	Error       string
	// Policy fields for audit trail (Issue #1020)
	PoliciesChecked   []string
	PoliciesTriggered []PolicyEventInput
}

// PolicyEventInput represents a policy event for snapshot input (Issue #1020)
type PolicyEventInput struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Action     string `json:"action"`
	Matched    string `json:"matched"`
	Resolution string `json:"resolution"`
}

// WorkflowEngine handles basic 2-3 step workflow execution
type WorkflowEngine struct {
	stepProcessors map[string]StepProcessor
	storage        WorkflowStorage
	replayRecorder ReplayRecorder    // Execution replay recorder (#763)
	pricingConfig  PlanCostEstimator // Cost calculation for step snapshots
	// stepGate decides every step before it runs (map_step_gate.go, #4382).
	// The orchestrator wires it at boot on every posture; an engine without one
	// decides nothing, and the execute handlers refuse to run on it.
	stepGate *mapStepGate
}

// Workflow represents a workflow definition
type Workflow struct {
	APIVersion       string           `json:"apiVersion"`
	Kind             string           `json:"kind"`
	Metadata         WorkflowMetadata `json:"metadata"`
	Spec             WorkflowSpec     `json:"spec"`
	EstimatedCostUSD *float64         `json:"estimated_cost_usd,omitempty"`
}

type WorkflowMetadata struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version"`
	Tags        []string `json:"tags"`
}

type WorkflowSpec struct {
	Timeout string            `json:"timeout"`
	Retries int               `json:"retries"`
	Input   InputSchema       `json:"input"`
	Steps   []WorkflowStep    `json:"steps"`
	Output  map[string]string `json:"output"`
	// SoftFailureTolerance configures how parallel step failures are handled (Issue #1082)
	// Supported values:
	//   - "none" or "" - All steps must succeed (default)
	//   - "any" - Continue if any step succeeds
	//   - "count:N" - At most N failures allowed
	//   - "percentage:N" - At least N% of steps must succeed
	//   - "required:step1,step2" - These specific steps must succeed, others can fail
	SoftFailureTolerance string `json:"soft_failure_tolerance,omitempty"`
}

type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

type WorkflowStep struct {
	Name      string                  `json:"name"`
	Type      string                  `json:"type"` // "llm-call", "connector-call", "conditional", etc.
	Provider  string                  `json:"provider,omitempty"`
	Model     string                  `json:"model,omitempty"`
	Prompt    string                  `json:"prompt,omitempty"`
	Function  string                  `json:"function,omitempty"`
	Condition string                  `json:"condition,omitempty"`
	IfTrue    []WorkflowStep          `json:"if_true,omitempty"`
	IfFalse   []WorkflowStep          `json:"if_false,omitempty"`
	Timeout   string                  `json:"timeout,omitempty"`
	MaxTokens int                     `json:"max_tokens,omitempty"`
	Branches  map[string]WorkflowStep `json:"branches,omitempty"`
	Output    map[string]interface{}  `json:"output_schema,omitempty"`

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
	UserContext  UserContext            `json:"user_context"`
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

// EngineExecutionIDPrefix is the prefix carried by every in-process
// declarative workflow-engine run (POST /api/v1/workflows/execute).
//
// #3442: this was `wf_`, the SAME prefix as a control-plane workflow_id, and
// the two are not the same kind of thing. A control-plane workflow is an
// EXTERNAL orchestrator's run registered with AxonFlow for governance: it is a
// row in `workflows`, it is addressed by /api/v1/workflows/{id}, its steps are
// approved from the portal Approvals queue, and it has a 1:1 execution_history
// projection. An engine execution is AxonFlow's own declarative engine running
// a workflow spec it was handed in the request body: it lives in
// WorkflowStorage (InMemoryWorkflowStorage in the shipped wiring), it is
// reachable through none of those routes, and it appears in `workflows`,
// `workflow_steps` and `execution_history` nowhere at all. Its only persisted
// trace is the replay recorder's request_id (#763).
//
// Two concepts, so two prefixes. `wf_` stays with the identifier that the API
// routes, the audit trail and the operator's Approvals screen all key on;
// this one moved. Nothing parses either prefix except
// UnifiedExecutionHandler.resolveExecution, for which the change is strictly
// an improvement: an engine id handed to /api/v1/unified/executions/{id} no
// longer sends it hunting for a WCP workflow that cannot exist.
const EngineExecutionIDPrefix = "wfe_"

// newEngineExecutionID mints an in-process workflow-engine execution id.
//
// ENTROPY: a whole-second timestamp plus 8 characters drawn from a 36-symbol
// alphabet by generateRandomString, which is crypto/rand backed - about 41
// bits of randomness, and a collision additionally requires the same second.
// The shape is unchanged from before #3442 (only the prefix moved): the
// timestamp is load-bearing for sorting and log correlation, and 41 bits
// within one second is not the defect #3442 is about. Contrast the
// control-plane minter (workflow_control.NewWorkflowID, 122 bits), whose ids
// are a database-wide PRIMARY KEY over a table nothing prunes.
//
// One helper for its two call sites (ExecuteWorkflow,
// executeWorkflowWithStepGroups) so they cannot drift - the way the two control-plane copies did.
func newEngineExecutionID() string {
	return fmt.Sprintf("%s%d_%s", EngineExecutionIDPrefix, time.Now().Unix(), generateRandomString(8))
}

// StepProcessor interface for different step types
type StepProcessor interface {
	ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error)
}

// stepContentRenderer is a step processor that says what content a step will
// send, by the same function its ExecuteStep sends it with: the parts it sends,
// each presented as content (mapStepContent).
type stepContentRenderer interface {
	RenderStepContent(step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) []any
}

// sortedInputKeys returns m's keys in order.
func sortedInputKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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
	llmRouter LLMRouterInterface
}

func NewLLMCallProcessor(router LLMRouterInterface) *LLMCallProcessor {
	return &LLMCallProcessor{llmRouter: router}
}

func (p *LLMCallProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	log.Printf("[LLM] Executing step '%s' for workflow %s", step.Name, execution.ID)

	// The query this step sends is llmCallQuery's, the same function the
	// multi-agent plane decides the step's rendered content by.
	prompt := p.llmCallQuery(step, input, execution)
	log.Printf("[LLM] Step '%s': Prompt length = %d chars", step.Name, len(prompt))

	if p.isSynthesisStep(step.Name) {
		log.Printf("[LLM] Step '%s' is a synthesis step - previous outputs were injected", step.Name)

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

	// The organization's route rows bind this call as they bind
	// /api/v1/process, and rows that permit nothing refuse it before any
	// provider is called (#4249 row 5701303521, llm_call_route_effects.go).
	if err := applyLLMCallRoutes(ctx, req, &req); err != nil {
		log.Printf("[LLM] Step '%s': refused by the organization's route rows - %v", step.Name, err)
		// A policy refusal, never a failed step: typed as the plane's step
		// refusal, so an execution's soft_failure_tolerance does not absorb it
		// and the execute routes answer it 403 (sendStepRefusal). It carries the
		// route refusal, which errors.As still finds.
		var refusal *llmCallRouteRefusal
		if stderrors.As(err, &refusal) {
			return nil, &mapStepRefusal{code: mapStepRouteRefused, policy: refusal.Reason, reason: refusal.Error(), cause: refusal}
		}
		return nil, err
	}

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
		"response":      response.Content,
		"provider":      providerInfo.Provider,
		"model":         providerInfo.Model,
		"tokens_used":   providerInfo.TokensUsed,
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

// llmCallQuery is the query an llm-call step sends: its prompt with the template
// variables replaced, and for a synthesis step the previous steps' outputs
// appended. It is pure, so the multi-agent plane renders the step with it
// before the step runs and decides exactly what the step will send (#4249 row
// 5666236540); ExecuteStep sends what it returns.
func (p *LLMCallProcessor) llmCallQuery(step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) string {
	prompt := p.replaceTemplateVars(step.Prompt, input, execution)
	if p.isSynthesisStep(step.Name) {
		if previousOutputs := p.buildPreviousOutputsContext(execution); previousOutputs != "" {
			prompt = prompt + "\n\n" + previousOutputs
		}
	}
	return prompt
}

// RenderStepContent is the content an llm-call step sends: its query.
func (p *LLMCallProcessor) RenderStepContent(step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) []any {
	return []any{p.llmCallQuery(step, input, execution)}
}

func (p *LLMCallProcessor) replaceTemplateVars(template string, stepInput map[string]interface{}, execution *WorkflowExecution) string {
	result := template

	// Replace {{input.key}} variables, in key order: a value that itself holds
	// a placeholder is expanded the same way every time, so the content the
	// plane decides is the content the step sends.
	for _, key := range sortedInputKeys(stepInput) {
		value := stepInput[key]
		placeholder := fmt.Sprintf("{{input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}

	// Replace {{steps.stepname.output.key}} variables, in key order too.
	for _, stepExec := range execution.Steps {
		if stepExec.Status == "completed" {
			for _, key := range sortedInputKeys(stepExec.Output) {
				value := stepExec.Output[key]
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

			fmt.Fprintf(&builder, "## Step: %s\n", stepExec.Name)

			// Include the formatted response if available (for connectors)
			if response, ok := stepExec.Output["response"].(string); ok && response != "" {
				builder.WriteString(response)
				builder.WriteString("\n\n")
			} else {
				// Fallback: show raw output
				if len(stepExec.Output) > 0 {
					for _, key := range sortedInputKeys(stepExec.Output) {
						value := stepExec.Output[key]
						// Skip internal fields
						if key == "provider" || key == "model" || key == "tokens_used" || key == "response_time" || key == "duration" || key == "cached" || key == "connector" {
							continue
						}
						fmt.Fprintf(&builder, "  %s: %v\n", key, value)
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

// Conditional Step Processor - executes branches based on condition evaluation (Issue #1082)
type ConditionalProcessor struct {
	engine *WorkflowEngine
}

func NewConditionalProcessor(engine *WorkflowEngine) *ConditionalProcessor {
	return &ConditionalProcessor{engine: engine}
}

func (p *ConditionalProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	// #4249 row 5665091860: branch steps run only when each is presented to the
	// engine first, through the gate the presenting path carries on ctx
	// (map_conditional_gate.go). With no gate, a conditional carrying branch
	// steps is refused with the v11.0.0 message and nothing runs; with a gate
	// but no position, it is refused rather than recording unpathed decisions.
	gate := conditionalGateFrom(ctx)
	path := conditionalPathFrom(ctx)
	if branchSteps := len(step.IfTrue) + len(step.IfFalse); branchSteps > 0 {
		if gate == nil {
			return nil, p.unpresentedBranchesError(step, path, branchSteps)
		}
		if path == "" {
			return nil, errConditionalPathMissing
		}
	}

	// Evaluate condition
	conditionResult := p.evaluateCondition(step.Condition, execution)

	output := map[string]interface{}{
		"condition_evaluated": step.Condition,
		"condition_result":    conditionResult,
		"branch_taken":        "",
		"branch_steps":        make([]map[string]interface{}, 0),
	}

	// Select appropriate branch based on condition result
	var stepsToExecute []WorkflowStep
	if conditionResult {
		stepsToExecute = step.IfTrue
		output["branch_taken"] = "if_true"
	} else {
		stepsToExecute = step.IfFalse
		output["branch_taken"] = "if_false"
	}

	// Issue #1082: Actually execute branch steps instead of just recording
	branchOutputs := make([]map[string]interface{}, 0, len(stepsToExecute))
	currentInput := input

	branchName, _ := output["branch_taken"].(string)
	for branchIndex, branchStep := range stepsToExecute {
		// #4249: a conditional carrying no branch steps invokes nothing and is
		// not presented, as at top level.
		if mapStepNotPresented(branchStep) {
			continue
		}
		branchPath := fmt.Sprintf("%s.%s.%d", path, branchName, branchIndex)
		branchCtx := ctx
		if branchStep.Type == mapStepTypeConditional {
			// A conditional carrying branch steps is not itself presented (no
			// action names a conditional): its own branch steps are, one level
			// down, through this processor with the extended position.
			branchCtx = withConditionalPath(ctx, branchPath)
		} else if gate != nil {
			if err := gateBranchStep(ctx, gate, branchStep, currentInput, execution, branchPath); err != nil {
				return nil, err
			}
		}

		// Get processor for the step type
		processor, exists := p.engine.stepProcessors[branchStep.Type]
		if !exists {
			return nil, fmt.Errorf("unknown step type in conditional branch: %s", branchStep.Type)
		}

		// Record branch step in execution
		branchStepExec := StepExecution{
			Name:      branchStep.Name,
			Status:    "running",
			StartTime: time.Now(),
			Input:     currentInput,
		}
		execution.Steps = append(execution.Steps, branchStepExec)
		stepIdx := len(execution.Steps) - 1

		// Execute the branch step
		stepOutput, err := processor.ExecuteStep(branchCtx, branchStep, currentInput, execution)
		now := time.Now()

		if err != nil {
			execution.Steps[stepIdx].Status = "failed"
			execution.Steps[stepIdx].Error = err.Error()
			execution.Steps[stepIdx].EndTime = &now
			return nil, fmt.Errorf("branch step %s failed: %w", branchStep.Name, err)
		}

		// Update step execution record
		execution.Steps[stepIdx].Status = "completed"
		execution.Steps[stepIdx].Output = stepOutput
		execution.Steps[stepIdx].EndTime = &now
		execution.Steps[stepIdx].ProcessTime = now.Sub(branchStepExec.StartTime).String()

		// Collect output and merge into input for next step
		branchOutputs = append(branchOutputs, map[string]interface{}{
			"step_name": branchStep.Name,
			"output":    stepOutput,
		})

		// Merge step output into context for subsequent steps in branch
		if stepOutput != nil {
			for key, value := range stepOutput {
				currentInput[fmt.Sprintf("step_%s_%s", branchStep.Name, key)] = value
			}
		}

		log.Printf("Completed conditional branch step: %s", branchStep.Name)
	}

	output["branch_steps"] = branchOutputs
	output["steps_executed"] = len(branchOutputs)

	return output, nil
}

// runnableStepCount is how many steps a run of steps can execute, for sizing its
// timeout: a conditional carrying branch steps counts as the larger of its two
// branches, recursively (only one branch runs), and every other step, a
// branchless conditional included, counts as one. It reads no receiver state,
// so it is called on a nil *ConditionalProcessor; it lives here because only
// the conditional processor and the admission refusal read branch fields.
func (*ConditionalProcessor) runnableStepCount(steps []WorkflowStep) int {
	count := 0
	for _, step := range steps {
		if step.Type != mapStepTypeConditional || len(step.IfTrue)+len(step.IfFalse) == 0 {
			count++
			continue
		}
		ifTrue := (*ConditionalProcessor)(nil).runnableStepCount(step.IfTrue)
		ifFalse := (*ConditionalProcessor)(nil).runnableStepCount(step.IfFalse)
		count += max(ifTrue, ifFalse)
	}
	return count
}

// unpresentedBranchesError is the v11.0.0 refusal of a conditional carrying
// branch steps where nothing presents them, naming the conditional's position
// when the context carries one (refuseUnpresentableSteps names an index in the
// list it was given, which here would always be 0).
func (p *ConditionalProcessor) unpresentedBranchesError(step WorkflowStep, path string, branchSteps int) error {
	position := "at an unrecorded position"
	if path != "" {
		position = "at " + path
	}
	return fmt.Errorf("conditional step %q (%s) carries %d branch steps, and a branch step is not presented to the policy engine; refusing the whole workflow rather than executing them undecided",
		step.Name, position, branchSteps)
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
	// Issue #1082: ConditionalProcessor now requires engine reference to execute branch steps
	engine.stepProcessors["conditional"] = NewConditionalProcessor(engine)
	engine.stepProcessors["function-call"] = NewFunctionCallProcessor()

	return engine
}

// InitializeWithDependencies sets up processors that need external dependencies
func (e *WorkflowEngine) InitializeWithDependencies(router LLMRouterInterface, amadeusClient *AmadeusClient) {
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

// SetStepGate wires the per-step decision every execution of this engine runs
// (#4382): checker decides each step before it runs, and audit records the
// decision. A nil audit logger records nothing.
func (e *WorkflowEngine) SetStepGate(checker HITLPolicyChecker, audit hitlAuditLogger) {
	e.stepGate = &mapStepGate{checker: checker, audit: audit}
}

// PresentsSteps reports whether this engine decides every step before it runs.
func (e *WorkflowEngine) PresentsSteps() bool {
	return e != nil && e.stepGate.presentsSteps()
}

// governStep decides step before it runs (#4382). It returns the refusal when
// the step must not run, and nil when it may. The declarative engine cannot
// pause, so every challenge is withheld.
func (e *WorkflowEngine) governStep(ctx context.Context, execution *WorkflowExecution, workflowName string, step WorkflowStep, input map[string]interface{}) error {
	if !e.stepGate.presentsSteps() {
		return nil
	}
	return e.stepGate.decide(ctx, execution, workflowName, step, stepContentFor(e, step, input), execution.UserContext)
}

// governedContext is ctx carrying the gate this execution's conditional branch
// steps are decided through (#4249 row 5665091860), when the engine decides
// steps.
func (e *WorkflowEngine) governedContext(ctx context.Context, execution *WorkflowExecution, workflowName string) context.Context {
	if !e.stepGate.presentsSteps() {
		return ctx
	}
	return withConditionalGate(ctx, e.stepGate.conditionalGate(e, execution, workflowName, execution.UserContext))
}

// failRefused ends an execution whose step the gate refused before it ran: the
// execution fails with the refusal's detail, in storage and in replay.
func (e *WorkflowEngine) failRefused(ctx context.Context, execution *WorkflowExecution, refusal error) {
	execution.Status = "failed"
	if r, ok := refusal.(*mapStepRefusal); ok {
		execution.Error = r.detail()
	} else {
		execution.Error = refusal.Error()
	}
	_ = e.storage.UpdateExecution(execution)
	if e.replayRecorder != nil {
		if replayErr := e.replayRecorder.FailExecution(ctx, execution.ID, execution.Error); replayErr != nil {
			log.Printf("[Replay] ERROR: Failed to mark execution as failed: %v", replayErr)
		}
	}
}

// SetReplayRecorder sets the execution replay recorder for snapshot capture
func (e *WorkflowEngine) SetReplayRecorder(recorder ReplayRecorder) {
	e.replayRecorder = recorder
}

// SetPricingConfig sets the pricing configuration for step cost calculation
func (e *WorkflowEngine) SetPricingConfig(config PlanCostEstimator) {
	e.pricingConfig = config
}

// GetCostEstimator returns the pricing configuration for external step cost calculation.
func (e *WorkflowEngine) GetCostEstimator() PlanCostEstimator {
	return e.pricingConfig
}

// Execute a workflow
func (e *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error) {
	// Create execution instance
	execution := &WorkflowExecution{
		ID:           newEngineExecutionID(),
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

	// Start replay tracking (#763)
	if e.replayRecorder != nil {
		if err := e.replayRecorder.StartExecution(ctx, execution.ID, workflow.Metadata.Name, len(workflow.Spec.Steps), user.OrgID, user.TenantID, fmt.Sprintf("%d", user.ID)); err != nil {
			log.Printf("[Replay] Warning: Failed to start execution tracking: %v", err)
		}
	}

	// #4382: every step is decided before it runs, a conditional's branch steps
	// through the gate this context carries.
	ctx = e.governedContext(ctx, execution, workflow.Metadata.Name)

	// Execute steps sequentially (basic implementation)
	for stepIndex, step := range workflow.Spec.Steps {
		if refusal := e.governStep(ctx, execution, workflow.Metadata.Name, step, input); refusal != nil {
			e.failRefused(ctx, execution, refusal)
			return execution, refusal
		}
		stepCtx := ctx
		if step.Type == mapStepTypeConditional {
			// The conditional's position, read only for its branch decisions'
			// audit rows.
			stepCtx = withConditionalPath(ctx, strconv.Itoa(stepIndex))
		}

		stepExecution := StepExecution{
			Name:      step.Name,
			Status:    "running",
			StartTime: time.Now(),
			Input:     input, // Pass current input to step
		}

		execution.Steps = append(execution.Steps, stepExecution)
		// The step's own record: a conditional appends its branch steps' records
		// after it while it runs, so the last record is not this step's
		// (#4249 row 5774060413; the retired HITL engine kept this since #4353).
		recordIdx := len(execution.Steps) - 1

		// Get step processor
		processor, exists := e.stepProcessors[step.Type]
		if !exists {
			err := fmt.Errorf("unknown step type: %s", step.Type)
			stepExecution.Status = "failed"
			stepExecution.Error = err.Error()
			execution.Status = "failed"
			execution.Error = err.Error()
			_ = e.storage.UpdateExecution(execution)

			// Record failed step snapshot (#763)
			e.recordStepSnapshot(ctx, execution.ID, stepIndex, step.Name, "failed", stepExecution.StartTime, nil, nil, nil, err.Error(), input)

			// Mark execution as failed
			if e.replayRecorder != nil {
				if replayErr := e.replayRecorder.FailExecution(ctx, execution.ID, err.Error()); replayErr != nil {
					log.Printf("[Replay] ERROR: Failed to mark execution as failed: %v", replayErr)
				}
			}
			return execution, err
		}

		// Execute step
		stepOutput, err := processor.ExecuteStep(stepCtx, step, input, execution)
		now := time.Now()
		stepExecution.EndTime = &now
		stepExecution.ProcessTime = now.Sub(stepExecution.StartTime).String()
		durationMs := int(now.Sub(stepExecution.StartTime).Milliseconds())

		if err != nil {
			stepExecution.Status = "failed"
			stepExecution.Error = err.Error()
			execution.Status = "failed"
			execution.Error = fmt.Sprintf("Step %s failed: %v", step.Name, err)

			// Update execution state
			execution.Steps[recordIdx] = stepExecution
			_ = e.storage.UpdateExecution(execution)

			// Record failed step snapshot (#763)
			e.recordStepSnapshot(ctx, execution.ID, stepIndex, step.Name, "failed", stepExecution.StartTime, &now, &durationMs, stepOutput, err.Error(), input)

			// Mark execution as failed
			if e.replayRecorder != nil {
				if replayErr := e.replayRecorder.FailExecution(ctx, execution.ID, err.Error()); replayErr != nil {
					log.Printf("[Replay] ERROR: Failed to mark execution as failed: %v", replayErr)
				}
			}
			return execution, err
		}

		stepExecution.Status = "completed"
		stepExecution.Output = stepOutput

		// Update execution state
		execution.Steps[recordIdx] = stepExecution

		// Record completed step snapshot (#763)
		e.recordStepSnapshot(ctx, execution.ID, stepIndex, step.Name, "completed", stepExecution.StartTime, &now, &durationMs, stepOutput, "", input)

		// Update input for next step (pass output of current step)
		// Merge step output into available context for template replacement
		if stepOutput != nil {
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

	// Complete replay tracking (#763)
	if e.replayRecorder != nil {
		outputSummary, _ := json.Marshal(execution.Output)
		if err := e.replayRecorder.CompleteExecution(ctx, execution.ID, outputSummary); err != nil {
			log.Printf("[Replay] Warning: Failed to complete execution tracking: %v", err)
		}
	}

	log.Printf("Workflow execution completed: %s in %s", execution.ID, now.Sub(execution.StartTime).String())
	return execution, nil
}

// recordStepSnapshot records a step execution snapshot for replay (#763)
// Added input parameter for policy extraction (Issue #1020)
func (e *WorkflowEngine) recordStepSnapshot(ctx context.Context, requestID string, stepIndex int, stepName, status string, startedAt time.Time, completedAt *time.Time, durationMs *int, output map[string]interface{}, errMsg string, input map[string]interface{}) {
	if e.replayRecorder == nil {
		return
	}

	// Convert output to JSON
	var outputJSON json.RawMessage
	if output != nil {
		outputJSON, _ = json.Marshal(output)
	}

	// Extract LLM details from output if available
	var provider, model string
	var tokensIn, tokensOut int
	if output != nil {
		if p, ok := output["provider"].(string); ok {
			provider = p
		}
		if m, ok := output["model"].(string); ok {
			model = m
		}
		switch t := output["tokens_used"].(type) {
		case int:
			tokensIn = t / 2 // Approximate split
			tokensOut = t - tokensIn
		case float64:
			total := int(t)
			tokensIn = total / 2
			tokensOut = total - tokensIn
		case json.Number:
			if total, err := t.Int64(); err == nil {
				tokensIn = int(total) / 2
				tokensOut = int(total) - tokensIn
			}
		case string:
			if total, err := strconv.Atoi(t); err == nil {
				tokensIn = total / 2
				tokensOut = total - tokensIn
			}
		}
	}

	// Calculate cost from tokens using pricing config
	var costUSD float64
	if e.pricingConfig != nil && tokensIn+tokensOut > 0 {
		costUSD = e.pricingConfig.EstimateCost(provider, model, tokensIn, tokensOut)
	}

	// Extract policy info from input context (Issue #1020)
	var policiesChecked []string
	var policiesTriggered []PolicyEventInput
	if input != nil {
		if policyResultRaw, ok := input["_policy_result"]; ok {
			// Type assertion to extract policy result fields
			// The policy result is stored as *PolicyEvaluationResult
			if policyResult, ok := policyResultRaw.(*PolicyEvaluationResult); ok && policyResult != nil {
				policiesChecked = policyResult.AppliedPolicies
				// Note: PolicyEvaluationResult doesn't have detailed PolicyEvents,
				// so we create minimal events from applied policies
				for _, policyName := range policyResult.AppliedPolicies {
					policiesTriggered = append(policiesTriggered, PolicyEventInput{
						PolicyName: policyName,
						Action:     "evaluated",
						Resolution: "allowed",
					})
				}
			}
		}
	}

	snapshot := &ReplaySnapshotInput{
		RequestID:         requestID,
		StepIndex:         stepIndex,
		StepName:          stepName,
		Status:            status,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		DurationMs:        durationMs,
		Output:            outputJSON,
		Provider:          provider,
		Model:             model,
		TokensIn:          tokensIn,
		TokensOut:         tokensOut,
		CostUSD:           costUSD,
		Error:             errMsg,
		PoliciesChecked:   policiesChecked,
		PoliciesTriggered: policiesTriggered,
	}

	if err := e.replayRecorder.RecordStep(ctx, snapshot); err != nil {
		log.Printf("[Replay] Warning: Failed to record step snapshot: %v", err)
	}
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
//
//nolint:unused // Used in tests
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
	// Group steps by parallelizability
	stepGroups := e.groupStepsForExecution(workflow.Spec.Steps, enableParallel)
	return e.executeWorkflowWithStepGroups(ctx, workflow, input, user, stepGroups, enableParallel)
}

// executeWorkflowWithStepGroups is the shared execution loop for both parallel and balanced modes.
// It takes pre-computed step groups and executes them in order.
func (e *WorkflowEngine) executeWorkflowWithStepGroups(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext, stepGroups []StepGroup, enableParallel bool) (*WorkflowExecution, error) {
	// Initialize input map if nil
	if input == nil {
		input = make(map[string]interface{})
	}

	// Create execution instance
	execution := &WorkflowExecution{
		ID:           newEngineExecutionID(),
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

	// Start replay tracking (#835: wire MAP execution to replay)
	if e.replayRecorder != nil {
		if err := e.replayRecorder.StartExecution(ctx, execution.ID, workflow.Metadata.Name, len(workflow.Spec.Steps), user.OrgID, user.TenantID, fmt.Sprintf("%d", user.ID)); err != nil {
			log.Printf("[Replay] Warning: Failed to start execution tracking: %v", err)
		}
	}

	// Track global step index across groups for replay snapshots (#835)
	globalStepIndex := 0

	// #4382: every step is decided before it runs, a conditional's branch steps
	// through the gate this context carries.
	ctx = e.governedContext(ctx, execution, workflow.Metadata.Name)

	// Execute step groups
	for groupIdx, group := range stepGroups {
		log.Printf("[Workflow] Executing step group %d/%d with %d steps (parallel=%v)",
			groupIdx+1, len(stepGroups), len(group.Steps), group.IsParallel)

		if group.IsParallel && len(group.Steps) > 1 {
			// #4382: the whole group is decided before any of its steps launches,
			// and a refusal of any one runs none of them.
			for _, step := range group.Steps {
				if refusal := e.governStep(ctx, execution, workflow.Metadata.Name, step, input); refusal != nil {
					log.Printf("[Workflow] Step group %d refused before it ran: %v", groupIdx+1, refusal)
					e.failRefused(ctx, execution, refusal)
					return execution, refusal
				}
			}
			// Execute steps in parallel with configurable failure tolerance (Issue #1082)
			groupResults, err := e.executeStepsParallel(ctx, group, input, execution, workflow.Spec.SoftFailureTolerance)
			if err != nil {
				log.Printf("[Workflow] Step group %d FAILED: %v", groupIdx+1, err)
				execution.Status = "failed"
				execution.Error = err.Error()
				_ = e.storage.UpdateExecution(execution)

				// Record failed parallel step snapshots for replay (#835)
				for i, result := range groupResults {
					status := "completed"
					errMsg := ""
					if result.Error != "" {
						status = "failed"
						errMsg = result.Error
					}
					var durationMs *int
					if result.EndTime != nil {
						d := int(result.EndTime.Sub(result.StartTime).Milliseconds())
						durationMs = &d
					}
					e.recordStepSnapshot(ctx, execution.ID, globalStepIndex+i, result.Name, status, result.StartTime, result.EndTime, durationMs, result.Output, errMsg, input)
				}
				// Mark replay execution as failed (#835)
				if e.replayRecorder != nil {
					if replayErr := e.replayRecorder.FailExecution(ctx, execution.ID, err.Error()); replayErr != nil {
						log.Printf("[Replay] ERROR: Failed to mark execution as failed: %v", replayErr)
					}
				}
				return execution, err
			}

			// Record parallel step snapshots for replay (#835)
			for i, result := range groupResults {
				status := "completed"
				errMsg := ""
				if result.Error != "" {
					status = "failed"
					errMsg = result.Error
				}
				var durationMs *int
				if result.EndTime != nil {
					d := int(result.EndTime.Sub(result.StartTime).Milliseconds())
					durationMs = &d
				}
				e.recordStepSnapshot(ctx, execution.ID, globalStepIndex+i, result.Name, status, result.StartTime, result.EndTime, durationMs, result.Output, errMsg, input)
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
			globalStepIndex += len(groupResults)
		} else {
			// Execute steps sequentially
			log.Printf("[Workflow] Executing %d steps sequentially in group %d", len(group.Steps), groupIdx+1)
			for j, step := range group.Steps {
				if refusal := e.governStep(ctx, execution, workflow.Metadata.Name, step, input); refusal != nil {
					log.Printf("[Workflow] Sequential step '%s' refused before it ran in group %d: %v", step.Name, groupIdx+1, refusal)
					e.failRefused(ctx, execution, refusal)
					return execution, refusal
				}
				stepCtx := ctx
				if step.Type == mapStepTypeConditional {
					// The conditional's position in the workflow, read only for its
					// branch decisions' audit rows.
					stepCtx = withConditionalPath(ctx, strconv.Itoa(group.position(j, globalStepIndex)))
				}
				stepResult, err := e.executeSingleStep(stepCtx, step, input, execution)

				// Record step snapshot for replay (#835)
				stepStatus := "completed"
				errMsg := ""
				if err != nil {
					stepStatus = "failed"
					errMsg = err.Error()
				}
				var durationMs *int
				if stepResult.EndTime != nil {
					d := int(stepResult.EndTime.Sub(stepResult.StartTime).Milliseconds())
					durationMs = &d
				}
				e.recordStepSnapshot(ctx, execution.ID, globalStepIndex, stepResult.Name, stepStatus, stepResult.StartTime, stepResult.EndTime, durationMs, stepResult.Output, errMsg, input)
				globalStepIndex++

				if err != nil {
					log.Printf("[Workflow] Sequential step '%s' FAILED in group %d: %v", step.Name, groupIdx+1, err)
					// Note: Clients handle their own fallback logic - orchestrator returns errors
					execution.Status = "failed"
					execution.Error = fmt.Sprintf("Step %s failed: %v", step.Name, err)
					_ = e.storage.UpdateExecution(execution)
					// Mark replay execution as failed (#835)
					if e.replayRecorder != nil {
						if replayErr := e.replayRecorder.FailExecution(ctx, execution.ID, err.Error()); replayErr != nil {
							log.Printf("[Replay] ERROR: Failed to mark execution as failed: %v", replayErr)
						}
					}
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

	// Complete replay tracking (#835: wire MAP execution to replay)
	if e.replayRecorder != nil {
		outputSummary, _ := json.Marshal(execution.Output)
		if err := e.replayRecorder.CompleteExecution(ctx, execution.ID, outputSummary); err != nil {
			log.Printf("[Replay] Warning: Failed to complete execution tracking: %v", err)
		}
	}

	log.Printf("Workflow execution completed: %s in %s", execution.ID, now.Sub(execution.StartTime).String())
	return execution, nil
}

// StepGroup represents a group of steps that can be executed together
type StepGroup struct {
	IsParallel bool
	Steps      []WorkflowStep
	// Positions is each step's index in the workflow's steps, in Steps' order;
	// balanced grouping reorders steps. Empty when the group was built without
	// them.
	Positions []int
}

// position is the workflow index of the group's j-th step, or fallback when
// the group carries no positions.
func (g StepGroup) position(j, fallback int) int {
	if j < len(g.Positions) {
		return g.Positions[j]
	}
	return fallback
}

// indexRange is [from, to).
func indexRange(from, to int) []int {
	out := make([]int, 0, to-from)
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

// Group steps for execution (parallel vs sequential)
func (e *WorkflowEngine) groupStepsForExecution(steps []WorkflowStep, enableParallel bool) []StepGroup {
	if !enableParallel || len(steps) <= 1 {
		// All steps sequential
		return []StepGroup{{IsParallel: false, Steps: steps, Positions: indexRange(0, len(steps))}}
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
			Positions:  indexRange(0, len(steps)-1),
		})

		// Last step sequential (synthesis)
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      []WorkflowStep{steps[len(steps)-1]},
			Positions:  []int{len(steps) - 1},
		})
	} else {
		// Single step
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      steps,
			Positions:  indexRange(0, len(steps)),
		})
	}

	return groups
}

// ExecuteWorkflowBalanced executes a workflow with balanced mode:
// - connector-call steps run in parallel (I/O-bound)
// - llm-call steps run sequentially (rate-limit sensitive)
// - synthesis step always runs last
func (e *WorkflowEngine) ExecuteWorkflowBalanced(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error) {
	log.Printf("[Workflow] Executing in balanced mode: %s", workflow.Metadata.Name)

	stepGroups := groupStepsForBalancedExecution(workflow.Spec.Steps)
	log.Printf("[Workflow] Balanced mode grouped %d steps into %d groups", len(workflow.Spec.Steps), len(stepGroups))

	return e.executeWorkflowWithStepGroups(ctx, workflow, input, user, stepGroups, true)
}

// groupStepsForBalancedExecution groups steps by type for balanced execution:
// connector-call steps are grouped for parallel execution,
// llm-call steps run sequentially, synthesis step always last.
func groupStepsForBalancedExecution(steps []WorkflowStep) []StepGroup {
	if len(steps) <= 1 {
		return []StepGroup{{IsParallel: false, Steps: steps, Positions: indexRange(0, len(steps))}}
	}

	var groups []StepGroup
	var connectorSteps []WorkflowStep
	var llmSteps []WorkflowStep
	var synthesisStep *WorkflowStep
	var connectorPositions, llmPositions []int
	synthesisPosition := 0

	// Classify steps
	for i := range steps {
		step := steps[i]
		nameLower := strings.ToLower(step.Name)

		// Detect synthesis step (always last)
		if strings.Contains(nameLower, "synthesize") ||
			strings.Contains(nameLower, "combine") ||
			strings.Contains(nameLower, "final") ||
			strings.Contains(nameLower, "summary") {
			synthesisStep = &step
			synthesisPosition = i
			continue
		}

		if step.Type == "connector-call" {
			connectorSteps = append(connectorSteps, step)
			connectorPositions = append(connectorPositions, i)
		} else {
			llmSteps = append(llmSteps, step)
			llmPositions = append(llmPositions, i)
		}
	}

	// Connector calls run in parallel (I/O-bound)
	if len(connectorSteps) > 0 {
		groups = append(groups, StepGroup{
			IsParallel: len(connectorSteps) > 1,
			Steps:      connectorSteps,
			Positions:  connectorPositions,
		})
	}

	// LLM calls run sequentially (rate-limit sensitive)
	if len(llmSteps) > 0 {
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      llmSteps,
			Positions:  llmPositions,
		})
	}

	// Synthesis step always runs last, sequentially
	if synthesisStep != nil {
		groups = append(groups, StepGroup{
			IsParallel: false,
			Steps:      []WorkflowStep{*synthesisStep},
			Positions:  []int{synthesisPosition},
		})
	}

	return groups
}

// Execute steps in parallel using goroutines
// softFailureTolerance configures how failures are handled (Issue #1082):
//   - "none" or "" - All steps must succeed (strict mode)
//   - "any" - Continue if any step succeeds
//   - "count:N" - At most N failures allowed
//   - "percentage:N" - At least N% of steps must succeed
//   - "required:step1,step2" - These specific steps must succeed, others can fail
//
// The group carries its steps' workflow positions, so a conditional among them
// has its branch decisions recorded at its position (#4382).
func (e *WorkflowEngine) executeStepsParallel(ctx context.Context, group StepGroup, input map[string]interface{}, execution *WorkflowExecution, softFailureTolerance string) ([]StepExecution, error) {
	steps := group.Steps
	numSteps := len(steps)
	results := make([]StepExecution, numSteps)
	errors := make([]error, numSteps)

	var wg sync.WaitGroup

	// Create a read-only snapshot of input for parallel goroutines.
	// This prevents potential data races if any step processor writes to the input map.
	inputSnapshot := make(map[string]interface{}, len(input))
	for k, v := range input {
		inputSnapshot[k] = v
	}

	for i, step := range steps {
		wg.Add(1)
		go func(idx int, s WorkflowStep) {
			defer wg.Done()

			log.Printf("[Parallel] Starting step %d/%d: %s", idx+1, numSteps, s.Name)

			stepCtx := ctx
			if s.Type == mapStepTypeConditional {
				// The conditional's position in the workflow, read only for its
				// branch decisions' audit rows.
				stepCtx = withConditionalPath(ctx, strconv.Itoa(group.position(idx, idx)))
			}
			stepResult, err := e.executeSingleStep(stepCtx, s, inputSnapshot, execution)
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

	// #4382: a step the plane refused (a conditional's branch step, decided
	// inside its processor) is a governance decision, not a failure a
	// soft_failure_tolerance can absorb: the group fails with the refusal.
	for _, err := range errors {
		var refusal *mapStepRefusal
		if stderrors.As(err, &refusal) {
			return results, refusal
		}
	}

	// Collect failed and succeeded steps
	failedSteps := []string{}
	succeededSteps := []string{}

	for i, err := range errors {
		if err != nil {
			failedSteps = append(failedSteps, steps[i].Name)
		} else {
			succeededSteps = append(succeededSteps, steps[i].Name)
		}
	}

	// If all steps succeeded, return success
	if len(failedSteps) == 0 {
		return results, nil
	}

	// Apply soft failure tolerance policy (Issue #1082)
	shouldFail := e.evaluateFailureTolerance(softFailureTolerance, steps, failedSteps, succeededSteps)

	if shouldFail {
		if len(failedSteps) == len(steps) {
			return results, fmt.Errorf("all parallel steps failed: %v", failedSteps)
		}
		return results, fmt.Errorf("parallel execution failed per tolerance policy '%s': failed steps: %v", softFailureTolerance, failedSteps)
	}

	// Continue with partial results
	log.Printf("[Parallel] %d/%d steps failed (%v), continuing per tolerance policy '%s'",
		len(failedSteps), len(steps), failedSteps, softFailureTolerance)
	return results, nil
}

// evaluateFailureTolerance determines if workflow should fail based on tolerance policy
func (e *WorkflowEngine) evaluateFailureTolerance(tolerance string, steps []WorkflowStep, failedSteps, succeededSteps []string) bool {
	totalSteps := len(steps)
	failedCount := len(failedSteps)
	succeededCount := len(succeededSteps)

	// Default: strict mode - all steps must succeed
	if tolerance == "" || tolerance == "none" {
		return failedCount > 0
	}

	// "any" - continue if any step succeeds
	if tolerance == "any" {
		return succeededCount == 0
	}

	// "count:N" - at most N failures allowed
	if strings.HasPrefix(tolerance, "count:") {
		maxFailures := 0
		if _, err := fmt.Sscanf(tolerance, "count:%d", &maxFailures); err == nil {
			return failedCount > maxFailures
		}
		// Parse failed - fall through to default "none" behavior
	}

	// "percentage:N" - at least N% must succeed
	if strings.HasPrefix(tolerance, "percentage:") {
		minPercent := 0
		if _, err := fmt.Sscanf(tolerance, "percentage:%d", &minPercent); err == nil {
			actualPercent := (succeededCount * 100) / totalSteps
			return actualPercent < minPercent
		}
		// Parse failed - fall through to default "none" behavior
	}

	// "required:step1,step2" - these specific steps must succeed
	if strings.HasPrefix(tolerance, "required:") {
		requiredStepsStr := strings.TrimPrefix(tolerance, "required:")
		requiredSteps := strings.Split(requiredStepsStr, ",")

		// Check if any required step failed
		failedSet := make(map[string]bool)
		for _, s := range failedSteps {
			failedSet[s] = true
		}

		for _, required := range requiredSteps {
			required = strings.TrimSpace(required)
			if failedSet[required] {
				log.Printf("[Parallel] Required step '%s' failed", required)
				return true
			}
		}
		// All required steps succeeded, allow partial failure
		return false
	}

	// Unknown tolerance - default to strict
	log.Printf("[Parallel] Unknown soft_failure_tolerance '%s', using strict mode", tolerance)
	return failedCount > 0
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
