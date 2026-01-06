// Package axonflow provides Execution Replay API methods for debugging and compliance.
//
// The Execution Replay API captures every step of workflow execution for debugging,
// auditing, and compliance purposes.
package axonflow

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

// ============================================================================
// Execution Replay Types
// ============================================================================

// ExecutionSummary represents a workflow execution summary
type ExecutionSummary struct {
	RequestID      string  `json:"request_id"`
	WorkflowName   string  `json:"workflow_name"`
	Status         string  `json:"status"` // "running", "completed", "failed"
	TotalSteps     int     `json:"total_steps"`
	CompletedSteps int     `json:"completed_steps"`
	StartedAt      string  `json:"started_at"`
	CompletedAt    *string `json:"completed_at,omitempty"`
	DurationMs     *int    `json:"duration_ms,omitempty"`
	TotalTokens    int     `json:"total_tokens"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	OrgID          string  `json:"org_id,omitempty"`
	TenantID       string  `json:"tenant_id,omitempty"`
	UserID         string  `json:"user_id,omitempty"`
	ErrorMessage   string  `json:"error_message,omitempty"`
	InputSummary   any     `json:"input_summary,omitempty"`
	OutputSummary  any     `json:"output_summary,omitempty"`
}

// ExecutionSnapshot represents a step in a workflow execution
type ExecutionSnapshot struct {
	RequestID         string   `json:"request_id"`
	StepIndex         int      `json:"step_index"`
	StepName          string   `json:"step_name"`
	Status            string   `json:"status"` // "pending", "running", "completed", "failed", "paused", "skipped"
	StartedAt         string   `json:"started_at"`
	CompletedAt       *string  `json:"completed_at,omitempty"`
	DurationMs        *int     `json:"duration_ms,omitempty"`
	Provider          string   `json:"provider,omitempty"`
	Model             string   `json:"model,omitempty"`
	TokensIn          int      `json:"tokens_in"`
	TokensOut         int      `json:"tokens_out"`
	CostUSD           float64  `json:"cost_usd"`
	Input             any      `json:"input,omitempty"`
	Output            any      `json:"output,omitempty"`
	ErrorMessage      string   `json:"error_message,omitempty"`
	PoliciesChecked   []string `json:"policies_checked,omitempty"`
	PoliciesTriggered []string `json:"policies_triggered,omitempty"`
	ApprovalRequired  bool     `json:"approval_required,omitempty"`
	ApprovedBy        string   `json:"approved_by,omitempty"`
	ApprovedAt        string   `json:"approved_at,omitempty"`
}

// TimelineEntry represents an entry in the execution timeline
type TimelineEntry struct {
	StepIndex   int     `json:"step_index"`
	StepName    string  `json:"step_name"`
	Status      string  `json:"status"`
	StartedAt   string  `json:"started_at"`
	CompletedAt *string `json:"completed_at,omitempty"`
	DurationMs  *int    `json:"duration_ms,omitempty"`
	HasError    bool    `json:"has_error"`
	HasApproval bool    `json:"has_approval"`
}

// ListExecutionsResponse represents the response from list executions API
type ListExecutionsResponse struct {
	Executions []ExecutionSummary `json:"executions"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}

// ExecutionDetail represents a full execution with summary and steps
type ExecutionDetail struct {
	Summary *ExecutionSummary   `json:"summary"`
	Steps   []ExecutionSnapshot `json:"steps"`
}

// ListExecutionsOptions represents options for listing executions
type ListExecutionsOptions struct {
	Limit      int    // Number of results (default: 50, max: 100)
	Offset     int    // Pagination offset (default: 0)
	Status     string // Filter by status: "running", "completed", "failed"
	WorkflowID string // Filter by workflow name
	StartTime  string // Filter from timestamp (RFC3339)
	EndTime    string // Filter to timestamp (RFC3339)
}

// ExecutionExportOptions represents options for exporting an execution
type ExecutionExportOptions struct {
	Format          string // Export format: "json" (default)
	IncludeInput    bool   // Include step inputs (default: true)
	IncludeOutput   bool   // Include step outputs (default: true)
	IncludePolicies bool   // Include policy details (default: true)
}

// ============================================================================
// Execution Replay Methods
// ============================================================================

// Note: getOrchestratorURL was removed in v2.0.0 (ADR-026 Single Entry Point).
// All routes now go through the Agent endpoint (c.config.Endpoint).

// ListExecutions retrieves a paginated list of execution summaries.
//
// Example:
//
//	executions, err := client.ListExecutions(&ListExecutionsOptions{
//	    Status: "completed",
//	    Limit:  10,
//	})
//	for _, exec := range executions.Executions {
//	    fmt.Printf("%s: %s (%d steps)\n", exec.RequestID, exec.Status, exec.TotalSteps)
//	}
func (c *AxonFlowClient) ListExecutions(options *ListExecutionsOptions) (*ListExecutionsResponse, error) {
	baseURL := c.config.Endpoint

	// Build query parameters
	params := url.Values{}
	if options != nil {
		if options.Limit > 0 {
			params.Set("limit", strconv.Itoa(options.Limit))
		}
		if options.Offset > 0 {
			params.Set("offset", strconv.Itoa(options.Offset))
		}
		if options.Status != "" {
			params.Set("status", options.Status)
		}
		if options.WorkflowID != "" {
			params.Set("workflow_id", options.WorkflowID)
		}
		if options.StartTime != "" {
			params.Set("start_time", options.StartTime)
		}
		if options.EndTime != "" {
			params.Set("end_time", options.EndTime)
		}
	}

	reqURL := baseURL + "/api/v1/executions"
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to list executions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var result ListExecutionsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listed %d executions (total: %d)", len(result.Executions), result.Total)
	}

	return &result, nil
}

// GetExecution retrieves a complete execution record including summary and all steps.
//
// Example:
//
//	execution, err := client.GetExecution("exec-abc123")
//	fmt.Printf("Execution: %s - %s\n", execution.Summary.RequestID, execution.Summary.Status)
//	for _, step := range execution.Steps {
//	    fmt.Printf("  Step %d: %s (%dms)\n", step.StepIndex, step.StepName, *step.DurationMs)
//	}
func (c *AxonFlowClient) GetExecution(executionID string) (*ExecutionDetail, error) {
	baseURL := c.config.Endpoint
	reqURL := fmt.Sprintf("%s/api/v1/executions/%s", baseURL, executionID)

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var result ExecutionDetail
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Got execution %s: %s (%d steps)",
			executionID, result.Summary.Status, len(result.Steps))
	}

	return &result, nil
}

// GetExecutionSteps retrieves all step snapshots for an execution.
//
// Example:
//
//	steps, err := client.GetExecutionSteps("exec-abc123")
//	for _, step := range steps {
//	    fmt.Printf("Step %d: %s - %s\n", step.StepIndex, step.StepName, step.Status)
//	}
func (c *AxonFlowClient) GetExecutionSteps(executionID string) ([]ExecutionSnapshot, error) {
	baseURL := c.config.Endpoint
	reqURL := fmt.Sprintf("%s/api/v1/executions/%s/steps", baseURL, executionID)

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution steps: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var result []ExecutionSnapshot
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Got %d steps for execution %s", len(result), executionID)
	}

	return result, nil
}

// GetExecutionTimeline retrieves a timeline view of execution events for visualization.
//
// Example:
//
//	timeline, err := client.GetExecutionTimeline("exec-abc123")
//	for _, entry := range timeline {
//	    fmt.Printf("[%d] %s: %s", entry.StepIndex, entry.StepName, entry.Status)
//	    if entry.HasError {
//	        fmt.Print(" [ERROR]")
//	    }
//	    fmt.Println()
//	}
func (c *AxonFlowClient) GetExecutionTimeline(executionID string) ([]TimelineEntry, error) {
	baseURL := c.config.Endpoint
	reqURL := fmt.Sprintf("%s/api/v1/executions/%s/timeline", baseURL, executionID)

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution timeline: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var result []TimelineEntry
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Got timeline with %d entries for execution %s", len(result), executionID)
	}

	return result, nil
}

// ExportExecution downloads a complete execution record for compliance or archival.
//
// Example:
//
//	export, err := client.ExportExecution("exec-abc123", &ExecutionExportOptions{
//	    IncludeInput:  true,
//	    IncludeOutput: true,
//	})
//	// Save to file for audit
//	data, _ := json.MarshalIndent(export, "", "  ")
//	os.WriteFile("audit-export.json", data, 0644)
func (c *AxonFlowClient) ExportExecution(executionID string, options *ExecutionExportOptions) (map[string]interface{}, error) {
	baseURL := c.config.Endpoint

	// Build query parameters
	params := url.Values{}
	if options != nil {
		if options.Format != "" {
			params.Set("format", options.Format)
		}
		if options.IncludeInput {
			params.Set("include_input", "true")
		}
		if options.IncludeOutput {
			params.Set("include_output", "true")
		}
		if options.IncludePolicies {
			params.Set("include_policies", "true")
		}
	}

	reqURL := fmt.Sprintf("%s/api/v1/executions/%s/export", baseURL, executionID)
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	resp, err := c.httpClient.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to export execution: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Exported execution %s", executionID)
	}

	return result, nil
}

// DeleteExecution deletes an execution and all associated step snapshots.
//
// Example:
//
//	err := client.DeleteExecution("exec-abc123")
//	if err != nil {
//	    log.Printf("Failed to delete: %v", err)
//	}
func (c *AxonFlowClient) DeleteExecution(executionID string) error {
	baseURL := c.config.Endpoint
	reqURL := fmt.Sprintf("%s/api/v1/executions/%s", baseURL, executionID)

	req, err := http.NewRequest(http.MethodDelete, reqURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete execution: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Deleted execution %s", executionID)
	}

	return nil
}
