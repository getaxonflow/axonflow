package axonflow

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ListExecutions returns a paginated list of execution summaries.
func (c *Client) ListExecutions(opts ListOptions) (*ListExecutionsResponse, error) {
	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.Itoa(opts.Offset))
	}
	if opts.Status != "" {
		params.Set("status", opts.Status)
	}
	if opts.WorkflowID != "" {
		params.Set("workflow_id", opts.WorkflowID)
	}

	path := "/api/v1/executions"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	body, status, err := c.do("GET", path)
	if err != nil {
		return nil, err
	}
	if err := checkError(body, status); err != nil {
		return nil, err
	}

	var resp ListExecutionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &resp, nil
}

// GetExecution returns the full execution details including all steps.
func (c *Client) GetExecution(requestID string) (*Execution, error) {
	path := fmt.Sprintf("/api/v1/executions/%s", url.PathEscape(requestID))

	body, status, err := c.do("GET", path)
	if err != nil {
		return nil, err
	}
	if err := checkError(body, status); err != nil {
		return nil, err
	}

	var exec Execution
	if err := json.Unmarshal(body, &exec); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &exec, nil
}

// GetExecutionSteps returns all steps for an execution.
func (c *Client) GetExecutionSteps(requestID string) ([]ExecutionSnapshot, error) {
	path := fmt.Sprintf("/api/v1/executions/%s/steps", url.PathEscape(requestID))

	body, status, err := c.do("GET", path)
	if err != nil {
		return nil, err
	}
	if err := checkError(body, status); err != nil {
		return nil, err
	}

	var steps []ExecutionSnapshot
	if err := json.Unmarshal(body, &steps); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return steps, nil
}

// GetExecutionTimeline returns a simplified timeline view of an execution.
func (c *Client) GetExecutionTimeline(requestID string) ([]TimelineEntry, error) {
	path := fmt.Sprintf("/api/v1/executions/%s/timeline", url.PathEscape(requestID))

	body, status, err := c.do("GET", path)
	if err != nil {
		return nil, err
	}
	if err := checkError(body, status); err != nil {
		return nil, err
	}

	var timeline []TimelineEntry
	if err := json.Unmarshal(body, &timeline); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return timeline, nil
}

// ExportExecution downloads the exported execution data as raw JSON.
func (c *Client) ExportExecution(requestID string, includeIO bool) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("format", "json")
	if includeIO {
		params.Set("include_input", "true")
		params.Set("include_output", "true")
	}
	params.Set("include_policies", "true")

	path := fmt.Sprintf("/api/v1/executions/%s/export?%s", url.PathEscape(requestID), params.Encode())

	body, status, err := c.do("GET", path)
	if err != nil {
		return nil, err
	}
	if err := checkError(body, status); err != nil {
		return nil, err
	}

	return json.RawMessage(body), nil
}
