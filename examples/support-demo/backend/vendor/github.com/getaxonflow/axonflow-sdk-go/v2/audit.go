// Audit log read methods for AxonFlow SDK
// These methods allow querying and retrieving audit logs from the AxonFlow platform.
package axonflow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ============================================================================
// Audit Log Types
// ============================================================================

// AuditSearchRequest represents a request to search audit logs
type AuditSearchRequest struct {
	// UserEmail filters logs by user email
	UserEmail string `json:"user_email,omitempty"`
	// ClientID filters logs by client/application ID
	ClientID string `json:"client_id,omitempty"`
	// StartTime is the beginning of the time range to search
	StartTime *time.Time `json:"start_time,omitempty"`
	// EndTime is the end of the time range to search
	EndTime *time.Time `json:"end_time,omitempty"`
	// RequestType filters by request type (e.g., "llm_chat", "policy_check")
	RequestType string `json:"request_type,omitempty"`
	// Limit is the maximum number of results to return (default: 100, max: 1000)
	Limit int `json:"limit,omitempty"`
	// Offset is the pagination offset (default: 0)
	Offset int `json:"offset,omitempty"`
}

// AuditQueryOptions provides options for GetAuditLogsByTenant
type AuditQueryOptions struct {
	// Limit is the maximum number of results to return (default: 50)
	Limit int `json:"limit,omitempty"`
	// Offset is the pagination offset (default: 0)
	Offset int `json:"offset,omitempty"`
}

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	// ID is the unique identifier for this audit entry
	ID string `json:"id"`
	// RequestID is the correlation ID for the original request
	RequestID string `json:"request_id"`
	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp"`
	// UserEmail is the email of the user who made the request
	UserEmail string `json:"user_email"`
	// ClientID is the client/application that made the request
	ClientID string `json:"client_id"`
	// TenantID is the tenant identifier
	TenantID string `json:"tenant_id"`
	// RequestType is the type of request (e.g., "llm_chat", "sql", "mcp-query")
	RequestType string `json:"request_type"`
	// QuerySummary is a summary of the query/request
	QuerySummary string `json:"query_summary"`
	// Success indicates whether the request succeeded
	Success bool `json:"success"`
	// Blocked indicates whether the request was blocked by policy
	Blocked bool `json:"blocked"`
	// RiskScore is the calculated risk score (0.0-1.0)
	RiskScore float64 `json:"risk_score"`
	// Provider is the LLM provider used (if applicable)
	Provider string `json:"provider"`
	// Model is the model used (if applicable)
	Model string `json:"model"`
	// TokensUsed is the total tokens consumed
	TokensUsed int `json:"tokens_used"`
	// LatencyMs is the request latency in milliseconds
	LatencyMs int `json:"latency_ms"`
	// PolicyViolations is a list of violated policy IDs (if any)
	PolicyViolations []string `json:"policy_violations,omitempty"`
	// Metadata contains additional context
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AuditSearchResponse represents the response from an audit search
type AuditSearchResponse struct {
	// Entries contains the audit log entries
	Entries []AuditLogEntry `json:"entries"`
	// Total is the total number of matching entries (for pagination)
	Total int `json:"total"`
	// Limit is the limit that was applied
	Limit int `json:"limit"`
	// Offset is the offset that was applied
	Offset int `json:"offset"`
}

// ============================================================================
// Audit Log Read Methods
// ============================================================================

// SearchAuditLogs searches audit logs with the specified filters.
//
// This method queries the AxonFlow orchestrator for audit logs matching
// the specified criteria. Use this for compliance dashboards, security
// investigations, and operational monitoring.
//
// Example:
//
//	// Search for audit logs from a specific user in the last 24 hours
//	yesterday := time.Now().Add(-24 * time.Hour)
//	now := time.Now()
//	req := &axonflow.AuditSearchRequest{
//	    UserEmail: "analyst@company.com",
//	    StartTime: &yesterday,
//	    EndTime:   &now,
//	    Limit:     100,
//	}
//
//	result, err := client.SearchAuditLogs(context.Background(), req)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, entry := range result.Entries {
//	    fmt.Printf("[%s] %s: %s (blocked: %v)\n",
//	        entry.Timestamp.Format(time.RFC3339),
//	        entry.UserEmail,
//	        entry.QuerySummary,
//	        entry.Blocked)
//	}
func (c *AxonFlowClient) SearchAuditLogs(ctx context.Context, req *AuditSearchRequest) (*AuditSearchResponse, error) {
	if req == nil {
		req = &AuditSearchRequest{}
	}

	// Apply defaults
	if req.Limit == 0 {
		req.Limit = 100
	}
	if req.Limit > 1000 {
		req.Limit = 1000
	}

	// Build request body
	reqBody := map[string]interface{}{}
	if req.UserEmail != "" {
		reqBody["user_email"] = req.UserEmail
	}
	if req.ClientID != "" {
		reqBody["client_id"] = req.ClientID
	}
	if req.StartTime != nil {
		reqBody["start_time"] = req.StartTime.Format(time.RFC3339)
	}
	if req.EndTime != nil {
		reqBody["end_time"] = req.EndTime.Format(time.RFC3339)
	}
	if req.RequestType != "" {
		reqBody["request_type"] = req.RequestType
	}
	reqBody["limit"] = req.Limit
	if req.Offset > 0 {
		reqBody["offset"] = req.Offset
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit search request: %w", err)
	}

	fullURL := c.config.Endpoint + "/api/v1/audit/search"

	httpReq, err := http.NewRequestWithContext(ctx, "POST", fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit search request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Audit search - Limit: %d, Offset: %d", req.Limit, req.Offset)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit search request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit search response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	// The API returns an array directly, wrap it in a response
	var entries []AuditLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// Try parsing as wrapped response
		var wrappedResp AuditSearchResponse
		if wrapErr := json.Unmarshal(body, &wrappedResp); wrapErr == nil {
			if c.config.Debug {
				log.Printf("[AxonFlow] Audit search returned %d entries", len(wrappedResp.Entries))
			}
			return &wrappedResp, nil
		}
		return nil, fmt.Errorf("failed to unmarshal audit search response: %w", err)
	}

	result := &AuditSearchResponse{
		Entries: entries,
		Total:   len(entries), // API doesn't return total, use entries count
		Limit:   req.Limit,
		Offset:  req.Offset,
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Audit search returned %d entries", len(result.Entries))
	}

	return result, nil
}

// GetAuditLogsByTenant retrieves recent audit logs for a specific tenant.
//
// This is a convenience method for tenant-scoped audit queries. Use this
// when you need to view all recent activity for a specific tenant.
//
// Example:
//
//	// Get the last 50 audit logs for a tenant
//	result, err := client.GetAuditLogsByTenant(context.Background(), "tenant-abc", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Found %d audit entries for tenant\n", len(result.Entries))
//	for _, entry := range result.Entries {
//	    fmt.Printf("  [%s] %s - %s\n",
//	        entry.Timestamp.Format(time.RFC3339),
//	        entry.RequestType,
//	        entry.QuerySummary)
//	}
//
//	// With custom options
//	opts := &axonflow.AuditQueryOptions{Limit: 100, Offset: 50}
//	result, err = client.GetAuditLogsByTenant(context.Background(), "tenant-abc", opts)
func (c *AxonFlowClient) GetAuditLogsByTenant(ctx context.Context, tenantID string, opts *AuditQueryOptions) (*AuditSearchResponse, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID is required")
	}

	// Apply defaults
	limit := 50
	offset := 0
	if opts != nil {
		if opts.Limit > 0 {
			limit = opts.Limit
		}
		if opts.Limit > 1000 {
			limit = 1000
		}
		if opts.Offset > 0 {
			offset = opts.Offset
		}
	}

	fullURL := fmt.Sprintf("%s/api/v1/audit/tenant/%s?limit=%d&offset=%d",
		c.config.Endpoint, tenantID, limit, offset)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant audit request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	c.addAuthHeaders(httpReq)

	if c.config.Debug {
		log.Printf("[AxonFlow] Get audit logs for tenant: %s (limit: %d, offset: %d)", tenantID, limit, offset)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tenant audit request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read tenant audit response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	// The API returns an array directly, wrap it in a response
	var entries []AuditLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// Try parsing as wrapped response
		var wrappedResp AuditSearchResponse
		if wrapErr := json.Unmarshal(body, &wrappedResp); wrapErr == nil {
			if c.config.Debug {
				log.Printf("[AxonFlow] Tenant audit returned %d entries", len(wrappedResp.Entries))
			}
			return &wrappedResp, nil
		}
		return nil, fmt.Errorf("failed to unmarshal tenant audit response: %w", err)
	}

	result := &AuditSearchResponse{
		Entries: entries,
		Total:   len(entries),
		Limit:   limit,
		Offset:  offset,
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Tenant audit returned %d entries", len(result.Entries))
	}

	return result, nil
}

// addAuthHeaders adds authentication headers to the request
func (c *AxonFlowClient) addAuthHeaders(req *http.Request) {
	if c.config.LicenseKey != "" {
		req.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		req.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}
}
