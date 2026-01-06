// Code Governance types and methods for enterprise Git provider integration
// and PR creation from LLM-generated code.
package axonflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// ============================================================================
// Git Provider Types
// ============================================================================

// GitProviderType represents supported Git providers
type GitProviderType string

const (
	GitProviderGitHub    GitProviderType = "github"
	GitProviderGitLab    GitProviderType = "gitlab"
	GitProviderBitbucket GitProviderType = "bitbucket"
)

// ConfigureGitProviderRequest represents a request to configure a Git provider
type ConfigureGitProviderRequest struct {
	// Type is the provider type: github, gitlab, or bitbucket
	Type GitProviderType `json:"type"`
	// Token is the access token (PAT, app password, or access token)
	Token string `json:"token,omitempty"`
	// BaseURL is for self-hosted instances
	BaseURL string `json:"base_url,omitempty"`
	// AppID is the GitHub App ID (for GitHub App authentication)
	AppID int `json:"app_id,omitempty"`
	// InstallationID is the GitHub App Installation ID
	InstallationID int `json:"installation_id,omitempty"`
	// PrivateKey is the GitHub App private key (PEM format)
	PrivateKey string `json:"private_key,omitempty"`
}

// ValidateGitProviderRequest represents a request to validate Git provider credentials
type ValidateGitProviderRequest struct {
	// Type is the provider type: github, gitlab, or bitbucket
	Type GitProviderType `json:"type"`
	// Token is the access token
	Token string `json:"token,omitempty"`
	// BaseURL is for self-hosted instances
	BaseURL string `json:"base_url,omitempty"`
	// AppID is the GitHub App ID
	AppID int `json:"app_id,omitempty"`
	// InstallationID is the GitHub App Installation ID
	InstallationID int `json:"installation_id,omitempty"`
	// PrivateKey is the GitHub App private key
	PrivateKey string `json:"private_key,omitempty"`
}

// ValidateGitProviderResponse represents the validation result
type ValidateGitProviderResponse struct {
	// Valid indicates if credentials are valid
	Valid bool `json:"valid"`
	// Message contains validation result message
	Message string `json:"message"`
}

// ConfigureGitProviderResponse represents the configuration result
type ConfigureGitProviderResponse struct {
	// Message is the success message
	Message string `json:"message"`
	// Type is the configured provider type
	Type string `json:"type"`
}

// GitProviderInfo represents basic info about a configured provider
type GitProviderInfo struct {
	// Type is the provider type
	Type GitProviderType `json:"type"`
}

// ListGitProvidersResponse represents the list of configured providers
type ListGitProvidersResponse struct {
	// Providers is the list of configured providers
	Providers []GitProviderInfo `json:"providers"`
	// Count is the number of providers
	Count int `json:"count"`
}

// ============================================================================
// PR/MR Types
// ============================================================================

// FileAction represents the action for a code file
type FileAction string

const (
	FileActionCreate FileAction = "create"
	FileActionUpdate FileAction = "update"
	FileActionDelete FileAction = "delete"
)

// CodeFile represents a file to include in a PR
type CodeFile struct {
	// Path is the file path relative to repository root
	Path string `json:"path"`
	// Content is the file content
	Content string `json:"content"`
	// Language is the programming language (optional)
	Language string `json:"language,omitempty"`
	// Action is the file action: create, update, or delete
	Action FileAction `json:"action"`
}

// CreatePRRequest represents a request to create a PR
type CreatePRRequest struct {
	// Owner is the repository owner (org or user)
	Owner string `json:"owner"`
	// Repo is the repository name
	Repo string `json:"repo"`
	// Title is the PR title
	Title string `json:"title"`
	// Description is the PR description/body
	Description string `json:"description,omitempty"`
	// BaseBranch is the base branch to merge into (default: main)
	BaseBranch string `json:"base_branch,omitempty"`
	// BranchName is the head branch name (auto-generated if not provided)
	BranchName string `json:"branch_name,omitempty"`
	// Draft creates the PR as a draft
	Draft bool `json:"draft,omitempty"`
	// Files is the list of files to include in the PR
	Files []CodeFile `json:"files"`
	// AgentRequestID is for traceability back to the AI request
	AgentRequestID string `json:"agent_request_id,omitempty"`
	// Model is the LLM model used to generate code
	Model string `json:"model,omitempty"`
	// PoliciesChecked lists policies checked during code generation
	PoliciesChecked []string `json:"policies_checked,omitempty"`
	// SecretsDetected is the count of secrets detected in code
	SecretsDetected int `json:"secrets_detected,omitempty"`
	// UnsafePatterns is the count of unsafe patterns detected
	UnsafePatterns int `json:"unsafe_patterns,omitempty"`
}

// CreatePRResponse represents the result of creating a PR
type CreatePRResponse struct {
	// PRID is the internal PR record ID
	PRID string `json:"pr_id"`
	// PRNumber is the PR number on Git provider
	PRNumber int `json:"pr_number"`
	// PRURL is the PR URL
	PRURL string `json:"pr_url"`
	// State is the PR state (open, merged, closed)
	State string `json:"state"`
	// HeadBranch is the head branch name
	HeadBranch string `json:"head_branch"`
	// CreatedAt is the creation timestamp
	CreatedAt time.Time `json:"created_at"`
}

// PRRecord represents a PR record in the system
type PRRecord struct {
	// ID is the internal PR record ID
	ID string `json:"id"`
	// PRNumber is the PR number on Git provider
	PRNumber int `json:"pr_number"`
	// PRURL is the PR URL
	PRURL string `json:"pr_url"`
	// Title is the PR title
	Title string `json:"title"`
	// State is the PR state
	State string `json:"state"`
	// Owner is the repository owner
	Owner string `json:"owner"`
	// Repo is the repository name
	Repo string `json:"repo"`
	// HeadBranch is the head branch
	HeadBranch string `json:"head_branch"`
	// BaseBranch is the base branch
	BaseBranch string `json:"base_branch"`
	// FilesCount is the number of files in PR
	FilesCount int `json:"files_count"`
	// SecretsDetected is the secrets detected count
	SecretsDetected int `json:"secrets_detected"`
	// UnsafePatterns is the unsafe patterns count
	UnsafePatterns int `json:"unsafe_patterns"`
	// CreatedAt is the creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// CreatedBy is the user who created the PR
	CreatedBy string `json:"created_by,omitempty"`
	// ProviderType is the Git provider type
	ProviderType string `json:"provider_type,omitempty"`
}

// ListPRsOptions represents options for listing PRs
type ListPRsOptions struct {
	// Limit is the maximum number of PRs to return
	Limit int
	// Offset is the offset for pagination
	Offset int
	// State filters by state: open, merged, closed
	State string
}

// ListPRsResponse represents the list of PRs
type ListPRsResponse struct {
	// PRs is the list of PR records
	PRs []PRRecord `json:"prs"`
	// Count is the total count
	Count int `json:"count"`
}

// ============================================================================
// Portal URL Helper (for Enterprise PR Workflow)
// ============================================================================

// Note: getPortalURL was removed in v2.0.0 (ADR-026 Single Entry Point).
// All routes now go through the Agent endpoint (c.config.Endpoint).

// portalRequest makes an HTTP request to the Customer Portal API (for enterprise features).
// Requires prior authentication via LoginToPortal().
func (c *AxonFlowClient) portalRequest(method, path string, body interface{}, result interface{}) error {
	// Check if logged in
	if c.sessionCookie == "" {
		return fmt.Errorf("not logged in to Customer Portal. Call LoginToPortal() first")
	}

	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	fullURL := c.config.Endpoint + path

	req, err := http.NewRequest(method, fullURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add session cookie for authentication
	req.AddCookie(&http.Cookie{
		Name:  "axonflow_session",
		Value: c.sessionCookie,
	})

	if c.config.Debug {
		log.Printf("[AxonFlow] Portal request: %s %s", method, path)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	// Handle no-content responses
	if resp.StatusCode == 204 || len(respBody) == 0 {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// portalRequestRaw makes an HTTP request to portal and returns raw bytes (for CSV export).
// Requires prior authentication via LoginToPortal().
func (c *AxonFlowClient) portalRequestRaw(method, path string) ([]byte, error) {
	// Check if logged in
	if c.sessionCookie == "" {
		return nil, fmt.Errorf("not logged in to Customer Portal. Call LoginToPortal() first")
	}

	fullURL := c.config.Endpoint + path

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add session cookie for authentication
	req.AddCookie(&http.Cookie{
		Name:  "axonflow_session",
		Value: c.sessionCookie,
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// ============================================================================
// Code Governance Methods
// ============================================================================

// ValidateGitProvider validates Git provider credentials before configuration.
// Use this to verify tokens and connectivity before saving.
func (c *AxonFlowClient) ValidateGitProvider(req *ValidateGitProviderRequest) (*ValidateGitProviderResponse, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Validating Git provider: %s", req.Type)
	}

	var resp ValidateGitProviderResponse
	if err := c.portalRequest("POST", "/api/v1/code-governance/git-providers/validate", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ConfigureGitProvider configures a Git provider for code governance.
// Supports GitHub, GitLab, and Bitbucket (cloud and self-hosted).
func (c *AxonFlowClient) ConfigureGitProvider(req *ConfigureGitProviderRequest) (*ConfigureGitProviderResponse, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Configuring Git provider: %s", req.Type)
	}

	var resp ConfigureGitProviderResponse
	if err := c.portalRequest("POST", "/api/v1/code-governance/git-providers", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ListGitProviders lists all configured Git providers for the tenant.
func (c *AxonFlowClient) ListGitProviders() (*ListGitProvidersResponse, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Listing Git providers")
	}

	var resp ListGitProvidersResponse
	if err := c.portalRequest("GET", "/api/v1/code-governance/git-providers", nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// DeleteGitProvider deletes a configured Git provider.
func (c *AxonFlowClient) DeleteGitProvider(providerType GitProviderType) error {
	if c.config.Debug {
		log.Printf("[AxonFlow] Deleting Git provider: %s", providerType)
	}

	return c.portalRequest("DELETE", "/api/v1/code-governance/git-providers/"+string(providerType), nil, nil)
}

// CreatePR creates a Pull Request from LLM-generated code.
// This creates a PR with full audit trail linking back to the AI request.
func (c *AxonFlowClient) CreatePR(req *CreatePRRequest) (*CreatePRResponse, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Creating PR: %s/%s - %s", req.Owner, req.Repo, req.Title)
	}

	var resp CreatePRResponse
	if err := c.portalRequest("POST", "/api/v1/code-governance/prs", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// buildQueryParams builds query parameters for ListPRsOptions
func (o *ListPRsOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", o.Limit))
	}
	if o.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", o.Offset))
	}
	if o.State != "" {
		params.Set("state", o.State)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// ListPRs lists Pull Requests created through code governance.
func (c *AxonFlowClient) ListPRs(options *ListPRsOptions) (*ListPRsResponse, error) {
	path := "/api/v1/code-governance/prs"
	if options != nil {
		path += options.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listing PRs: %s", path)
	}

	var resp ListPRsResponse
	if err := c.portalRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetPR gets a specific PR record by ID.
func (c *AxonFlowClient) GetPR(prID string) (*PRRecord, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting PR: %s", prID)
	}

	var resp PRRecord
	if err := c.portalRequest("GET", "/api/v1/code-governance/prs/"+prID, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// SyncPRStatus syncs PR status with the Git provider.
// This updates the local record with the current state from GitHub/GitLab/Bitbucket.
func (c *AxonFlowClient) SyncPRStatus(prID string) (*PRRecord, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Syncing PR status: %s", prID)
	}

	var resp PRRecord
	if err := c.portalRequest("POST", "/api/v1/code-governance/prs/"+prID+"/sync", nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ============================================================================
// Metrics and Export Types
// ============================================================================

// CodeGovernanceMetrics contains aggregated metrics for code governance
type CodeGovernanceMetrics struct {
	// TenantID is the tenant identifier
	TenantID string `json:"tenant_id"`
	// TotalPRs is the total number of PRs created
	TotalPRs int `json:"total_prs"`
	// OpenPRs is the number of open PRs
	OpenPRs int `json:"open_prs"`
	// MergedPRs is the number of merged PRs
	MergedPRs int `json:"merged_prs"`
	// ClosedPRs is the number of closed (not merged) PRs
	ClosedPRs int `json:"closed_prs"`
	// TotalFiles is the total number of files modified across all PRs
	TotalFiles int `json:"total_files"`
	// TotalSecretsDetected is the total secrets detected across all PRs
	TotalSecretsDetected int `json:"total_secrets_detected"`
	// TotalUnsafePatterns is the total unsafe patterns detected
	TotalUnsafePatterns int `json:"total_unsafe_patterns"`
	// FirstPRAt is the timestamp of the first PR (nil if no PRs)
	FirstPRAt *time.Time `json:"first_pr_at,omitempty"`
	// LastPRAt is the timestamp of the most recent PR
	LastPRAt *time.Time `json:"last_pr_at,omitempty"`
}

// ExportOptions contains options for exporting code governance data
type ExportOptions struct {
	// Format is the export format: "json" or "csv"
	Format string
	// StartDate filters PRs created on or after this date
	StartDate *time.Time
	// EndDate filters PRs created on or before this date
	EndDate *time.Time
	// State filters by PR state: open, merged, closed
	State string
}

// ExportResponse represents the export result (JSON format)
type ExportResponse struct {
	// Records is the list of PR records
	Records []PRRecord `json:"records"`
	// Count is the number of records
	Count int `json:"count"`
	// ExportedAt is when the export was generated
	ExportedAt string `json:"exported_at"`
}

// buildQueryParams builds query parameters for ExportOptions
func (o *ExportOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Format != "" {
		params.Set("format", o.Format)
	}
	if o.StartDate != nil {
		params.Set("start_date", o.StartDate.Format(time.RFC3339))
	}
	if o.EndDate != nil {
		params.Set("end_date", o.EndDate.Format(time.RFC3339))
	}
	if o.State != "" {
		params.Set("state", o.State)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// ============================================================================
// Metrics and Export Methods
// ============================================================================

// GetCodeGovernanceMetrics returns aggregated code governance metrics for the tenant.
// This provides compliance dashboard data including PR counts, file totals,
// and security findings (secrets detected, unsafe patterns).
func (c *AxonFlowClient) GetCodeGovernanceMetrics() (*CodeGovernanceMetrics, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting code governance metrics")
	}

	var resp CodeGovernanceMetrics
	if err := c.portalRequest("GET", "/api/v1/code-governance/metrics", nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ExportCodeGovernanceData exports code governance data for compliance reporting.
// Supports JSON and CSV formats with optional date filtering.
// For CSV format, use ExportCodeGovernanceDataCSV which returns []byte.
func (c *AxonFlowClient) ExportCodeGovernanceData(options *ExportOptions) (*ExportResponse, error) {
	path := "/api/v1/code-governance/export"
	if options != nil {
		// Force JSON format for structured response
		opts := *options
		opts.Format = "json"
		path += opts.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Exporting code governance data: %s", path)
	}

	var resp ExportResponse
	if err := c.portalRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// ExportCodeGovernanceDataCSV exports code governance data as CSV.
// Returns the raw CSV bytes suitable for saving to file or streaming.
func (c *AxonFlowClient) ExportCodeGovernanceDataCSV(options *ExportOptions) ([]byte, error) {
	path := "/api/v1/code-governance/export?format=csv"
	if options != nil {
		opts := *options
		opts.Format = "csv"
		path = "/api/v1/code-governance/export" + opts.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Exporting code governance data as CSV: %s", path)
	}

	return c.portalRequestRaw("GET", path)
}
