// Policy CRUD types and methods for the Unified Policy Architecture v2.0.0
package axonflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================================
// Policy Categories and Tiers
// ============================================================================

// PolicyCategory represents policy categories for organization and filtering
type PolicyCategory string

const (
	// Static policy categories - Security
	CategorySecuritySQLI  PolicyCategory = "security-sqli"
	CategorySecurityAdmin PolicyCategory = "security-admin"

	// Static policy categories - PII Detection
	CategoryPIIGlobal PolicyCategory = "pii-global"
	CategoryPIIUS     PolicyCategory = "pii-us"
	CategoryPIIEU     PolicyCategory = "pii-eu"
	CategoryPIIIndia  PolicyCategory = "pii-india"

	// Static policy categories - Code Governance
	CategoryCodeSecrets    PolicyCategory = "code-secrets"
	CategoryCodeUnsafe     PolicyCategory = "code-unsafe"
	CategoryCodeCompliance PolicyCategory = "code-compliance"

	// Sensitive data category
	CategorySensitiveData PolicyCategory = "sensitive-data"

	// Dynamic policy categories
	CategoryDynamicRisk       PolicyCategory = "dynamic-risk"
	CategoryDynamicCompliance PolicyCategory = "dynamic-compliance"
	CategoryDynamicSecurity   PolicyCategory = "dynamic-security"
	CategoryDynamicCost       PolicyCategory = "dynamic-cost"
	CategoryDynamicAccess     PolicyCategory = "dynamic-access"
)

// PolicyTier determines where policies apply
type PolicyTier string

const (
	TierSystem       PolicyTier = "system"
	TierOrganization PolicyTier = "organization"
	TierTenant       PolicyTier = "tenant"
)

// OverrideAction represents the action to take for policy overrides
// - block: Immediately block the request
// - require_approval: Pause for human approval (HITL)
// - redact: Mask sensitive content
// - warn: Log warning, allow request
// - log: Audit only
type OverrideAction string

const (
	OverrideActionBlock           OverrideAction = "block"
	OverrideActionRequireApproval OverrideAction = "require_approval"
	OverrideActionRedact          OverrideAction = "redact"
	OverrideActionWarn            OverrideAction = "warn"
	OverrideActionLog             OverrideAction = "log"
)

// PolicyAction represents the action to take when a policy matches
// - block: Immediately block the request
// - require_approval: Pause for human approval (HITL)
// - redact: Mask sensitive content
// - warn: Log warning, allow request
// - log: Audit only
// - allow: Explicitly allow (for overrides)
type PolicyAction string

const (
	ActionBlock           PolicyAction = "block"
	ActionRequireApproval PolicyAction = "require_approval"
	ActionRedact          PolicyAction = "redact"
	ActionWarn            PolicyAction = "warn"
	ActionLog             PolicyAction = "log"
	ActionAllow           PolicyAction = "allow"
)

// PolicySeverity represents policy severity levels
type PolicySeverity string

const (
	SeverityCritical PolicySeverity = "critical"
	SeverityHigh     PolicySeverity = "high"
	SeverityMedium   PolicySeverity = "medium"
	SeverityLow      PolicySeverity = "low"
)

// ============================================================================
// Static Policy Types
// ============================================================================

// StaticPolicy represents a static policy definition
type StaticPolicy struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description,omitempty"`
	Category       PolicyCategory  `json:"category"`
	Tier           PolicyTier      `json:"tier"`
	Pattern        string          `json:"pattern"`
	Severity       PolicySeverity  `json:"severity"`
	Enabled        bool            `json:"enabled"`
	Action         PolicyAction    `json:"action"`
	OrganizationID *string         `json:"organization_id,omitempty"`
	TenantID       *string         `json:"tenant_id,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Version        int             `json:"version,omitempty"`
	HasOverride    bool            `json:"has_override,omitempty"`
	Override       *PolicyOverride `json:"override,omitempty"`
}

// PolicyOverride represents an override for a static policy
type PolicyOverride struct {
	PolicyID  string         `json:"policy_id"`
	Action    OverrideAction `json:"action_override"`
	Reason    string         `json:"override_reason"`
	CreatedBy string         `json:"created_by,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Active    bool           `json:"active"`
}

// ListStaticPoliciesOptions represents options for listing static policies
type ListStaticPoliciesOptions struct {
	Category       PolicyCategory
	Tier           PolicyTier
	OrganizationID string // Filter by organization ID (Enterprise)
	Enabled        *bool
	Limit          int
	Offset         int
	SortBy         string
	SortOrder      string
	Search         string
}

// ListStaticPoliciesRequest is an alias for ListStaticPoliciesOptions for backward compatibility
type ListStaticPoliciesRequest = ListStaticPoliciesOptions

// CreateStaticPolicyRequest represents a request to create a new static policy
type CreateStaticPolicyRequest struct {
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	Category       PolicyCategory `json:"category"`
	Tier           PolicyTier     `json:"tier,omitempty"`
	OrganizationID string         `json:"organization_id,omitempty"` // Organization ID for organization-tier policies (Enterprise)
	Pattern        string         `json:"pattern"`
	Severity       PolicySeverity `json:"severity,omitempty"`
	Enabled        bool           `json:"enabled"`
	Action         PolicyAction   `json:"action,omitempty"`
}

// UpdateStaticPolicyRequest represents a request to update an existing static policy
type UpdateStaticPolicyRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Category    *PolicyCategory `json:"category,omitempty"`
	Pattern     *string         `json:"pattern,omitempty"`
	Severity    *PolicySeverity `json:"severity,omitempty"`
	Enabled     *bool           `json:"enabled,omitempty"`
	Action      *PolicyAction   `json:"action,omitempty"`
}

// CreatePolicyOverrideRequest represents a request to create a policy override
type CreatePolicyOverrideRequest struct {
	Action    OverrideAction `json:"action_override"`
	Reason    string         `json:"override_reason"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

// CreateOverrideRequest is an alias for CreatePolicyOverrideRequest for backward compatibility
type CreateOverrideRequest = CreatePolicyOverrideRequest

// ============================================================================
// Dynamic Policy Types
// ============================================================================

// DynamicPolicyCondition represents a condition for dynamic policy evaluation
type DynamicPolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// DynamicPolicyAction represents an action for dynamic policy enforcement
type DynamicPolicyAction struct {
	Type   string                 `json:"type"` // "block", "alert", "redact", "log", "route", "modify_risk"
	Config map[string]interface{} `json:"config,omitempty"`
}

// DynamicPolicy represents a dynamic policy definition
// Dynamic policies are LLM-powered policies that can evaluate complex,
// context-aware rules that can't be expressed with simple regex patterns.
//
// For provider restrictions (GDPR, HIPAA, RBI compliance), use action config:
//
//	Actions: []DynamicPolicyAction{{Type: "route", Config: map[string]interface{}{"allowed_providers": []string{"ollama", "azure-eu"}}}}
type DynamicPolicy struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Type        string                   `json:"type"`               // "risk", "content", "user", "cost"
	Category    string                   `json:"category,omitempty"` // "dynamic-risk", "dynamic-compliance", etc.
	Tier        string                   `json:"tier,omitempty"`     // "system", "organization", "tenant"
	Conditions  []DynamicPolicyCondition `json:"conditions,omitempty"`
	Actions     []DynamicPolicyAction    `json:"actions,omitempty"`
	Priority    int                      `json:"priority"`
	Enabled     bool                     `json:"enabled"`
	Version     int                      `json:"version,omitempty"`
	TenantID    string                   `json:"tenant_id,omitempty"`
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
}

// ListDynamicPoliciesOptions represents options for listing dynamic policies
type ListDynamicPoliciesOptions struct {
	Type      string // Filter by policy type: "risk", "content", "user", "cost"
	Enabled   *bool
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
	Search    string
}

// CreateDynamicPolicyRequest represents a request to create a dynamic policy
//
// For provider restrictions (GDPR, HIPAA, RBI compliance), use action config:
//
//	Actions: []DynamicPolicyAction{{Type: "route", Config: map[string]interface{}{"allowed_providers": []string{"ollama"}}}}
type CreateDynamicPolicyRequest struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description,omitempty"`
	Type        string                   `json:"type"`               // "risk", "content", "user", "cost"
	Category    string                   `json:"category,omitempty"` // Must start with "dynamic-"
	Conditions  []DynamicPolicyCondition `json:"conditions,omitempty"`
	Actions     []DynamicPolicyAction    `json:"actions,omitempty"`
	Priority    int                      `json:"priority"`
	Enabled     bool                     `json:"enabled"`
}

// UpdateDynamicPolicyRequest represents a request to update a dynamic policy
//
// For provider restrictions, use action config with "allowed_providers" key.
type UpdateDynamicPolicyRequest struct {
	Name        *string                  `json:"name,omitempty"`
	Description *string                  `json:"description,omitempty"`
	Type        *string                  `json:"type,omitempty"`
	Category    *string                  `json:"category,omitempty"`
	Conditions  []DynamicPolicyCondition `json:"conditions,omitempty"`
	Actions     []DynamicPolicyAction    `json:"actions,omitempty"`
	Priority    *int                     `json:"priority,omitempty"`
	Enabled     *bool                    `json:"enabled,omitempty"`
}

// ============================================================================
// Pattern Testing Types
// ============================================================================

// TestPatternResult represents the result of testing a regex pattern
type TestPatternResult struct {
	Valid   bool               `json:"valid"`
	Error   string             `json:"error,omitempty"`
	Pattern string             `json:"pattern"`
	Inputs  []string           `json:"inputs"`
	Matches []TestPatternMatch `json:"matches"`
	Results []TestPatternMatch `json:"-"` // Alias for Matches for backward compatibility
}

// GetResults returns the pattern match results (alias for Matches)
func (r *TestPatternResult) GetResults() []TestPatternMatch {
	return r.Matches
}

// TestPatternMatch represents an individual pattern match result
type TestPatternMatch struct {
	Input       string `json:"input"`
	Matched     bool   `json:"matched"`
	MatchedText string `json:"matched_text,omitempty"`
	Position    int    `json:"position,omitempty"`
}

// ============================================================================
// Policy Version Types
// ============================================================================

// PolicyVersion represents a policy version history entry
type PolicyVersion struct {
	Version           int                    `json:"version"`
	ChangedBy         string                 `json:"changed_by,omitempty"`
	ChangedAt         time.Time              `json:"changed_at"`
	ChangeType        string                 `json:"change_type"`
	ChangeDescription string                 `json:"change_description,omitempty"`
	PreviousValues    map[string]interface{} `json:"previous_values,omitempty"`
	NewValues         map[string]interface{} `json:"new_values,omitempty"`
}

// EffectivePoliciesOptions represents options for getting effective policies
type EffectivePoliciesOptions struct {
	Category          PolicyCategory
	IncludeDisabled   bool
	IncludeOverridden bool
}

// GetEffectiveRequest is an alias for EffectivePoliciesOptions for backward compatibility
type GetEffectiveRequest = EffectivePoliciesOptions

// ============================================================================
// HTTP Helper for Policy Requests
// ============================================================================

// orchestratorPolicyRequest makes an HTTP request to the Orchestrator policy API (for dynamic policies)
func (c *AxonFlowClient) orchestratorPolicyRequest(method, path string, body interface{}, result interface{}) error {
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

	// Skip auth headers for localhost (self-hosted mode)
	isLocalhost := strings.Contains(c.config.Endpoint, "localhost") ||
		strings.Contains(c.config.Endpoint, "127.0.0.1")
	if !isLocalhost {
		req.Header.Set("X-Client-Secret", c.config.ClientSecret)
		if c.config.LicenseKey != "" {
			req.Header.Set("X-License-Key", c.config.LicenseKey)
		}
	}

	// Always set tenant ID for policy APIs (uses ClientID as tenant)
	if c.config.ClientID != "" {
		req.Header.Set("X-Tenant-ID", c.config.ClientID)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Orchestrator policy request: %s %s", method, path)
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

// policyRequest makes an HTTP request to the policy API
func (c *AxonFlowClient) policyRequest(method, path string, body interface{}, result interface{}) error {
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

	// Skip auth headers for localhost (self-hosted mode)
	isLocalhost := strings.Contains(c.config.Endpoint, "localhost") ||
		strings.Contains(c.config.Endpoint, "127.0.0.1")
	if !isLocalhost {
		req.Header.Set("X-Client-Secret", c.config.ClientSecret)
		if c.config.LicenseKey != "" {
			req.Header.Set("X-License-Key", c.config.LicenseKey)
		}
	}

	// Always set tenant ID for policy APIs (uses ClientID as tenant)
	if c.config.ClientID != "" {
		req.Header.Set("X-Tenant-ID", c.config.ClientID)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Policy request: %s %s", method, path)
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

// policyRequestRaw makes an HTTP request and returns raw bytes (for CSV export)
func (c *AxonFlowClient) policyRequestRaw(method, path string) ([]byte, error) {
	fullURL := c.config.Endpoint + path

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Skip auth headers for localhost (self-hosted mode)
	isLocalhost := strings.Contains(c.config.Endpoint, "localhost") ||
		strings.Contains(c.config.Endpoint, "127.0.0.1")
	if !isLocalhost {
		req.Header.Set("X-Client-Secret", c.config.ClientSecret)
		if c.config.LicenseKey != "" {
			req.Header.Set("X-License-Key", c.config.LicenseKey)
		}
	}

	// Always set tenant ID for policy APIs (uses ClientID as tenant)
	if c.config.ClientID != "" {
		req.Header.Set("X-Tenant-ID", c.config.ClientID)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Raw policy request: %s %s", method, path)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	return respBody, nil
}

// buildQueryParams builds query parameters from options
func (o *ListStaticPoliciesOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Category != "" {
		params.Set("category", string(o.Category))
	}
	if o.Tier != "" {
		params.Set("tier", string(o.Tier))
	}
	if o.OrganizationID != "" {
		params.Set("organization_id", o.OrganizationID)
	}
	if o.Enabled != nil {
		if *o.Enabled {
			params.Set("enabled", "true")
		} else {
			params.Set("enabled", "false")
		}
	}
	if o.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", o.Limit))
	}
	if o.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", o.Offset))
	}
	if o.SortBy != "" {
		params.Set("sort_by", o.SortBy)
	}
	if o.SortOrder != "" {
		params.Set("sort_order", o.SortOrder)
	}
	if o.Search != "" {
		params.Set("search", o.Search)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func (o *ListDynamicPoliciesOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Type != "" {
		params.Set("type", o.Type)
	}
	if o.Enabled != nil {
		if *o.Enabled {
			params.Set("enabled", "true")
		} else {
			params.Set("enabled", "false")
		}
	}
	if o.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", o.Limit))
	}
	if o.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", o.Offset))
	}
	if o.SortBy != "" {
		params.Set("sort_by", o.SortBy)
	}
	if o.SortOrder != "" {
		params.Set("sort_order", o.SortOrder)
	}
	if o.Search != "" {
		params.Set("search", o.Search)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

func (o *EffectivePoliciesOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Category != "" {
		params.Set("category", string(o.Category))
	}
	if o.IncludeDisabled {
		params.Set("include_disabled", "true")
	}
	if o.IncludeOverridden {
		params.Set("include_overridden", "true")
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// ============================================================================
// Static Policy Methods
// ============================================================================

// staticPoliciesResponse wraps the list static policies API response
type staticPoliciesResponse struct {
	Policies []StaticPolicy `json:"policies"`
}

// ListStaticPolicies lists all static policies with optional filtering.
func (c *AxonFlowClient) ListStaticPolicies(options *ListStaticPoliciesOptions) ([]StaticPolicy, error) {
	path := "/api/v1/static-policies"
	if options != nil {
		path += options.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listing static policies: %s", path)
	}

	var response staticPoliciesResponse
	if err := c.policyRequest("GET", path, nil, &response); err != nil {
		return nil, err
	}

	return response.Policies, nil
}

// GetStaticPolicy gets a specific static policy by ID.
func (c *AxonFlowClient) GetStaticPolicy(id string) (*StaticPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting static policy: %s", id)
	}

	var policy StaticPolicy
	if err := c.policyRequest("GET", "/api/v1/static-policies/"+id, nil, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// CreateStaticPolicy creates a new static policy.
func (c *AxonFlowClient) CreateStaticPolicy(req *CreateStaticPolicyRequest) (*StaticPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Creating static policy: %s", req.Name)
	}

	// Set default tier if not specified
	if req.Tier == "" {
		req.Tier = TierTenant
	}

	var policy StaticPolicy
	if err := c.policyRequest("POST", "/api/v1/static-policies", req, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// UpdateStaticPolicy updates an existing static policy.
func (c *AxonFlowClient) UpdateStaticPolicy(id string, req *UpdateStaticPolicyRequest) (*StaticPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Updating static policy: %s", id)
	}

	var policy StaticPolicy
	if err := c.policyRequest("PUT", "/api/v1/static-policies/"+id, req, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// DeleteStaticPolicy deletes a static policy.
func (c *AxonFlowClient) DeleteStaticPolicy(id string) error {
	if c.config.Debug {
		log.Printf("[AxonFlow] Deleting static policy: %s", id)
	}

	return c.policyRequest("DELETE", "/api/v1/static-policies/"+id, nil, nil)
}

// ToggleStaticPolicy toggles a static policy's enabled status.
func (c *AxonFlowClient) ToggleStaticPolicy(id string, enabled bool) (*StaticPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Toggling static policy: %s (enabled=%v)", id, enabled)
	}

	body := map[string]bool{"enabled": enabled}
	var policy StaticPolicy
	if err := c.policyRequest("PATCH", "/api/v1/static-policies/"+id, body, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// effectivePoliciesResponse wraps the effective policies API response
type effectivePoliciesResponse struct {
	Static  []StaticPolicy  `json:"static"`
	Dynamic []DynamicPolicy `json:"dynamic"`
}

// GetEffectiveStaticPolicies gets effective static policies with tier inheritance applied.
func (c *AxonFlowClient) GetEffectiveStaticPolicies(options *EffectivePoliciesOptions) ([]StaticPolicy, error) {
	path := "/api/v1/static-policies/effective"
	if options != nil {
		path += options.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting effective static policies: %s", path)
	}

	var response effectivePoliciesResponse
	if err := c.policyRequest("GET", path, nil, &response); err != nil {
		return nil, err
	}

	return response.Static, nil
}

// TestPattern tests a regex pattern against sample inputs.
func (c *AxonFlowClient) TestPattern(pattern string, testInputs []string) (*TestPatternResult, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Testing pattern: %s (%d inputs)", pattern, len(testInputs))
	}

	body := map[string]interface{}{
		"pattern": pattern,
		"inputs":  testInputs,
	}

	var result TestPatternResult
	if err := c.policyRequest("POST", "/api/v1/static-policies/test", body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetStaticPolicyVersions gets version history for a static policy.
func (c *AxonFlowClient) GetStaticPolicyVersions(id string) ([]PolicyVersion, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting static policy versions: %s", id)
	}

	var response struct {
		PolicyID string          `json:"policy_id"`
		Versions []PolicyVersion `json:"versions"`
		Count    int             `json:"count"`
	}
	if err := c.policyRequest("GET", "/api/v1/static-policies/"+id+"/versions", nil, &response); err != nil {
		return nil, err
	}

	return response.Versions, nil
}

// ============================================================================
// Policy Override Methods (Enterprise)
// ============================================================================

// CreatePolicyOverride creates an override for a static policy.
func (c *AxonFlowClient) CreatePolicyOverride(policyID string, req *CreatePolicyOverrideRequest) (*PolicyOverride, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Creating policy override for: %s", policyID)
	}

	var override PolicyOverride
	if err := c.policyRequest("POST", "/api/v1/static-policies/"+policyID+"/override", req, &override); err != nil {
		return nil, err
	}

	return &override, nil
}

// DeletePolicyOverride deletes an override for a static policy.
func (c *AxonFlowClient) DeletePolicyOverride(policyID string) error {
	if c.config.Debug {
		log.Printf("[AxonFlow] Deleting policy override for: %s", policyID)
	}

	return c.policyRequest("DELETE", "/api/v1/static-policies/"+policyID+"/override", nil, nil)
}

// ListPolicyOverrides lists all active policy overrides (Enterprise).
func (c *AxonFlowClient) ListPolicyOverrides() ([]PolicyOverride, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Listing policy overrides")
	}

	var response struct {
		Overrides []PolicyOverride `json:"overrides"`
		Count     int              `json:"count"`
	}
	err := c.policyRequest("GET", "/api/v1/static-policies/overrides", nil, &response)
	if err != nil {
		return nil, err
	}
	return response.Overrides, nil
}

// ============================================================================
// Dynamic Policy Methods
// ============================================================================

// dynamicPoliciesResponse wraps the list dynamic policies API response
type dynamicPoliciesResponse struct {
	Policies []DynamicPolicy `json:"policies"`
}

// dynamicPolicyResponse wraps single dynamic policy API responses
type dynamicPolicyResponse struct {
	Policy DynamicPolicy `json:"policy"`
}

// ListDynamicPolicies lists all dynamic policies with optional filtering.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) ListDynamicPolicies(options *ListDynamicPoliciesOptions) ([]DynamicPolicy, error) {
	path := "/api/v1/dynamic-policies"
	if options != nil {
		path += options.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listing dynamic policies: %s", path)
	}

	var response dynamicPoliciesResponse
	if err := c.orchestratorPolicyRequest("GET", path, nil, &response); err != nil {
		return nil, err
	}

	return response.Policies, nil
}

// GetDynamicPolicy gets a specific dynamic policy by ID.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) GetDynamicPolicy(id string) (*DynamicPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting dynamic policy: %s", id)
	}

	var response dynamicPolicyResponse
	if err := c.orchestratorPolicyRequest("GET", "/api/v1/dynamic-policies/"+id, nil, &response); err != nil {
		return nil, err
	}

	return &response.Policy, nil
}

// CreateDynamicPolicy creates a new dynamic policy.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) CreateDynamicPolicy(req *CreateDynamicPolicyRequest) (*DynamicPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Creating dynamic policy: %s", req.Name)
	}

	var response dynamicPolicyResponse
	if err := c.orchestratorPolicyRequest("POST", "/api/v1/dynamic-policies", req, &response); err != nil {
		return nil, err
	}

	return &response.Policy, nil
}

// UpdateDynamicPolicy updates an existing dynamic policy.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) UpdateDynamicPolicy(id string, req *UpdateDynamicPolicyRequest) (*DynamicPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Updating dynamic policy: %s", id)
	}

	var response dynamicPolicyResponse
	if err := c.orchestratorPolicyRequest("PUT", "/api/v1/dynamic-policies/"+id, req, &response); err != nil {
		return nil, err
	}

	return &response.Policy, nil
}

// DeleteDynamicPolicy deletes a dynamic policy.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) DeleteDynamicPolicy(id string) error {
	if c.config.Debug {
		log.Printf("[AxonFlow] Deleting dynamic policy: %s", id)
	}

	return c.orchestratorPolicyRequest("DELETE", "/api/v1/dynamic-policies/"+id, nil, nil)
}

// ToggleDynamicPolicy toggles a dynamic policy's enabled status.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) ToggleDynamicPolicy(id string, enabled bool) (*DynamicPolicy, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Toggling dynamic policy: %s (enabled=%v)", id, enabled)
	}

	body := map[string]bool{"enabled": enabled}
	var response dynamicPolicyResponse
	if err := c.orchestratorPolicyRequest("PUT", "/api/v1/dynamic-policies/"+id, body, &response); err != nil {
		return nil, err
	}

	return &response.Policy, nil
}

// GetEffectiveDynamicPolicies gets effective dynamic policies with tier inheritance applied.
// Dynamic policies are stored on the Orchestrator (not Agent).
func (c *AxonFlowClient) GetEffectiveDynamicPolicies(options *EffectivePoliciesOptions) ([]DynamicPolicy, error) {
	path := "/api/v1/dynamic-policies/effective"
	if options != nil {
		path += options.buildQueryParams()
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting effective dynamic policies: %s", path)
	}

	// Agent proxy (Issue #886) returns {"policies": [...]} wrapper
	var response dynamicPoliciesResponse
	if err := c.orchestratorPolicyRequest("GET", path, nil, &response); err != nil {
		return nil, err
	}

	return response.Policies, nil
}
