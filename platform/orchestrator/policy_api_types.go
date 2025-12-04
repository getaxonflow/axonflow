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

package main

import (
	"context"
	"time"
)

// PolicyResource represents a policy for the API (extends DynamicPolicy with API-specific fields)
type PolicyResource struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type"` // content, user, risk, cost
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	Version     int               `json:"version"`
	TenantID    string            `json:"tenant_id"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
	UpdatedBy   string            `json:"updated_by,omitempty"`
}

// CreatePolicyRequest for POST /api/v1/policies
type CreatePolicyRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"` // content, user, risk, cost
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
}

// UpdatePolicyRequest for PUT /api/v1/policies/{id}
type UpdatePolicyRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Type        *string           `json:"type,omitempty"`
	Conditions  []PolicyCondition `json:"conditions,omitempty"`
	Actions     []PolicyAction    `json:"actions,omitempty"`
	Priority    *int              `json:"priority,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
}

// ListPoliciesParams for GET /api/v1/policies query params
type ListPoliciesParams struct {
	Type     string `json:"type"`
	Enabled  *bool  `json:"enabled"`
	Search   string `json:"search"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	SortBy   string `json:"sort_by"`
	SortDir  string `json:"sort_dir"`
}

// TestPolicyRequest for POST /api/v1/policies/{id}/test
type TestPolicyRequest struct {
	Query       string                 `json:"query"`
	User        map[string]interface{} `json:"user"`
	RequestType string                 `json:"request_type"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ImportPoliciesRequest for POST /api/v1/policies/import
type ImportPoliciesRequest struct {
	Policies      []CreatePolicyRequest `json:"policies"`
	OverwriteMode string                `json:"overwrite_mode"` // skip, overwrite, error
}

// PolicyResponse for single policy responses
type PolicyResponse struct {
	Policy *PolicyResource `json:"policy"`
}

// PoliciesListResponse for paginated list
type PoliciesListResponse struct {
	Policies   []PolicyResource `json:"policies"`
	Pagination PaginationMeta   `json:"pagination"`
}

// PaginationMeta metadata for pagination
type PaginationMeta struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// TestPolicyResponse for policy test results
type TestPolicyResponse struct {
	Matched     bool              `json:"matched"`
	Blocked     bool              `json:"blocked"`
	Actions     []TriggeredAction `json:"actions"`
	Explanation string            `json:"explanation"`
	EvalTimeMs  float64           `json:"eval_time_ms"`
}

// TriggeredAction shows which action would execute
type TriggeredAction struct {
	Type    string                 `json:"type"`
	Config  map[string]interface{} `json:"config"`
	Message string                 `json:"message,omitempty"`
}

// ImportPoliciesResponse for bulk import
type ImportPoliciesResponse struct {
	Created  int      `json:"created"`
	Updated  int      `json:"updated"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors,omitempty"`
}

// ExportPoliciesResponse for bulk export
type ExportPoliciesResponse struct {
	Policies   []PolicyResource `json:"policies"`
	ExportedAt time.Time        `json:"exported_at"`
	TenantID   string           `json:"tenant_id"`
}

// PolicyVersionResponse for version history
type PolicyVersionResponse struct {
	Versions []PolicyVersionEntry `json:"versions"`
}

// PolicyVersionEntry represents a point-in-time snapshot
type PolicyVersionEntry struct {
	Version       int            `json:"version"`
	Snapshot      PolicyResource `json:"snapshot"`
	ChangedBy     string         `json:"changed_by"`
	ChangedAt     time.Time      `json:"changed_at"`
	ChangeType    string         `json:"change_type"`
	ChangeSummary string         `json:"change_summary,omitempty"`
}

// PolicyAPIError for API errors
type PolicyAPIError struct {
	Error PolicyAPIErrorDetail `json:"error"`
}

// PolicyAPIErrorDetail contains error information
type PolicyAPIErrorDetail struct {
	Code    string             `json:"code"`
	Message string             `json:"message"`
	Details []PolicyFieldError `json:"details,omitempty"`
}

// PolicyFieldError for validation errors
type PolicyFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Valid policy types
var ValidPolicyTypes = []string{"content", "user", "risk", "cost"}

// ValidPolicyOperators for condition validation
var ValidPolicyOperators = []string{
	"equals",
	"not_equals",
	"contains",
	"not_contains",
	"contains_any",
	"regex",
	"greater_than",
	"less_than",
	"in",
	"not_in",
}

// ValidPolicyFields for condition validation
var ValidPolicyFields = []string{
	"query",
	"response",
	"user.email",
	"user.role",
	"user.department",
	"user.tenant_id",
	"risk_score",
	"request_type",
	"connector",
	"cost_estimate",
}

// Valid action types
var ValidActionTypes = []string{"block", "redact", "alert", "log", "route", "modify_risk"}

// PolicyServicer defines the interface for policy service operations
// This interface enables dependency injection and testability
type PolicyServicer interface {
	CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error)
	GetPolicy(ctx context.Context, tenantID, policyID string) (*PolicyResource, error)
	ListPolicies(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error)
	UpdatePolicy(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error)
	DeletePolicy(ctx context.Context, tenantID, policyID string, deletedBy string) error
	TestPolicy(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error)
	GetPolicyVersions(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error)
	ExportPolicies(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error)
	ImportPolicies(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error)
}
