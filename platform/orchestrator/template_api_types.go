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

// PolicyTemplate represents a template for creating policies
type PolicyTemplate struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Category    string                 `json:"category"`
	Subcategory string                 `json:"subcategory,omitempty"`
	Template    map[string]interface{} `json:"template"`
	Variables   []TemplateVariable     `json:"variables"`
	IsBuiltin   bool                   `json:"is_builtin"`
	IsActive    bool                   `json:"is_active"`
	Version     string                 `json:"version"`
	Tags        []string               `json:"tags"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// TemplateVariable defines a variable that can be substituted in a template
type TemplateVariable struct {
	Name        string      `json:"name"`
	Type        string      `json:"type,omitempty"`         // string, number, boolean, array
	Default     interface{} `json:"default,omitempty"`
	Description string      `json:"description,omitempty"`
	Required    bool        `json:"required,omitempty"`
	Validation  string      `json:"validation,omitempty"`   // regex pattern for validation
}

// PolicyTemplateUsage tracks when a template is used to create a policy
type PolicyTemplateUsage struct {
	ID         string    `json:"id"`
	TemplateID string    `json:"template_id"`
	TenantID   string    `json:"tenant_id"`
	PolicyID   string    `json:"policy_id,omitempty"`
	UsedAt     time.Time `json:"used_at"`
}

// ListTemplatesParams for GET /api/v1/templates query params
type ListTemplatesParams struct {
	Category string `json:"category"`
	Search   string `json:"search"`
	Tags     string `json:"tags"`      // Comma-separated tags
	Active   *bool  `json:"active"`
	Builtin  *bool  `json:"builtin"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// ApplyTemplateRequest for POST /api/v1/templates/{id}/apply
type ApplyTemplateRequest struct {
	Variables   map[string]interface{} `json:"variables"`
	PolicyName  string                 `json:"policy_name"`
	Description string                 `json:"description,omitempty"`
	Enabled     bool                   `json:"enabled"`
	Priority    *int                   `json:"priority,omitempty"`
}

// TemplateResponse for single template responses
type TemplateResponse struct {
	Template *PolicyTemplate `json:"template"`
}

// TemplatesListResponse for paginated list
type TemplatesListResponse struct {
	Templates  []PolicyTemplate       `json:"templates"`
	Pagination TemplatePaginationMeta `json:"pagination"`
}

// TemplatePaginationMeta metadata for pagination
type TemplatePaginationMeta struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// ApplyTemplateResponse for template application result
type ApplyTemplateResponse struct {
	Success    bool            `json:"success"`
	Policy     *PolicyResource `json:"policy,omitempty"`
	UsageID    string          `json:"usage_id"`
	Message    string          `json:"message,omitempty"`
}

// TemplateUsageStatsResponse for template usage statistics
type TemplateUsageStatsResponse struct {
	TemplateID   string    `json:"template_id"`
	TemplateName string    `json:"template_name"`
	UsageCount   int       `json:"usage_count"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
}

// TemplateAPIError for API errors
type TemplateAPIError struct {
	Error TemplateAPIErrorDetail `json:"error"`
}

// TemplateAPIErrorDetail contains error information
type TemplateAPIErrorDetail struct {
	Code    string               `json:"code"`
	Message string               `json:"message"`
	Details []TemplateFieldError `json:"details,omitempty"`
}

// TemplateFieldError for validation errors
type TemplateFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidTemplateCategories defines valid template categories
var ValidTemplateCategories = []string{
	"general",
	"security",
	"compliance",
	"content_safety",
	"rate_limiting",
	"access_control",
	"data_protection",
	"custom",
}

// TemplateServicer defines the interface for template service operations
// This interface enables dependency injection and testability
type TemplateServicer interface {
	GetTemplate(ctx context.Context, templateID string) (*PolicyTemplate, error)
	ListTemplates(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error)
	ApplyTemplate(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, userID string) (*ApplyTemplateResponse, error)
	GetCategories(ctx context.Context) ([]string, error)
	GetUsageStats(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error)
}
