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
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TemplateRepository handles database operations for policy templates
type TemplateRepository struct {
	db *sql.DB
}

// NewTemplateRepository creates a new template repository
func NewTemplateRepository(db *sql.DB) *TemplateRepository {
	return &TemplateRepository{db: db}
}

// GetByID retrieves a template by its ID
func (r *TemplateRepository) GetByID(ctx context.Context, templateID string) (*PolicyTemplate, error) {
	query := `
		SELECT id, name, COALESCE(display_name, ''), COALESCE(description, ''),
		       category, COALESCE(subcategory, ''), template, COALESCE(variables, '[]'::jsonb),
		       is_builtin, is_active, COALESCE(version, '1.0'),
		       COALESCE(tags, '[]'::jsonb), created_at, updated_at
		FROM policy_templates
		WHERE id = $1 AND is_active = true
	`

	template := &PolicyTemplate{}
	var templateJSON, variablesJSON, tagsJSON []byte

	err := r.db.QueryRowContext(ctx, query, templateID).Scan(
		&template.ID, &template.Name, &template.DisplayName, &template.Description,
		&template.Category, &template.Subcategory, &templateJSON, &variablesJSON,
		&template.IsBuiltin, &template.IsActive, &template.Version,
		&tagsJSON, &template.CreatedAt, &template.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	if err := json.Unmarshal(templateJSON, &template.Template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	if err := json.Unmarshal(variablesJSON, &template.Variables); err != nil {
		return nil, fmt.Errorf("failed to unmarshal variables: %w", err)
	}

	if err := json.Unmarshal(tagsJSON, &template.Tags); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	return template, nil
}

// List retrieves templates with filtering and pagination
func (r *TemplateRepository) List(ctx context.Context, params ListTemplatesParams) ([]PolicyTemplate, int, error) {
	// Build dynamic query
	whereConditions := []string{"is_active = true"}
	args := []interface{}{}
	argIndex := 1

	if params.Category != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("category = $%d", argIndex))
		args = append(args, params.Category)
		argIndex++
	}

	if params.Active != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *params.Active)
		argIndex++
	}

	if params.Builtin != nil {
		whereConditions = append(whereConditions, fmt.Sprintf("is_builtin = $%d", argIndex))
		args = append(args, *params.Builtin)
		argIndex++
	}

	if params.Search != "" {
		whereConditions = append(whereConditions, fmt.Sprintf("(name ILIKE $%d OR display_name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, "%"+params.Search+"%")
		argIndex++
	}

	if params.Tags != "" {
		// Split comma-separated tags and search for any match
		tags := strings.Split(params.Tags, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
		tagsJSON, _ := json.Marshal(tags)
		whereConditions = append(whereConditions, fmt.Sprintf("tags ?| $%d", argIndex))
		args = append(args, string(tagsJSON))
		argIndex++
	}

	whereClause := strings.Join(whereConditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM policy_templates WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count templates: %w", err)
	}

	// Default pagination
	if params.Page < 1 {
		params.Page = 1
	}
	if params.PageSize < 1 || params.PageSize > 100 {
		params.PageSize = 20
	}

	offset := (params.Page - 1) * params.PageSize

	query := fmt.Sprintf(`
		SELECT id, name, COALESCE(display_name, ''), COALESCE(description, ''),
		       category, COALESCE(subcategory, ''), template, COALESCE(variables, '[]'::jsonb),
		       is_builtin, is_active, COALESCE(version, '1.0'),
		       COALESCE(tags, '[]'::jsonb), created_at, updated_at
		FROM policy_templates
		WHERE %s
		ORDER BY category ASC, name ASC
		LIMIT %d OFFSET %d
	`, whereClause, params.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list templates: %w", err)
	}
	defer rows.Close()

	var templates []PolicyTemplate
	for rows.Next() {
		var template PolicyTemplate
		var templateJSON, variablesJSON, tagsJSON []byte

		err := rows.Scan(
			&template.ID, &template.Name, &template.DisplayName, &template.Description,
			&template.Category, &template.Subcategory, &templateJSON, &variablesJSON,
			&template.IsBuiltin, &template.IsActive, &template.Version,
			&tagsJSON, &template.CreatedAt, &template.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan template: %w", err)
		}

		if err := json.Unmarshal(templateJSON, &template.Template); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal template: %w", err)
		}

		if err := json.Unmarshal(variablesJSON, &template.Variables); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal variables: %w", err)
		}

		if err := json.Unmarshal(tagsJSON, &template.Tags); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal tags: %w", err)
		}

		templates = append(templates, template)
	}

	return templates, total, nil
}

// ListByCategory retrieves all templates for a specific category
func (r *TemplateRepository) ListByCategory(ctx context.Context, category string) ([]PolicyTemplate, error) {
	params := ListTemplatesParams{
		Category: category,
		PageSize: 100,
		Page:     1,
	}
	templates, _, err := r.List(ctx, params)
	return templates, err
}

// RecordUsage creates a usage record when a template is applied
func (r *TemplateRepository) RecordUsage(ctx context.Context, usage *PolicyTemplateUsage) error {
	if usage.ID == "" {
		usage.ID = uuid.New().String()
	}
	if usage.UsedAt.IsZero() {
		usage.UsedAt = time.Now()
	}

	query := `
		INSERT INTO policy_template_usage (id, template_id, tenant_id, policy_id, used_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(ctx, query,
		usage.ID, usage.TemplateID, usage.TenantID, usage.PolicyID, usage.UsedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to record template usage: %w", err)
	}

	return nil
}

// GetUsageStats retrieves usage statistics for templates
func (r *TemplateRepository) GetUsageStats(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error) {
	query := `
		SELECT pt.id, pt.name, COUNT(ptu.id) as usage_count, MAX(ptu.used_at) as last_used
		FROM policy_templates pt
		LEFT JOIN policy_template_usage ptu ON pt.id = ptu.template_id AND ptu.tenant_id = $1
		WHERE pt.is_active = true
		GROUP BY pt.id, pt.name
		ORDER BY usage_count DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}
	defer rows.Close()

	var stats []TemplateUsageStatsResponse
	for rows.Next() {
		var stat TemplateUsageStatsResponse
		var lastUsed sql.NullTime

		err := rows.Scan(&stat.TemplateID, &stat.TemplateName, &stat.UsageCount, &lastUsed)
		if err != nil {
			return nil, fmt.Errorf("failed to scan usage stat: %w", err)
		}

		if lastUsed.Valid {
			stat.LastUsedAt = lastUsed.Time
		}

		stats = append(stats, stat)
	}

	return stats, nil
}

// GetUsageByTenant retrieves all usage records for a tenant
func (r *TemplateRepository) GetUsageByTenant(ctx context.Context, tenantID string) ([]PolicyTemplateUsage, error) {
	query := `
		SELECT id, template_id, tenant_id, COALESCE(policy_id, ''), used_at
		FROM policy_template_usage
		WHERE tenant_id = $1
		ORDER BY used_at DESC
		LIMIT 100
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage by tenant: %w", err)
	}
	defer rows.Close()

	var usages []PolicyTemplateUsage
	for rows.Next() {
		var usage PolicyTemplateUsage
		err := rows.Scan(&usage.ID, &usage.TemplateID, &usage.TenantID, &usage.PolicyID, &usage.UsedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan usage: %w", err)
		}
		usages = append(usages, usage)
	}

	return usages, nil
}

// GetCategories retrieves all unique template categories
func (r *TemplateRepository) GetCategories(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT category
		FROM policy_templates
		WHERE is_active = true
		ORDER BY category
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get categories: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, fmt.Errorf("failed to scan category: %w", err)
		}
		categories = append(categories, category)
	}

	return categories, nil
}
