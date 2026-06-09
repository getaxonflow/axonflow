package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"time"
)

// PolicyLoader loads policies from the database with caching.
type PolicyLoader struct {
	db    *sql.DB
	cache *PolicyCache

	// Query templates
	queryRequestPhase  string
	queryResponsePhase string
}

// NewPolicyLoader creates a new policy loader.
func NewPolicyLoader(db *sql.DB, cache *PolicyCache) *PolicyLoader {
	l := &PolicyLoader{
		db:    db,
		cache: cache,
	}
	l.initQueries()
	return l
}

// initQueries initializes the SQL query templates.
func (l *PolicyLoader) initQueries() {
	// Query for request-phase policies
	l.queryRequestPhase = `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND phase IN ('request', 'both')
		  AND (tenant_id = $1 OR tenant_id = 'global')
		ORDER BY priority DESC, created_at ASC
	`

	// Query for response-phase policies
	l.queryResponsePhase = `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND phase IN ('response', 'both')
		  AND (tenant_id = $1 OR tenant_id = 'global')
		ORDER BY priority DESC, created_at ASC
	`
}

// GetPolicies retrieves policies for a tenant and phase from cache or database.
func (l *PolicyLoader) GetPolicies(ctx context.Context, tenantID string, orgID *string, phase Phase) ([]CompiledPolicy, error) {
	// Check cache first
	if policies, found := l.cache.Get(tenantID, orgID, phase); found {
		return policies, nil
	}

	// Load from database
	policies, err := l.loadFromDatabase(ctx, tenantID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Cache the policies
	l.cache.Set(tenantID, orgID, policies)

	// Return filtered by phase
	return l.filterByPhase(policies, phase), nil
}

// loadFromDatabase loads all policies for a tenant from the database.
func (l *PolicyLoader) loadFromDatabase(ctx context.Context, tenantID string, orgID *string) ([]CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	// Query for all policies (both phases)
	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND (tenant_id = $1 OR tenant_id = 'global')
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := l.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var policies []CompiledPolicy

	for rows.Next() {
		var p policyRow
		err := rows.Scan(
			&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
			&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
			&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
		)
		if err != nil {
			log.Printf("[PolicyLoader] Error scanning row: %v", err)
			continue
		}

		compiled, err := l.compilePolicy(p)
		if err != nil {
			log.Printf("[PolicyLoader] Error compiling policy %s: %v", p.PolicyID, err)
			continue
		}

		policies = append(policies, *compiled)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return policies, nil
}

// policyRow represents a row from the static_policies table.
type policyRow struct {
	ID             string
	PolicyID       string
	Name           string
	Category       string
	Tier           string
	Pattern        string
	Severity       string
	Description    sql.NullString
	Phase          sql.NullString
	ActionRequest  sql.NullString
	ActionResponse sql.NullString
	Enabled        bool
	Priority       int
	TenantID       string
	OrganizationID sql.NullString
	Metadata       json.RawMessage
}

// compilePolicy converts a database row to a CompiledPolicy.
func (l *PolicyLoader) compilePolicy(row policyRow) (*CompiledPolicy, error) {
	// Compile regex pattern
	re, err := regexp.Compile(row.Pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	// Parse phase
	phase := PhaseBoth
	if row.Phase.Valid {
		phase = Phase(row.Phase.String)
	}

	// Parse actions
	var actionRequest, actionResponse Action
	if row.ActionRequest.Valid {
		actionRequest = Action(row.ActionRequest.String)
	}
	if row.ActionResponse.Valid {
		actionResponse = Action(row.ActionResponse.String)
	}

	// Parse organization ID
	var orgID *string
	if row.OrganizationID.Valid {
		orgID = &row.OrganizationID.String
	}

	// Get description
	description := ""
	if row.Description.Valid {
		description = row.Description.String
	}

	return &CompiledPolicy{
		ID:             row.ID,
		PolicyID:       row.PolicyID,
		Name:           row.Name,
		Category:       PolicyCategory(row.Category),
		Tier:           row.Tier,
		Pattern:        re,
		PatternStr:     row.Pattern,
		Severity:       Severity(row.Severity),
		Description:    description,
		Phase:          phase,
		ActionRequest:  actionRequest,
		ActionResponse: actionResponse,
		Enabled:        row.Enabled,
		Priority:       row.Priority,
		TenantID:       row.TenantID,
		OrganizationID: orgID,
		Validator:      l.getValidatorForPolicy(row.PolicyID, PolicyCategory(row.Category)),
	}, nil
}

// getValidatorForPolicy returns the appropriate validator for a policy.
//
// Selection is by PII-type token within the policy ID (so "sys_pii_email" → the
// email validator), falling back to the category default only when no token
// matches. The previous exact-match GetValidatorByType(policyID) never matched a
// "sys_pii_*" ID against the bare type-keyed registry, so EVERY pii-global policy
// fell back to the category default (the credit-card validator) and email/phone/ip
// detection was inert on every DB-loaded path. See ValidatorForPolicyID for the
// full per-policy resolution change (incl. PAN and the two locale phone policies).
func (l *PolicyLoader) getValidatorForPolicy(policyID string, category PolicyCategory) ValidatorFunc {
	if validator := ValidatorForPolicyID(policyID); validator != nil {
		return validator
	}
	return GetValidatorForCategory(category)
}

// filterByPhase filters policies by evaluation phase.
func (l *PolicyLoader) filterByPhase(policies []CompiledPolicy, phase Phase) []CompiledPolicy {
	var filtered []CompiledPolicy

	for _, p := range policies {
		switch phase {
		case PhaseRequest:
			if p.Phase == PhaseRequest || p.Phase == PhaseBoth {
				filtered = append(filtered, p)
			}
		case PhaseResponse:
			if p.Phase == PhaseResponse || p.Phase == PhaseBoth {
				filtered = append(filtered, p)
			}
		case PhaseBoth:
			filtered = append(filtered, p)
		}
	}

	return filtered
}

// RefreshAll refreshes the cache for all tenants.
func (l *PolicyLoader) RefreshAll(ctx context.Context) error {
	startTime := time.Now()

	// Get list of all tenants from cache
	// In a real implementation, this would query for active tenants
	l.cache.InvalidateAll()

	// Record refresh time
	l.cache.SetLastRefresh(time.Since(startTime))

	return nil
}

// LoadSystemPolicies loads system-tier policies (global, immutable).
func (l *PolicyLoader) LoadSystemPolicies(ctx context.Context) ([]CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE enabled = true
		  AND deleted_at IS NULL
		  AND tier = 'system'
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := l.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var policies []CompiledPolicy

	for rows.Next() {
		var p policyRow
		err := rows.Scan(
			&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
			&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
			&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
		)
		if err != nil {
			continue
		}

		compiled, err := l.compilePolicy(p)
		if err != nil {
			continue
		}

		policies = append(policies, *compiled)
	}

	return policies, nil
}

// GetPolicyByID retrieves a single policy by ID.
func (l *PolicyLoader) GetPolicyByID(ctx context.Context, policyID string) (*CompiledPolicy, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	query := `
		SELECT
			id, policy_id, name, category, tier, pattern, severity,
			description, phase, action_request, action_response,
			enabled, priority, tenant_id, organization_id, metadata
		FROM static_policies
		WHERE policy_id = $1
		  AND deleted_at IS NULL
		LIMIT 1
	`

	var p policyRow
	err := l.db.QueryRowContext(ctx, query, policyID).Scan(
		&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Tier, &p.Pattern,
		&p.Severity, &p.Description, &p.Phase, &p.ActionRequest, &p.ActionResponse,
		&p.Enabled, &p.Priority, &p.TenantID, &p.OrganizationID, &p.Metadata,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	return l.compilePolicy(p)
}
