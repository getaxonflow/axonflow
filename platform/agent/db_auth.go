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

package agent

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"axonflow/platform/agent/license"
)

// safePrefix returns up to n characters from s for safe logging
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ============================================================
// Database-Backed Authentication (Option 3)
// ============================================================

// CustomerInfo represents a customer from the database
type CustomerInfo struct {
	CustomerID       string
	OrganizationName string
	OrganizationID   string
	DeploymentMode   string
	Tier             string
	TenantID         string
	Status           string
	Enabled          bool
}

// APIKeyInfo represents an API key from the database
type APIKeyInfo struct {
	APIKeyID         string
	CustomerID       string
	LicenseKey       string
	KeyName          string
	KeyType          string
	ExpiresAt        time.Time
	GracePeriodDays  int
	Permissions      []string
	CustomRateLimit  *int // NULL = use tier default
	Enabled          bool
	RevokedAt        *time.Time
	LastUsedAt       *time.Time
	TotalRequests    int64
}

// PricingTierInfo represents a pricing tier from the database
type PricingTierInfo struct {
	Tier               string
	DeploymentMode     string
	MonthlyPrice       int
	IncludedRequests   *int64 // NULL for in-vpc
	MaxNodes           *int
	MaxUsers           *int
	RequestsPerMinute  int
	OverageRatePer1K   *float64 // NULL for in-vpc
	SupportSLAHours    int
	Features           map[string]interface{}
	Active             bool
}

// validateClientLicenseDB validates a client using database lookup
// Supports both api_keys (legacy) and organizations (new) tables
func validateClientLicenseDB(ctx context.Context, db *sql.DB, clientID, licenseKey string) (*Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID required")
	}

	if licenseKey == "" {
		return nil, fmt.Errorf("license key required")
	}

	// Try API keys authentication first (legacy path)
	client, err := validateViaAPIKeys(ctx, db, clientID, licenseKey)
	if err == nil {
		return client, nil
	}

	// Fallback to organizations authentication (new path)
	return validateViaOrganizations(ctx, db, clientID, licenseKey)
}

// validateViaAPIKeys validates using api_keys + customers tables (legacy)
func validateViaAPIKeys(ctx context.Context, db *sql.DB, clientID, licenseKey string) (*Client, error) {
	// Hash the license key for lookup
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeyHash := hex.EncodeToString(hash[:])

	// Query database for API key and customer information
	query := `
		SELECT
			k.api_key_id,
			k.customer_id,
			k.license_key,
			k.key_name,
			k.key_type,
			k.expires_at,
			k.grace_period_days,
			k.permissions,
			k.custom_rate_limit,
			k.enabled,
			k.revoked_at,
			k.last_used_at,
			k.total_requests,
			c.customer_id,
			c.organization_name,
			c.organization_id,
			c.deployment_mode,
			c.tier,
			c.tenant_id,
			c.status,
			c.enabled,
			pt.requests_per_minute
		FROM api_keys k
		JOIN customers c ON k.customer_id = c.customer_id
		JOIN pricing_tiers pt ON c.tier = pt.tier AND c.deployment_mode = pt.deployment_mode
		WHERE k.license_key_hash = $1
		AND k.enabled = true
		AND c.enabled = true
		AND c.status = 'active'
	`

	var apiKey APIKeyInfo
	var customer CustomerInfo
	var tierRateLimit int
	var customRateLimitNullable sql.NullInt64
	var revokedAtNullable sql.NullTime
	var lastUsedAtNullable sql.NullTime

	// Permissions will be parsed from JSONB array
	var permissionsJSON []byte

	err := db.QueryRowContext(ctx, query, licenseKeyHash).Scan(
		&apiKey.APIKeyID,
		&apiKey.CustomerID,
		&apiKey.LicenseKey,
		&apiKey.KeyName,
		&apiKey.KeyType,
		&apiKey.ExpiresAt,
		&apiKey.GracePeriodDays,
		&permissionsJSON,
		&customRateLimitNullable,
		&apiKey.Enabled,
		&revokedAtNullable,
		&lastUsedAtNullable,
		&apiKey.TotalRequests,
		&customer.CustomerID,
		&customer.OrganizationName,
		&customer.OrganizationID,
		&customer.DeploymentMode,
		&customer.Tier,
		&customer.TenantID,
		&customer.Status,
		&customer.Enabled,
		&tierRateLimit,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid license key or client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Verify the license key matches (stored plaintext matches provided)
	if apiKey.LicenseKey != licenseKey {
		return nil, fmt.Errorf("license key mismatch")
	}

	// Check if revoked
	if revokedAtNullable.Valid {
		return nil, fmt.Errorf("API key has been revoked")
	}

	// Validate license key using existing license validation system
	validationResult, err := license.ValidateLicense(ctx, licenseKey)
	if err != nil {
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Parse permissions from JSONB
	// For simplicity, assuming permissions is a JSON array like ["query", "llm"]
	// In production, use proper JSON parsing
	permissions := []string{"query", "llm"} // Default permissions
	// TODO: Parse permissionsJSON properly

	// Determine rate limit (custom override or tier default)
	rateLimit := tierRateLimit
	if customRateLimitNullable.Valid && customRateLimitNullable.Int64 > 0 {
		rateLimit = int(customRateLimitNullable.Int64)
	}

	// Update last_used_at asynchronously (fire and forget)
	go updateAPIKeyLastUsed(context.Background(), db, apiKey.APIKeyID)

	// Return authenticated client
	return &Client{
		ID:            customer.OrganizationID,
		Name:          customer.OrganizationName,
		OrgID:         validationResult.OrgID, // From license validation
		TenantID:      customer.TenantID,
		Permissions:   permissions,
		RateLimit:     rateLimit,
		Enabled:       true,
		LicenseTier:   customer.Tier,
		LicenseExpiry: validationResult.ExpiresAt,
		APIKeyID:      apiKey.APIKeyID, // For usage tracking
	}, nil
}

// validateViaOrganizations validates using organizations table (new customer portal path)
func validateViaOrganizations(ctx context.Context, db *sql.DB, clientID, licenseKey string) (*Client, error) {
	// Debug: Log license key format detection
	isV2Format := len(licenseKey) > 8 && licenseKey[:8] == "AXON-V2-"
	log.Printf("[V2-DEBUG] validateViaOrganizations: clientID=%s, isV2Format=%v, keyLen=%d, keyPrefix=%s",
		clientID, isV2Format, len(licenseKey), safePrefix(licenseKey, 20))

	// First, validate the license key cryptographically
	validationResult, err := license.ValidateLicense(ctx, licenseKey)
	if err != nil {
		log.Printf("[V2-DEBUG] License validation ERROR: %v", err)
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		log.Printf("[V2-DEBUG] License INVALID: %s", validationResult.Error)
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Debug: Log validation result
	log.Printf("[V2-DEBUG] License validation SUCCESS: ServiceName='%s', Tier='%s', OrgID='%s', Perms=%v",
		validationResult.ServiceName, validationResult.Tier, validationResult.OrgID, validationResult.Permissions)

	// Extract org_id from validated license
	orgID := validationResult.OrgID

	// Detect if this is a V2 service license (format: AXON-V2-...)
	isV2ServiceLicense := len(validationResult.ServiceName) > 0
	log.Printf("[V2-DEBUG] V2 service license check: isV2ServiceLicense=%v (ServiceName len=%d)",
		isV2ServiceLicense, len(validationResult.ServiceName))

	// V2 service licenses are self-contained - the cryptographic signature validates
	// all claims (tenant_id, tier, permissions, expiry). No database lookup needed.
	// This enables stateless validation and multi-region deployments without
	// requiring organization records in every database.
	if isV2ServiceLicense {
		// Map tier to rate limit from license payload
		rateLimit := 100 // Default PRO
		switch validationResult.Tier {
		case license.TierEnterprise:
			rateLimit = 500
		case license.TierEnterprisePlus:
			rateLimit = 1000
		}

		// Use permissions from signed license payload
		permissions := validationResult.Permissions
		if len(permissions) == 0 {
			permissions = []string{"query", "llm"} // Default if not specified
		}

		return &Client{
			ID:            orgID,
			Name:          validationResult.ServiceName, // Use service name as display name
			OrgID:         orgID,
			TenantID:      orgID,
			Permissions:   permissions,
			RateLimit:     rateLimit,
			Enabled:       true,
			LicenseTier:   string(validationResult.Tier),
			LicenseExpiry: validationResult.ExpiresAt,
			ServiceName:   validationResult.ServiceName,
		}, nil
	}

	// V1 license format is deprecated and no longer supported
	// All licenses must use V2 format: AXON-V2-{BASE64_JSON}-{SIGNATURE}
	// See ADR-009 for migration guide
	return nil, fmt.Errorf("V1 license format is deprecated. Please migrate to V2 format. See docs/LICENSE_MIGRATION.md")
}

// updateAPIKeyLastUsed updates the last_used_at timestamp for an API key
func updateAPIKeyLastUsed(ctx context.Context, db *sql.DB, apiKeyID string) {
	query := `
		UPDATE api_keys
		SET last_used_at = NOW(),
		    total_requests = total_requests + 1,
		    updated_at = NOW()
		WHERE api_key_id = $1
	`

	_, err := db.ExecContext(ctx, query, apiKeyID)
	if err != nil {
		// Log error but don't fail the request
		// In production, send to monitoring/logging system
		fmt.Printf("Warning: Failed to update last_used_at for API key %s: %v\n", apiKeyID, err)
	}
}

// trackRequestUsage records a request in the usage metrics
// This should be called for every request to track usage for billing
func trackRequestUsage(ctx context.Context, db *sql.DB, customerID, apiKeyID string, requestType string, success bool, latencyMS float64) error {
	// For real-time tracking, we'll use INSERT with ON CONFLICT to aggregate hourly
	query := `
		INSERT INTO usage_metrics (
			customer_id,
			api_key_id,
			period_start,
			period_end,
			period_type,
			total_requests,
			successful_requests,
			failed_requests,
			query_requests,
			llm_requests,
			connector_requests,
			planning_requests
		) VALUES (
			$1, $2,
			date_trunc('hour', NOW()),
			date_trunc('hour', NOW()) + INTERVAL '1 hour',
			'hourly',
			1,
			CASE WHEN $3 THEN 1 ELSE 0 END,
			CASE WHEN $3 THEN 0 ELSE 1 END,
			CASE WHEN $4 = 'query' THEN 1 ELSE 0 END,
			CASE WHEN $4 = 'llm' THEN 1 ELSE 0 END,
			CASE WHEN $4 = 'connector' THEN 1 ELSE 0 END,
			CASE WHEN $4 = 'planning' THEN 1 ELSE 0 END
		)
		ON CONFLICT (customer_id, period_start, period_type)
		DO UPDATE SET
			total_requests = usage_metrics.total_requests + 1,
			successful_requests = usage_metrics.successful_requests + CASE WHEN $3 THEN 1 ELSE 0 END,
			failed_requests = usage_metrics.failed_requests + CASE WHEN $3 THEN 0 ELSE 1 END,
			query_requests = usage_metrics.query_requests + CASE WHEN $4 = 'query' THEN 1 ELSE 0 END,
			llm_requests = usage_metrics.llm_requests + CASE WHEN $4 = 'llm' THEN 1 ELSE 0 END,
			connector_requests = usage_metrics.connector_requests + CASE WHEN $4 = 'connector' THEN 1 ELSE 0 END,
			planning_requests = usage_metrics.planning_requests + CASE WHEN $4 = 'planning' THEN 1 ELSE 0 END,
			updated_at = NOW()
	`

	_, err := db.ExecContext(ctx, query, customerID, apiKeyID, success, requestType)
	return err
}

// getCustomerUsageForMonth retrieves usage statistics for a customer in a given month
func getCustomerUsageForMonth(ctx context.Context, db *sql.DB, customerID string, month time.Time) (*UsageStats, error) {
	monthStart := time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, month.Location())

	query := `
		SELECT
			customer_id,
			COALESCE(SUM(total_requests), 0) as total_requests,
			COALESCE(SUM(successful_requests), 0) as successful_requests,
			COALESCE(SUM(failed_requests), 0) as failed_requests,
			COALESCE(SUM(blocked_requests), 0) as blocked_requests
		FROM usage_metrics
		WHERE customer_id = $1
		AND period_start >= $2
		AND period_start < $2 + INTERVAL '1 month'
		GROUP BY customer_id
	`

	var stats UsageStats
	err := db.QueryRowContext(ctx, query, customerID, monthStart).Scan(
		&stats.CustomerID,
		&stats.TotalRequests,
		&stats.SuccessfulRequests,
		&stats.FailedRequests,
		&stats.BlockedRequests,
	)

	if err == sql.ErrNoRows {
		// No usage for this month
		return &UsageStats{
			CustomerID: customerID,
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get usage stats: %w", err)
	}

	return &stats, nil
}

// UsageStats represents usage statistics for a customer
type UsageStats struct {
	CustomerID         string
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	BlockedRequests    int64
}

// createAPIKey creates a new API key for a customer
func createAPIKey(ctx context.Context, db *sql.DB, customerID, keyName string, expiryDays int) (string, error) {
	// Get customer info
	var orgID, tier string
	err := db.QueryRowContext(ctx,
		"SELECT organization_id, tier FROM customers WHERE customer_id = $1",
		customerID,
	).Scan(&orgID, &tier)

	if err != nil {
		return "", fmt.Errorf("customer not found: %w", err)
	}

	// Generate license key
	licenseKey, err := license.GenerateLicenseKey(license.Tier(tier), orgID, expiryDays)
	if err != nil {
		return "", fmt.Errorf("failed to generate license key: %w", err)
	}

	// Hash the license key
	hash := sha256.Sum256([]byte(licenseKey))
	licenseKeyHash := hex.EncodeToString(hash[:])

	// Insert into database
	query := `
		INSERT INTO api_keys (
			customer_id,
			license_key,
			license_key_hash,
			key_name,
			key_type,
			expires_at,
			enabled
		) VALUES ($1, $2, $3, $4, 'production', NOW() + INTERVAL '1 day' * $5, true)
		RETURNING api_key_id
	`

	var apiKeyID string
	err = db.QueryRowContext(ctx, query,
		customerID, licenseKey, licenseKeyHash, keyName, expiryDays,
	).Scan(&apiKeyID)

	if err != nil {
		return "", fmt.Errorf("failed to create API key: %w", err)
	}

	return licenseKey, nil
}

// revokeAPIKey revokes an API key
func revokeAPIKey(ctx context.Context, db *sql.DB, apiKeyID, revokedBy, reason string) error {
	query := `
		UPDATE api_keys
		SET enabled = false,
		    revoked_at = NOW(),
		    revoked_by = $2,
		    revoke_reason = $3,
		    updated_at = NOW()
		WHERE api_key_id = $1
	`

	result, err := db.ExecContext(ctx, query, apiKeyID, revokedBy, reason)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check revocation: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("API key not found")
	}

	return nil
}
