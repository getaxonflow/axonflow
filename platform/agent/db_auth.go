// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent/license"
	logutil "axonflow/platform/shared/logger"
)

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
	APIKeyID        string
	CustomerID      string
	LicenseKey      string
	KeyName         string
	KeyType         string
	ExpiresAt       time.Time
	GracePeriodDays int
	Permissions     []string
	CustomRateLimit *int // NULL = use tier default
	Enabled         bool
	RevokedAt       *time.Time
	LastUsedAt      *time.Time
	TotalRequests   int64
}

// PricingTierInfo represents a pricing tier from the database
type PricingTierInfo struct {
	Tier              string
	DeploymentMode    string
	MonthlyPrice      int
	IncludedRequests  *int64 // NULL for in-vpc
	MaxNodes          *int
	MaxUsers          *int
	RequestsPerMinute int
	OverageRatePer1K  *float64 // NULL for in-vpc
	SupportSLAHours   int
	Features          map[string]interface{}
	Active            bool
}

// validateClientCredentialsDB validates a client using database lookup.
// The clientSecret is the Ed25519-signed license key sent via OAuth2 Basic auth.
// Supports both api_keys (legacy) and organizations (new) tables.
func validateClientCredentialsDB(ctx context.Context, db *sql.DB, clientID, clientSecret string) (*Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID required")
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("client secret required")
	}

	// Try API keys authentication first (legacy path)
	client, err := validateViaAPIKeys(ctx, db, clientID, clientSecret)
	if err == nil {
		return client, nil
	}

	// Fallback to organizations authentication (new path)
	return validateViaOrganizations(ctx, db, clientID, clientSecret)
}

// validateViaAPIKeys validates using api_keys + customers tables (legacy).
//
// The lookup is delegated to the auth_lookup_api_key(TEXT) SECURITY DEFINER
// function (migration 108, Epic #2230 Phase 8 B6). The function bypasses
// FORCE RLS on api_keys + customers + pricing_tiers, which is required
// because this lookup runs BEFORE app.current_org_id can be established
// (chicken-and-egg: the lookup IS what establishes the caller's org_id).
//
// The function's RETURN TABLE column list must match the Scan() order
// below one-for-one — any drift surfaces as a column-mismatch error at
// runtime. The Go-side filters (enabled=true, status='active') live
// inside the function body; this call site no longer needs them.
func validateViaAPIKeys(ctx context.Context, db *sql.DB, clientID, clientSecret string) (*Client, error) {
	// Hash the client secret (license key format) for lookup
	hash := sha256.Sum256([]byte(clientSecret))
	secretHash := hex.EncodeToString(hash[:])

	query := `SELECT * FROM auth_lookup_api_key($1)`

	var apiKey APIKeyInfo
	var customer CustomerInfo
	var tierRateLimit int
	var customRateLimitNullable sql.NullInt64
	var revokedAtNullable sql.NullTime
	var lastUsedAtNullable sql.NullTime

	// Permissions will be parsed from JSONB array
	var permissionsJSON []byte

	err := db.QueryRowContext(ctx, query, secretHash).Scan(
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
		return nil, fmt.Errorf("invalid credentials or client not found")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	// Verify the client secret matches the stored license key
	if apiKey.LicenseKey != clientSecret {
		return nil, fmt.Errorf("credentials mismatch")
	}

	// Check if revoked
	if revokedAtNullable.Valid {
		return nil, fmt.Errorf("API key has been revoked")
	}

	// Validate license key format using license validation system
	validationResult, err := license.ValidateLicense(ctx, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Parse permissions from JSONB array
	permissions := []string{"query", "llm"} // Default permissions
	if len(permissionsJSON) > 0 {
		var parsedPermissions []string
		if err := json.Unmarshal(permissionsJSON, &parsedPermissions); err != nil {
			log.Printf("[AUTH] Warning: Failed to parse permissions JSON, using defaults: %v", err)
		} else if len(parsedPermissions) > 0 {
			permissions = parsedPermissions
		}
	}

	// Determine rate limit (custom override or tier default)
	rateLimit := tierRateLimit
	if customRateLimitNullable.Valid && customRateLimitNullable.Int64 > 0 {
		rateLimit = int(customRateLimitNullable.Int64)
	}

	// Update last_used_at asynchronously (fire and forget)
	go updateAPIKeyLastUsed(context.Background(), db, apiKey.APIKeyID)

	// Return authenticated client.
	// ADR-052 §5: ClientID is the API credential identity (the api_key_id),
	// NOT the org_id. Collapsing them was a misreading of the ADR — every
	// api_key for one org would share the same ClientID, which breaks any
	// post-v10 unique-index lookup keyed on client_id. ID retains
	// OrganizationID for the legacy compat window.
	return &Client{
		ID:            customer.OrganizationID,
		ClientID:      apiKey.APIKeyID, // ADR-052 §5: credential identity, not org scope
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
func validateViaOrganizations(ctx context.Context, db *sql.DB, clientID, clientSecret string) (*Client, error) {
	// Debug: Log client secret format detection
	isEd25519Format := len(clientSecret) > 5 && clientSecret[:5] == "AXON-" && strings.Contains(clientSecret[5:], ".")
	log.Printf("[LICENSE-DEBUG] validateViaOrganizations: clientID=%s, isEd25519=%v, secretLen=%d, secretPrefix=%s",
		logutil.Sanitize(clientID), isEd25519Format, len(clientSecret), logutil.MaskSecret(clientSecret, 10))

	// First, validate the license key format cryptographically
	validationResult, err := license.ValidateLicense(ctx, clientSecret)
	if err != nil {
		log.Printf("[LICENSE-DEBUG] License validation ERROR: %v", err)
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !validationResult.Valid {
		log.Printf("[LICENSE-DEBUG] License INVALID: %s", logutil.Sanitize(validationResult.Error))
		return nil, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Debug: Log validation result
	log.Printf("[LICENSE-DEBUG] License validation SUCCESS: ServiceName='%s', Tier='%s', OrgID='%s', Perms=%v",
		validationResult.ServiceName, validationResult.Tier, validationResult.OrgID, validationResult.Permissions)

	// Extract org_id from validated license
	orgID := validationResult.OrgID

	// Detect if this is a service license (has service_name in payload)
	isServiceLicense := len(validationResult.ServiceName) > 0
	log.Printf("[LICENSE-DEBUG] Service license check: isServiceLicense=%v (ServiceName len=%d)",
		isServiceLicense, len(validationResult.ServiceName))

	// Service licenses are self-contained - the Ed25519 signature validates
	// all claims (tenant_id, tier, permissions, expiry). No database lookup needed.
	// This enables stateless validation and multi-region deployments without
	// requiring organization records in every database.
	if isServiceLicense {
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

		// Auto-register tenant and org (fire-and-forget, non-blocking)
		if db != nil {
			go registerTenantAndOrg(db, clientID, orgID, string(validationResult.Tier), validationResult.MaxNodes)
		}

		return &Client{
			ID:            clientID,                     // From Basic auth username (tenant identity)
			ClientID:      clientID,                     // v9 ADR-052: API credential/app identity
			Name:          validationResult.ServiceName, // Use service name as display name
			OrgID:         orgID,                        // From license (org entitlement)
			TenantID:      clientID,                     // From Basic auth username (data isolation)
			Permissions:   permissions,
			RateLimit:     rateLimit,
			Enabled:       true,
			LicenseTier:   string(validationResult.Tier),
			LicenseExpiry: validationResult.ExpiresAt,
			ServiceName:   validationResult.ServiceName,
		}, nil
	}

	// Non-service licenses (no service_name) are not supported for organization auth.
	// All licenses must be Ed25519-signed service licenses with a service_name field.
	// See ADR-032 for format specification.
	return nil, fmt.Errorf("license does not contain service identity (service_name). Use a service license generated via the license portal or keygen CLI")
}

// updateAPIKeyLastUsed updates the last_used_at timestamp for an API key.
//
// Delegated to the auth_touch_api_key(VARCHAR) SECURITY DEFINER helper
// (migration 108, Epic #2230 Phase 8 B6). This call site is invoked as a
// fire-and-forget goroutine after validateViaAPIKeys returns success, on a
// fresh DB connection that does NOT carry the request handler's
// transactional GUC. Without the SECURITY DEFINER wrapper, the UPDATE
// would match zero rows under FORCE RLS once it lands on api_keys.
func updateAPIKeyLastUsed(ctx context.Context, db *sql.DB, apiKeyID string) {
	_, err := db.ExecContext(ctx, "SELECT auth_touch_api_key($1)", apiKeyID)
	if err != nil {
		// Route through the [AUTH]-prefixed agent logger so the failure
		// lands in CloudWatch alongside the rest of db_auth.go's emit
		// pattern. Previous fmt.Printf went to stderr only and depending
		// on log driver config could be invisible to ops — surfaced by
		// R3 hostile review as MEDIUM-2 (observability gap that would
		// have masked the HIGH-1 UUID/VARCHAR cast bug for hours).
		redactedKeyID := apiKeyID
		if len(apiKeyID) > 8 {
			redactedKeyID = apiKeyID[:4] + "***" + apiKeyID[len(apiKeyID)-4:]
		}
		// Route err.Error() through logutil.Sanitize to strip control chars
		// (NUL/CR/LF/TAB/ANSI) and bound the message length — same hardening
		// the existing [AUTH] log sites apply (lines 531/538). NOTE:
		// Sanitize does NOT mask UUIDs; api_key_id is a DB primary key
		// (not a secret like license_key) so its appearance in CloudWatch
		// for diagnostic purposes is acceptable, but if that ever changes,
		// add explicit UUID-shape redaction here.
		log.Printf("[AUTH] auth_touch_api_key failed for %s: %s", redactedKeyID, logutil.Sanitize(err.Error()))
	}
}

// trackRequestUsage records a request in the usage metrics
// This should be called for every request to track usage for billing.
//
// v9 Phase 8 #2384 PR-C1: usage_metrics is ENABLE-RLS (mig 018) — under
// axonflow_app_role the INSERT/UPDATE WITH CHECK predicate
// org_id = current_setting('app.current_org_id') fires. The signature now
// takes an orgID so callers can pin app.current_org_id via WithOrgScope.
// The INSERT column list grew an explicit org_id; the ON CONFLICT path
// (customer_id, period_start, period_type) is unchanged but the UPDATE
// arm doesn't need to re-write org_id since the conflict target already
// constrains the matched row to the same tenant.
//
//nolint:unused // Used in tests
func trackRequestUsage(ctx context.Context, db *sql.DB, orgID, customerID, apiKeyID string, requestType string, success bool, latencyMS float64) error {
	if orgID == "" {
		return fmt.Errorf("trackRequestUsage: orgID must be non-empty (RLS on usage_metrics)")
	}
	// For real-time tracking, we'll use INSERT with ON CONFLICT to aggregate hourly
	query := `
		INSERT INTO usage_metrics (
			org_id,
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
			$1, $2, $3,
			date_trunc('hour', NOW()),
			date_trunc('hour', NOW()) + INTERVAL '1 hour',
			'hourly',
			1,
			CASE WHEN $4 THEN 1 ELSE 0 END,
			CASE WHEN $4 THEN 0 ELSE 1 END,
			CASE WHEN $5 = 'query' THEN 1 ELSE 0 END,
			CASE WHEN $5 = 'llm' THEN 1 ELSE 0 END,
			CASE WHEN $5 = 'connector' THEN 1 ELSE 0 END,
			CASE WHEN $5 = 'planning' THEN 1 ELSE 0 END
		)
		ON CONFLICT (customer_id, period_start, period_type)
		DO UPDATE SET
			total_requests = usage_metrics.total_requests + 1,
			successful_requests = usage_metrics.successful_requests + CASE WHEN $4 THEN 1 ELSE 0 END,
			failed_requests = usage_metrics.failed_requests + CASE WHEN $4 THEN 0 ELSE 1 END,
			query_requests = usage_metrics.query_requests + CASE WHEN $5 = 'query' THEN 1 ELSE 0 END,
			llm_requests = usage_metrics.llm_requests + CASE WHEN $5 = 'llm' THEN 1 ELSE 0 END,
			connector_requests = usage_metrics.connector_requests + CASE WHEN $5 = 'connector' THEN 1 ELSE 0 END,
			planning_requests = usage_metrics.planning_requests + CASE WHEN $5 = 'planning' THEN 1 ELSE 0 END,
			updated_at = NOW()
	`

	return WithOrgScope(ctx, db, orgID, func(tx *sql.Tx) error {
		_, exErr := tx.ExecContext(ctx, query, orgID, customerID, apiKeyID, success, requestType)
		return exErr
	})
}

// getCustomerUsageForMonth retrieves usage statistics for a customer in a given month
//
//nolint:unused // Used in tests
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
//
//nolint:unused // Used in tests
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

	// v9 Phase 8 PR-A (mig 109): route through auth_insert_api_key SECURITY
	// DEFINER helper so the INSERT bypasses FORCE RLS on api_keys (mig 108).
	// Companion to mig 108's auth_lookup_api_key / auth_touch_api_key — closes
	// the INSERT side of the in-VPC enterprise auth chicken-and-egg.
	// orgID is populated from the customers lookup above; passing it so the
	// row's org_id column is non-NULL — the column mig 108's FORCE RLS policy
	// keys off (pre-PR-A raw INSERT omitted org_id, rows invisible to direct
	// app_role SELECTs). Community-mode DBs lack 006_option3 schema so this
	// call never fires there.
	var apiKeyID string
	err = db.QueryRowContext(ctx,
		`SELECT auth_insert_api_key($1, $2, $3, $4, $5, $6)`,
		customerID, licenseKey, licenseKeyHash, keyName, expiryDays, orgID,
	).Scan(&apiKeyID)

	if err != nil {
		return "", fmt.Errorf("failed to create API key: %w", err)
	}

	return licenseKey, nil
}

// revokeAPIKey revokes an API key
//
//nolint:unused // Used in tests
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

// registeredTenants tracks which tenant+org pairs have been registered in the DB.
// Avoids hitting the database on every authenticated request — only on first-seen.
var registeredTenants sync.Map

// registerTenantAndOrg auto-registers the tenant and org in the database.
// Called as a fire-and-forget goroutine after successful auth — never blocks the request.
// Uses the register_tenant() and register_org() SQL functions from migration 062.
// Skips DB calls if this tenant+org pair has already been registered in this process lifetime.
func registerTenantAndOrg(db *sql.DB, tenantID, orgID, tier string, maxNodes int) {
	if db == nil || tenantID == "" || orgID == "" {
		return
	}

	// Skip if already registered (in-memory cache — reset on restart)
	cacheKey := tenantID + "|" + orgID
	if _, loaded := registeredTenants.LoadOrStore(cacheKey, true); loaded {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Register org first (tenant FK references it) — pass tier and maxNodes from license
	_, err := db.ExecContext(ctx, "SELECT register_org($1, $2, $3, $4)", orgID, orgID, tier, maxNodes)
	if err != nil {
		log.Printf("[AUTH] Failed to auto-register org %s: %v", logutil.Sanitize(orgID), err)
		registeredTenants.Delete(cacheKey) // Allow retry on next request
	}

	// Register tenant
	_, err = db.ExecContext(ctx, "SELECT register_tenant($1, $2)", tenantID, orgID)
	if err != nil {
		log.Printf("[AUTH] Failed to auto-register tenant %s: %v", logutil.Sanitize(tenantID), err)
		registeredTenants.Delete(cacheKey) // Allow retry on next request
	}
}
