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

package orchestrator

// RLS (Row-Level Security) Middleware for AxonFlow Agent
// Purpose: Set PostgreSQL session variable for database-level tenant isolation
// Following: Principle 0 (Quality Over Velocity), Principle 3 (No Silent Failures)
//
// Architecture:
// 1. After license validation, extract org_id from Client
// 2. Set app.current_org_id session variable on database connection
// 3. All subsequent queries automatically filtered by RLS policies
// 4. Reset session variable after request (cleanup for connection pooling)
//
// Usage in handler:
//   client, err := validateClientLicense(...)
//   if err := SetRLSContext(ctx, db, client.OrgID); err != nil {
//       // Handle error
//   }
//   defer ResetRLSContext(ctx, db)
//   // All database queries now automatically filtered by org_id

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// SetRLSContext sets the app.current_org_id session variable for RLS enforcement
// This must be called after license validation and before any database queries
func SetRLSContext(ctx context.Context, db *sql.DB, orgID string) error {
	if db == nil {
		// No database configured - RLS not applicable
		return nil
	}

	if orgID == "" {
		return fmt.Errorf("RLS: org_id cannot be empty")
	}

	// Create context with timeout for RLS setup
	rlsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Call PostgreSQL function to set session variable
	// Using function instead of raw SET for better error handling
	_, err := db.ExecContext(rlsCtx, "SELECT set_org_id($1)", orgID)
	if err != nil {
		log.Printf("❌ RLS: Failed to set org_id='%s': %v", orgID, err)
		return fmt.Errorf("RLS: failed to set session variable: %w", err)
	}

	log.Printf("🔒 RLS: Set org_id='%s' for connection", orgID)
	return nil
}

// ResetRLSContext clears the app.current_org_id session variable
// This should be called after request completion to prevent session variable leakage
// in connection pooling scenarios
func ResetRLSContext(ctx context.Context, db *sql.DB) {
	if db == nil {
		return
	}

	// Create context with short timeout
	rlsCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	// Call PostgreSQL function to reset session variable
	_, err := db.ExecContext(rlsCtx, "SELECT reset_org_id()")
	if err != nil {
		// Log warning but don't fail - this is cleanup
		log.Printf("⚠️  RLS: Failed to reset org_id (non-fatal): %v", err)
	} else {
		log.Printf("🔓 RLS: Reset org_id (connection cleaned up)")
	}
}

// WithRLS wraps a database operation with RLS context setup and cleanup
// This is a helper function for operations that need RLS protection
//
// Example:
//   err := WithRLS(ctx, db, client.OrgID, func(db *sql.DB) error {
//       return recordUsageEvent(db, event)
//   })
func WithRLS(ctx context.Context, db *sql.DB, orgID string, fn func(*sql.DB) error) error {
	// Set RLS context
	if err := SetRLSContext(ctx, db, orgID); err != nil {
		return err
	}

	// Always reset RLS context, even if fn returns error
	defer ResetRLSContext(ctx, db)

	// Execute operation
	return fn(db)
}

// GetCurrentOrgID retrieves the current app.current_org_id session variable value
// This is useful for debugging and verification
func GetCurrentOrgID(ctx context.Context, db *sql.DB) (string, error) {
	if db == nil {
		return "", fmt.Errorf("database connection is nil")
	}

	var orgID sql.NullString
	err := db.QueryRowContext(ctx, "SELECT current_setting('app.current_org_id', true)").Scan(&orgID)
	if err != nil {
		return "", fmt.Errorf("failed to get current org_id: %w", err)
	}

	if !orgID.Valid || orgID.String == "" {
		return "", fmt.Errorf("org_id not set in session")
	}

	return orgID.String, nil
}

// VerifyRLSActive checks if RLS is enabled on a given table
// This is useful for testing and verification
func VerifyRLSActive(ctx context.Context, db *sql.DB, tableName string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database connection is nil")
	}

	var rlsEnabled bool
	query := `
		SELECT COALESCE(rowsecurity, false)
		FROM pg_tables
		WHERE schemaname = 'public' AND tablename = $1
	`

	err := db.QueryRowContext(ctx, query, tableName).Scan(&rlsEnabled)
	if err == sql.ErrNoRows {
		return false, fmt.Errorf("table '%s' not found", tableName)
	}
	if err != nil {
		return false, fmt.Errorf("failed to check RLS status: %w", err)
	}

	return rlsEnabled, nil
}

// RLSStats provides statistics about RLS enforcement
type RLSStats struct {
	TablesWithRLS int      `json:"tables_with_rls"`
	PolicyCount   int      `json:"policy_count"`
	EnabledTables []string `json:"enabled_tables"`
}

// GetRLSStats retrieves statistics about RLS configuration
// This is useful for monitoring and health checks
func GetRLSStats(ctx context.Context, db *sql.DB) (*RLSStats, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	stats := &RLSStats{}

	// Count tables with RLS enabled
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM pg_tables
		WHERE schemaname = 'public' AND rowsecurity = true
	`).Scan(&stats.TablesWithRLS)
	if err != nil {
		return nil, fmt.Errorf("failed to count RLS tables: %w", err)
	}

	// Count policies
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM pg_policies
		WHERE schemaname = 'public'
	`).Scan(&stats.PolicyCount)
	if err != nil {
		return nil, fmt.Errorf("failed to count policies: %w", err)
	}

	// Get table names
	rows, err := db.QueryContext(ctx, `
		SELECT tablename
		FROM pg_tables
		WHERE schemaname = 'public' AND rowsecurity = true
		ORDER BY tablename
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query RLS tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, fmt.Errorf("failed to scan table name: %w", err)
		}
		stats.EnabledTables = append(stats.EnabledTables, tableName)
	}

	return stats, nil
}

// RLSHealthCheck performs a comprehensive health check of RLS configuration
// Returns error if RLS is not properly configured
func RLSHealthCheck(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database connection is nil")
	}

	// Check if helper functions exist
	funcs := []string{"get_current_org_id", "set_org_id", "reset_org_id"}
	for _, funcName := range funcs {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_proc p
				JOIN pg_namespace n ON p.pronamespace = n.oid
				WHERE n.nspname = 'public' AND p.proname = $1
			)
		`, funcName).Scan(&exists)

		if err != nil {
			return fmt.Errorf("failed to check function '%s': %w", funcName, err)
		}

		if !exists {
			return fmt.Errorf("RLS helper function '%s' not found - migration 022 not applied", funcName)
		}
	}

	// Check if RLS is enabled on critical tables (OSS tables only)
	// Note: enterprise tables (usage_events, agent_heartbeats) are not in OSS builds
	criticalTables := []string{
		"organizations",
		"user_sessions",
		"dynamic_policies",
		"static_policies",
	}

	for _, table := range criticalTables {
		enabled, err := VerifyRLSActive(ctx, db, table)
		if err != nil {
			return fmt.Errorf("failed to verify RLS on table '%s': %w", table, err)
		}

		if !enabled {
			return fmt.Errorf("RLS not enabled on critical table '%s' - migration 022 may not be fully applied", table)
		}
	}

	// Get stats for logging
	stats, err := GetRLSStats(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to get RLS stats: %w", err)
	}

	log.Printf("✅ RLS Health Check PASSED: %d tables with RLS, %d policies", stats.TablesWithRLS, stats.PolicyCount)
	return nil
}
