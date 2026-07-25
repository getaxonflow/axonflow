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

package llm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"axonflow/platform/agent/rls"
)

// PostgresStorage implements Storage using PostgreSQL.
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new PostgreSQL-backed storage.
func NewPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

// SaveProvider persists a provider configuration to the database.
//
// v9 Phase 8 PR-C2 (#2384): llm_providers is mig 027 ENABLE RLS with policy
// `tenant_id = current_setting('app.current_org_id', true)`. The INSERT
// already reads the GUC in-line, so wrapping with WithOrgScope using
// config.TenantID makes the GUC value match the tenant_id row value. Without
// the wrap (master-role legacy path) both sides of the policy comparison
// would be empty strings — the row would land with tenant_id='' visible to
// nobody.
func (s *PostgresStorage) SaveProvider(ctx context.Context, config *ProviderConfig) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}
	if config.TenantID == "" {
		return errors.New("config.TenantID must be set for RLS scoping")
	}

	settingsJSON, err := json.Marshal(config.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	query := `
		INSERT INTO llm_providers (
			tenant_id, name, type, api_key_encrypted, api_key_secret_arn,
			endpoint, model, region, enabled, priority, weight,
			rate_limit, timeout_seconds, settings
		) VALUES (
			current_setting('app.current_org_id', true), $1, $2, $3, $4,
			$5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
			type = EXCLUDED.type,
			api_key_encrypted = EXCLUDED.api_key_encrypted,
			api_key_secret_arn = EXCLUDED.api_key_secret_arn,
			endpoint = EXCLUDED.endpoint,
			model = EXCLUDED.model,
			region = EXCLUDED.region,
			enabled = EXCLUDED.enabled,
			priority = EXCLUDED.priority,
			weight = EXCLUDED.weight,
			rate_limit = EXCLUDED.rate_limit,
			timeout_seconds = EXCLUDED.timeout_seconds,
			settings = EXCLUDED.settings,
			updated_at = NOW()
	`

	if wrapErr := rls.WithOrgScope(ctx, s.db, config.TenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			config.Name,
			config.Type,
			config.APIKey,
			config.APIKeySecretARN,
			config.Endpoint,
			config.Model,
			config.Region,
			config.Enabled,
			config.Priority,
			config.Weight,
			config.RateLimit,
			config.TimeoutSeconds,
			settingsJSON,
		)
		return execErr
	}); wrapErr != nil {
		return fmt.Errorf("failed to save provider: %w", wrapErr)
	}

	return nil
}

// GetProvider retrieves a provider configuration by name.
func (s *PostgresStorage) GetProvider(ctx context.Context, name string) (*ProviderConfig, error) {
	query := `
		SELECT name, type, api_key_encrypted, api_key_secret_arn,
			   endpoint, model, region, enabled, priority, weight,
			   rate_limit, timeout_seconds, settings
		FROM llm_providers
		WHERE name = $1
		  AND tenant_id = current_setting('app.current_org_id', true)
	`

	var config ProviderConfig
	var apiKey, apiKeySecretARN, endpoint, model, region sql.NullString
	var settingsJSON []byte

	err := s.db.QueryRowContext(ctx, query, name).Scan(
		&config.Name,
		&config.Type,
		&apiKey,
		&apiKeySecretARN,
		&endpoint,
		&model,
		&region,
		&config.Enabled,
		&config.Priority,
		&config.Weight,
		&config.RateLimit,
		&config.TimeoutSeconds,
		&settingsJSON,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("provider %q not found", name)
		}
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	// Handle nullable fields
	config.APIKey = apiKey.String
	config.APIKeySecretARN = apiKeySecretARN.String
	config.Endpoint = endpoint.String
	config.Model = model.String
	config.Region = region.String

	// Initialize settings to empty map to avoid nil pointer issues
	config.Settings = make(map[string]any)

	// Parse settings if present
	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &config.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}
	}

	return &config, nil
}

// DeleteProvider removes a provider configuration from the database.
//
// v9 Phase 8 PR-C2 (#2384): wraps the DELETE so the mig 027 ENABLE RLS policy
// (`tenant_id = current_setting('app.current_org_id', true)`) sees the orgID
// on app_role. Without the GUC the DELETE filters to 0 rows silently.
func (s *PostgresStorage) DeleteProvider(ctx context.Context, orgID, name string) error {
	query := `
		DELETE FROM llm_providers
		WHERE name = $1
		  AND tenant_id = current_setting('app.current_org_id', true)
	`

	var rowsAffected int64
	if wrapErr := rls.WithOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		result, execErr := tx.ExecContext(ctx, query, name)
		if execErr != nil {
			return fmt.Errorf("failed to delete provider: %w", execErr)
		}
		var raErr error
		rowsAffected, raErr = result.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("failed to check rows affected: %w", raErr)
		}
		return nil
	}); wrapErr != nil {
		return wrapErr
	}

	if rowsAffected == 0 {
		return fmt.Errorf("provider %q not found", name)
	}

	return nil
}

// ListProviders returns all provider names for an organization.
func (s *PostgresStorage) ListProviders(ctx context.Context, orgID string) ([]string, error) {
	query := `
		SELECT name FROM llm_providers
		WHERE tenant_id = $1
		ORDER BY name
	`

	// #3048: llm_providers is RLS-enabled (mig 027) — the bare read matched
	// 0 rows under axonflow_app_role. Same org key as the write wraps.
	var names []string
	err := rls.WithOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, orgID)
		if qErr != nil {
			return fmt.Errorf("failed to list providers: %w", qErr)
		}
		defer rows.Close()

		for rows.Next() {
			var name string
			if sErr := rows.Scan(&name); sErr != nil {
				return fmt.Errorf("failed to scan provider name: %w", sErr)
			}
			names = append(names, name)
		}
		if rErr := rows.Err(); rErr != nil {
			return fmt.Errorf("error iterating providers: %w", rErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return names, nil
}

// ListAllProviders returns all provider names (admin use).
// This uses the RLS context so it returns providers for the current org.
func (s *PostgresStorage) ListAllProviders(ctx context.Context) ([]string, error) {
	query := `
		SELECT name FROM llm_providers
		WHERE tenant_id = current_setting('app.current_org_id', true)
		ORDER BY name
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list all providers: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan provider name: %w", err)
		}
		names = append(names, name)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating providers: %w", err)
	}

	return names, nil
}

// SaveHealth persists provider health status to the database.
func (s *PostgresStorage) SaveHealth(ctx context.Context, providerName string, health *HealthCheckResult) error {
	query := `
		INSERT INTO llm_provider_health (provider_id, status, message, latency_ms, last_checked_at, consecutive_failures)
		SELECT id, $2, $3, $4, NOW(), $5
		FROM llm_providers
		WHERE name = $1 AND tenant_id = current_setting('app.current_org_id', true)
		ON CONFLICT (provider_id) DO UPDATE SET
			status = EXCLUDED.status,
			message = EXCLUDED.message,
			latency_ms = EXCLUDED.latency_ms,
			last_checked_at = NOW(),
			consecutive_failures = EXCLUDED.consecutive_failures,
			updated_at = NOW()
	`

	_, err := s.db.ExecContext(ctx, query,
		providerName,
		health.Status,
		health.Message,
		health.Latency.Milliseconds(),
		health.ConsecutiveFailures,
	)
	if err != nil {
		return fmt.Errorf("failed to save health: %w", err)
	}

	return nil
}

// RecordUsage records usage metrics for a provider.
//
// v9 Phase 8 PR-C2 (#2384): llm_provider_usage is mig 027 ENABLE RLS with
// policy `tenant_id = current_setting('app.current_org_id', true)`. usage.TenantID
// is required so the wrap can set the GUC before the INSERT — both the SELECT
// (to resolve provider_id) and the WITH CHECK on the INSERT depend on it.
func (s *PostgresStorage) RecordUsage(ctx context.Context, usage *ProviderUsage) error {
	if usage == nil {
		return errors.New("usage cannot be nil")
	}
	if usage.TenantID == "" {
		return errors.New("usage.TenantID must be set for RLS scoping")
	}
	query := `
		INSERT INTO llm_provider_usage (
			tenant_id, provider_id, request_id, model,
			input_tokens, output_tokens, total_tokens,
			estimated_cost_usd, latency_ms, status, error_message
		)
		SELECT
			current_setting('app.current_org_id', true),
			id, $2, $3, $4, $5, $6, $7, $8, $9, $10
		FROM llm_providers
		WHERE name = $1 AND tenant_id = current_setting('app.current_org_id', true)
	`

	if wrapErr := rls.WithOrgScope(ctx, s.db, usage.TenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			usage.ProviderName,
			usage.RequestID,
			usage.Model,
			usage.InputTokens,
			usage.OutputTokens,
			usage.TotalTokens,
			usage.EstimatedCostUSD,
			usage.LatencyMs,
			usage.Status,
			usage.ErrorMessage,
		)
		return execErr
	}); wrapErr != nil {
		return fmt.Errorf("failed to record usage: %w", wrapErr)
	}

	return nil
}

// ProviderUsage contains usage metrics for a provider request.
type ProviderUsage struct {
	// TenantID is the per-org RLS scope identifier. Required.
	TenantID         string
	ProviderName     string
	RequestID        string
	Model            string
	InputTokens      int
	OutputTokens     int
	TotalTokens      int
	EstimatedCostUSD float64
	LatencyMs        int64
	Status           string // "success", "error", "timeout", "rate_limited"
	ErrorMessage     string
}

// Ensure PostgresStorage implements Storage interface.
var _ Storage = (*PostgresStorage)(nil)
