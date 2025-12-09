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

package llm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
func (s *PostgresStorage) SaveProvider(ctx context.Context, config *ProviderConfig) error {
	if config == nil {
		return errors.New("config cannot be nil")
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

	_, err = s.db.ExecContext(ctx, query,
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
	if err != nil {
		return fmt.Errorf("failed to save provider: %w", err)
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
func (s *PostgresStorage) DeleteProvider(ctx context.Context, name string) error {
	query := `
		DELETE FROM llm_providers
		WHERE name = $1
		  AND tenant_id = current_setting('app.current_org_id', true)
	`

	result, err := s.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete provider: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
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

	rows, err := s.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
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
func (s *PostgresStorage) RecordUsage(ctx context.Context, usage *ProviderUsage) error {
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

	_, err := s.db.ExecContext(ctx, query,
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
	if err != nil {
		return fmt.Errorf("failed to record usage: %w", err)
	}

	return nil
}

// ProviderUsage contains usage metrics for a provider request.
type ProviderUsage struct {
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
