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

// Package testutil provides shared test utilities including database containers.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	dockerclient "github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PostgresContainer wraps a testcontainers PostgreSQL instance.
type PostgresContainer struct {
	Container testcontainers.Container
	DB        *sql.DB
	URL       string
}

// PostgresConfig holds configuration for the test container.
type PostgresConfig struct {
	Database string
	Username string
	Password string
	Image    string
}

// DefaultPostgresConfig returns sensible defaults for test containers.
func DefaultPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Database: "axonflow_test",
		Username: "test",
		Password: "test",
		Image:    "postgres:16-alpine",
	}
}

// StartPostgres starts a PostgreSQL container for testing.
// The container is automatically terminated when the test completes.
func StartPostgres(t *testing.T, cfg PostgresConfig) *PostgresContainer {
	t.Helper()

	ctx := context.Background()

	container, err := postgres.Run(ctx,
		cfg.Image,
		postgres.WithDatabase(cfg.Database),
		postgres.WithUsername(cfg.Username),
		postgres.WithPassword(cfg.Password),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Register cleanup
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Warning: failed to terminate PostgreSQL container: %v", err)
		}
	})

	// Get connection string
	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("Failed to get PostgreSQL connection string: %v", err)
	}

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		t.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Verify connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping PostgreSQL: %v", err)
	}

	// Register DB cleanup
	t.Cleanup(func() {
		db.Close()
	})

	return &PostgresContainer{
		Container: container,
		DB:        db,
		URL:       connStr,
	}
}

// RunMigration executes a SQL migration on the test database.
func (pc *PostgresContainer) RunMigration(t *testing.T, migration string) {
	t.Helper()

	_, err := pc.DB.Exec(migration)
	if err != nil {
		t.Fatalf("Failed to run migration: %v", err)
	}
}

// SkipIfNoDocker skips the test if Docker is not available.
// Use this at the start of integration tests to provide a graceful skip.
func SkipIfNoDocker(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider, err := testcontainers.NewDockerProvider()
	if err != nil {
		t.Skipf("Docker not available: %v", err)
		return
	}
	defer provider.Close()

	// Try to ping Docker
	if _, err := provider.Client().Ping(ctx, dockerclient.PingOptions{}); err != nil {
		t.Skipf("Docker daemon not responding: %v", err)
	}
}

// GatewayContextsSchema returns the schema for the gateway_contexts table.
func GatewayContextsSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS gateway_contexts (
			context_id VARCHAR(36) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_token_hash VARCHAR(64) NOT NULL,
			query_hash VARCHAR(64) NOT NULL,
			data_sources TEXT[],
			policies_evaluated TEXT[],
			approved BOOLEAN DEFAULT true,
			block_reason TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		)
	`
}

// ConnectorRegistrySchema returns the schema for connector storage tables.
func ConnectorRegistrySchema() string {
	return `
		CREATE TABLE IF NOT EXISTS connector_registry (
			id VARCHAR(255) PRIMARY KEY,
			connector_type VARCHAR(50) NOT NULL,
			config JSONB NOT NULL,
			enabled BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS connector_state (
			connector_id VARCHAR(255) PRIMARY KEY,
			state JSONB NOT NULL,
			last_health_check TIMESTAMPTZ,
			health_status VARCHAR(20) DEFAULT 'unknown',
			error_message TEXT,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (connector_id) REFERENCES connector_registry(id) ON DELETE CASCADE
		);
	`
}

// ExecWithRetry executes a database query with retry logic.
func ExecWithRetry(db *sql.DB, query string, maxRetries int) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		_, lastErr = db.Exec(query)
		if lastErr == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("failed after %d retries: %w", maxRetries, lastErr)
}

// LLMProvidersSchema returns the schema for LLM provider storage.
// Must match the columns expected by llm.PostgresStorage (storage.go).
func LLMProvidersSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS llm_providers (
			id SERIAL PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(50) NOT NULL,
			api_key_encrypted TEXT,
			api_key_secret_arn TEXT,
			endpoint TEXT,
			model TEXT,
			region TEXT,
			enabled BOOLEAN DEFAULT true,
			priority INTEGER DEFAULT 0,
			weight INTEGER DEFAULT 0,
			rate_limit INTEGER DEFAULT 0,
			timeout_seconds INTEGER DEFAULT 30,
			settings JSONB DEFAULT '{}',
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(tenant_id, name)
		);

		CREATE TABLE IF NOT EXISTS llm_provider_health (
			id SERIAL PRIMARY KEY,
			provider_id INTEGER NOT NULL REFERENCES llm_providers(id) ON DELETE CASCADE,
			status VARCHAR(20) NOT NULL DEFAULT 'unknown',
			message TEXT,
			latency_ms BIGINT DEFAULT 0,
			last_checked_at TIMESTAMPTZ DEFAULT NOW(),
			consecutive_failures INTEGER DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(provider_id)
		);

		CREATE TABLE IF NOT EXISTS llm_provider_usage (
			id SERIAL PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			provider_id INTEGER NOT NULL REFERENCES llm_providers(id) ON DELETE CASCADE,
			request_id TEXT,
			model TEXT,
			input_tokens INTEGER DEFAULT 0,
			output_tokens INTEGER DEFAULT 0,
			total_tokens INTEGER DEFAULT 0,
			estimated_cost_usd NUMERIC(10,6) DEFAULT 0,
			latency_ms BIGINT DEFAULT 0,
			status VARCHAR(20) DEFAULT 'success',
			error_message TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)
	`
}

// DynamicPoliciesSchema returns the schema for dynamic policies.
// Matches the PolicyRepository expected schema (policy_api_repository.go).
//
// The `org_id` + `client_id` columns mirror migration 090
// (v9_policy_tables_client_id). The orchestrator's INSERT path writes
// both; omitting them here causes "column does not exist" failures on
// every integration test that creates a policy via the repository.
// Kept in sync with the production migration shape — if migration 090
// adds a new column, mirror it here.
//
// `segment_id` mirrors migration 159 (ADR-060 #2989 P3b): nullable,
// orthogonal to tenant_id. L10 (#3239 round 2) added this — it was
// missing here (divergent from db_policy_engine_integration_test.go's own
// local dbPolicyEngineSchema(), which already carried it), so an
// integration test using THIS shared fixture instead could not reproduce a
// non-NULL segment_id row at all.
func DynamicPoliciesSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS dynamic_policies (
			policy_id VARCHAR(100) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			policy_type VARCHAR(50) NOT NULL,
			category VARCHAR(50),
			tier VARCHAR(20) DEFAULT 'tenant',
			conditions JSONB NOT NULL DEFAULT '[]',
			actions JSONB NOT NULL DEFAULT '[]',
			tenant_id VARCHAR(255) NOT NULL,
			client_id VARCHAR(100),
			org_id VARCHAR(255),
			-- legacy org column: TEXT (not UUID) to match prod after migration 133
			-- (org ids are free-form license strings, not UUIDs). org_id is canonical.
			organization_id TEXT,
			segment_id VARCHAR(255),
			priority INTEGER DEFAULT 100,
			enabled BOOLEAN DEFAULT true,
			version INTEGER DEFAULT 1,
			created_by VARCHAR(255),
			updated_by VARCHAR(255),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		);

		CREATE TABLE IF NOT EXISTS policy_versions (
			id VARCHAR(36) PRIMARY KEY,
			policy_id VARCHAR(100) NOT NULL REFERENCES dynamic_policies(policy_id) ON DELETE CASCADE,
			version INTEGER NOT NULL,
			snapshot JSONB,
			changed_by VARCHAR(255),
			changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			change_type VARCHAR(50),
			change_summary TEXT
		)
	`
}

// CostSchema returns the schema for cost management tables.
// Must match the columns expected by cost.PostgresRepository (postgres_repository.go).
func CostSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS budgets (
			id VARCHAR(36) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			scope VARCHAR(50) NOT NULL,
			scope_id VARCHAR(255),
			limit_usd DECIMAL(15,2) NOT NULL,
			period VARCHAR(20) NOT NULL,
			on_exceed VARCHAR(20) NOT NULL DEFAULT 'warn',
			alert_thresholds JSONB DEFAULT '[]',
			enabled BOOLEAN DEFAULT true,
			org_id VARCHAR(255),
			tenant_id VARCHAR(255),
			created_by VARCHAR(255),
			updated_by VARCHAR(255),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS budget_alerts (
			id BIGSERIAL PRIMARY KEY,
			budget_id VARCHAR(36) NOT NULL REFERENCES budgets(id) ON DELETE CASCADE,
			threshold INTEGER NOT NULL,
			percentage_reached DECIMAL(5,2) NOT NULL DEFAULT 0,
			amount_usd DECIMAL(15,6) NOT NULL DEFAULT 0,
			alert_type VARCHAR(50) NOT NULL,
			message TEXT,
			acknowledged BOOLEAN DEFAULT false,
			acknowledged_by VARCHAR(255),
			acknowledged_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS usage_records (
			id BIGSERIAL PRIMARY KEY,
			request_id VARCHAR(255) NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			org_id VARCHAR(255),
			tenant_id VARCHAR(255),
			team_id VARCHAR(255),
			agent_id VARCHAR(255),
			workflow_id VARCHAR(255),
			user_id VARCHAR(255),
			provider VARCHAR(50) NOT NULL,
			model VARCHAR(100) NOT NULL,
			tokens_in INTEGER DEFAULT 0,
			tokens_out INTEGER DEFAULT 0,
			cost_usd DECIMAL(15,6) DEFAULT 0,
			request_type VARCHAR(50),
			cached BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS usage_aggregates (
			id BIGSERIAL PRIMARY KEY,
			scope VARCHAR(50) NOT NULL,
			scope_id VARCHAR(255) NOT NULL,
			period VARCHAR(20) NOT NULL,
			period_start TIMESTAMPTZ NOT NULL,
			total_cost_usd DECIMAL(15,6) DEFAULT 0,
			total_tokens_in BIGINT DEFAULT 0,
			total_tokens_out BIGINT DEFAULT 0,
			request_count INTEGER DEFAULT 0,
			org_id VARCHAR(255),
			tenant_id VARCHAR(255),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(scope, scope_id, period, period_start, org_id, tenant_id)
		)
	`
}

// WorkflowControlSchema returns the schema for workflow control tables.
func WorkflowControlSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS workflow_definitions (
			id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT,
			config JSONB NOT NULL,
			enabled BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS workflow_executions (
			id VARCHAR(36) PRIMARY KEY,
			workflow_id VARCHAR(36) NOT NULL REFERENCES workflow_definitions(id) ON DELETE CASCADE,
			tenant_id VARCHAR(255) NOT NULL,
			status VARCHAR(20) NOT NULL,
			input JSONB,
			output JSONB,
			error TEXT,
			started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMPTZ
		)
	`
}

// StaticPoliciesSchema returns the schema for static policies.
// Must match the columns expected by agent.StaticPolicyRepository (static_policy_repository.go).
func StaticPoliciesSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS static_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			category VARCHAR(50) NOT NULL,
			pattern TEXT NOT NULL,
			severity VARCHAR(20) NOT NULL,
			description TEXT,
			action VARCHAR(20) NOT NULL DEFAULT 'block',
			tier VARCHAR(20) NOT NULL DEFAULT 'tenant',
			priority INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT true,
			-- legacy org column: TEXT (not UUID) to match prod after migration 133
			-- (org ids are free-form license strings, not UUIDs). org_id is canonical.
			organization_id TEXT,
			tenant_id VARCHAR(255),
			org_id VARCHAR(255),
			tags JSONB DEFAULT '[]',
			metadata JSONB DEFAULT '{}',
			version INTEGER DEFAULT 1,
			phase VARCHAR(20) DEFAULT 'request',
			action_request VARCHAR(20),
			action_response VARCHAR(20),
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			created_by VARCHAR(255),
			updated_by VARCHAR(255),
			deleted_at TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS static_policy_versions (
			id VARCHAR(36) PRIMARY KEY,
			policy_id UUID NOT NULL,
			version INTEGER NOT NULL,
			snapshot JSONB,
			change_type VARCHAR(50),
			change_summary TEXT,
			changed_by VARCHAR(255),
			changed_at TIMESTAMPTZ DEFAULT NOW()
		)
	`
}

// SingaporePIISeedData returns INSERT statements that seed Singapore PII policies
// into the static_policies table for integration testing.
func SingaporePIISeedData() string {
	return `
		INSERT INTO static_policies (policy_id, name, description, category, pattern, severity, action, tier, priority, enabled)
		VALUES
		('sys_pii_singapore_nric', 'Singapore NRIC Detection',
		 'Singapore National Registration Identity Card detected',
		 'pii-singapore', '\b[STFGM]\d{7}[A-Z]\b', 'critical', 'redact', 'system', 100, true),
		('sys_pii_singapore_fin', 'Singapore FIN Detection',
		 'Singapore Foreign Identification Number detected',
		 'pii-singapore', '\b[FG]\d{7}[A-Z]\b', 'critical', 'redact', 'system', 100, true),
		('sys_pii_singapore_uen', 'Singapore UEN Detection',
		 'Singapore Unique Entity Number detected',
		 'pii-singapore', '\b\d{8,9}[A-Z]\b|\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b', 'high', 'redact', 'system', 90, true),
		('sys_pii_singapore_phone', 'Singapore Phone Detection',
		 'Singapore phone number detected',
		 'pii-singapore', '\+65\s?[689]\d{3}\s?\d{4}\b', 'medium', 'redact', 'system', 70, true),
		('sys_pii_singapore_postal', 'Singapore Postal Code Detection',
		 'Singapore postal code detected',
		 'pii-singapore', '\b(?:0[1-9]|[1-7]\d|8[0-2])\d{4}\b', 'low', 'warn', 'system', 30, true)
	`
}

// RuntimeConfigSchema returns the schema for runtime configuration.
func RuntimeConfigSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS runtime_config (
			id VARCHAR(36) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			config_type VARCHAR(50) NOT NULL,
			config JSONB NOT NULL,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, config_type)
		)
	`
}
