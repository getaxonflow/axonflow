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

package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/config"
)

// Names of the env vars consumed by the agent's app-role helper. Duplicated
// here (rather than imported from platform/agent) to avoid a circular
// import: platform/agent already imports platform/connectors/registry, so
// the dependency must run the other way via the AppRoleOpener function
// injection. Kept in sync with platform/agent/db_connection.go constants.
const (
	envUseAppRoleName = "AXONFLOW_DB_USE_APP_ROLE"
	envAppRoleURLName = "AXONFLOW_DB_APP_ROLE_URL"
)

// useAppRoleEnabled mirrors platform/agent.UseAppRoleEnabled — defaults to
// true under v9.0.0, false only when explicitly set to a falsy value. Kept
// here to render the canonical boot-log shape without importing the agent
// package.
func useAppRoleEnabled() bool {
	switch os.Getenv(envUseAppRoleName) {
	case "false", "FALSE", "False", "0":
		return false
	}
	return true
}

// PostgreSQLStorage implements persistent storage for connector registry
type PostgreSQLStorage struct {
	db        *sql.DB
	encryptor *config.CredentialEncryptor
	logger    *log.Logger
}

// ConnectorRecord represents a persisted connector configuration
type ConnectorRecord struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	TenantID     string                 `json:"tenant_id"`
	Options      map[string]interface{} `json:"options"`
	Credentials  map[string]string      `json:"credentials"`
	InstalledAt  time.Time              `json:"installed_at"`
	LastHealthCheck *time.Time          `json:"last_health_check,omitempty"`
	HealthStatus *base.HealthStatus     `json:"health_status,omitempty"`
}

// AppRoleOpener is the signature shared with platform/agent.OpenAppRoleConnection.
// Callers from inside an `axonflow/platform/agent`-aware package (e.g.
// platform/orchestrator) inject the helper here so connector_registry's
// runtime pool authenticates as axonflow_app_role under v9.0.0's
// AXONFLOW_DB_USE_APP_ROLE=true gate. Tests and dev paths that don't have
// access to the agent helper fall through to the default no-role-assertion
// opener.
type AppRoleOpener func(ctx context.Context, fallbackDSN string, maxRetries int) (*sql.DB, error)

// NewPostgreSQLStorage creates a new PostgreSQL storage backend whose runtime
// pool uses raw sql.Open (no role assertion). Kept for the registry's tests
// + dev paths that bypass the agent boot. Production orchestrator code MUST
// use NewPostgreSQLStorageWithOpener and inject agent.OpenAppRoleConnection
// so the runtime pool honors the v9 RLS gate.
func NewPostgreSQLStorage(dbURL string) (*PostgreSQLStorage, error) {
	return newPostgreSQLStorage(dbURL, nil)
}

// NewPostgreSQLStorageWithOpener creates a new PostgreSQL storage backend
// with the runtime pool opened via the injected AppRoleOpener. The schema
// init step (initSchema) still uses the master DSN because axonflow_app_role
// lacks CREATE TABLE / ALTER TABLE privileges per migration 098's grants.
// The master pool is closed immediately after schema init completes; only
// the app-role runtime pool survives the constructor.
func NewPostgreSQLStorageWithOpener(dbURL string, openAppRole AppRoleOpener) (*PostgreSQLStorage, error) {
	if openAppRole == nil {
		return nil, fmt.Errorf("NewPostgreSQLStorageWithOpener: nil opener — use NewPostgreSQLStorage for the no-opener path")
	}
	return newPostgreSQLStorage(dbURL, openAppRole)
}

// newPostgreSQLStorage holds the connection retry + init flow shared by the
// two public constructors. When openAppRole == nil, the runtime pool is just
// the master pool. When non-nil, schema init runs under master and is then
// closed, and the runtime pool is opened via the injected opener.
func newPostgreSQLStorage(dbURL string, openAppRole AppRoleOpener) (*PostgreSQLStorage, error) {
	// Retry master-pool connection with exponential backoff to handle Docker
	// DNS initialization delay (127.0.0.11:53 takes 1-2 seconds to wake on
	// container start). Master pool is needed unconditionally for initSchema
	// because axonflow_app_role lacks DDL privileges (migration 098 only
	// grants SELECT/INSERT/UPDATE/DELETE).
	maxRetries := 5
	var masterDB *sql.DB
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		masterDB, err = sql.Open("postgres", dbURL)
		if err == nil {
			err = masterDB.Ping()
			if err == nil {
				log.Printf("[ConnectorStorage] ✅ Connected to database (attempt %d/%d)", attempt, maxRetries)
				break
			}
		}

		if attempt < maxRetries {
			backoff := time.Duration(attempt*2) * time.Second
			log.Printf("[ConnectorStorage] ⚠️  Database connection failed (attempt %d/%d): %v", attempt, maxRetries, err)
			log.Printf("[ConnectorStorage]    Retrying in %v... (Docker DNS may still be initializing)", backoff)
			time.Sleep(backoff)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	// Run schema init under master.
	schemaInitStorage := &PostgreSQLStorage{
		db:     masterDB,
		logger: log.New(log.Writer(), "[ConnectorStorage] ", log.LstdFlags),
	}
	if err := schemaInitStorage.initSchema(); err != nil {
		_ = masterDB.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Branch on opener presence: with opener, swap to app-role runtime pool;
	// without, keep the master pool as runtime (NewPostgreSQLStorage legacy).
	if openAppRole == nil {
		schemaInitStorage.logger.Println("PostgreSQL connector storage initialized (master runtime pool — no app-role opener injected)")
		return schemaInitStorage, nil
	}

	// Open the app-role runtime pool. Helper internally pings + asserts
	// connected role when AXONFLOW_DB_USE_APP_ROLE=true.
	runtimeDB, err := openAppRole(context.Background(), dbURL, maxRetries)
	if err != nil {
		_ = masterDB.Close()
		return nil, fmt.Errorf("failed to open runtime pool via app-role opener: %w", err)
	}

	// Schema init is done; close the master pool — runtime traffic goes
	// through the app-role pool only.
	if err := masterDB.Close(); err != nil {
		log.Printf("[ConnectorStorage] WARNING: failed to close master pool after schema init: %v", err)
	}

	var connectedRole string
	if err := runtimeDB.QueryRowContext(context.Background(), "SELECT current_user").Scan(&connectedRole); err != nil {
		log.Printf("[ConnectorStorage] WARNING: failed to query current_user on runtime pool: %v (continuing)", err)
	}
	storage := &PostgreSQLStorage{
		db:     runtimeDB,
		logger: log.New(log.Writer(), "[ConnectorStorage] ", log.LstdFlags),
	}
	storage.logger.Printf("✅ runtime pool connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
		connectedRole, useAppRoleEnabled(), envAppRoleURLName, os.Getenv(envAppRoleURLName) != "")
	return storage, nil
}

// initSchema creates the connectors table if it doesn't exist
func (s *PostgreSQLStorage) initSchema() error {
	// v9 Phase 8 B8 (#2339): org_id is included in the fresh CREATE TABLE.
	// For environments where the table already exists (created by an earlier
	// version of the binary or by mig 012), ALTER TABLE ADD COLUMN IF NOT
	// EXISTS adds it idempotently. The NOT NULL constraint is applied by
	// migration 107's backfill+SET NOT NULL — initSchema leaves it nullable
	// to remain backward-compatible with tests/dev paths that bypass the
	// migration runner.
	query := `
	CREATE TABLE IF NOT EXISTS connectors (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(50) NOT NULL,
		tenant_id VARCHAR(255) NOT NULL,
		org_id VARCHAR(255),
		options JSONB NOT NULL DEFAULT '{}'::jsonb,
		credentials JSONB NOT NULL DEFAULT '{}'::jsonb,
		installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_health_check TIMESTAMPTZ,
		health_status JSONB,
		UNIQUE(name, tenant_id)
	);

	ALTER TABLE connectors ADD COLUMN IF NOT EXISTS org_id VARCHAR(255);

	CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_connectors_org_id ON connectors(org_id);
	CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(type);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	s.logger.Println("Connector schema initialized")
	return nil
}

// withOrgScopeTx opens a transaction, sets app.current_org_id transaction-local
// via set_config(..., true), runs fn, then COMMITs (or ROLLBACKs on error).
// Mirrors platform/agent.WithOrgScope inline because platform/agent imports
// this package — we cannot import agent back without creating a cycle. Kept
// in sync with platform/agent/rls/scope.go::WithOrgScope.
//
// LINT: keep in sync with platform/agent/rls/scope.go (the canonical impl).
// PR-D's AST audit walker recognizes both this in-package helper + rls.WithOrgScope
// as valid wrap shapes; if a future change touches one, touch the other.
func (s *PostgreSQLStorage) withOrgScopeTx(ctx context.Context, orgID string, fn func(*sql.Tx) error) (err error) {
	if orgID == "" {
		return fmt.Errorf("withOrgScopeTx: orgID must be non-empty (cross-org work belongs on the admin role)")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("withOrgScopeTx: begin txn: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID); err != nil {
		return fmt.Errorf("withOrgScopeTx: set_config(app.current_org_id, %q, true): %w", orgID, err)
	}
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("withOrgScopeTx: commit: %w", err)
	}
	return nil
}

// SaveConnector persists a connector configuration. Under v9 FORCE RLS the
// INSERT into connectors is gated by `org_id = current_setting('app.current_org_id')`
// (see mig 107). config.TenantID carries the orgID at this writer (the
// historical tenant_id == org_id collapse) so withOrgScopeTx unconditionally
// sets the GUC to that value before the INSERT runs.
func (s *PostgreSQLStorage) SaveConnector(ctx context.Context, id string, config *base.ConnectorConfig) error {
	optionsJSON, err := json.Marshal(config.Options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	var credentialsJSON []byte
	if s.encryptor != nil {
		credentialsJSON, err = s.encryptor.Encrypt(config.Credentials)
	} else {
		credentialsJSON, err = json.Marshal(config.Credentials)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// v9 Phase 8 B8 (#2339): mig 107 makes org_id NOT NULL on connectors.
	// At this writer org_id == tenant_id (per the historical schema's
	// tenant_id collapse) — pre-Phase-6 customers have org_id == tenant_id
	// and post-Phase-6 cs_* customers carry their per-customer org_id in
	// tenant_id (which we map through). Backfill in mig 107 follows the
	// same shape via the tenants table JOIN.
	query := `
		INSERT INTO connectors (id, name, type, tenant_id, org_id, options, credentials)
		VALUES ($1, $2, $3, $4, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			type = EXCLUDED.type,
			options = EXCLUDED.options,
			credentials = EXCLUDED.credentials
	`

	if err := s.withOrgScopeTx(ctx, config.TenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			id,
			config.Name,
			config.Type,
			config.TenantID,
			optionsJSON,
			credentialsJSON,
		)
		return execErr
	}); err != nil {
		return fmt.Errorf("failed to save connector: %w", err)
	}

	s.logger.Printf("Saved connector: %s (tenant: %s)", id, config.TenantID)
	return nil
}

// GetConnector retrieves a connector configuration
func (s *PostgreSQLStorage) GetConnector(ctx context.Context, id string) (*base.ConnectorConfig, error) {
	query := `
		SELECT name, type, tenant_id, options, credentials
		FROM connectors
		WHERE id = $1
	`

	var name, connType, tenantID string
	var optionsJSON, credentialsJSON []byte

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&name,
		&connType,
		&tenantID,
		&optionsJSON,
		&credentialsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("connector not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}

	var options map[string]interface{}
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		return nil, fmt.Errorf("failed to unmarshal options: %w", err)
	}

	var credentials map[string]string
	if s.encryptor != nil {
		credentials, err = s.encryptor.Decrypt(credentialsJSON)
	} else {
		err = json.Unmarshal(credentialsJSON, &credentials)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	config := &base.ConnectorConfig{
		Name:        name,
		Type:        connType,
		TenantID:    tenantID,
		Options:     options,
		Credentials: credentials,
		Timeout:     30 * time.Second,
	}

	return config, nil
}

// DeleteConnector removes a connector configuration. orgID is required so the
// DELETE runs inside a withOrgScopeTx transaction: mig 018's ENABLE RLS +
// mig 107's FORCE RLS on connectors gate DELETE on
// `USING (org_id = get_current_org_id())`. Without the GUC set, every DELETE
// silently affects 0 rows under axonflow_app_role.
func (s *PostgreSQLStorage) DeleteConnector(ctx context.Context, orgID, id string) error {
	query := `DELETE FROM connectors WHERE id = $1`

	var rows int64
	if err := s.withOrgScopeTx(ctx, orgID, func(tx *sql.Tx) error {
		result, execErr := tx.ExecContext(ctx, query, id)
		if execErr != nil {
			return fmt.Errorf("failed to delete connector: %w", execErr)
		}
		var raErr error
		rows, raErr = result.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("failed to check rows affected: %w", raErr)
		}
		return nil
	}); err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("connector not found: %s", id)
	}

	s.logger.Printf("Deleted connector: %s", id)
	return nil
}

// ListConnectors returns all connector configurations
func (s *PostgreSQLStorage) ListConnectors(ctx context.Context) ([]string, error) {
	query := `SELECT id FROM connectors ORDER BY installed_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return ids, nil
}

// ListConnectorsByTenant returns all connectors for a specific tenant
func (s *PostgreSQLStorage) ListConnectorsByTenant(ctx context.Context, tenantID string) ([]string, error) {
	query := `SELECT id FROM connectors WHERE tenant_id = $1 OR tenant_id = '*' ORDER BY installed_at DESC`

	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return ids, nil
}

// UpdateHealthStatus updates the health status of a connector. orgID is
// required so the UPDATE runs inside a withOrgScopeTx transaction: the
// mig 018 ENABLE RLS + mig 107 FORCE RLS policy gates UPDATE on
// `USING (org_id = get_current_org_id())`. Without the GUC, every UPDATE
// silently affects 0 rows under axonflow_app_role.
func (s *PostgreSQLStorage) UpdateHealthStatus(ctx context.Context, orgID, id string, status *base.HealthStatus) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal health status: %w", err)
	}

	query := `
		UPDATE connectors
		SET last_health_check = NOW(), health_status = $2
		WHERE id = $1
	`

	if err := s.withOrgScopeTx(ctx, orgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query, id, statusJSON)
		return execErr
	}); err != nil {
		return fmt.Errorf("failed to update health status: %w", err)
	}

	return nil
}

// UnsafeRuntimeDBForTests exposes the runtime pool for integration tests that
// need to assert the connected Postgres role. NOT for production use — the
// returned handle bypasses the storage's encryption wrapping and tenant-scope
// helpers. Named "Unsafe...ForTests" to discourage accidental usage.
func (s *PostgreSQLStorage) UnsafeRuntimeDBForTests() *sql.DB {
	return s.db
}

// Close closes the database connection
func (s *PostgreSQLStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
