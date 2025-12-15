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
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/connectors/base"
)

// PostgreSQLStorage implements persistent storage for connector registry
type PostgreSQLStorage struct {
	db     *sql.DB
	logger *log.Logger
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

// NewPostgreSQLStorage creates a new PostgreSQL storage backend
func NewPostgreSQLStorage(dbURL string) (*PostgreSQLStorage, error) {
	// Retry connection with exponential backoff to handle Docker DNS initialization delay
	// Docker DNS (127.0.0.11:53) takes 1-2 seconds to initialize after container start
	// Without retry, RDS hostname resolution fails immediately
	maxRetries := 5
	var db *sql.DB
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = sql.Open("postgres", dbURL)
		if err == nil {
			// Test connection with ping
			err = db.Ping()
			if err == nil {
				log.Printf("[ConnectorStorage] ✅ Connected to database (attempt %d/%d)", attempt, maxRetries)
				break
			}
		}

		// Connection or ping failed
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

	storage := &PostgreSQLStorage{
		db:     db,
		logger: log.New(log.Writer(), "[ConnectorStorage] ", log.LstdFlags),
	}

	// Initialize schema
	if err := storage.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	storage.logger.Println("PostgreSQL connector storage initialized")
	return storage, nil
}

// initSchema creates the connectors table if it doesn't exist
func (s *PostgreSQLStorage) initSchema() error {
	query := `
	CREATE TABLE IF NOT EXISTS connectors (
		id VARCHAR(255) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(50) NOT NULL,
		tenant_id VARCHAR(255) NOT NULL,
		options JSONB NOT NULL DEFAULT '{}'::jsonb,
		credentials JSONB NOT NULL DEFAULT '{}'::jsonb,
		installed_at TIMESTAMP NOT NULL DEFAULT NOW(),
		last_health_check TIMESTAMP,
		health_status JSONB,
		UNIQUE(name, tenant_id)
	);

	CREATE INDEX IF NOT EXISTS idx_connectors_tenant ON connectors(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_connectors_type ON connectors(type);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	s.logger.Println("Connector schema initialized")
	return nil
}

// SaveConnector persists a connector configuration
func (s *PostgreSQLStorage) SaveConnector(ctx context.Context, id string, config *base.ConnectorConfig) error {
	optionsJSON, err := json.Marshal(config.Options)
	if err != nil {
		return fmt.Errorf("failed to marshal options: %w", err)
	}

	credentialsJSON, err := json.Marshal(config.Credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	query := `
		INSERT INTO connectors (id, name, type, tenant_id, options, credentials)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			type = EXCLUDED.type,
			options = EXCLUDED.options,
			credentials = EXCLUDED.credentials
	`

	_, err = s.db.ExecContext(ctx, query,
		id,
		config.Name,
		config.Type,
		config.TenantID,
		optionsJSON,
		credentialsJSON,
	)

	if err != nil {
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
	if err := json.Unmarshal(credentialsJSON, &credentials); err != nil {
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

// DeleteConnector removes a connector configuration
func (s *PostgreSQLStorage) DeleteConnector(ctx context.Context, id string) error {
	query := `DELETE FROM connectors WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete connector: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
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

// UpdateHealthStatus updates the health status of a connector
func (s *PostgreSQLStorage) UpdateHealthStatus(ctx context.Context, id string, status *base.HealthStatus) error {
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal health status: %w", err)
	}

	query := `
		UPDATE connectors
		SET last_health_check = NOW(), health_status = $2
		WHERE id = $1
	`

	_, err = s.db.ExecContext(ctx, query, id, statusJSON)
	if err != nil {
		return fmt.Errorf("failed to update health status: %w", err)
	}

	return nil
}

// Close closes the database connection
func (s *PostgreSQLStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
