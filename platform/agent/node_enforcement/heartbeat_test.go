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

//go:build enterprise

package node_enforcement

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	_ "github.com/lib/pq"
)

func TestHashLicenseKey(t *testing.T) {
	tests := []struct {
		name string
		key1 string
		key2 string
		shouldMatch bool
	}{
		{
			name:        "Same keys produce same hash",
			key1:        "AXON-ENT-testorg-20261028-abc12345",
			key2:        "AXON-ENT-testorg-20261028-abc12345",
			shouldMatch: true,
		},
		{
			name:        "Different keys produce different hashes",
			key1:        "AXON-ENT-testorg1-20261028-abc12345",
			key2:        "AXON-ENT-testorg2-20261028-abc12345",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := hashLicenseKey(tt.key1)
			hash2 := hashLicenseKey(tt.key2)

			if tt.shouldMatch && hash1 != hash2 {
				t.Errorf("Expected hashes to match:\n  %s\n  %s", hash1, hash2)
			}

			if !tt.shouldMatch && hash1 == hash2 {
				t.Errorf("Expected hashes to differ, both were: %s", hash1)
			}

			// Verify hash length (SHA256 = 64 hex chars)
			if len(hash1) != 64 {
				t.Errorf("Expected hash length 64, got %d", len(hash1))
			}
		})
	}
}

func TestGetHostInfo(t *testing.T) {
	info, err := getHostInfo()
	if err != nil {
		t.Fatalf("Failed to get host info: %v", err)
	}

	if info.Hostname == "" {
		t.Error("Hostname should not be empty")
	}

	if info.Port <= 0 || info.Port > 65535 {
		t.Errorf("Invalid port: %d", info.Port)
	}

	if info.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestHeartbeatService(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Skip if no test database available
	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("No test database URL provided (set TEST_DATABASE_URL)")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Ensure heartbeats table exists (matches production schema from migration 101)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS agent_heartbeats (
			id SERIAL PRIMARY KEY,
			instance_id VARCHAR(255) NOT NULL,
			instance_type VARCHAR(50) NOT NULL,
			host_name VARCHAR(255),
			license_key_hash VARCHAR(512) NOT NULL,
			org_id VARCHAR(255),
			last_heartbeat TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			host_info JSONB,
			ip_address INET,
			port INTEGER,
			version VARCHAR(50),
			region VARCHAR(100),
			heartbeat_count INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(instance_id, instance_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Clean up test data
	defer func() { _, _ = db.Exec("DELETE FROM agent_heartbeats WHERE org_id = 'test_org'") }()

	// Create heartbeat service
	service := NewHeartbeatService(db, "agent", "AXON-ENT-test-20261028-abc", "test_org")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start heartbeat
	err = service.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start heartbeat: %v", err)
	}

	// Wait for initial heartbeat
	time.Sleep(100 * time.Millisecond)

	// Verify heartbeat in database
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM agent_heartbeats WHERE org_id = 'test_org'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query heartbeats: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 heartbeat, found %d", count)
	}

	// Stop heartbeat
	service.Stop()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify heartbeat removed
	err = db.QueryRow("SELECT COUNT(*) FROM agent_heartbeats WHERE org_id = 'test_org'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query heartbeats after stop: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 heartbeats after stop, found %d", count)
	}
}

func TestGetActiveNodeCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("No test database URL provided")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Setup test data
	licenseHash := hashLicenseKey("AXON-ENT-test-20261028-abc")

	_, err = db.Exec(`
		INSERT INTO agent_heartbeats (instance_id, instance_type, license_key_hash, org_id, last_heartbeat)
		VALUES
			('test-1', 'agent', $1, 'test_org', NOW()),
			('test-2', 'agent', $1, 'test_org', NOW()),
			('test-3', 'orchestrator', $1, 'test_org', NOW()),
			('test-stale', 'agent', $1, 'test_org', NOW() - INTERVAL '10 minutes')
		ON CONFLICT (instance_id, instance_type) DO NOTHING
	`, licenseHash)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	defer func() { _, _ = db.Exec("DELETE FROM agent_heartbeats WHERE instance_id LIKE 'test-%'") }()

	ctx := context.Background()

	// Get active node count (should be 3, excluding stale)
	count, err := GetActiveNodeCount(ctx, db, licenseHash)
	if err != nil {
		t.Fatalf("Failed to get node count: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 active nodes, got %d", count)
	}
}

func TestCleanupStaleHeartbeats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("No test database URL provided")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert stale heartbeat
	_, err = db.Exec(`
		INSERT INTO agent_heartbeats (instance_id, instance_type, org_id, license_key_hash, last_heartbeat)
		VALUES ('test-stale-cleanup', 'agent', 'test_org', 'test-license-hash-cleanup', NOW() - INTERVAL '2 hours')
		ON CONFLICT (instance_id, instance_type) DO NOTHING
	`)
	if err != nil {
		t.Fatalf("Failed to insert stale heartbeat: %v", err)
	}

	ctx := context.Background()

	// Run cleanup
	err = CleanupStaleHeartbeats(ctx, db)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify stale heartbeat was removed
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM agent_heartbeats WHERE instance_id = 'test-stale-cleanup'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query after cleanup: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected stale heartbeat to be removed, found %d", count)
	}
}

// Helper to get test database URL from environment
func getTestDatabaseURL() string {
	// Try TEST_DATABASE_URL first, fall back to DATABASE_URL
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		return url
	}
	return os.Getenv("DATABASE_URL")
}

// Unit tests with sqlmock for local coverage

func TestNewHeartbeatService_Unit(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tests := []struct {
		name         string
		instanceType string
		licenseKey   string
		orgID        string
	}{
		{"agent instance", "agent", "test-key", "test-org"},
		{"orchestrator instance", "orchestrator", "test-key-2", "test-org-2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewHeartbeatService(db, tt.instanceType, tt.licenseKey, tt.orgID)

			if svc == nil {
				t.Fatal("expected service, got nil")
			}
			if svc.instanceType != tt.instanceType {
				t.Errorf("instanceType = %v, want %v", svc.instanceType, tt.instanceType)
			}
			if svc.interval != 2*time.Minute {
				t.Errorf("interval = %v, want 2m", svc.interval)
			}
		})
	}
}

func TestSendHeartbeat_Unit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			// v9 Phase 8 #2384 PR-C1: sendHeartbeat wraps the UPSERT in a
			// BEGIN/SET-CONFIG/EXEC/COMMIT txn for RLS scoping.
			name: "successful upsert",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO agent_heartbeats`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr: false,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO agent_heartbeats`).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			svc := NewHeartbeatService(db, "agent", "test-key", "test-org")
			tt.setupMock(mock)

			err = svc.sendHeartbeat(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("sendHeartbeat() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestRemoveHeartbeat_Unit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			// v9 Phase 8 #2384 PR-C1: removeHeartbeat wraps the DELETE in a
			// BEGIN/SET-CONFIG/EXEC/COMMIT txn for RLS scoping.
			name: "successful delete",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`DELETE FROM agent_heartbeats WHERE instance_id`).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
			},
			wantErr: false,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`DELETE FROM agent_heartbeats WHERE instance_id`).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			svc := NewHeartbeatService(db, "agent", "test-key", "test-org")
			tt.setupMock(mock)

			err = svc.removeHeartbeat(context.Background())

			if (err != nil) != tt.wantErr {
				t.Errorf("removeHeartbeat() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetActiveNodeCount_Unit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mock sqlmock.Sqlmock)
		wantCount int
		wantErr   bool
	}{
		{
			name: "5 active nodes",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(5)
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM agent_heartbeats`).
					WillReturnRows(rows)
			},
			wantCount: 5,
			wantErr:   false,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\) FROM agent_heartbeats`).
					WillReturnError(sql.ErrConnDone)
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			count, err := GetActiveNodeCount(context.Background(), db, "test-hash")

			if (err != nil) != tt.wantErr {
				t.Errorf("GetActiveNodeCount() error = %v, wantErr %v", err, tt.wantErr)
			}
			if count != tt.wantCount {
				t.Errorf("GetActiveNodeCount() = %v, want %v", count, tt.wantCount)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestGetActiveNodesByOrg_Unit(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(mock sqlmock.Sqlmock)
		wantResult map[string]int
		wantErr    bool
	}{
		{
			name: "multiple orgs",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"org_id", "count"}).
					AddRow("org-1", 5).
					AddRow("org-2", 10)
				mock.ExpectQuery(`SELECT org_id, COUNT\(\*\) FROM agent_heartbeats`).
					WillReturnRows(rows)
			},
			wantResult: map[string]int{"org-1": 5, "org-2": 10},
			wantErr:    false,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT org_id, COUNT\(\*\) FROM agent_heartbeats`).
					WillReturnError(sql.ErrConnDone)
			},
			wantResult: nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			result, err := GetActiveNodesByOrg(context.Background(), db)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetActiveNodesByOrg() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !mapsEqual(result, tt.wantResult) {
				t.Errorf("GetActiveNodesByOrg() = %v, want %v", result, tt.wantResult)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestCleanupStaleHeartbeats_Unit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "cleanup 5 rows",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM agent_heartbeats WHERE last_heartbeat`).
					WillReturnResult(sqlmock.NewResult(0, 5))
			},
			wantErr: false,
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`DELETE FROM agent_heartbeats WHERE last_heartbeat`).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)

			err = CleanupStaleHeartbeats(context.Background(), db)

			if (err != nil) != tt.wantErr {
				t.Errorf("CleanupStaleHeartbeats() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestStart_Unit(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(mock sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			// v9 Phase 8 #2384 PR-C1: heartbeat.go INSERTs are wrapped in a
			// txn (BEGIN → app.current_org_id set_config → INSERT → COMMIT)
			// so RLS WITH CHECK clears under axonflow_app_role. The mock
			// must expect the full sequence.
			name: "successful start",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO agent_heartbeats`).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
			},
			wantErr: false,
		},
		{
			name: "initial heartbeat fails",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
					WithArgs("test-org").
					WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(`INSERT INTO agent_heartbeats`).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			svc := NewHeartbeatService(db, "agent", "test-key", "test-org")
			tt.setupMock(mock)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err = svc.Start(ctx)

			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				svc.Stop()
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

func TestStop_Unit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	svc := NewHeartbeatService(db, "agent", "test-key", "test-org")

	// v9 Phase 8 #2384 PR-C1: removeHeartbeat wraps the DELETE in a txn for
	// the same RLS reason as the INSERT path.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("test-org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`DELETE FROM agent_heartbeats WHERE instance_id`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	svc.Stop()

	time.Sleep(50 * time.Millisecond)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// Helper function for map comparison
func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func BenchmarkHashLicenseKey(b *testing.B) {
	key := "AXON-ENT-testorg-20261028-abc12345"

	for i := 0; i < b.N; i++ {
		_ = hashLicenseKey(key)
	}
}
