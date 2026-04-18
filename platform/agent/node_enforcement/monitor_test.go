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
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// MockAlerter for testing alerts without external dependencies
type MockAlerter struct {
	ViolationAlerts []string
	WarningAlerts   []string
}

func (m *MockAlerter) SendNodeViolationAlert(ctx context.Context, violation *ViolationInfo) error {
	m.ViolationAlerts = append(m.ViolationAlerts, violation.OrgID)
	return nil
}

func (m *MockAlerter) SendNodeCountWarning(ctx context.Context, orgID string, usage float64) error {
	m.WarningAlerts = append(m.WarningAlerts, orgID)
	return nil
}

func Test_hashLicenseKey(t *testing.T) {
	tests := []struct {
		name        string
		licenseKey  string
		wantLength  int
		shouldMatch bool
		otherKey    string
	}{
		{
			name:       "valid license key produces 64-char hash",
			licenseKey: "AXON-ENT-test-20261103-abc123",
			wantLength: 64,
		},
		{
			name:        "same keys produce same hash",
			licenseKey:  "AXON-ENT-test-20261103-abc123",
			shouldMatch: true,
			otherKey:    "AXON-ENT-test-20261103-abc123",
			wantLength:  64,
		},
		{
			name:        "different keys produce different hash",
			licenseKey:  "AXON-ENT-test1-20261103-abc123",
			shouldMatch: false,
			otherKey:    "AXON-ENT-test2-20261103-abc123",
			wantLength:  64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := hashLicenseKey(tt.licenseKey)

			if len(hash1) != tt.wantLength {
				t.Errorf("hash length = %d, want %d", len(hash1), tt.wantLength)
			}

			if tt.otherKey != "" {
				hash2 := hashLicenseKey(tt.otherKey)
				if tt.shouldMatch && hash1 != hash2 {
					t.Errorf("expected hashes to match, got different hashes")
				}
				if !tt.shouldMatch && hash1 == hash2 {
					t.Errorf("expected hashes to differ, got same hash")
				}
			}
		})
	}
}

func TestNewNodeMonitor(t *testing.T) {
	db, err := sql.Open("postgres", "")
	if err == nil {
		defer func() { _ = db.Close() }()
	}

	alerter := &MockAlerter{}
	monitor := NewNodeMonitor(db, alerter)

	if monitor == nil {
		t.Fatal("NewNodeMonitor returned nil")
	}

	if monitor.db != db {
		t.Error("db not set correctly")
	}

	if monitor.alerter != alerter {
		t.Error("alerter not set correctly")
	}

	if monitor.interval != 5*time.Minute {
		t.Errorf("interval = %v, want 5m", monitor.interval)
	}
}

func TestNodeMonitor_Start_Stop(t *testing.T) {
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

	// Ensure tables exist
	setupTestTables(t, db)

	alerter := &MockAlerter{}
	monitor := NewNodeMonitor(db, alerter)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start monitor
	monitor.Start(ctx)

	// Let it run briefly
	time.Sleep(200 * time.Millisecond)

	// Stop monitor
	monitor.Stop()

	// Should not panic or hang
}

func TestNodeMonitor_checkAllNodeCounts(t *testing.T) {
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

	setupTestTables(t, db)
	defer cleanupTestData(t, db)

	// Insert test organization
	_, err = db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, max_nodes)
		VALUES ('test_org_monitor', 'Test Org', 'Professional', 'test-key', 5)
		ON CONFLICT (org_id) DO UPDATE SET max_nodes = 5
	`)
	if err != nil {
		t.Fatalf("Failed to insert test org: %v", err)
	}

	// Insert test heartbeats (within limit)
	for i := 1; i <= 3; i++ {
		_, err = db.Exec(`
			INSERT INTO agent_heartbeats (instance_id, instance_type, org_id, license_key_hash, last_heartbeat)
			VALUES ($1, 'agent', 'test_org_monitor', 'test-hash-monitor', NOW())
			ON CONFLICT (instance_id, instance_type) DO UPDATE SET last_heartbeat = NOW()
		`, fmt.Sprintf("test-monitor-%d", i))
		if err != nil {
			t.Fatalf("Failed to insert heartbeat: %v", err)
		}
	}

	alerter := &MockAlerter{}
	monitor := NewNodeMonitor(db, alerter)

	ctx := context.Background()
	err = monitor.checkAllNodeCounts(ctx)
	if err != nil {
		t.Errorf("checkAllNodeCounts failed: %v", err)
	}

	// Should not trigger alerts (3 nodes, limit is 5)
	if len(alerter.ViolationAlerts) > 0 {
		t.Errorf("unexpected violation alerts: %v", alerter.ViolationAlerts)
	}
}

func TestNodeMonitor_checkOrgNodeCount_Violation(t *testing.T) {
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

	setupTestTables(t, db)
	defer cleanupTestData(t, db)

	// Insert test organization with max_nodes = 3
	_, err = db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, max_nodes)
		VALUES ('test_violation_org', 'Test Violation Org', 'Professional', 'test-key', 3)
		ON CONFLICT (org_id) DO UPDATE SET max_nodes = 3
	`)
	if err != nil {
		t.Fatalf("Failed to insert test org: %v", err)
	}

	// Insert 5 heartbeats (exceeds limit of 3)
	for i := 1; i <= 5; i++ {
		_, err = db.Exec(`
			INSERT INTO agent_heartbeats (instance_id, instance_type, org_id, license_key_hash, last_heartbeat)
			VALUES ($1, 'agent', 'test_violation_org', 'test-hash-violation', NOW())
			ON CONFLICT (instance_id, instance_type) DO UPDATE SET last_heartbeat = NOW()
		`, fmt.Sprintf("test-violation-%d", i))
		if err != nil {
			t.Fatalf("Failed to insert heartbeat: %v", err)
		}
	}

	alerter := &MockAlerter{}
	monitor := NewNodeMonitor(db, alerter)

	ctx := context.Background()

	// This should trigger a violation (5 nodes, limit is 3)
	err = monitor.checkOrgNodeCount(ctx, "test_violation_org", 5)
	if err != nil {
		t.Errorf("checkOrgNodeCount failed: %v", err)
	}

	// Should have triggered violation alert
	if len(alerter.ViolationAlerts) != 1 {
		t.Errorf("expected 1 violation alert, got %d", len(alerter.ViolationAlerts))
	}

	if len(alerter.ViolationAlerts) > 0 && alerter.ViolationAlerts[0] != "test_violation_org" {
		t.Errorf("violation alert for wrong org: %s", alerter.ViolationAlerts[0])
	}

	// Verify violation was recorded in database
	var violationCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM node_violations
		WHERE org_id = 'test_violation_org' AND resolved = FALSE
	`).Scan(&violationCount)
	if err != nil {
		t.Fatalf("Failed to query violations: %v", err)
	}

	if violationCount != 1 {
		t.Errorf("expected 1 violation record, got %d", violationCount)
	}
}

func TestNodeMonitor_checkOrgNodeCount_Warning(t *testing.T) {
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

	setupTestTables(t, db)
	defer cleanupTestData(t, db)

	// Insert test organization with max_nodes = 10
	_, err = db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, max_nodes)
		VALUES ('test_warning_org', 'Test Warning Org', 'Professional', 'test-key', 10)
		ON CONFLICT (org_id) DO UPDATE SET max_nodes = 10
	`)
	if err != nil {
		t.Fatalf("Failed to insert test org: %v", err)
	}

	alerter := &MockAlerter{}
	monitor := NewNodeMonitor(db, alerter)

	ctx := context.Background()

	// 8 nodes out of 10 = 80% (should trigger warning)
	err = monitor.checkOrgNodeCount(ctx, "test_warning_org", 8)
	if err != nil {
		t.Errorf("checkOrgNodeCount failed: %v", err)
	}

	// Should have triggered warning alert (>=80% usage)
	if len(alerter.WarningAlerts) != 1 {
		t.Errorf("expected 1 warning alert, got %d", len(alerter.WarningAlerts))
	}
}

func TestGetActiveNodesByOrg(t *testing.T) {
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

	setupTestTables(t, db)
	defer cleanupTestData(t, db)

	// Insert test heartbeats for multiple orgs
	testData := []struct {
		instanceID   string
		orgID        string
		instanceType string
		stale        bool
	}{
		{"active-1", "org1", "agent", false},
		{"active-2", "org1", "agent", false},
		{"active-3", "org1", "orchestrator", false},
		{"active-4", "org2", "agent", false},
		{"stale-1", "org1", "agent", true}, // Stale, should not count
	}

	for _, td := range testData {
		lastHeartbeat := "NOW()"
		if td.stale {
			lastHeartbeat = "NOW() - INTERVAL '10 minutes'"
		}

		_, err = db.Exec(fmt.Sprintf(`
			INSERT INTO agent_heartbeats (instance_id, instance_type, org_id, license_key_hash, last_heartbeat)
			VALUES ($1, $2, $3, 'test-hash-active', %s)
			ON CONFLICT (instance_id, instance_type) DO UPDATE SET last_heartbeat = %s
		`, lastHeartbeat, lastHeartbeat), td.instanceID, td.instanceType, td.orgID)
		if err != nil {
			t.Fatalf("Failed to insert heartbeat: %v", err)
		}
	}

	ctx := context.Background()
	nodesByOrg, err := GetActiveNodesByOrg(ctx, db)
	if err != nil {
		t.Fatalf("GetActiveNodesByOrg failed: %v", err)
	}

	// org1 should have 3 active nodes (excluding stale)
	if nodesByOrg["org1"] != 3 {
		t.Errorf("org1: expected 3 nodes, got %d", nodesByOrg["org1"])
	}

	// org2 should have 1 active node
	if nodesByOrg["org2"] != 1 {
		t.Errorf("org2: expected 1 node, got %d", nodesByOrg["org2"])
	}
}

func TestGetViolationHistory(t *testing.T) {
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

	setupTestTables(t, db)
	defer cleanupTestData(t, db)

	// Insert test organization
	_, err = db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, max_nodes)
		VALUES ('test_history_org', 'Test History Org', 'Enterprise', 'test-key', 10)
		ON CONFLICT (org_id) DO NOTHING
	`)
	if err != nil {
		t.Fatalf("Failed to insert test org: %v", err)
	}

	// Insert test violations
	_, err = db.Exec(`
		INSERT INTO node_violations (org_id, tier, max_nodes_allowed, actual_node_count, excess_nodes, resolved)
		VALUES
			('test_history_org', 'Enterprise', 10, 15, 5, TRUE),
			('test_history_org', 'Enterprise', 10, 12, 2, FALSE)
	`)
	if err != nil {
		t.Fatalf("Failed to insert violations: %v", err)
	}

	ctx := context.Background()
	violations, err := GetViolationHistory(ctx, db, "test_history_org")
	if err != nil {
		t.Fatalf("GetViolationHistory failed: %v", err)
	}

	if len(violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(violations))
	}
}

// Helper functions

func setupTestTables(t *testing.T, db *sql.DB) {
	// Create tables if they don't exist
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS organizations (
			id SERIAL PRIMARY KEY,
			org_id VARCHAR(100) UNIQUE NOT NULL,
			name VARCHAR(255) NOT NULL,
			tier VARCHAR(20) NOT NULL,
			license_key VARCHAR(255),
			max_nodes INT DEFAULT 10,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create organizations table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS agent_heartbeats (
			id SERIAL PRIMARY KEY,
			instance_id VARCHAR(255) NOT NULL,
			instance_type VARCHAR(50) NOT NULL,
			org_id VARCHAR(100),
			host_name VARCHAR(255),
			license_key_hash VARCHAR(512) NOT NULL,
			last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			host_info JSONB,
			UNIQUE(instance_id, instance_type)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create agent_heartbeats table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS node_violations (
			id SERIAL PRIMARY KEY,
			org_id VARCHAR(100) NOT NULL,
			license_key_hash VARCHAR(64),
			tier VARCHAR(20) NOT NULL,
			max_nodes_allowed INTEGER NOT NULL,
			actual_node_count INTEGER NOT NULL,
			excess_nodes INTEGER NOT NULL,
			violation_start TIMESTAMP DEFAULT NOW(),
			violation_end TIMESTAMP,
			resolved BOOLEAN DEFAULT FALSE,
			alert_sent BOOLEAN DEFAULT FALSE,
			metadata JSONB,
			created_at TIMESTAMP DEFAULT NOW()
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create node_violations table: %v", err)
	}
}

func cleanupTestData(t *testing.T, db *sql.DB) {
	// Clean up test data
	_, _ = db.Exec("DELETE FROM node_violations WHERE org_id LIKE 'test_%'")
	_, _ = db.Exec("DELETE FROM agent_heartbeats WHERE instance_id LIKE 'test-%'")
	_, _ = db.Exec("DELETE FROM agent_heartbeats WHERE org_id LIKE 'test_%'")
	_, _ = db.Exec("DELETE FROM agent_heartbeats WHERE org_id LIKE 'org%'")
	_, _ = db.Exec("DELETE FROM organizations WHERE org_id LIKE 'test_%'")
	_, _ = db.Exec("DELETE FROM organizations WHERE org_id LIKE 'org%'")
}

// getTestDatabaseURL is defined in heartbeat_test.go
