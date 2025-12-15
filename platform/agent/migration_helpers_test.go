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
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// TestEnsureSchemaMigrationsTable_UpgradeOldSchema tests upgrading from old schema to new
func TestEnsureSchemaMigrationsTable_UpgradeOldSchema(t *testing.T) {
	// Skip if no test database available
	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Clean up any existing table
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations_old CASCADE")

	// Create old schema (version + dirty columns only)
	_, err = db.Exec(`
		CREATE TABLE schema_migrations (
			version BIGINT NOT NULL,
			dirty BOOLEAN NOT NULL,
			PRIMARY KEY (version)
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create old schema table: %v", err)
	}

	// Insert some test data
	_, err = db.Exec(`
		INSERT INTO schema_migrations (version, dirty) VALUES
		(1, false),
		(2, false),
		(3, false)
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Run the upgrade function
	ensureSchemaMigrationsTable(db)

	// Verify new schema exists
	var hasNameColumn bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'schema_migrations'
			AND column_name = 'name'
		)
	`).Scan(&hasNameColumn)
	if err != nil {
		t.Fatalf("Failed to check for name column: %v", err)
	}
	if !hasNameColumn {
		t.Error("Expected 'name' column to exist after upgrade")
	}

	// Verify success column exists
	var hasSuccessColumn bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'schema_migrations'
			AND column_name = 'success'
		)
	`).Scan(&hasSuccessColumn)
	if err != nil {
		t.Fatalf("Failed to check for success column: %v", err)
	}
	if !hasSuccessColumn {
		t.Error("Expected 'success' column to exist after upgrade")
	}

	// Verify old data was migrated
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE success = true").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count migrated rows: %v", err)
	}
	if count != 3 {
		t.Errorf("Expected 3 migrated rows, got %d", count)
	}

	// Verify old table was dropped
	var oldTableExists bool
	err = db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_name = 'schema_migrations_old'
		)
	`).Scan(&oldTableExists)
	if err != nil {
		t.Fatalf("Failed to check for old table: %v", err)
	}
	if oldTableExists {
		t.Error("Expected schema_migrations_old table to be dropped")
	}

	// Cleanup
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")
}

// TestEnsureSchemaMigrationsTable_NewSchema tests creating new schema from scratch
func TestEnsureSchemaMigrationsTable_NewSchema(t *testing.T) {
	// Skip if no test database available
	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Clean up any existing table
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")

	// Run the function (should create new schema)
	ensureSchemaMigrationsTable(db)

	// Verify new schema was created with all columns
	columns := []string{"id", "version", "name", "applied_at", "execution_time_ms", "success", "error_message", "checksum", "applied_by", "hostname", "git_commit", "created_at"}

	for _, col := range columns {
		var exists bool
		err = db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_name = 'schema_migrations'
				AND column_name = $1
			)
		`, col).Scan(&exists)
		if err != nil {
			t.Fatalf("Failed to check for %s column: %v", col, err)
		}
		if !exists {
			t.Errorf("Expected column '%s' to exist in new schema", col)
		}
	}

	// Verify table is empty
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rows: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected empty table, got %d rows", count)
	}

	// Cleanup
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")
}

// TestEnsureSchemaMigrationsTable_AlreadyUpgraded tests idempotency when schema is already new
func TestEnsureSchemaMigrationsTable_AlreadyUpgraded(t *testing.T) {
	// Skip if no test database available
	dbURL := getTestDatabaseURL()
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Clean up
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")

	// Create table with new schema
	ensureSchemaMigrationsTable(db)

	// Insert test data
	_, err = db.Exec(`
		INSERT INTO schema_migrations (version, name, success)
		VALUES ('001', 'test_migration', true)
	`)
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	// Run function again (should be no-op)
	ensureSchemaMigrationsTable(db)

	// Verify data still exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = '001'").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 row after re-running function, got %d", count)
	}

	// Verify no duplicate tables
	var tableCount int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_name LIKE 'schema_migrations%'
	`).Scan(&tableCount)
	if err != nil {
		t.Fatalf("Failed to count tables: %v", err)
	}
	if tableCount != 1 {
		t.Errorf("Expected 1 schema_migrations table, got %d", tableCount)
	}

	// Cleanup
	_, _ = db.Exec("DROP TABLE IF EXISTS schema_migrations CASCADE")
}

// getTestDatabaseURL returns the test database URL from environment
func getTestDatabaseURL() string {
	// Try TEST_DATABASE_URL first
	if url := getEnvOrDefault("TEST_DATABASE_URL", ""); url != "" {
		return url
	}
	// Fall back to DATABASE_URL if available
	return getEnvOrDefault("DATABASE_URL", "")
}

// getEnvOrDefault is a helper to get environment variables with defaults
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Unit Tests for Migration Version Sorting (ADR-012)
// Note: TestExtractMigrationVersion and TestExtractMigrationName are in main_test.go
// =============================================================================

// TestMigrationVersionSorting validates that zero-padded versions sort correctly
// This is critical for ADR-012 multi-edition migration architecture
func TestMigrationVersionSorting(t *testing.T) {
	// Test that our zero-padded versions sort correctly with string comparison
	versions := []string{
		"001", "002", "010", "011", "020", "021", "022", "023", "024",
		"100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
		"200", "201", "250", "251",
	}

	// Verify each version is less than the next
	for i := 0; i < len(versions)-1; i++ {
		if versions[i] >= versions[i+1] {
			t.Errorf("Version ordering broken: %q should be < %q", versions[i], versions[i+1])
		}
	}

	// Verify specific cross-category comparisons
	crossTests := []struct {
		v1, v2 string
	}{
		{"099", "100"}, // Core -> Enterprise boundary
		{"199", "200"}, // Enterprise -> Industry boundary
		{"024", "100"}, // Last core -> First enterprise
	}

	for _, tt := range crossTests {
		if tt.v1 >= tt.v2 {
			t.Errorf("Cross-category version ordering broken: %q should be < %q", tt.v1, tt.v2)
		}
	}
}

// TestMigrationVersionSortingEdgeCases tests edge cases that could break sorting
func TestMigrationVersionSortingEdgeCases(t *testing.T) {
	// These would break with non-zero-padded versions
	// "9" > "10" alphabetically, but "009" < "010"
	testCases := []struct {
		name     string
		v1, v2   string
		expected bool // v1 < v2 with string comparison
	}{
		{"single digit padded", "009", "010", true},
		{"double digit padded", "099", "100", true},
		{"triple digit", "100", "101", true},
		{"cross hundred", "099", "100", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.v1 < tc.v2
			if result != tc.expected {
				t.Errorf("%s: %q < %q = %v, expected %v", tc.name, tc.v1, tc.v2, result, tc.expected)
			}
		})
	}
}

// TestExtractDependencies tests dependency extraction from SQL content
func TestExtractDependencies(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected []string
	}{
		{
			name: "single dependency",
			content: `-- Migration: 101_agent_heartbeats.sql
-- Category: enterprise
-- Depends: 002_organizations_and_auth
-- Description: Agent heartbeats

CREATE TABLE agent_heartbeats...`,
			expected: []string{"002_organizations_and_auth"},
		},
		{
			name: "multiple dependencies",
			content: `-- Migration: 105_node_enforcement.sql
-- Depends: 002_organizations_and_auth
-- Depends: 101_agent_heartbeats
-- Description: Node enforcement

CREATE TABLE...`,
			expected: []string{"002_organizations_and_auth", "101_agent_heartbeats"},
		},
		{
			name:     "no dependencies",
			content:  `-- Migration: 001_schema_migrations.sql\n\nCREATE TABLE...`,
			expected: []string{},
		},
		{
			name:     "empty content",
			content:  "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDependencies(tt.content)
			if len(result) != len(tt.expected) {
				t.Errorf("extractDependencies() returned %d deps, want %d", len(result), len(tt.expected))
				return
			}
			for i, dep := range result {
				if dep != tt.expected[i] {
					t.Errorf("extractDependencies()[%d] = %q, want %q", i, dep, tt.expected[i])
				}
			}
		})
	}
}

// TestGetMigrationPaths tests migration path selection based on deployment mode
func TestGetMigrationPaths(t *testing.T) {
	basePath := "/test/migrations"

	tests := []struct {
		name          string
		deployMode    string
		expectedPaths []string
	}{
		{
			name:       "OSS mode",
			deployMode: "oss",
			expectedPaths: []string{
				"/test/migrations/core",
			},
		},
		{
			name:       "SaaS mode",
			deployMode: "saas",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
				"/test/migrations/industry/healthcare",
				"/test/migrations/industry/banking",
				"/test/migrations/industry/travel",
			},
		},
		{
			name:       "In-VPC Healthcare",
			deployMode: "in-vpc-healthcare",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
				"/test/migrations/industry/healthcare",
			},
		},
		{
			name:       "In-VPC Banking",
			deployMode: "in-vpc-banking",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
				"/test/migrations/industry/banking",
			},
		},
		{
			name:       "In-VPC Travel",
			deployMode: "in-vpc-travel",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
				"/test/migrations/industry/travel",
			},
		},
		{
			name:       "In-VPC Enterprise",
			deployMode: "in-vpc-enterprise",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
			},
		},
		{
			name:       "Legacy invpc mode",
			deployMode: "invpc",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
			},
		},
		{
			name:       "Unknown mode defaults to saas",
			deployMode: "unknown",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
				"/test/migrations/industry/healthcare",
				"/test/migrations/industry/banking",
				"/test/migrations/industry/travel",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			os.Setenv("DEPLOYMENT_MODE", tt.deployMode)
			defer os.Unsetenv("DEPLOYMENT_MODE")

			paths := getMigrationPaths(basePath)

			if len(paths) != len(tt.expectedPaths) {
				t.Errorf("Expected %d paths, got %d", len(tt.expectedPaths), len(paths))
				return
			}

			for i, expectedPath := range tt.expectedPaths {
				if paths[i] != expectedPath {
					t.Errorf("Path[%d] = %q, want %q", i, paths[i], expectedPath)
				}
			}
		})
	}
}

// TestGetMigrationPaths_DefaultMode tests default deployment mode
func TestGetMigrationPaths_DefaultMode(t *testing.T) {
	// Clear any existing DEPLOYMENT_MODE
	os.Unsetenv("DEPLOYMENT_MODE")

	basePath := "/test/migrations"
	paths := getMigrationPaths(basePath)

	// Should default to oss mode (core only) for docker-compose and OSS users
	expectedCount := 1 // core only
	if len(paths) != expectedCount {
		t.Errorf("Expected %d paths for default mode (oss), got %d", expectedCount, len(paths))
	}

	// First path should be core
	if len(paths) > 0 && !strings.Contains(paths[0], "core") {
		t.Errorf("First path should be core, got %s", paths[0])
	}
}

// TestCollectMigrations tests migration file collection
func TestCollectMigrations(t *testing.T) {
	// Create temporary migration directories
	tmpDir := t.TempDir()
	coreDir := filepath.Join(tmpDir, "core")
	enterpriseDir := filepath.Join(tmpDir, "enterprise")

	if err := os.MkdirAll(coreDir, 0755); err != nil {
		t.Fatalf("Failed to create core dir: %v", err)
	}
	if err := os.MkdirAll(enterpriseDir, 0755); err != nil {
		t.Fatalf("Failed to create enterprise dir: %v", err)
	}

	// Create test migration files
	coreFiles := []string{
		"001_schema_migrations.sql",
		"002_organizations_and_auth.sql",
	}
	enterpriseFiles := []string{
		"100_agent_heartbeats.sql",
		"101_marketplace_metering.sql",
	}

	for _, file := range coreFiles {
		if err := os.WriteFile(filepath.Join(coreDir, file), []byte("-- Test migration"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}
	for _, file := range enterpriseFiles {
		if err := os.WriteFile(filepath.Join(enterpriseDir, file), []byte("-- Test migration"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Set to saas mode to collect all migrations
	os.Setenv("DEPLOYMENT_MODE", "saas")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	migrations, err := collectMigrations(tmpDir)
	if err != nil {
		t.Fatalf("collectMigrations() error = %v", err)
	}

	// Should have 4 migrations (2 core + 2 enterprise)
	if len(migrations) != 4 {
		t.Errorf("Expected 4 migrations, got %d", len(migrations))
	}

	// Verify migrations are sorted by version
	for i := 0; i < len(migrations)-1; i++ {
		if migrations[i].Version >= migrations[i+1].Version {
			t.Errorf("Migrations not sorted: %s >= %s", migrations[i].Version, migrations[i+1].Version)
		}
	}

	// Verify categories
	coreCount := 0
	enterpriseCount := 0
	for _, m := range migrations {
		if m.Category == "core" {
			coreCount++
		} else if m.Category == "enterprise" {
			enterpriseCount++
		}
	}

	if coreCount != 2 {
		t.Errorf("Expected 2 core migrations, got %d", coreCount)
	}
	if enterpriseCount != 2 {
		t.Errorf("Expected 2 enterprise migrations, got %d", enterpriseCount)
	}
}

// TestCollectMigrations_SkipDownMigrations tests that down migrations are skipped
func TestCollectMigrations_SkipDownMigrations(t *testing.T) {
	tmpDir := t.TempDir()
	coreDir := filepath.Join(tmpDir, "core")

	if err := os.MkdirAll(coreDir, 0755); err != nil {
		t.Fatalf("Failed to create core dir: %v", err)
	}

	// Create up and down migrations
	files := []string{
		"001_test_migration.sql",
		"001_test_migration_down.sql",
	}

	for _, file := range files {
		if err := os.WriteFile(filepath.Join(coreDir, file), []byte("-- Test"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	os.Setenv("DEPLOYMENT_MODE", "oss")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	migrations, err := collectMigrations(tmpDir)
	if err != nil {
		t.Fatalf("collectMigrations() error = %v", err)
	}

	// Should only have 1 migration (down migration should be skipped)
	if len(migrations) != 1 {
		t.Errorf("Expected 1 migration (skipping _down.sql), got %d", len(migrations))
	}

	if len(migrations) > 0 && strings.Contains(migrations[0].Path, "_down.sql") {
		t.Error("Down migration should be skipped")
	}
}

// TestCollectMigrations_NonexistentDirectory tests behavior with missing directories
func TestCollectMigrations_NonexistentDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("DEPLOYMENT_MODE", "oss")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	// Should not error, just log and skip
	migrations, err := collectMigrations(tmpDir)
	if err != nil {
		t.Errorf("collectMigrations() with nonexistent dirs error = %v, want nil", err)
	}

	// Should return empty slice
	if len(migrations) != 0 {
		t.Errorf("Expected 0 migrations for nonexistent dirs, got %d", len(migrations))
	}
}

// TestValidateMigrationDependencies tests dependency validation
func TestValidateMigrationDependencies(t *testing.T) {
	tests := []struct {
		name        string
		migrations  []MigrationFile
		expectError bool
	}{
		{
			name: "valid dependencies",
			migrations: []MigrationFile{
				{
					Path:     "/test/001_base.sql",
					Category: "core",
					Version:  "001",
					Name:     "base",
				},
				{
					Path:     "/test/002_depends_on_001.sql",
					Category: "core",
					Version:  "002",
					Name:     "depends_on_001",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary files with content
			tmpDir := t.TempDir()
			for i, m := range tt.migrations {
				content := "-- Test migration\nCREATE TABLE test();"
				if i > 0 {
					// Add dependency for non-first migrations using version_name format
					prevMig := tt.migrations[i-1]
					depName := fmt.Sprintf("%s_%s", prevMig.Version, prevMig.Name)
					content = fmt.Sprintf("-- Depends: %s\n%s", depName, content)
				}

				filePath := filepath.Join(tmpDir, filepath.Base(m.Path))
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}

				// Update path to temp location
				tt.migrations[i].Path = filePath
			}

			err := validateMigrationDependencies(tt.migrations)

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestValidateMigrationDependencies_MissingDependency tests missing dependency error
func TestValidateMigrationDependencies_MissingDependency(t *testing.T) {
	tmpDir := t.TempDir()

	// Create migration file that depends on missing migration
	filePath := filepath.Join(tmpDir, "100_depends_on_missing.sql")
	content := "-- Depends: 050_missing_migration\nCREATE TABLE test();"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	migrations := []MigrationFile{
		{
			Path:     filePath,
			Category: "enterprise",
			Version:  "100",
			Name:     "depends_on_missing",
		},
	}

	err := validateMigrationDependencies(migrations)
	if err == nil {
		t.Error("Expected error for missing dependency, got nil")
	}

	if err != nil && !strings.Contains(err.Error(), "depends on") {
		t.Errorf("Expected dependency error, got: %v", err)
	}
}
