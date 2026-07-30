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
	"runtime"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// TestEnsureSchemaMigrationsTable_UpgradeOldSchema tests upgrading from old schema to new
func TestEnsureSchemaMigrationsTable_UpgradeOldSchema(t *testing.T) {
	// Get test database URL (uses testcontainers if not set)
	dbURL := getTestDatabaseURLWithContainer(t)

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
	// Get test database URL (uses testcontainers if not set)
	dbURL := getTestDatabaseURLWithContainer(t)

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
	// Get test database URL (uses testcontainers if not set)
	dbURL := getTestDatabaseURLWithContainer(t)

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

// getTestDatabaseURLWithContainer returns a test database URL, using testcontainers if needed.
func getTestDatabaseURLWithContainer(t *testing.T) string {
	t.Helper()

	if url := getTestDatabaseURL(); url != "" {
		return url
	}

	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	return pg.URL
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
			name:       "Community mode",
			deployMode: "community",
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
			// #3167. This is the value docker-compose.enterprise.yml,
			// docker-compose.test.yml, docker/docker-compose.base.yaml and
			// scripts/setup-e2e-testing.sh all use. It was NOT a case, so it hit
			// the default arm and every self-hosted enterprise stack applied the
			// SaaS set — enterprise/ plus all three industry verticals.
			name:       "enterprise aliases in-vpc-enterprise (#3167)",
			deployMode: "enterprise",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/enterprise",
			},
		},
		{
			name:       "Evaluation mode",
			deployMode: "evaluation",
			expectedPaths: []string{
				"/test/migrations/core",
			},
		},
		{
			name:       "Community-SaaS mode",
			deployMode: "community-saas",
			expectedPaths: []string{
				"/test/migrations/core",
				"/test/migrations/community-saas",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tt.deployMode)

			paths, err := getMigrationPaths(basePath)
			if err != nil {
				t.Fatalf("getMigrationPaths(%q) error = %v, want nil", tt.deployMode, err)
			}

			if len(paths) != len(tt.expectedPaths) {
				t.Errorf("Expected %d paths, got %d (%v)", len(tt.expectedPaths), len(paths), paths)
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

// TestGetMigrationPaths_DefaultMode characterizes the #3128 asymmetry rather
// than merely restating the default.
//
// Since #3117 an unset DEPLOYMENT_MODE means the ENTERPRISE posture at runtime
// (isCommunityMode fails closed) while it still means COMMUNITY here. The two
// halves of one variable disagree, and this test is the tripwire: a future edit
// that flips the selector to match will turn it red, which is the point. Read
// technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md before changing
// it — the flip was measured against a real database and is a 45-table schema
// event with four RLS-blind tables, not a consistency edit.
//
// The pairing with isCommunityMode() is asserted directly so the disagreement
// cannot be half-resolved: changing either side alone fails here.
//
// #3167 kept this contract deliberately. What it changed is the OTHER half of
// the same variable: an unrecognised value no longer falls through to the
// widest set, so the population that reaches this asymmetry is now exactly
// "unset" rather than "unset or mistyped". `unsetDeploymentMode` is asserted
// below so the constant cannot be repointed without turning this red.
func TestGetMigrationPaths_DefaultMode(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "")

	basePath := "/test/migrations"
	paths, err := getMigrationPaths(basePath)
	if err != nil {
		t.Fatalf("getMigrationPaths() with an unset mode error = %v, want nil — unset must NOT be fatal (#3167); "+
			"it is the state of the in-repo docker run launchers including the Marketplace deploy path", err)
	}

	// Should default to community mode (core only) for docker-compose and Community users
	expectedCount := 1 // core only
	if len(paths) != expectedCount {
		t.Errorf("Expected %d paths for default mode (community), got %d (%v)", expectedCount, len(paths), paths)
	}

	// First path should be core
	if len(paths) > 0 && !strings.Contains(paths[0], "core") {
		t.Errorf("First path should be core, got %s", paths[0])
	}

	if unsetDeploymentMode != "community" {
		t.Errorf("unsetDeploymentMode = %q, want \"community\". Repointing it at an enterprise mode was MEASURED "+
			"to leave connector_configs with no org_id, RLS off and zero policies, and three sso_* tables "+
			"unforced, because core/106, core/107 and core/138 have already run and no-op'd. "+
			"See technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md and #3128.", unsetDeploymentMode)
	}

	// #3128: the runtime half of the same variable already reads unset as NOT
	// community. Pin both readings in one place so the divergence is visible at
	// the point a reader is most likely to try to close it.
	if isCommunityMode() {
		t.Error("isCommunityMode() must fail closed on unset (#3117/#3096) — if this is now true, #3128 was resolved by relaxing the runtime half, which is the wrong direction")
	}
}

// TestGetMigrationPaths_UnrecognisedModeIsRefused is the inversion of the
// former "Unknown mode defaults to saas" case (#3167).
//
// The old default arm logged a warning and applied core + enterprise +
// industry/healthcare + industry/banking + industry/travel. That is how the
// `enterprise` spelling put eight industry migrations onto every self-hosted
// enterprise stack without anyone misconfiguring anything: the widest set is
// what you got for a value the selector did not understand.
//
// A selector that widens on unrecognised input cannot distinguish "the operator
// asked for the SaaS schema" from "the operator typed something we have never
// heard of". It must refuse.
func TestGetMigrationPaths_UnrecognisedModeIsRefused(t *testing.T) {
	// Values that must NOT be accepted. The whitespace and case variants are
	// here because resolveDeploymentMode deliberately does not trim or
	// case-fold, matching isCommunityMode()'s contract.
	for _, mode := range []string{
		"unknown",
		"Enterprise",
		" enterprise",
		"enterprise ",
		"in-vpc",
		"prod",
		"in-vpc-fintech",
		"COMMUNITY",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)

			paths, err := getMigrationPaths("/test/migrations")
			if err == nil {
				t.Fatalf("getMigrationPaths() with DEPLOYMENT_MODE=%q returned %v and no error — "+
					"an unrecognised mode must refuse, not select a migration set", mode, paths)
			}
			if paths != nil {
				t.Errorf("getMigrationPaths() returned %v alongside the error — want nil", paths)
			}
			// The operator has to be able to act on this. Name the bad value
			// and list the accepted ones.
			if !strings.Contains(err.Error(), mode) {
				t.Errorf("error %q does not name the rejected value %q", err, mode)
			}
			for _, accepted := range recognisedDeploymentModes() {
				if !strings.Contains(err.Error(), accepted) {
					t.Errorf("error %q does not list the accepted mode %q", err, accepted)
				}
			}
		})
	}
}

// TestResolveDeploymentMode_AliasesAreRecognisedAndCanonical pins the alias
// table itself: every alias must resolve to a mode that canonicalDeploymentModes
// actually has categories for. An alias pointing at a typo would resolve
// "successfully" to an empty category list and silently run ZERO migrations.
func TestResolveDeploymentMode_AliasesAreRecognisedAndCanonical(t *testing.T) {
	for alias, canonical := range deploymentModeAliases {
		if _, ok := canonicalDeploymentModes[canonical]; !ok {
			t.Errorf("alias %q resolves to %q, which is not a canonical mode", alias, canonical)
		}
		if _, ok := canonicalDeploymentModes[alias]; ok {
			t.Errorf("%q is both an alias and a canonical mode — the alias is dead code", alias)
		}
		got, err := resolveDeploymentMode(alias)
		if err != nil {
			t.Errorf("resolveDeploymentMode(%q) error = %v, want nil", alias, err)
			continue
		}
		if got != canonical {
			t.Errorf("resolveDeploymentMode(%q) = %q, want %q", alias, got, canonical)
		}
	}

	// Every canonical mode must select at least core/. A mode with an empty
	// list would apply nothing and boot on an unmigrated database.
	for mode, categories := range canonicalDeploymentModes {
		if len(categories) == 0 {
			t.Errorf("mode %q selects no categories", mode)
			continue
		}
		if categories[0] != "core" {
			t.Errorf("mode %q selects %v — core/ must be first and always present", mode, categories)
		}
	}
}

// TestMigrationCategories_InternalIsSelectedByNoMode is the guard on the #3168
// relocation. migrations/internal/ holds AxonFlow's own E2E fixtures and demo
// tenants; if any mode ever selects it they land in a customer's portal again.
func TestMigrationCategories_InternalIsSelectedByNoMode(t *testing.T) {
	for _, never := range neverSelectedMigrationCategories {
		for mode, categories := range canonicalDeploymentModes {
			for _, c := range categories {
				if c == never {
					t.Errorf("DEPLOYMENT_MODE=%q selects migrations/%s/, which no deployment may load", mode, never)
				}
			}
		}

		// Belt and braces: drive the real selector for every recognised
		// spelling, including the aliases and unset, and assert the path never
		// appears.
		modes := append(recognisedDeploymentModes(), "")
		for _, mode := range modes {
			t.Run(never+"/"+mode, func(t *testing.T) {
				t.Setenv("DEPLOYMENT_MODE", mode)
				paths, err := getMigrationPaths("/test/migrations")
				if err != nil {
					t.Fatalf("getMigrationPaths(%q): %v", mode, err)
				}
				for _, p := range paths {
					if p == "/test/migrations/"+never {
						t.Errorf("DEPLOYMENT_MODE=%q selected %s", mode, p)
					}
				}
			})
		}
	}
}

// axonflowInternalTenantMarkers are identifiers that belong to AxonFlow's own
// hosted environments. A migration that seeds one of them into a customer's
// database puts our test data in the customer's portal (#3168).
var axonflowInternalTenantMarkers = []string{
	"e2e-test-saas",     // migrations/internal/115 — our portal-UI E2E tenant
	"travel-us",         // migrations/internal/125 — our demo org
	"ecommerce-prod-us", // migrations/internal/125 — our demo org
}

// TestNoDeploymentModeLoadsAxonFlowInternalSeeds is the property behind the
// #3168 relocation, stated over the REAL migrations tree rather than over the
// category list.
//
// It runs the production selector for every recognised DEPLOYMENT_MODE and for
// unset, collects the files that selector actually returns, and reads them. A
// customer deployment must not apply a migration that names an AxonFlow tenant.
//
// Stated this way it also catches the NEXT one: a seed added to enterprise/
// tomorrow for our own staging convenience fails here, where a test that merely
// asserted "internal/ is not selected" would not.
func TestNoDeploymentModeLoadsAxonFlowInternalSeeds(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	migrationsRoot := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), "migrations")

	modes := append(recognisedDeploymentModes(), "")
	for _, mode := range modes {
		label := mode
		if label == "" {
			label = "unset"
		}
		t.Run(label, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)

			migrations, err := collectMigrations(migrationsRoot)
			if err != nil {
				t.Fatalf("collectMigrations: %v", err)
			}
			if len(migrations) == 0 {
				t.Fatalf("mode %q selected ZERO migrations — the walk is broken, not the tree", label)
			}

			for _, m := range migrations {
				content, err := os.ReadFile(m.Path)
				if err != nil {
					t.Fatalf("read %s: %v", m.Path, err)
				}
				for _, marker := range axonflowInternalTenantMarkers {
					if strings.Contains(string(content), marker) {
						rel, _ := filepath.Rel(migrationsRoot, m.Path)
						t.Errorf("DEPLOYMENT_MODE=%q applies migrations/%s, which names the AxonFlow-internal tenant %q. "+
							"A customer deployment must not seed our data into tables their own portal renders (#3168). "+
							"Move it to migrations/internal/.", label, rel, marker)
					}
				}
			}
		})
	}
}

// TestShellCopiesOfRecognisedModesMatchGo pins EVERY shell-side copy of the
// recognised DEPLOYMENT_MODE set to recognisedDeploymentModes().
//
// Three of them are pinned here: `scripts/lint-deployment-mode.sh` runs in CI
// with no Go toolchain, and the two deploy scripts run over SSM on a remote host
// with no repository checked out, so none can import the Go map.
//
// They are not the only lists of mode strings in the repository, and this test
// does not claim otherwise. Two more exist and are deliberately NOT pinned:
// `scripts/deployment/deploy-cloudformation.sh` mirrors the CloudFormation
// template's `AllowedValues` and is legitimately a narrower SUBSET, and
// `scripts/lib/validate-migrations.sh` groups modes by which tables it expects
// rather than by which are recognised (it gained a fail-closed `*)` arm in the
// same change, so an unrecognised mode no longer passes its verification
// vacuously).
//
// What this test guards is drift in one direction: a shell copy that still
// ACCEPTS a value the platform now refuses lets a deploy proceed to a container
// that will not boot. `enterprise` spent the entire life of the previous lint in
// exactly that state.
//
// An earlier revision of this test pinned only the lint, while the same commit
// introduced the two `case` lists — taking the number of unpinned copies from
// one to two while claiming the map was "the ONLY definition of recognised".
func TestShellCopiesOfRecognisedModesMatchGo(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	want := recognisedDeploymentModes()

	// Each entry names a file, the marker that opens its mode list, and how the
	// list is spelled. Adding a fourth copy without adding it here is the gap
	// this test is guarding, so keep the list with the code that produces it.
	//
	// `esacGuard` is the SECOND half, and it is the one that matters. An earlier
	// revision parsed only from the begin marker to the end marker, which pinned
	// the wrong direction: deleting a mode from inside the block turned it red,
	// but ADDING a `case` arm below the end marker left the extracted list
	// byte-identical while the shell accepted more values than Go — exactly the
	// direction this test's own doc comment calls dangerous. The block is now
	// read to `esac`, and any pattern token outside the pinned list is a
	// failure.
	sources := []struct {
		path      string
		open      string
		close     string
		separator string // "" = one per line, otherwise a delimiter
		esacGuard bool   // also assert no case arm outside the pinned block
	}{
		{filepath.Join("scripts", "lint-deployment-mode.sh"), "RECOGNISED_MODES=(", ")", "", false},
		{filepath.Join("scripts", "marketplace", "deploy-with-metering.sh"), "# axonflow-modes: begin\n", "# axonflow-modes: end", "|", true},
		{filepath.Join("scripts", "utilities", "rolling-deployment.sh"), "# axonflow-modes: begin\n", "# axonflow-modes: end", "|", true},
	}

	for _, src := range sources {
		t.Run(src.path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(repoRoot, src.path))
			if err != nil {
				t.Fatalf("read %s: %v", src.path, err)
			}
			body := string(data)

			start := strings.Index(body, src.open)
			if start < 0 {
				t.Fatalf("%s has no %q marker — the mode list moved or changed shape, and this test "+
					"would otherwise check nothing and report success", src.path, src.open)
			}
			rest := body[start+len(src.open):]
			end := strings.Index(rest, src.close)
			if end < 0 {
				t.Fatalf("%s: %q is never closed by %q", src.path, src.open, src.close)
			}
			raw := rest[:end]

			var got []string
			if src.separator == "" {
				for _, line := range strings.Split(raw, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					got = append(got, line)
				}
			} else {
				// A `case` pattern list: strip comments and shell punctuation,
				// then split on the alternation separator.
				var cleaned []string
				for _, line := range strings.Split(raw, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					line = strings.TrimSuffix(line, ")")
					cleaned = append(cleaned, line)
				}
				for _, tok := range strings.Split(strings.Join(cleaned, src.separator), src.separator) {
					tok = strings.TrimSpace(tok)
					if tok != "" {
						got = append(got, tok)
					}
				}
			}

			if len(got) == 0 {
				t.Fatalf("parsed ZERO modes out of %s — the parse is broken, not the script", src.path)
			}
			sort.Strings(got)
			if len(got) != len(want) {
				t.Fatalf("%s declares %d modes %v, Go recognises %d %v", src.path, len(got), got, len(want), want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("%s mode[%d] = %q, Go has %q", src.path, i, got[i], want[i])
				}
			}

			if !src.esacGuard {
				return
			}

			// Everything between the end marker and `esac` may contain only the
			// catch-all `*)` arm and its body. Any other pattern arm widens the
			// shell's accepting set without touching the pinned block.
			tail := rest[end+len(src.close):]
			esac := strings.Index(tail, "esac")
			if esac < 0 {
				t.Fatalf("%s: no `esac` after the pinned mode block — the case statement this test "+
					"guards is not shaped the way it assumes, and the guard is meaningless", src.path)
			}
			accepted := map[string]bool{"*": true}
			for _, mode := range want {
				accepted[mode] = true
			}
			for lineNo, line := range strings.Split(tail[:esac], "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				// A case arm is `<patterns>)` as the whole statement. Anything
				// else on these lines is arm BODY, which is not our business.
				if !strings.HasSuffix(trimmed, ")") || strings.Contains(trimmed, "(") {
					continue
				}
				for _, pat := range strings.Split(strings.TrimSuffix(trimmed, ")"), "|") {
					pat = strings.TrimSpace(pat)
					if pat == "" {
						continue
					}
					if !accepted[pat] {
						t.Errorf("%s:+%d declares the case arm %q OUTSIDE the pinned "+
							"`# axonflow-modes` block. The shell would accept it; Go does not. "+
							"Put every accepted mode inside the block, or remove the arm.",
							src.path, lineNo, pat)
					}
				}
			}
		})
	}
}

// TestMigrationCategories_MatchDisk asserts the declared category set is
// exactly what is on disk. A new directory under migrations/ that nobody added
// to canonicalDeploymentModes or neverSelectedMigrationCategories would be
// applied by nothing AND walked by none of the collision guards — invisible in
// both directions.
func TestMigrationCategories_MatchDisk(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	root := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))), "migrations")

	declared := map[string]bool{}
	for _, c := range allMigrationCategories() {
		declared[c] = true
	}

	onDisk := map[string]bool{}
	// Two levels: migrations/<cat>/ and migrations/industry/<vertical>/.
	top, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	for _, e := range top {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "industry" {
			sub, err := os.ReadDir(filepath.Join(root, "industry"))
			if err != nil {
				t.Fatalf("ReadDir(industry): %v", err)
			}
			for _, s := range sub {
				if s.IsDir() {
					onDisk["industry/"+s.Name()] = true
				}
			}
			continue
		}
		// v9_tests/ is a psql test harness, not a migration category.
		if e.Name() == "v9_tests" {
			continue
		}
		onDisk[e.Name()] = true
	}

	if len(onDisk) == 0 {
		t.Fatalf("found no directories under %s — path resolution broken", root)
	}

	for c := range onDisk {
		if !declared[c] {
			t.Errorf("migrations/%s/ exists on disk but is in neither canonicalDeploymentModes nor "+
				"neverSelectedMigrationCategories — it is applied by nothing and walked by no guard", c)
		}
	}
	// The other direction is NOT an error. industry/healthcare is a declared
	// placeholder with no directory yet, and collectMigrations explicitly
	// tolerates a missing category ("Migration directory not found … skipping").
	// Logged so the drift is visible rather than assumed.
	for c := range declared {
		if !onDisk[c] {
			t.Logf("category %q is declared but has no directory under migrations/ yet (tolerated: collectMigrations skips missing paths)", c)
		}
	}

	// #3128: the runtime half of the same variable already reads unset as NOT
	// community. Pin both readings in one place so the divergence is visible at
	// the point a reader is most likely to try to close it.
	if isCommunityMode() {
		t.Error("isCommunityMode() must fail closed on unset (#3117/#3096) — if this is now true, #3128 was resolved by relaxing the runtime half, which is the wrong direction")
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

	os.Setenv("DEPLOYMENT_MODE", "community")
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

// TestCollectMigrations_NameTiebreaksOnSameVersion locks in the
// deterministic Name tiebreak in collectMigrations' sort.Slice. The
// historical same-version-different-name pairs (025_decision_chain +
// 025_hitl_oversight_queue and 3 others) rely on stable apply ordering
// across runs — without the tiebreak, Go's sort.Slice is unstable for
// ties and a same-version pair could apply in either order.
//
// Belt-and-suspenders defense behind TestCoreMigrationDir_HasNoVersionDuplicates:
// the guard catches NEW collisions at PR time, this test protects the
// runtime ordering of the historical pairs the guard tolerates.
func TestCollectMigrations_NameTiebreaksOnSameVersion(t *testing.T) {
	tmpDir := t.TempDir()
	coreDir := filepath.Join(tmpDir, "core")
	if err := os.MkdirAll(coreDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Two same-version files; name sort puts "alpha" before "zebra".
	for _, f := range []string{
		"025_zebra.sql",
		"025_alpha.sql",
	} {
		if err := os.WriteFile(filepath.Join(coreDir, f), []byte("-- test"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	migrations, err := collectMigrations(tmpDir)
	if err != nil {
		t.Fatalf("collectMigrations: %v", err)
	}
	if len(migrations) != 2 {
		t.Fatalf("expected 2 migrations, got %d", len(migrations))
	}
	if migrations[0].Name != "alpha" || migrations[1].Name != "zebra" {
		t.Errorf("Name tiebreak not applied: got %q then %q, want \"alpha\" then \"zebra\"",
			migrations[0].Name, migrations[1].Name)
	}
}

// TestCollectMigrations_NonexistentDirectory tests behavior with missing directories
func TestCollectMigrations_NonexistentDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	os.Setenv("DEPLOYMENT_MODE", "community")
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
