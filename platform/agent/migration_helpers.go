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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// =============================================================================
// Multi-Edition Migration Architecture (ADR-012)
// =============================================================================
// This implements the Flyway-style multi-location pattern for migrations.
// Directory structure:
//   migrations/
//   ├── core/           (001-099) Always run on every deployment
//   ├── enterprise/     (100-199) Enterprise self-hosted deployments
//   ├── community-saas/ (086+)    try.getaxonflow.com hosted infra ONLY
//   └── industry/       (200+) Industry-specific verticals
//       ├── travel/     (200-249) Travel vertical (EU AI Act)
//       ├── healthcare/ (250-299) Healthcare vertical
//       ├── banking/    (300-349) Banking vertical (SEBI)
//       └── (future)    (350+) Additional verticals
//
// IMPORTANT: Industry migrations MUST use numbers >= 200 to ensure they run
// AFTER all core and enterprise migrations. Using 001-099 will cause failures
// because dependencies (like static_policies) won't exist yet.
//
// IMPORTANT: community-saas/ migrations apply ONLY when DEPLOYMENT_MODE=
// community-saas. Self-hosted community / enterprise / in-vpc-* deployments
// must NEVER load this category — these tables (tenant registrations, the
// A1.5 adoption bridge role, etc.) are operational infra for our hosted
// SaaS only. Version numbers can overlap with core/ (since the schema_
// migrations table is keyed by version+filename and the runner skips
// already-applied migrations by version).
//
// DEPLOYMENT_MODE controls which paths are included:
//   - community:         core/
//   - saas:              core/ + enterprise/ + industry/*
//   - in-vpc-healthcare: core/ + enterprise/ + industry/healthcare/
//   - in-vpc-banking:    core/ + enterprise/ + industry/banking/
//   - in-vpc-travel:     core/ + enterprise/ + industry/travel/
//   - in-vpc-enterprise: core/ + enterprise/
//   - community-saas:    core/ + community-saas/
// =============================================================================

// MigrationFile represents a migration file with metadata
type MigrationFile struct {
	Path     string // Full path to the file
	Category string // core, enterprise, healthcare, banking, travel
	Version  string // Numeric version (e.g., "001", "100")
	Name     string // Human-readable name
}

// getMigrationPaths returns the migration directories to scan based on DEPLOYMENT_MODE
func getMigrationPaths(basePath string) []string {
	mode := os.Getenv("DEPLOYMENT_MODE")
	if mode == "" {
		mode = "community" // Default to Community mode for local development and docker-compose
	}

	// Handle legacy 'invpc' value (backwards compatibility)
	if mode == "invpc" {
		mode = "in-vpc-enterprise"
		log.Println("📦 Note: DEPLOYMENT_MODE=invpc is deprecated, treating as in-vpc-enterprise")
	}

	paths := []string{}

	// Core migrations always run
	paths = append(paths, filepath.Join(basePath, "core"))

	switch mode {
	case "community":
		// Community only runs core migrations
		log.Println("📦 DEPLOYMENT_MODE=community: Running core migrations only")

	case "evaluation":
		// Evaluation runs core migrations only (community binary with evaluation license)
		log.Println("📦 DEPLOYMENT_MODE=evaluation: Running core migrations only (evaluation tier)")

	case "saas":
		// SaaS runs everything
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		paths = append(paths, filepath.Join(basePath, "industry", "healthcare"))
		paths = append(paths, filepath.Join(basePath, "industry", "banking"))
		paths = append(paths, filepath.Join(basePath, "industry", "travel"))
		log.Println("📦 DEPLOYMENT_MODE=saas: Running all migrations (core + enterprise + industry)")

	case "in-vpc-healthcare":
		// Healthcare runs core + enterprise + healthcare industry
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		paths = append(paths, filepath.Join(basePath, "industry", "healthcare"))
		log.Println("📦 DEPLOYMENT_MODE=in-vpc-healthcare: Running core + enterprise + healthcare migrations")

	case "in-vpc-banking":
		// Banking runs core + enterprise + banking industry
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		paths = append(paths, filepath.Join(basePath, "industry", "banking"))
		log.Println("📦 DEPLOYMENT_MODE=in-vpc-banking: Running core + enterprise + banking migrations")

	case "in-vpc-travel":
		// Travel runs core + enterprise + travel industry
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		paths = append(paths, filepath.Join(basePath, "industry", "travel"))
		log.Println("📦 DEPLOYMENT_MODE=in-vpc-travel: Running core + enterprise + travel migrations")

	case "in-vpc-enterprise":
		// Enterprise runs core + enterprise only
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		log.Println("📦 DEPLOYMENT_MODE=in-vpc-enterprise: Running core + enterprise migrations")

	case "community-saas":
		// Community-SaaS: core migrations + the dedicated community-saas/
		// category. The community-SaaS hosted deployment (try.getaxonflow.com)
		// has internal-only infrastructure (tenant registrations, the A1.5
		// adoption bridge, etc.) that does NOT belong in core/ because
		// self-hosted community + enterprise customers don't need those
		// tables.
		//
		// Migrations 085 + 086 live in community-saas/ from inception
		// (085 was added 2026-05-08, post-v7.8.0 release, so no customer
		// self-host environment had applied it yet at relocation time —
		// move was safe). Migrations 068 / 073 / 075 / 076 (and a few
		// other tenant-related ones) remain in core/ for now because they
		// shipped in releases <= v7.8.0 and customer environments have
		// applied them; relocating them needs a drift-detection runbook
		// that's planned as a separate refactor.
		paths = append(paths, filepath.Join(basePath, "community-saas"))
		log.Println("📦 DEPLOYMENT_MODE=community-saas: Running core + community-saas migrations")

	default:
		// Unknown mode - default to saas for safety
		log.Printf("⚠️  Unknown DEPLOYMENT_MODE=%s, defaulting to saas", mode)
		paths = append(paths, filepath.Join(basePath, "enterprise"))
		paths = append(paths, filepath.Join(basePath, "industry", "healthcare"))
		paths = append(paths, filepath.Join(basePath, "industry", "banking"))
		paths = append(paths, filepath.Join(basePath, "industry", "travel"))
	}

	return paths
}

// collectMigrations collects all migration files from configured paths
func collectMigrations(basePath string) ([]MigrationFile, error) {
	paths := getMigrationPaths(basePath)
	var migrations []MigrationFile

	for _, path := range paths {
		// Check if directory exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Printf("ℹ️  Migration directory not found: %s (skipping)", path)
			continue
		}

		// Get category from path (e.g., "core", "enterprise", "healthcare", "banking")
		category := filepath.Base(path)

		// Find all SQL files
		files, err := filepath.Glob(filepath.Join(path, "*.sql"))
		if err != nil {
			return nil, fmt.Errorf("failed to list migrations in %s: %w", path, err)
		}

		for _, file := range files {
			filename := filepath.Base(file)
			// Skip down migrations (handled separately)
			if strings.HasSuffix(filename, "_down.sql") {
				continue
			}

			version := extractMigrationVersion(filename)
			name := extractMigrationName(filename)

			migrations = append(migrations, MigrationFile{
				Path:     file,
				Category: category,
				Version:  version,
				Name:     name,
			})
		}
	}

	// Sort migrations by version number
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// validateMigrationDependencies validates that dependencies are satisfied
// Dependencies are extracted from SQL comment headers: "-- Depends: 002_organizations_and_auth"
func validateMigrationDependencies(migrations []MigrationFile) error {
	appliedVersions := make(map[string]bool)

	for _, m := range migrations {
		// Read the file to check for dependencies
		content, err := os.ReadFile(m.Path)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", m.Path, err)
		}

		// Extract dependencies from header
		deps := extractDependencies(string(content))
		for _, dep := range deps {
			depVersion := extractMigrationVersion(dep)
			if !appliedVersions[depVersion] {
				return fmt.Errorf("migration %s depends on %s which is not included in this deployment mode",
					filepath.Base(m.Path), dep)
			}
		}

		// Mark this migration as available
		appliedVersions[m.Version] = true
	}

	log.Println("✅ Migration dependency validation passed")
	return nil
}

// extractDependencies extracts dependency declarations from SQL content
// Format: "-- Depends: 002_organizations_and_auth"
func extractDependencies(content string) []string {
	var deps []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-- Depends:") {
			dep := strings.TrimSpace(strings.TrimPrefix(line, "-- Depends:"))
			if dep != "" {
				deps = append(deps, dep)
			}
		}
	}
	return deps
}

// =============================================================================
// Migration Tracking Helpers (Principle 0: Quality Over Velocity)
// =============================================================================

// ensureSchemaMigrationsTable creates or upgrades the schema_migrations table
// This handles migration from old schema (version, dirty) to new schema (all columns)
func ensureSchemaMigrationsTable(db *sql.DB) {
	// Check if table exists and what schema it has
	var hasNameColumn bool
	err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'schema_migrations'
			AND column_name = 'name'
		)
	`).Scan(&hasNameColumn)

	if err != nil {
		log.Printf("⚠️  Failed to check schema_migrations schema: %v", err)
		// Continue anyway, will try to create table
	}

	// If table exists with old schema, upgrade it
	if !hasNameColumn {
		var tableExists bool
		if err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_name = 'schema_migrations'
			)
		`).Scan(&tableExists); err != nil {
			log.Printf("⚠️  Failed to check for old schema_migrations table: %v", err)
			tableExists = false
		}

		if tableExists {
			log.Println("🔄 Upgrading old schema_migrations table to new schema...")
			upgradeSQL := `
				-- Rename old table
				ALTER TABLE schema_migrations RENAME TO schema_migrations_old;

				-- Create new table with full schema
				CREATE TABLE schema_migrations (
					id SERIAL PRIMARY KEY,
					version VARCHAR(20) NOT NULL UNIQUE,
					name VARCHAR(255) NOT NULL,
					applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
					execution_time_ms INTEGER,
					success BOOLEAN NOT NULL DEFAULT true,
					error_message TEXT,
					checksum VARCHAR(64),
					applied_by VARCHAR(100) DEFAULT 'agent',
					hostname VARCHAR(255),
					git_commit VARCHAR(40),
					created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
				);

				-- Migrate data from old table (only successful migrations)
				INSERT INTO schema_migrations (version, name, applied_at, success)
				SELECT
					version::VARCHAR(20),
					'migration_' || version::VARCHAR(20),
					NOW() - (version::INTEGER || ' days')::INTERVAL,
					true
				FROM schema_migrations_old
				WHERE dirty = false;

				-- Drop old table
				DROP TABLE schema_migrations_old;

				-- Create indexes
				CREATE INDEX IF NOT EXISTS idx_schema_migrations_version
					ON schema_migrations(version);
			`

			_, err = db.Exec(upgradeSQL)
			if err != nil {
				log.Printf("⚠️  Failed to upgrade schema_migrations table: %v", err)
				// Don't fail here - fall back to running all migrations
				return
			}

			log.Println("✅ Schema migrations table upgraded successfully")
			return
		}
	}

	// Table doesn't exist or already has new schema, create with new schema
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id SERIAL PRIMARY KEY,
			version VARCHAR(20) NOT NULL UNIQUE,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			execution_time_ms INTEGER,
			success BOOLEAN NOT NULL DEFAULT true,
			error_message TEXT,
			checksum VARCHAR(64),
			applied_by VARCHAR(100) DEFAULT 'agent',
			hostname VARCHAR(255),
			git_commit VARCHAR(40),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);

		CREATE INDEX IF NOT EXISTS idx_schema_migrations_version
			ON schema_migrations(version);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Printf("⚠️  Failed to create schema_migrations table: %v", err)
		// Don't fail here - fall back to running all migrations
		return
	}

	log.Println("✅ Schema migrations tracking table ready")
}

// getAppliedMigrations returns a map of migration versions that have been successfully applied
func getAppliedMigrations(db *sql.DB) map[string]bool {
	applied := make(map[string]bool)

	rows, err := db.Query(`
		SELECT version
		FROM schema_migrations
		WHERE success = true
		ORDER BY version
	`)
	if err != nil {
		log.Printf("⚠️  Failed to query schema_migrations: %v", err)
		// Return empty map - will run all migrations
		return applied
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			log.Printf("⚠️  Failed to scan migration version: %v", err)
			continue
		}
		applied[version] = true
	}

	if len(applied) > 0 {
		log.Printf("📋 Found %d previously applied migrations", len(applied))
	}

	return applied
}

// extractMigrationVersion extracts the version number from a migration filename
// Examples:
//   "006_customer_portal.sql" -> "006"
//   "020_schema_migrations.sql" -> "020"
func extractMigrationVersion(filename string) string {
	// Remove .sql extension
	name := strings.TrimSuffix(filename, ".sql")

	// Split by underscore and take first part
	parts := strings.Split(name, "_")
	if len(parts) > 0 {
		return parts[0]
	}

	return name
}

// extractMigrationName extracts the human-readable name from a migration filename
// Examples:
//   "006_customer_portal.sql" -> "customer_portal"
//   "020_schema_migrations.sql" -> "schema_migrations"
func extractMigrationName(filename string) string {
	// Remove .sql extension
	name := strings.TrimSuffix(filename, ".sql")

	// Split by underscore and take everything after first part
	parts := strings.Split(name, "_")
	if len(parts) > 1 {
		return strings.Join(parts[1:], "_")
	}

	return name
}

// calculateFileChecksum calculates SHA-256 checksum of a file
//
//nolint:unused // Used in tests
func calculateFileChecksum(filepath string) string {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// recordMigrationSuccess records a successful migration in schema_migrations table
func recordMigrationSuccess(db *sql.DB, version, filename string, executionTimeMs int) {
	name := extractMigrationName(filename)
	hostname, _ := os.Hostname()
	gitCommit := os.Getenv("GIT_COMMIT") // Can be set during build

	_, err := db.Exec(`
		INSERT INTO schema_migrations (
			version, name, applied_at, execution_time_ms,
			success, applied_by, hostname, git_commit
		)
		VALUES ($1, $2, NOW(), $3, true, 'agent', $4, $5)
		ON CONFLICT (version) DO UPDATE SET
			applied_at = NOW(),
			execution_time_ms = $3,
			success = true,
			error_message = NULL
	`, version, name, executionTimeMs, hostname, gitCommit)

	if err != nil {
		log.Printf("⚠️  Failed to record migration success for %s: %v", filename, err)
		// Don't fail the migration itself
	}
}

// recordMigrationFailure records a failed migration in schema_migrations table
func recordMigrationFailure(db *sql.DB, version, filename string, migrationErr error, executionTimeMs int) {
	name := extractMigrationName(filename)
	hostname, _ := os.Hostname()
	gitCommit := os.Getenv("GIT_COMMIT")

	_, err := db.Exec(`
		INSERT INTO schema_migrations (
			version, name, applied_at, execution_time_ms,
			success, error_message, applied_by, hostname, git_commit
		)
		VALUES ($1, $2, NOW(), $3, false, $4, 'agent', $5, $6)
		ON CONFLICT (version) DO UPDATE SET
			applied_at = NOW(),
			execution_time_ms = $3,
			success = false,
			error_message = $4
	`, version, name, executionTimeMs, migrationErr.Error(), hostname, gitCommit)

	if err != nil {
		log.Printf("⚠️  Failed to record migration failure for %s: %v", filename, err)
		// Don't fail here - the original migration error is more important
	}
}

// getMigrationStatus returns a status message about applied migrations for debugging
//
//nolint:unused // Used in tests
func getMigrationStatus(db *sql.DB) string {
	var count int
	var lastVersion string
	var lastApplied string

	err := db.QueryRow(`
		SELECT COUNT(*), MAX(version), MAX(applied_at)::text
		FROM schema_migrations
		WHERE success = true
	`).Scan(&count, &lastVersion, &lastApplied)

	if err != nil {
		return fmt.Sprintf("Failed to query migration status: %v", err)
	}

	return fmt.Sprintf("%d migrations applied (latest: %s at %s)", count, lastVersion, lastApplied)
}
