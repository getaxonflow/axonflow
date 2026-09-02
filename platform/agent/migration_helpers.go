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

	"axonflow/platform/shared/deploymode"
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
//   ├── internal/       AxonFlow-operated seed data — selected by NO mode
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
// DEPLOYMENT_MODE controls which paths are included — see
// canonicalDeploymentModes below, which is the single definition of both
// "which categories" and "which values are recognised at all".
// =============================================================================

// canonicalDeploymentModes and deploymentModeAliases are init-time COPIES of
// the shared definitions in platform/shared/deploymode, referred to by the
// names every test and every reader in this package already uses.
//
// Copies rather than the shared map objects, so that neither this package nor
// any other can mutate the definition the migration selector reads - and the
// selector decides which database schema a deployment applies. deploymode's
// accessors return fresh maps for exactly that reason.
//
// They moved out of this file because they answer a question a SECOND process
// has to ask. platform/shared/deploymode's package comment carries the full
// argument; the short form is that "does this deployment apply
// migrations/enterprise/" decides whether an Enterprise-only table can exist,
// the orchestrator needs that answer too, and it cannot import package agent.
// Restating the list there would put a predicate and the migration selector on
// two lists that disagree the first time one is edited alone.
//
// The map is still the ONLY definition of "recognised". A value that is
// neither a key of it nor a key of the alias map is REFUSED - getMigrationPaths
// returns an error and the agent refuses to boot. It does not fall through to
// the widest set, which is what shipped before #3167: `enterprise` - the value
// our own docker-compose.enterprise.yml has always defaulted to - was not a
// case, so every self-hosted enterprise stack silently applied the SaaS set,
// including all three industry verticals it never asked for.
var canonicalDeploymentModes = deploymode.CanonicalModes()

// deploymentModeAliases maps accepted non-canonical spellings onto a canonical
// mode. An alias is recognised; anything outside these two maps is not. See
// platform/shared/deploymode for the per-alias history.
var deploymentModeAliases = deploymode.Aliases()

// unsetDeploymentMode is what an EMPTY DEPLOYMENT_MODE resolves to.
//
// It is `community`, UNCHANGED from before #3167, and the divergence from
// isCommunityMode() — which fails closed on unset and therefore gives an
// unconfigured deployment the ENTERPRISE posture — is the open, measured,
// deliberately-not-closed-here issue #3128. See the getMigrationPaths doc
// comment for what pointing this at an enterprise mode was measured to do to an
// existing stack, and
// technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md for the full
// replay and the options.
//
// Unset is deliberately NOT fatal either, and the reason is NOT "the launchers
// leave it unset" — #3170 fixed those in the same change, and
// scripts/marketplace/deploy-with-metering.sh now refuses to run without it. The
// reason is that this process cannot tell an operator who never configured the
// variable from one whose configuration failed to reach the container, and the
// population in the first group is every deployment that predates #3117. Making
// it fatal is Option 2 in the decision document: the most internally consistent
// answer, and a breaking change that belongs in a major.
//
// An unrecognised value IS fatal, because that is an operator asserting
// something the platform cannot honour — a distinction the old `default:` arm
// could not make.
const unsetDeploymentMode = deploymode.Unset

// neverSelectedMigrationCategories are directories under migrations/ that NO
// deployment mode loads, in any configuration.
//
// migrations/internal/ holds AxonFlow's own E2E fixtures and demo-tenant
// mappings. They lived in enterprise/ and therefore shipped onto every customer
// stack — five dynamic_policies rows for our `e2e-test-saas` tenant and two
// `customers` rows for our `travel-us` / `ecommerce-prod-us` demo orgs, both
// visible in the customer's own portal (#3168). The tenant and FOUR of the five
// policies are seeded for real by .github/workflows/seed-test-data.yml against
// the portal API; `115` was a superset that ran everywhere instead. The fifth,
// `e2e-pii-detection-001`, has no counterpart in that workflow — nothing in the
// repository references it. See migrations/internal/README.md.
var neverSelectedMigrationCategories = []string{"internal"}

// allMigrationCategories returns every category directory that is expected to
// exist under migrations/, selected or not, sorted. Tests that walk the
// migrations tree use it so that adding a directory can never silently escape
// their coverage.
func allMigrationCategories() []string {
	set := map[string]bool{}
	for _, cats := range canonicalDeploymentModes {
		for _, c := range cats {
			set[c] = true
		}
	}
	for _, c := range neverSelectedMigrationCategories {
		set[c] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// recognisedDeploymentModes returns every accepted DEPLOYMENT_MODE spelling —
// canonical names and aliases — sorted. Used in the boot-failure message and
// by scripts/lint-deployment-mode.sh's fixture, so an operator who mistyped is
// told what the accepted values actually are.
func recognisedDeploymentModes() []string {
	out := make([]string, 0, len(canonicalDeploymentModes)+len(deploymentModeAliases))
	for m := range canonicalDeploymentModes {
		out = append(out, m)
	}
	for m := range deploymentModeAliases {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// resolveDeploymentMode maps a raw DEPLOYMENT_MODE value onto a canonical mode.
//
// The value is matched EXACTLY — not trimmed, not case-folded — for the same
// reason isCommunityMode() is (see platform/agent/run.go). This string selects
// the database schema; normalising it would silently accept a value the
// operator did not write, and " community" would quietly become Community.
// Since an unrecognised value is now refused rather than widened, a whitespace
// or case slip surfaces as a named boot failure instead of a silent schema
// choice.
func resolveDeploymentMode(raw string) (string, error) {
	// Resolution ORDER lives in exactly one place too (deploymode.Resolve):
	// aliases first, then canonical names, empty to the unset default. A copy
	// of the order here would be a second thing to keep in step with the maps.
	if mode, recognised := deploymode.Resolve(raw); recognised {
		return mode, nil
	}
	return "", fmt.Errorf(
		"unrecognised DEPLOYMENT_MODE=%q — refusing to guess which database schema to apply. "+
			"Accepted values (matched exactly, no trimming or case-folding): %s. "+
			"Do NOT resolve this by unsetting the variable: unset selects %q (core migrations only) "+
			"while the RUNTIME posture of an unset value has been the enterprise one since #3096, "+
			"which is the open asymmetry #3128 — name the mode this deployment actually is",
		raw, strings.Join(recognisedDeploymentModes(), ", "), unsetDeploymentMode)
}

// MigrationFile represents a migration file with metadata
type MigrationFile struct {
	Path     string // Full path to the file
	Category string // core, enterprise, healthcare, banking, travel
	Version  string // Numeric version (e.g., "001", "100")
	Name     string // Human-readable name
}

// getMigrationPaths returns the migration directories to scan based on
// DEPLOYMENT_MODE, or an error if the configured value is not recognised.
//
// The error is fatal to the boot (see run.go). Refusal is the point: the
// previous default arm applied core + enterprise + all three industry
// verticals to anything it did not recognise, which is how `enterprise`
// — a value we ship ourselves — put eight industry migrations on every
// self-hosted enterprise stack (#3167). A selector that widens on input it does
// not understand cannot tell "the operator chose the SaaS schema" from "the
// operator typed something we've never heard of".
//
// #3128 — UNSET STILL MEANS `community` HERE, AND THAT IS DELIBERATE.
//
// #3117 made isCommunityMode() fail CLOSED on unset, so unset means the
// ENTERPRISE posture at runtime while it still means COMMUNITY here. The two
// halves disagree, and closing that gap is NOT part of the #3167 fix.
//
// Do not close it by pointing unsetDeploymentMode at an enterprise mode. It was
// measured against a real PostgreSQL 15 and the flip SUCCEEDS — 33 applied, 0
// failed — which is the trap. What it leaves behind is `connector_configs` with
// no `org_id`, RLS OFF and ZERO policies, plus `sso_configurations`,
// `sso_sessions` and `sso_login_attempts` with no `org_id` and RLS unforced,
// because `core/106`, `core/107` and `core/138` — the migrations that add
// exactly those columns and policies — already ran and no-op'd on a stack whose
// community schema had none of those tables yet. The runner skips by
// (version, name), so they never run again, and `enterprise/108` / `enterprise/120`
// then create the tables in their pre-v9 shape with nothing to repair them.
// That is #2782 re-created inside a fix for #3167.
//
// Closing it needs a bundled re-repair migration and is an operator decision on
// whether an unconfigured deployment should ever be handed the enterprise schema
// automatically. Both the measurement and the four options are in
// technical-docs/DEPLOYMENT_MODE_MIGRATION_SELECTOR_DECISION.md; #3128 stays
// open for it. What #3167 removes is the *other* half of the same variable: an
// unrecognised value no longer selects the widest set, so the population that
// can reach this asymmetry is now exactly "unset", not "unset or mistyped".
//
// The community-saas note that used to live on its own case arm: the
// community-SaaS hosted deployment (try.getaxonflow.com) has internal-only
// infrastructure (tenant registrations, the A1.5 adoption bridge) that does NOT
// belong in core/, because self-hosted community and enterprise customers do
// not need those tables. Migrations 085 + 086 live in community-saas/ from
// inception. Migrations 068 / 073 / 075 / 076 (and a few other tenant-related
// ones) remain in core/ because they shipped in releases <= v7.8.0 and customer
// environments have applied them; relocating them needs a drift-detection
// runbook planned as a separate refactor.
func getMigrationPaths(basePath string) ([]string, error) {
	raw := os.Getenv("DEPLOYMENT_MODE")

	mode, err := resolveDeploymentMode(raw)
	if err != nil {
		return nil, err
	}

	switch {
	case raw == "":
		log.Printf("⚠️  DEPLOYMENT_MODE is not set. Applying the %q migration set — but since #3096 an unset "+
			"value is NOT Community at RUNTIME: this agent runs the enterprise posture on the community "+
			"schema. That mismatch is #3128 and it is not fixed by this warning. "+
			"Set DEPLOYMENT_MODE explicitly (accepted: %s).",
			mode, strings.Join(recognisedDeploymentModes(), ", "))
	case raw != mode:
		log.Printf("📦 Note: DEPLOYMENT_MODE=%s is an alias, treating as %s", raw, mode)
	}

	categories := canonicalDeploymentModes[mode]
	paths := make([]string, 0, len(categories))
	for _, category := range categories {
		paths = append(paths, filepath.Join(basePath, filepath.FromSlash(category)))
	}

	log.Printf("📦 DEPLOYMENT_MODE=%s: running migration categories %s",
		mode, strings.Join(categories, " + "))

	return paths, nil
}

// collectMigrations collects all migration files from configured paths
func collectMigrations(basePath string) ([]MigrationFile, error) {
	paths, err := getMigrationPaths(basePath)
	if err != nil {
		return nil, err
	}
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

	// Sort migrations by version number, then by name for deterministic
	// ordering when two files share a version (the same-version-different-name
	// case the composite key tolerates — see migration 096 + the
	// TestCoreMigrationDir_HasNoVersionDuplicates guard). Without the Name
	// tiebreak, Go's sort.Slice is unstable for ties and a same-version pair
	// could apply in either order across runs.
	sort.Slice(migrations, func(i, j int) bool {
		if migrations[i].Version != migrations[j].Version {
			return migrations[i].Version < migrations[j].Version
		}
		return migrations[i].Name < migrations[j].Name
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

// ensureCompositeUniqueConstraint idempotently retro-fits the
// (version, name) composite UNIQUE constraint on an existing
// schema_migrations table that may have been created under the v1
// shape with UNIQUE(version) only.
//
// Must run BEFORE the migration loop because recordMigrationSuccess
// uses ON CONFLICT (version, name); without the matching constraint,
// every per-migration INSERT raises "there is no unique or exclusion
// constraint matching the ON CONFLICT specification" and the runner
// fatals.
//
// Idempotent: every step guards on pg_constraint state. Safe to call
// repeatedly across reboots.
func ensureCompositeUniqueConstraint(db *sql.DB) error {
	// Add composite UNIQUE(version, name) if absent. The IF NOT EXISTS
	// guard is server-side, but Postgres does NOT serialize the SELECT
	// against a concurrent ALTER's AccessExclusiveLock on the table —
	// two agents booting against the same RDS can both pass the guard,
	// queue the ALTER, and the second raises 42710 (duplicate_object).
	// Swallow 42710 with an EXCEPTION block so concurrent boots are
	// idempotent end-to-end. SQLSTATE 42710 is the only error we
	// expect on the race path; anything else propagates as a real
	// failure.
	_, err := db.Exec(`
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1
				FROM pg_constraint con
				JOIN pg_class rel ON rel.oid = con.conrelid
				WHERE rel.relname = 'schema_migrations'
				  AND con.contype = 'u'
				  AND array_length(con.conkey, 1) = 2
			) THEN
				BEGIN
					ALTER TABLE schema_migrations
						ADD CONSTRAINT schema_migrations_version_name_uniq
						UNIQUE (version, name);
				EXCEPTION WHEN duplicate_object THEN
					-- Concurrent peer agent landed the same ADD CONSTRAINT
					-- between our IF check and our ALTER. Treat as success.
					NULL;
				END;
			END IF;
		END $$;
	`)
	if err != nil {
		return err
	}

	// Drop the legacy version-only UNIQUE if present. It conflicts with
	// the composite (a row needs to fit both), so leaving it would
	// re-introduce the silent-dedup bug for any pair of files sharing a
	// version prefix. Same concurrent-boot caveat as above — wrap the
	// DROP in an EXCEPTION block for undefined_object (42704) in case
	// a peer agent already dropped it.
	_, err = db.Exec(`
		DO $$
		DECLARE
			legacy_name TEXT;
		BEGIN
			SELECT con.conname INTO legacy_name
			FROM pg_constraint con
			JOIN pg_class rel ON rel.oid = con.conrelid
			WHERE rel.relname = 'schema_migrations'
			  AND con.contype = 'u'
			  AND array_length(con.conkey, 1) = 1
			  AND (
				SELECT attname FROM pg_attribute
				WHERE attrelid = con.conrelid AND attnum = con.conkey[1]
			  ) = 'version'
			LIMIT 1;

			IF legacy_name IS NOT NULL THEN
				BEGIN
					EXECUTE format('ALTER TABLE schema_migrations DROP CONSTRAINT %I', legacy_name);
				EXCEPTION WHEN undefined_object THEN
					NULL;
				END;
			END IF;
		END $$;
	`)
	return err
}

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
			// New schema lands with the v9 composite UNIQUE(version, name)
			// from the start — the version-only UNIQUE was the migration
			// runner dedup bug we are fixing here, and the recordMigration*
			// helpers rely on the composite ON CONFLICT existing before any
			// numbered migration runs. See migration 096 for the matching
			// idempotent upgrade SQL for callers that already booted past
			// this code path on an earlier version.
			upgradeSQL := `
				-- Rename old table
				ALTER TABLE schema_migrations RENAME TO schema_migrations_old;

				-- Create new table with full schema (composite dedup key)
				CREATE TABLE schema_migrations (
					id SERIAL PRIMARY KEY,
					version VARCHAR(20) NOT NULL,
					name VARCHAR(255) NOT NULL,
					applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
					execution_time_ms INTEGER,
					success BOOLEAN NOT NULL DEFAULT true,
					error_message TEXT,
					checksum VARCHAR(64),
					applied_by VARCHAR(100) DEFAULT 'agent',
					hostname VARCHAR(255),
					git_commit VARCHAR(40),
					created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
					CONSTRAINT schema_migrations_version_name_uniq UNIQUE (version, name)
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
			`

			_, err = db.Exec(upgradeSQL)
			if err != nil {
				log.Printf("⚠️  Failed to upgrade schema_migrations table: %v", err)
				// Don't fail here - fall back to running all migrations
				return
			}

			log.Println("✅ Schema migrations table upgraded successfully (composite dedup key)")
			return
		}
	}

	// Table doesn't exist or already has new schema, create with new schema.
	// The composite UNIQUE(version, name) must exist before any numbered
	// migration runs because recordMigrationSuccess uses ON CONFLICT on it.
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id SERIAL PRIMARY KEY,
			version VARCHAR(20) NOT NULL,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			execution_time_ms INTEGER,
			success BOOLEAN NOT NULL DEFAULT true,
			error_message TEXT,
			checksum VARCHAR(64),
			applied_by VARCHAR(100) DEFAULT 'agent',
			hostname VARCHAR(255),
			git_commit VARCHAR(40),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			CONSTRAINT schema_migrations_version_name_uniq UNIQUE (version, name)
		);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Printf("⚠️  Failed to create schema_migrations table: %v", err)
		// Don't fail here - fall back to running all migrations
		return
	}

	// For existing installs that already created the table under the v1
	// shape (version-only UNIQUE), retro-fit the composite constraint
	// idempotently so the in-flight migration loop can use ON CONFLICT
	// (version, name). Migration 096 also does this — having it here
	// prevents the chicken-and-egg failure for migrations 001-095.
	if err := ensureCompositeUniqueConstraint(db); err != nil {
		log.Printf("⚠️  Failed to ensure composite UNIQUE(version, name): %v (continuing anyway)", err)
	}

	log.Println("✅ Schema migrations tracking table ready")
}

// migrationKey returns the composite dedup key for a migration. Files that
// share a numeric prefix (e.g. 025_decision_chain.sql + 025_hitl_oversight_queue.sql)
// must be tracked independently. See migrations/core/096_schema_migrations_dedup_composite.sql
// for the bug context and the matching Postgres composite UNIQUE constraint.
func migrationKey(version, name string) string {
	return version + "/" + name
}

// getAppliedMigrations returns a map of (version, name) pairs that have
// been successfully applied. Pre-migration-096 schema rows have a single
// (version, name) tuple per version because the UNIQUE constraint allowed
// only one entry per version — those tuples still satisfy the composite
// key on read, so the upgrade is transparent for existing installs.
func getAppliedMigrations(db *sql.DB) map[string]bool {
	applied := make(map[string]bool)

	rows, err := db.Query(`
		SELECT version, name
		FROM schema_migrations
		WHERE success = true
		ORDER BY version, name
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
		var version, name string
		if err := rows.Scan(&version, &name); err != nil {
			log.Printf("⚠️  Failed to scan migration row: %v", err)
			continue
		}
		applied[migrationKey(version, name)] = true
	}

	if len(applied) > 0 {
		log.Printf("📋 Found %d previously applied migrations", len(applied))
	}

	return applied
}

// extractMigrationVersion extracts the version number from a migration filename
// Examples:
//
//	"006_customer_portal.sql" -> "006"
//	"020_schema_migrations.sql" -> "020"
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
//
//	"006_customer_portal.sql" -> "customer_portal"
//	"020_schema_migrations.sql" -> "schema_migrations"
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

// recordMigrationSuccess records a successful migration in schema_migrations
// table. ON CONFLICT keys off (version, name) — see migration 096 for the
// composite-key rationale. Same-version, different-name migrations get
// independent rows; reruns of the SAME migration overwrite the prior row.
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
		ON CONFLICT (version, name) DO UPDATE SET
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

// recordMigrationFailure records a failed migration in schema_migrations
// table. See recordMigrationSuccess for the (version, name) ON CONFLICT
// rationale.
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
		ON CONFLICT (version, name) DO UPDATE SET
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
