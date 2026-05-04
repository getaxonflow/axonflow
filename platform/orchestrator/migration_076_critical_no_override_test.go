// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// readMigrationFile reads the actual migration SQL from disk so the test
// follows the production migration file rather than a hand-copied snapshot.
// Path is repo-root-relative; run via `go test ./platform/orchestrator/...`
// from the repo root (CI runs from there).
func readMigrationFile(t *testing.T, name string) string {
	t.Helper()
	// orchestrator package lives at platform/orchestrator; migrations live at
	// migrations/core. Walk up two levels.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Join(cwd, "..", "..")
	path := filepath.Join(repoRoot, "migrations", "core", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestMigration076_FlipsCriticalSeverityToNoOverride verifies migration 076
// promotes severity='critical' system policies to risk_level='critical' with
// allow_override=FALSE, so the createOverrideHandler 403 enforcement at
// overrides_handler.go:343 is reachable for high-stakes patterns. Pre-076,
// every system policy had allow_override=TRUE because migration 070's
// category-based mapping never matched the seeded categories.
//
// Models the post-070, pre-076 state in a minimal schema, applies the 076
// SQL, then asserts each invariant. Schema is intentionally trimmed to the
// columns 076 reads/writes — the orchestrator's full schema is exercised by
// db_policy_engine_integration_test.go.
func TestMigration076_FlipsCriticalSeverityToNoOverride(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		testutil.SkipIfNoDocker(t)
	}

	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())

	pg.RunMigration(t, `
		CREATE TABLE static_policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id VARCHAR(64) UNIQUE NOT NULL,
			category VARCHAR(64) NOT NULL,
			tier VARCHAR(32) NOT NULL DEFAULT 'tenant',
			severity VARCHAR(16) NOT NULL DEFAULT 'medium',
			risk_level TEXT NOT NULL DEFAULT 'medium'
				CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
			allow_override BOOLEAN NOT NULL DEFAULT TRUE
		);

		CREATE TABLE policy_overrides (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			policy_id UUID NOT NULL,
			policy_type VARCHAR(16) NOT NULL,
			revoked_at TIMESTAMPTZ,
			revoked_by VARCHAR(255),
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			updated_by VARCHAR(255)
		);

		CREATE OR REPLACE FUNCTION enforce_critical_no_override()
		RETURNS TRIGGER AS $$
		BEGIN
			IF NEW.risk_level = 'critical' AND NEW.allow_override = TRUE THEN
				NEW.allow_override := FALSE;
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;

		CREATE TRIGGER trg_static_policies_critical_no_override
			BEFORE INSERT OR UPDATE ON static_policies
			FOR EACH ROW
			EXECUTE FUNCTION enforce_critical_no_override();
	`)

	// Seed rows mirroring post-070 state for system policies. Note the
	// critical-severity rows start at risk_level='high' or 'medium' with
	// allow_override=TRUE — exactly the pre-076 production state.
	pg.RunMigration(t, `
		INSERT INTO static_policies (policy_id, category, tier, severity, risk_level, allow_override) VALUES
		  ('sys_sqli_admin_bypass', 'security-sqli', 'system', 'critical', 'high',  TRUE),
		  ('sys_sqli_or_true',      'security-sqli', 'system', 'high',     'high',  TRUE),
		  ('sys_pii_us_ssn',        'pii-us',        'system', 'critical', 'medium', TRUE),
		  ('sys_pii_basic',         'pii-global',    'system', 'medium',   'medium', TRUE),
		  ('sys_test_tenant_only',  'security-sqli', 'tenant', 'critical', 'high',  TRUE);
	`)

	// Pre-existing active override on a row that's about to become
	// non-overridable. We need its id to assert revocation post-migration.
	var sqliPolicyUUID string
	if err := pg.DB.QueryRow(
		`SELECT id FROM static_policies WHERE policy_id = 'sys_sqli_admin_bypass'`,
	).Scan(&sqliPolicyUUID); err != nil {
		t.Fatalf("failed to fetch sys_sqli_admin_bypass id: %v", err)
	}

	pg.RunMigration(t, `
		INSERT INTO policy_overrides (policy_id, policy_type, updated_by) VALUES
		  ('`+sqliPolicyUUID+`', 'static', 'pre-076-test');
	`)

	// Apply migration 076 directly from the migration file — if someone
	// edits the SQL, this test follows automatically rather than passing
	// against a stale hand-copy.
	pg.RunMigration(t, readMigrationFile(t, "076_critical_system_policies_no_override.sql"))

	// Invariant 1: every severity='critical' system policy is now
	// risk_level='critical' AND allow_override=FALSE.
	var leakedCritical int
	if err := pg.DB.QueryRow(`
		SELECT COUNT(*) FROM static_policies
		WHERE tier = 'system' AND severity = 'critical'
		  AND (risk_level <> 'critical' OR allow_override = TRUE)
	`).Scan(&leakedCritical); err != nil {
		t.Fatalf("invariant 1 query failed: %v", err)
	}
	if leakedCritical != 0 {
		t.Errorf("invariant 1 violated: %d severity=critical system policies still allow override or are not risk_level=critical", leakedCritical)
	}

	// Invariant 2: non-critical-severity system policies and tenant policies
	// are untouched.
	var sqliOrTrue, piiBasic struct {
		risk     string
		allowOvr bool
	}
	if err := pg.DB.QueryRow(`
		SELECT risk_level, allow_override FROM static_policies WHERE policy_id = 'sys_sqli_or_true'
	`).Scan(&sqliOrTrue.risk, &sqliOrTrue.allowOvr); err != nil {
		t.Fatalf("sys_sqli_or_true scan failed: %v", err)
	}
	if sqliOrTrue.risk != "high" || !sqliOrTrue.allowOvr {
		t.Errorf("sys_sqli_or_true (severity=high) was modified: risk_level=%q allow_override=%v (want high/true)",
			sqliOrTrue.risk, sqliOrTrue.allowOvr)
	}

	if err := pg.DB.QueryRow(`
		SELECT risk_level, allow_override FROM static_policies WHERE policy_id = 'sys_pii_basic'
	`).Scan(&piiBasic.risk, &piiBasic.allowOvr); err != nil {
		t.Fatalf("sys_pii_basic scan failed: %v", err)
	}
	if piiBasic.risk != "medium" || !piiBasic.allowOvr {
		t.Errorf("sys_pii_basic (severity=medium) was modified: risk_level=%q allow_override=%v (want medium/true)",
			piiBasic.risk, piiBasic.allowOvr)
	}

	// Invariant 3: tenant-tier critical-severity rows untouched.
	var tenantRisk string
	var tenantAllowOvr bool
	if err := pg.DB.QueryRow(`
		SELECT risk_level, allow_override FROM static_policies WHERE policy_id = 'sys_test_tenant_only'
	`).Scan(&tenantRisk, &tenantAllowOvr); err != nil {
		t.Fatalf("tenant policy scan failed: %v", err)
	}
	if tenantRisk != "high" || !tenantAllowOvr {
		t.Errorf("tenant-tier critical policy was modified: risk_level=%q allow_override=%v (want high/true)",
			tenantRisk, tenantAllowOvr)
	}

	// Invariant 4: pre-existing active override on the now-non-overridable
	// policy was revoked with reason 'system:migration-076'. ADR-044:
	// "when a policy's allow_override flips to false, all active overrides
	// for that policy are revoked".
	var revokedAt *string
	var revokedBy *string
	if err := pg.DB.QueryRow(`
		SELECT revoked_at::text, revoked_by FROM policy_overrides
		WHERE policy_id::text = $1 AND policy_type = 'static'
	`, sqliPolicyUUID).Scan(&revokedAt, &revokedBy); err != nil {
		t.Fatalf("override revocation scan failed: %v", err)
	}
	if revokedAt == nil {
		t.Error("expected pre-existing override on sys_sqli_admin_bypass to be revoked")
	}
	if revokedBy == nil || *revokedBy != "system:migration-076" {
		got := "<nil>"
		if revokedBy != nil {
			got = *revokedBy
		}
		t.Errorf("revoked_by = %q, want system:migration-076", got)
	}
}
