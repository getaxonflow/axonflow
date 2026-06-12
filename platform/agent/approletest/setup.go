// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package approletest provides shared test fixtures for verifying that
// service main pools route through OpenAppRoleConnection and connect as the
// expected Postgres role under the v9 RLS gate.
//
// The package is intentionally importable (no build tag): the same helper
// scaffolding is used by integration tests in platform/agent,
// platform/orchestrator, and ee/platform/customer-portal. Each test exercises
// its service's boot-time call site against a throwaway postgres:15
// container with migrations 001..111 applied and axonflow_app_role +
// axonflow_platform_admin login passwords provisioned (mirrors
// scripts/operators/provision-app-role.sh).
//
// Tests gate on TEST_PG_INTEGRATION=1 + docker availability.
package approletest

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Env captures the per-test DSN trio + cleanup hook.
type Env struct {
	// MasterDSN authenticates as the postgres superuser (table owner under
	// migration 098 — BYPASSRLS).
	MasterDSN string
	// AppRoleDSN authenticates as axonflow_app_role (NOBYPASSRLS).
	AppRoleDSN string
	// AdminDSN authenticates as axonflow_platform_admin (BYPASSRLS — used by
	// cross-org workers + customer-portal admin handlers).
	AdminDSN string
	// Cleanup removes the docker container.
	Cleanup func()
}

// SkipUnlessEnabled skips the test unless TEST_PG_INTEGRATION=1.
func SkipUnlessEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping real-Postgres integration test")
	}
}

// Setup spins up a postgres:15 container, runs migrations 001..111, and
// provisions login passwords on the two RLS roles created by migration 098.
// Returns DSNs for the master, axonflow_app_role, and axonflow_platform_admin
// users, plus a cleanup callback. The caller is responsible for calling
// Cleanup() (typically via t.Cleanup).
func Setup(t *testing.T, migrationsDir string) *Env {
	t.Helper()
	masterDSN, cleanup := startPostgresContainer(t)
	t.Cleanup(cleanup)

	masterDB, err := sql.Open("postgres", masterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = masterDB.Close() }()

	// Pin to a single connection so SET (without LOCAL) persists across
	// queries inside this test session — matches the migration-runner
	// pattern in reference_postgres_testcontainer_pattern_for_migration_tests.
	masterDB.SetMaxOpenConns(1)

	// Mirror platform/agent/run.go::setMigrationSessionVars: production sets
	// three session GUCs before the migration loop runs.
	//   app.db_password         — migration 017/028 dblink_exec reads.
	//   app.deployment_org_id   — migration 094 Pass-2 backfill precondition.
	//   app.deployment_kind     — migration 094 #2320 prod-safety branch.
	//   app.current_org_id      — RLS app-role txns SET LOCAL this; harmless to seed.
	for _, kv := range []struct{ key, val string }{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := masterDB.Exec("SELECT set_config($1, $2, false)", kv.key, kv.val); err != nil {
			t.Fatalf("set_config %s: %v", kv.key, err)
		}
	}

	// Range tracks latest stable core migration. Bumped to 111 with
	// PR-C3's column rename so callers see the canonical org_id schema
	// (mig 109 = SECURITY DEFINER helpers, mig 110 = policy_overrides
	// org_id, mig 111 = custom_roles/role_assignments org_id).
	runMigrations(t, masterDB, migrationsDir, 1, 111)

	const (
		appRolePass = "appRoleTestPw_session20"
		adminPass   = "adminTestPw_session20"
	)
	if _, err := masterDB.Exec(`ALTER ROLE axonflow_app_role WITH LOGIN PASSWORD '` + appRolePass + `'`); err != nil {
		t.Fatalf("alter axonflow_app_role: %v", err)
	}
	if _, err := masterDB.Exec(`ALTER ROLE axonflow_platform_admin WITH LOGIN PASSWORD '` + adminPass + `'`); err != nil {
		t.Fatalf("alter axonflow_platform_admin: %v", err)
	}

	hostPort := extractHostPort(masterDSN)
	appRoleDSN := fmt.Sprintf("postgres://axonflow_app_role:%s@localhost:%s/axonflow_test?sslmode=disable", appRolePass, hostPort)
	adminDSN := fmt.Sprintf("postgres://axonflow_platform_admin:%s@localhost:%s/axonflow_test?sslmode=disable", adminPass, hostPort)

	// Smoke-verify each role can authenticate end-to-end before handing back.
	if err := pingAs(appRoleDSN, "axonflow_app_role"); err != nil {
		t.Fatalf("smoke-verify app_role login: %v", err)
	}
	if err := pingAs(adminDSN, "axonflow_platform_admin"); err != nil {
		t.Fatalf("smoke-verify platform_admin login: %v", err)
	}
	return &Env{
		MasterDSN:  masterDSN,
		AppRoleDSN: appRoleDSN,
		AdminDSN:   adminDSN,
		Cleanup:    cleanup,
	}
}

// AssertCurrentUser opens a fresh connection to dsn and asserts SELECT
// current_user matches want.
func AssertCurrentUser(t *testing.T, db *sql.DB, want string) {
	t.Helper()
	var got string
	if err := db.QueryRow("SELECT current_user").Scan(&got); err != nil {
		t.Fatalf("SELECT current_user: %v", err)
	}
	if got != want {
		t.Errorf("current_user mismatch: got %q, want %q", got, want)
	}
}

// pingAs opens dsn, runs SELECT current_user, and verifies it matches want.
// Closes the connection before returning either way.
func pingAs(dsn, want string) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = db.Close() }()
	var got string
	if err := db.QueryRow("SELECT current_user").Scan(&got); err != nil {
		return fmt.Errorf("select current_user: %w", err)
	}
	if got != want {
		return fmt.Errorf("current_user=%q, want %q", got, want)
	}
	return nil
}

// startPostgresContainer launches a throwaway docker postgres:15 instance and
// returns the master connection URL + a cleanup function. Identical shape to
// platform/agent/v9_followup_a_gaps_test.go::startPostgresContainer; lives in
// approletest so cross-package integration tests can reuse it.
func startPostgresContainer(t *testing.T) (string, func()) {
	t.Helper()
	containerName := fmt.Sprintf("axonflow-test-approle-pg-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-e", "POSTGRES_PASSWORD=testpass",
		"-e", "POSTGRES_DB=axonflow_test",
		"-p", "0:5432",
		"postgres:15",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	cleanup := func() {
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}
	// `docker port` can transiently fail (exit status 1) or return an empty
	// mapping for a brief window right after `docker run -d`: the container
	// exists but the daemon hasn't finished publishing the port yet. The race
	// widens sharply under concurrent container starts — `go test ./...` runs
	// many container-spinning packages in parallel, and a single-shot query
	// then intermittently reddens CI (observed: "docker port: exit status 1").
	// Poll until the mapping resolves instead of fataling on the first miss.
	var hostPort string
	portDeadline := time.Now().Add(30 * time.Second)
	for {
		portBytes, portErr := exec.Command("docker", "port", containerName, "5432/tcp").CombinedOutput()
		if portErr == nil {
			portLine := strings.TrimSpace(strings.Split(string(portBytes), "\n")[0])
			if parts := strings.Split(portLine, ":"); len(parts) >= 2 {
				if hp := parts[len(parts)-1]; hp != "" {
					hostPort = hp
					break
				}
			}
		}
		if time.Now().After(portDeadline) {
			cleanup()
			t.Fatalf("docker port did not resolve a host port for %s within 30s (last err: %v)", containerName, portErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
	url := fmt.Sprintf("postgres://postgres:testpass@localhost:%s/axonflow_test?sslmode=disable", hostPort)

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := sql.Open("postgres", url)
		if err == nil {
			if pingErr := conn.Ping(); pingErr == nil {
				_ = conn.Close()
				return url, cleanup
			}
			_ = conn.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	cleanup()
	t.Fatalf("postgres container did not become ready within 30s")
	return "", nil
}

// extractHostPort strips the host port out of a localhost DSN.
func extractHostPort(dsn string) string {
	// Expected format: postgres://user:pw@localhost:<port>/...
	atHost := strings.SplitN(dsn, "@localhost:", 2)
	if len(atHost) != 2 {
		return ""
	}
	portAndPath := strings.SplitN(atHost[1], "/", 2)
	return portAndPath[0]
}

// runMigrations applies migrations files in [lo, hi] from migrationsDir, in
// (version, name) composite key order — matches the production runner's
// dedup contract (see reference_migration_runner_composite_key).
func runMigrations(t *testing.T, db *sql.DB, migrationsDir string, lo, hi int) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migration dir %s: %v", migrationsDir, err)
	}
	type mig struct {
		version int
		name    string
		path    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") || strings.HasSuffix(e.Name(), "_down.sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) < 2 || len(parts[0]) != 3 {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
			continue
		}
		if v < lo || v > hi {
			continue
		}
		migs = append(migs, mig{version: v, name: e.Name(), path: migrationsDir + "/" + e.Name()})
	}
	for i := 0; i < len(migs); i++ {
		for j := i + 1; j < len(migs); j++ {
			if migs[i].version > migs[j].version ||
				(migs[i].version == migs[j].version && migs[i].name > migs[j].name) {
				migs[i], migs[j] = migs[j], migs[i]
			}
		}
	}
	for _, m := range migs {
		sqlBytes, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatalf("read migration %s: %v", m.path, err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}
}
