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
// container with EVERY core migration applied and axonflow_app_role +
// axonflow_platform_admin login passwords provisioned (mirrors
// scripts/operators/provision-app-role.sh).
//
// Tests gate on TEST_PG_INTEGRATION=1 + docker availability.
package approletest

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/testutil/pgstart"
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

// TestContainerLabel marks every container this package starts.
//
// It exists so orphans can be reaped by EXACT LABEL MATCH. The obvious
// alternative - a name glob like `--filter name=axonflow-test-` - is unsafe on
// a shared daemon, where a substring can collide with a peer's stack; that has
// already happened once in this repo (`wshitl` vs `wshitlchoke`). A label the
// reaper sets itself cannot collide with anything it did not create.
const TestContainerLabel = "axonflow.test.ephemeral=1"

// TestRunLabelKey is the label that names the run a container belongs to
// (#4184). TestContainerLabel says a container is a test's and may be reaped;
// it is a fixed contract (CI's reapers, deploy-platform.yml and several
// harnesses filter on it), so it cannot also carry a run id. This one can.
//
// A run that exports TestRunIDEnv gets `axonflow.test.run=<id>` on every
// container started here, beside TestContainerLabel, and its runner's exit
// trap reaps exactly those (scripts/ci/reap-test-run-containers.sh). A
// fleet-wide reap by TestContainerLabel alone would remove a peer's live
// containers on a shared daemon; a reap by run id cannot.
const TestRunLabelKey = "axonflow.test.run"

// TestRunIDEnv is the environment variable a runner exports to name its run.
// Unset, containers carry TestContainerLabel only, exactly as before #4184.
const TestRunIDEnv = "AXONFLOW_TEST_RUN_ID"

// testRunID is a run id safe to pass as a label value: letters, digits, '.',
// '_' and '-', at most 64 characters.
var testRunID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// runLabelArgs returns the docker run arguments that label a container with
// the run TestRunIDEnv names, or none when it is unset. A value that is set but
// malformed is an error, and the caller fails the test rather than start a
// container no run-scoped reap could find.
func runLabelArgs() ([]string, error) {
	id := os.Getenv(TestRunIDEnv)
	if id == "" {
		return nil, nil
	}
	if !testRunID.MatchString(id) {
		return nil, fmt.Errorf("%s=%q is not a run id: want 1-64 of [A-Za-z0-9._-]", TestRunIDEnv, id)
	}
	return []string{"--label", TestRunLabelKey + "=" + id}, nil
}

// TestOwnerLabelKey is the label that names the process that started a
// container, as "<hostname>:<pid>" (#4184). A test's own cleanup removes its
// container, but not when the test binary is killed (a -timeout, a Ctrl-C, a
// killed board), and nothing that killed it knows which containers it left.
// The owner label lets a reaper find exactly those: a container whose owner is
// on this host and whose pid is no longer running
// (scripts/ci/reap-test-run-containers.sh --dead-owners). That is safe on a
// shared daemon in the direction that matters: a recycled pid makes a dead
// owner look alive, so its container SURVIVES; no live process is ever read
// as dead.
//
// The owner label is sound ONLY because the process that labels a container
// is also the process that removes it, so the label lives exactly as long as
// the container should. DockerRunArgs takes a *testing.T, so it cannot be
// called outside a test: the container belongs to one test and dies with it.
// A helper that starts a container for a LATER process to use must not carry
// this label, or the reaper removes it the moment its starter exits.
const TestOwnerLabelKey = "axonflow.test.owner"

// ownerLabelValue is this process's owner label value, "<hostname>:<pid>".
func ownerLabelValue() (string, error) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "", fmt.Errorf("the host name for the %s label could not be read: %v", TestOwnerLabelKey, err)
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid()), nil
}

// DockerRunArgs is `docker run -d` with the labels every throwaway test
// container carries: TestContainerLabel, the owner (TestOwnerLabelKey) and,
// when TestRunIDEnv is set, the run (TestRunLabelKey); rest follows. Every test
// that starts a container with the docker CLI builds its arguments here, so the
// labels a reaper filters on are set in one place.
func DockerRunArgs(t *testing.T, rest ...string) []string {
	t.Helper()
	owner, err := ownerLabelValue()
	if err != nil {
		t.Fatal(err)
	}
	runLabel, err := runLabelArgs()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-d", "--label", TestContainerLabel, "--label", TestOwnerLabelKey + "=" + owner}
	args = append(args, runLabel...)
	return append(args, rest...)
}

// Setup spins up a postgres:15 container, runs every core migration, and
// provisions login passwords on the two RLS roles created by migration 098.
// Returns DSNs for the master, axonflow_app_role, and axonflow_platform_admin
// users, plus a cleanup callback. The caller is responsible for calling
// Cleanup() (typically via t.Cleanup).
func Setup(t *testing.T, migrationsDir string) *Env {
	t.Helper()
	return SetupAtVersion(t, migrationsDir, allCoreMigrations)
}

// SetupAtVersion is Setup with an explicit upper migration bound, for the rare
// test whose PREMISE is a historical schema -- one that reproduces a data shape
// a later migration repairs, and applies that migration itself partway through
// to observe the repair.
//
// Prefer Setup. A bound here freezes the fixture at a schema that stops
// resembling production the moment the next migration lands, so it must be a
// deliberate, commented choice tied to a specific migration -- never a
// hand-maintained "latest" marker, which is what it silently decayed into
// before #3490.
func SetupAtVersion(t *testing.T, migrationsDir string, maxVersion int) *Env {
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

	// Apply EVERY core migration present, with no upper bound.
	//
	// This used to be a hand-maintained literal ("range tracks latest stable
	// core migration", last bumped to 111). The bound's stated purpose was
	// always "the newest schema", so a literal could only ever be wrong: it
	// silently decays into "the schema as of whenever someone last edited this
	// line". It reached 55 migrations of drift, and the drift was not
	// cosmetic -- it changed a column TYPE. core/133 retypes
	// organization_id from uuid to text, so a fixture whose org key is an
	// ordinary string (the shape every caller actually uses) inserted fine on
	// a real deployment and failed here with
	//   pq: invalid input syntax for type uuid
	// against a schema that has not existed since core/133. A test harness
	// pinned to an obsolete schema does not test the product; worse, it can
	// fail on changes that are correct, which is how it surfaced (#3490).
	//
	// Unbounded is also self-maintaining: a new migration is exercised by
	// these tests the moment it lands, rather than when someone remembers to
	// edit this number.
	runMigrations(t, masterDB, migrationsDir, 1, maxVersion)

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
	window, err := pgstart.Window(t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	// THE DATA DIRECTORY IS A tmpfs, WHICH IS WHAT MAKES THE LEAK IMPOSSIBLE
	// RATHER THAN MERELY TIDIED UP.
	//
	// postgres:15 declares /var/lib/postgresql/data as a VOLUME, so absent any
	// mount at that path Docker creates an ANONYMOUS volume per container.
	// `docker rm -fv` in the cleanup below removes it - but ONLY if the
	// cleanup runs. It does not run on `go test -timeout` kill, on Ctrl-C, or
	// on a panic that takes the process down, and measured on a real daemon
	// that is not a rare path: 680 orphaned volumes holding 52.84 GB
	// accumulated in two days.
	//
	// Supplying ANY mount at the declared path stops the anonymous volume
	// being created at all, so there is nothing to leak however the process
	// dies. Measured: with the tmpfs, killing the container and never removing
	// it leaves the volume count unchanged.
	//
	// tmpfs specifically, not a bind or a named volume: the data is worthless
	// the moment the test ends, RAM makes the migration chain materially
	// faster, and it cannot outlive the container even in principle. 1g against
	// a measured 69 MB for a fresh initdb plus this repo's whole core
	// migration chain - roughly 15x headroom, and the container fails loudly on ENOSPC
	// rather than corrupting silently.
	//
	// The label is the second half: a container CAN still be orphaned by a
	// killed process, and a label makes those reapable by exact match instead
	// of by a name glob that would catch a peer's stack on a shared daemon.
	// Every attempt's container carries the same labels (DockerRunArgs, #4430),
	// so a retry's container is as reapable as the first.
	runArgs := func(name string) []string {
		return DockerRunArgs(t,
			"--name", name,
			"--tmpfs", "/var/lib/postgresql/data:rw,size=1g",
			"-e", "POSTGRES_PASSWORD=testpass",
			"-e", "POSTGRES_DB=axonflow_test",
			"-p", "0:5432",
			"postgres:15",
		)
	}
	start := func() (pgstart.Attempt, error) {
		name := fmt.Sprintf("axonflow-test-approle-pg-%d", time.Now().UnixNano())
		if out, err := exec.Command("docker", runArgs(name)...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("docker run: %v\n%s", err, string(out))
		}
		return dockerAttempt{name: name}, nil
	}
	// The wait-and-retry rule is pgstart's: one window (AXONFLOW_TEST_PG_START_WAIT,
	// default 90s, floor 30s) for the port and the first answer, the
	// container's state read on every failed poll, and ONE retry with a fresh
	// container when this one stopped or never published its port. A server
	// that answers with an error fails at once (#4249 rows 5771426373,
	// 5796048780).
	url, attempt, err := pgstart.Waiter{Window: window, Logf: t.Logf}.Start(start, pingPostgres)
	if err != nil {
		t.Fatal(err)
	}
	return url, attempt.Remove
}

// pingPostgres is one readiness probe: open and ping dsn.
func pingPostgres(dsn string) error {
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conn.Ping()
}

// dockerAttempt is one container started with the docker CLI.
type dockerAttempt struct{ name string }

func (d dockerAttempt) Name() string { return d.name }

// Endpoint resolves the host port the daemon published for 5432. `docker port`
// fails (exit status 1) or answers an empty mapping until the daemon has
// published it, which takes longest when many containers start at once.
func (d dockerAttempt) Endpoint() (string, error) {
	out, err := exec.Command("docker", "port", d.name, "5432/tcp").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker port: %v: %s", err, strings.TrimSpace(string(out)))
	}
	line := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	parts := strings.Split(line, ":")
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return "", fmt.Errorf("docker port answered no host port: %q", line)
	}
	return fmt.Sprintf("postgres://postgres:testpass@localhost:%s/axonflow_test?sslmode=disable", parts[len(parts)-1]), nil
}

func (d dockerAttempt) State() (pgstart.State, error) {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}} {{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}", d.name).CombinedOutput()
	if err != nil {
		return pgstart.State{}, fmt.Errorf("docker inspect: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var st pgstart.State
	var running, oom string
	if _, err := fmt.Sscan(strings.TrimSpace(string(out)), &running, &st.Status, &st.ExitCode, &oom); err != nil {
		return pgstart.State{}, fmt.Errorf("docker inspect answered %q: %v", strings.TrimSpace(string(out)), err)
	}
	st.Running, st.OOMKilled = running == "true", oom == "true"
	return st, nil
}

func (d dockerAttempt) Logs(n int) string {
	out, _ := exec.Command("docker", "logs", "--tail", strconv.Itoa(n), d.name).CombinedOutput()
	return string(out)
}

// Remove removes the container with -v, not just -f. postgres:15 declares
// /var/lib/postgresql/data as a VOLUME, so every container started here gets an
// ANONYMOUS volume, and `docker rm -f` removes the container while orphaning
// it. Each one holds a full initdb plus the whole migration chain, and a single
// run of the real-PG lanes starts hundreds of them: measured on a developer
// daemon after one full pass of the three arms, 339 dangling volumes holding
// 26.59 GB, none of them reachable by name. CI never noticed because its
// between-arms reaper runs `docker system prune -af --volumes`, which sweeps
// them up wholesale -- so the leak is invisible exactly where it is compensated
// and unbounded everywhere else.
func (d dockerAttempt) Remove() { _ = exec.Command("docker", "rm", "-fv", d.name).Run() }

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

// allCoreMigrations is the `hi` bound meaning "every migration in the
// directory". See the call site in Setup for why an explicit numeric cap is a
// defect rather than a configuration choice.
const allCoreMigrations = math.MaxInt32

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

// StartPostgres starts the labelled, tmpfs-backed postgres:15 container Setup
// uses, with no migration applied, and returns its superuser DSN and the
// cleanup that removes it together with its anonymous volume. It is for a
// test that applies its own migration chain: the #3894 upgrade test starts
// from v10.2.0's set.
func StartPostgres(t *testing.T) (string, func()) {
	t.Helper()
	return startPostgresContainer(t)
}
