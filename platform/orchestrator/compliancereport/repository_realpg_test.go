// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/shared/tenantscope"
)

// Real-Postgres tests for compliance_report_jobs (migration enterprise/136).
//
// Three properties cannot be tested any other way:
//
//  1. The migration APPLIES. A CHECK constraint with a typo, a policy that
//     references a column that does not exist, an index on a missing column -
//     all of these are invisible to `go build` and to every mock.
//  2. RLS actually ISOLATES. core/018's RLS loop ran at schema version 18 and
//     covers only the tables that existed then, so a table created later
//     inherits nothing (`[[reference_core018_rls_skips_tables_created_later]]`).
//     The only way to know 136's own policy works is to run a cross-org read
//     under axonflow_app_role, which is NOBYPASSRLS.
//  3. The "completed means downloadable" invariant is enforced by the DATABASE,
//     not only by the service. A future code path that sets status='completed'
//     without a stored artifact must be refused by the constraint.

const (
	realOrgSelf  = "creport-org-self"
	realOrgOther = "creport-org-other"
	realTenant   = "creport-tenant-self"
)

type realEnv struct {
	master  *sql.DB
	appRole *sql.DB
}

func setupRealPG(t *testing.T) *realEnv {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	env := approletest.Setup(t, "../../../migrations/core")

	master, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })

	applyMigration(t, master, "../../../migrations/enterprise/136_compliance_report_jobs.sql")

	appRole, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app role: %v", err)
	}
	t.Cleanup(func() { _ = appRole.Close() })
	// Pin the app-role handle to one connection so a transaction-local GUC and
	// the statement that depends on it cannot land on different connections.
	appRole.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, appRole, "axonflow_app_role")

	return &realEnv{master: master, appRole: appRole}
}

func applyMigration(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

func newJob(orgID, tenantID, id string) *ReportJob {
	return &ReportJob{
		ID:          id,
		OrgID:       orgID,
		TenantID:    tenantID,
		Regulator:   RegulatorOJK,
		Framework:   FrameworkUUPDP,
		Format:      FormatPDF,
		PeriodStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
		Status:      StatusPending,
		ReportState: ReportStateUndetermined,
		RequestedBy: "officer@example.com",
		CreatedAt:   time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestRealPG_Migration136AppliesWithRLS is property (1) and half of (2).
func TestRealPG_Migration136AppliesWithRLS(t *testing.T) {
	env := setupRealPG(t)

	var enabled, forced bool
	if err := env.master.QueryRow(
		`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'compliance_report_jobs'`,
	).Scan(&enabled, &forced); err != nil {
		t.Fatalf("read RLS flags: %v", err)
	}
	if !enabled || !forced {
		t.Errorf("RLS enabled=%v forced=%v, want both true", enabled, forced)
	}

	var policies int
	if err := env.master.QueryRow(
		`SELECT COUNT(*) FROM pg_policies WHERE tablename = 'compliance_report_jobs' AND policyname = 'compliance_report_jobs_org_isolation'`,
	).Scan(&policies); err != nil {
		t.Fatalf("read policies: %v", err)
	}
	if policies != 1 {
		t.Errorf("isolation policies = %d, want 1", policies)
	}
}

// TestRealPG_CrossOrgReadIsRefused is property (2): the by-id read under the
// real NOBYPASSRLS role cannot reach another organization's row.
//
// TWO mechanisms are in play and this exercises BOTH: the SQL org predicate and
// the RLS policy. Running as axonflow_app_role is what makes the second one
// observable at all - a superuser bypasses it.
func TestRealPG_CrossOrgReadIsRefused(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	self := newJob(realOrgSelf, realTenant, "creport-self-1")
	other := newJob(realOrgOther, "creport-tenant-other", "creport-other-1")
	if err := repo.Create(ctx, self); err != nil {
		t.Fatalf("create self job: %v", err)
	}
	if err := repo.Create(ctx, other); err != nil {
		t.Fatalf("create other job: %v", err)
	}

	selfScope, err := tenantscope.New(realOrgSelf, realTenant)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}

	// Positive control FIRST: without it, a repository that returns nothing at
	// all would pass the negative assertion below.
	got, err := repo.GetByID(ctx, selfScope, self.ID)
	if err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if got.ID != self.ID || got.OrgID != realOrgSelf {
		t.Fatalf("owner read returned %+v", got)
	}

	if _, err := repo.GetByID(ctx, selfScope, other.ID); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("cross-org read: err = %v, want ErrJobNotFound", err)
	}
}

// TestRealPG_CrossTenantUpdateWithinOneOrgIsRefused pins the OTHER dimension of
// the write predicate (#3241 round 2, the Update asymmetry LOW).
//
// Update is a blind write: the caller hands in a whole ReportJob and every
// mutable field is overwritten, while the row's tenancy is not among the
// columns being SET. With only an org predicate, a job whose TenantID had been
// altered in memory still updated the stored row - writing one tenancy's
// lifecycle state onto another tenancy's record, inside the same organization,
// with nothing in the row left to show it.
//
// Same organization on purpose: an org predicate alone catches nothing here,
// which is exactly why this case needed its own test. Verified by mutation -
// removing `AND tenant_id = $13` leaves every other test in this file green.
func TestRealPG_CrossTenantUpdateWithinOneOrgIsRefused(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	victim := newJob(realOrgSelf, "creport-tenant-a", "creport-victim-tenant-a")
	if err := repo.Create(ctx, victim); err != nil {
		t.Fatalf("create victim job: %v", err)
	}

	// Same ORG, different TENANCY, same job id.
	attack := newJob(realOrgSelf, "creport-tenant-b", victim.ID)
	attack.Status = StatusFailed
	attack.Error = "sibling tenancy wrote this"
	if err := repo.Update(ctx, attack); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("cross-tenant update within one org: err = %v, want ErrJobNotFound", err)
	}

	var status, errText, tenant string
	if err := env.master.QueryRow(
		`SELECT status, error, tenant_id FROM compliance_report_jobs WHERE id = $1`, victim.ID,
	).Scan(&status, &errText, &tenant); err != nil {
		t.Fatalf("read victim row: %v", err)
	}
	if status != string(StatusPending) || errText != "" || tenant != "creport-tenant-a" {
		t.Errorf("victim row was mutated by a sibling tenancy: status=%q error=%q tenant=%q",
			status, errText, tenant)
	}

	// CONTROL: the OWNING tenancy must still be able to update, or the
	// predicate has simply broken the write path.
	ok := newJob(realOrgSelf, "creport-tenant-a", victim.ID)
	ok.Status = StatusProcessing
	ok.Progress = 55
	if err := repo.Update(ctx, ok); err != nil {
		t.Fatalf("the owning tenancy cannot update its own job: %v", err)
	}
}

// TestRealPG_CrossOrgUpdateIsRefused pins the write side.
func TestRealPG_CrossOrgUpdateIsRefused(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	victim := newJob(realOrgOther, "creport-tenant-other", "creport-victim-1")
	if err := repo.Create(ctx, victim); err != nil {
		t.Fatalf("create victim job: %v", err)
	}

	// The attacker names the victim's ID but carries its OWN organization -
	// exactly the shape a scoping bug in a caller would produce.
	attack := newJob(realOrgSelf, realTenant, victim.ID)
	attack.Status = StatusFailed
	attack.Error = "attacker wrote this"
	if err := repo.Update(ctx, attack); !errors.Is(err, ErrJobNotFound) {
		t.Errorf("cross-org update: err = %v, want ErrJobNotFound", err)
	}

	var status, errText string
	if err := env.master.QueryRow(
		`SELECT status, error FROM compliance_report_jobs WHERE id = $1`, victim.ID,
	).Scan(&status, &errText); err != nil {
		t.Fatalf("read victim row: %v", err)
	}
	if status != string(StatusPending) || errText != "" {
		t.Errorf("victim row was mutated: status=%q error=%q", status, errText)
	}
}

// TestRealPG_UnscopedReadIsRefused pins that an unbound scope never degrades to
// an unscoped query.
func TestRealPG_UnscopedReadIsRefused(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	job := newJob(realOrgSelf, realTenant, "creport-unscoped-1")
	if err := repo.Create(ctx, job); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := repo.GetByID(ctx, tenantscope.Scope{}, job.ID); !errors.Is(err, tenantscope.ErrNoCallerScope) {
		t.Errorf("unbound scope: err = %v, want ErrNoCallerScope", err)
	}
}

// TestRealPG_BlankTenancyKeysAreRefused pins both halves of the invariant: the
// application refuses first, and the database refuses if the application is
// ever bypassed.
func TestRealPG_BlankTenancyKeysAreRefused(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	blank := newJob("", "", "creport-blank-1")
	if err := repo.Create(ctx, blank); err == nil {
		t.Error("the repository persisted a job with no tenancy keys")
	}

	// The database half, reached directly on the master handle so the
	// application check cannot be what refuses it.
	_, err := env.master.Exec(`
		INSERT INTO compliance_report_jobs
			(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
			 status, report_state, requested_by, created_at)
		VALUES ('creport-blank-2', '   ', 'tenant', 'ojk', 'UU_PDP', 'pdf',
		        NOW() - INTERVAL '1 day', NOW(), 'pending', '', 'x', NOW())`)
	if err == nil {
		t.Error("the database accepted a whitespace-only org_id")
	} else if !strings.Contains(err.Error(), "compliance_report_jobs_org_not_empty") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestRealPG_CompletedWithoutAnArtifactIsRefusedByTheDatabase is property (3):
// the EU AI Act export trap - a `completed` export with nothing to download -
// cannot be written here even by a future code path that forgets.
func TestRealPG_CompletedWithoutAnArtifactIsRefusedByTheDatabase(t *testing.T) {
	env := setupRealPG(t)

	for _, tc := range []struct {
		name        string
		reportState string
		storageKey  string
		checksum    string
	}{
		{"no storage key", "populated", "", "abc123"},
		{"no checksum", "populated", "compliance-reports/x/ojk/y.pdf", ""},
		{"undetermined state", "", "compliance-reports/x/ojk/y.pdf", "abc123"},
		{"not_available state", "not_available", "compliance-reports/x/ojk/y.pdf", "abc123"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := env.master.Exec(`
				INSERT INTO compliance_report_jobs
					(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
					 status, report_state, storage_key, checksum, requested_by, created_at)
				VALUES ($1, 'o', 't', 'ojk', 'UU_PDP', 'pdf',
				        NOW() - INTERVAL '1 day', NOW(), 'completed', $2, $3, $4, 'x', NOW())`,
				"creport-bad-"+strings.ReplaceAll(tc.name, " ", "-"), tc.reportState, tc.storageKey, tc.checksum)
			if err == nil {
				t.Fatal("the database accepted a completed job with no retrievable artifact")
			}
			if !strings.Contains(err.Error(), "compliance_report_jobs_completed_is_complete") {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}

	// Positive control: a properly completed job IS accepted, so the four
	// refusals above are the constraint firing and not a broken INSERT.
	if _, err := env.master.Exec(`
		INSERT INTO compliance_report_jobs
			(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
			 status, report_state, progress, size_bytes, storage_key, checksum,
			 requested_by, created_at, completed_at)
		VALUES ('creport-good-1', 'o', 't', 'ojk', 'UU_PDP', 'pdf',
		        NOW() - INTERVAL '1 day', NOW(), 'completed', 'populated', 100, 4096,
		        'compliance-reports/o/ojk/creport-good-1.pdf', 'deadbeef', 'x', NOW(), NOW())`); err != nil {
		t.Fatalf("a properly completed job was refused: %v", err)
	}
}

// TestRealPG_CompletedMustAlsoCarryProgressSizeAndCompletionTime covers the
// rest of the success-path invariant, and TestRealPG_FailedMustCarryACause the
// failure side. Split from the test above so a failure names which half broke.
func TestRealPG_CompletedMustAlsoCarryProgressSizeAndCompletionTime(t *testing.T) {
	env := setupRealPG(t)

	for _, tc := range []struct {
		name        string
		progress    int
		sizeBytes   int
		completedAt string
	}{
		{"progress short of 100", 55, 4096, "NOW()"},
		{"zero size", 100, 0, "NOW()"},
		{"no completion time", 100, 4096, "NULL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := env.master.Exec(`
				INSERT INTO compliance_report_jobs
					(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
					 status, report_state, progress, size_bytes, storage_key, checksum,
					 requested_by, created_at, completed_at)
				VALUES ($1, 'o', 't', 'ojk', 'UU_PDP', 'pdf',
				        NOW() - INTERVAL '1 day', NOW(), 'completed', 'populated', $2, $3,
				        'compliance-reports/o/ojk/y.pdf', 'deadbeef', 'x', NOW(),
				        CASE WHEN $4 = 'NULL' THEN NULL ELSE NOW() END)`,
				"creport-partial-"+strings.ReplaceAll(tc.name, " ", "-"), tc.progress, tc.sizeBytes, tc.completedAt)
			if err == nil {
				t.Fatal("the database accepted a half-completed job")
			}
			if !strings.Contains(err.Error(), "compliance_report_jobs_completed_is_complete") {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

func TestRealPG_FailedMustCarryACause(t *testing.T) {
	env := setupRealPG(t)

	_, err := env.master.Exec(`
		INSERT INTO compliance_report_jobs
			(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
			 status, report_state, error, requested_by, created_at)
		VALUES ('creport-silent-failure', 'o', 't', 'ojk', 'UU_PDP', 'pdf',
		        NOW() - INTERVAL '1 day', NOW(), 'failed', '', '   ', 'x', NOW())`)
	if err == nil {
		t.Fatal("the database accepted a failed job with no cause")
	}
	if !strings.Contains(err.Error(), "compliance_report_jobs_failed_has_a_cause") {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// Positive control: a failure WITH a cause is accepted.
	if _, err := env.master.Exec(`
		INSERT INTO compliance_report_jobs
			(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
			 status, report_state, error, requested_by, created_at)
		VALUES ('creport-honest-failure', 'o', 't', 'ojk', 'UU_PDP', 'pdf',
		        NOW() - INTERVAL '1 day', NOW(), 'failed', '', 'no storage backend is configured', 'x', NOW())`); err != nil {
		t.Fatalf("a failure carrying a cause was refused: %v", err)
	}
}

// TestRealPG_VocabularyConstraintsMatchTheGoEnums pins the database CHECK lists
// against the Go constants. Two copies of a vocabulary drift silently: the code
// starts writing a value the constraint rejects, and the failure lands in the
// async processor where it becomes a mysteriously failed job.
func TestRealPG_VocabularyConstraintsMatchTheGoEnums(t *testing.T) {
	env := setupRealPG(t)

	// `error` is always populated: the failed-has-a-cause constraint applies to
	// every row this helper writes with status='failed', and a vocabulary test
	// must not be measuring THAT constraint.
	// framework is a real value, not the 'F' placeholder this used to pass.
	// framework now carries its own CHECK (it was the one enum column without
	// one), so a placeholder made every case in this test fail on the WRONG
	// constraint - which is the shape where a lockstep test reports drift that
	// is really its own fixture.
	insertFW := func(id, regulator, framework, format, status, state string) error {
		_, err := env.master.Exec(`
			INSERT INTO compliance_report_jobs
				(id, org_id, tenant_id, regulator, framework, format, period_start, period_end,
				 status, report_state, error, requested_by, created_at)
			VALUES ($1, 'o', 't', $2, $3, $4, NOW() - INTERVAL '1 day', NOW(), $5, $6, 'vocabulary probe', 'x', NOW())`,
			id, regulator, framework, format, status, state)
		return err
	}
	insert := func(id, regulator, format, status, state string) error {
		return insertFW(id, regulator, string(FrameworkOJKAIGovernance), format, status, state)
	}

	for _, reg := range AllRegulators() {
		if err := insert("creport-reg-"+string(reg), string(reg), "json", "pending", ""); err != nil {
			t.Errorf("regulator %q is a Go constant the database rejects: %v", reg, err)
		}
	}
	for _, f := range []Format{FormatPDF, FormatCSV, FormatXLSX, FormatJSON} {
		if err := insert("creport-fmt-"+string(f), "ojk", string(f), "pending", ""); err != nil {
			t.Errorf("format %q is a Go constant the database rejects: %v", f, err)
		}
	}
	for _, s := range []Status{StatusPending, StatusProcessing, StatusFailed} {
		if err := insert("creport-st-"+string(s), "ojk", "json", string(s), ""); err != nil {
			t.Errorf("status %q is a Go constant the database rejects: %v", s, err)
		}
	}
	for _, rs := range []ReportState{ReportStateUndetermined, ReportStateNotAvailable, ReportStateEnabledEmpty, ReportStatePopulated} {
		if err := insert("creport-rs-"+string(rs)+"x", "ojk", "json", "pending", string(rs)); err != nil {
			t.Errorf("report state %q is a Go constant the database rejects: %v", rs, err)
		}
	}
	for _, f := range AllFrameworks() {
		if err := insertFW("creport-fw-"+string(f), "ojk", string(f), "json", "pending", ""); err != nil {
			t.Errorf("framework %q is a Go constant the database rejects: %v", f, err)
		}
	}
	// Negative control for the framework CHECK specifically, alongside the
	// regulator one below: without it, a constraint listing every value would
	// look identical to no constraint at all.
	if err := insertFW("creport-fw-bogus", "ojk", "MIFID_II", "json", "pending", ""); err == nil {
		t.Error("the database accepted an unknown framework - the framework CHECK constraint is inert")
	}
	// Negative control: a value NEITHER side knows must be refused, or the
	// CHECK constraints are not doing anything.
	if err := insert("creport-bogus", "fca", "json", "pending", ""); err == nil {
		t.Error("the database accepted an unknown regulator - the CHECK constraint is inert")
	}
}

// TestRealPG_CountSinceIsOrgScoped pins the durable half of the daily budget:
// the count Service.usedToday consults, scoped to one organization.
func TestRealPG_CountSinceIsOrgScoped(t *testing.T) {
	env := setupRealPG(t)
	repo := NewPostgresRepository(env.appRole)
	ctx := context.Background()

	for _, id := range []string{"creport-cs-1", "creport-cs-2"} {
		if err := repo.Create(ctx, newJob(realOrgSelf, realTenant, id)); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	if err := repo.Create(ctx, newJob(realOrgOther, "creport-tenant-other", "creport-cs-3")); err != nil {
		t.Fatalf("create other: %v", err)
	}

	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n, err := repo.CountSince(ctx, realOrgSelf, since)
	if err != nil {
		t.Fatalf("CountSince: %v", err)
	}
	if n != 2 {
		t.Errorf("CountSince = %d, want 2 (the other organization's job must not be counted)", n)
	}
}

// TestRealPG_DownMigrationDropsEverything pins the rollback path, including
// that it survives being run against a database where 136 never applied.
func TestRealPG_DownMigrationDropsEverything(t *testing.T) {
	env := setupRealPG(t)

	applyMigration(t, env.master, "../../../migrations/enterprise/136_compliance_report_jobs_down.sql")

	var n int
	if err := env.master.QueryRow(`SELECT COUNT(*) FROM pg_class WHERE relname = 'compliance_report_jobs'`).Scan(&n); err != nil {
		t.Fatalf("check table: %v", err)
	}
	if n != 0 {
		t.Errorf("the table survived the down migration")
	}

	// Idempotent: running it again on an absent table must not raise. A
	// `DROP POLICY IF EXISTS ... ON <table>` still errors when the TABLE is
	// missing, which is why the down migration guards it.
	applyMigration(t, env.master, "../../../migrations/enterprise/136_compliance_report_jobs_down.sql")
}
