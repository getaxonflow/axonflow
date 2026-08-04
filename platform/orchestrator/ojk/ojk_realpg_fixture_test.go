//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Real-Postgres fixture for the OJK export sections, readiness, dashboard and
// retention (#3242).
//
// # Why this is gated on TEST_PG_INTEGRATION and not DATABASE_URL
//
// These tests were first written against a `DATABASE_URL` an operator sets by
// hand. R3 round 1 established that the only CI job that runs this package under
// `-tags enterprise` (`unit-tests-enterprise-realpg` in test.yml) DELIBERATELY
// leaves `DATABASE_URL` unset -- its own header says so -- so every one of these
// tests skipped in every CI run. A test that never executes is a file, not a
// guard, and the casualties were the cross-org refusal proof and the app-role
// RLS proof: the two assertions this workstream most needs to be standing.
//
// They now use the repo's standard real-PG convention: `TEST_PG_INTEGRATION=1`
// plus `approletest.Setup`, which spins a throwaway postgres:15 container and
// provisions the two v9 roles. That is the gate the enterprise real-PG CI job
// actually sets.
//
// A throwaway container also removes the second hazard R3 found: a test that
// disables the global `pii-indonesia` policy to reach a fail branch was, against
// a shared DATABASE_URL, disarming a security control on somebody's dev or
// staging database. Here it cannot outlive the container.
//
// # One container per top-level test
//
// approletest.Setup registers its teardown with t.Cleanup, so the container dies
// with the test that created it. Tests are therefore grouped into a few
// top-level functions with subtests sharing one environment, rather than a dozen
// top-level functions each paying for a container.

import (
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"

	_ "github.com/lib/pq"
)

// Fixture identifiers. `ojk3242-` prefixes every row this package writes, so a
// cleanup can never reach a row it did not create.
const (
	fxOrgA = "ojk3242-org-a"
	fxOrgB = "ojk3242-org-b"
	// fxTenantA is org A's TENANT identifier -- a DIFFERENT value from its org
	// id, which is the v9 shape (#3071) in which the tenant/org conflation is
	// observable at all.
	fxTenantA = "ojk3242-tenant-a"
	// fxOrgOrphan owns audit rows written with a BLANK org_id -- the
	// single-identifier deployment shape. audit_logs.org_id is nullable and no
	// core migration constrains it (core/156's NOT NULL sweep does not cover
	// audit_logs), so these rows are real.
	fxOrgOrphan = "ojk3242-org-orphan"
	fxPrefix    = "ojk3242-"
)

var (
	fxStart = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// fxEnd is the END-OF-DAY form of 2026-07-31, matching what ExportAuditData
	// binds after extending the request's end_date.
	fxEnd = time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC).Add(24*time.Hour - time.Nanosecond)
	fxTS  = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
)

// ojkPGEnv is one throwaway database with the full core + enterprise schema.
type ojkPGEnv struct {
	// master is the table owner (BYPASSRLS). Fixture seeding runs here.
	master *sql.DB
	// appRole is axonflow_app_role (NOBYPASSRLS) -- the PRODUCTION posture.
	// Run as the owner, RLS does not apply and a missing withOrgScope wrap is
	// invisible; this connection is the only one that can observe it.
	appRole *sql.DB
	svc     *ojkAuditExportServiceImpl
}

// newOJKPGEnv brings up a container, applies the whole migration chain that this
// module depends on, and returns handles.
func newOJKPGEnv(t *testing.T) *ojkPGEnv {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	// approletest.Setup applies core migrations 001..111 and provisions the two
	// v9 roles. The OJK module needs a great deal more than that: the
	// audit_logs decision columns (core/119, /121, /126, /129), the tenancy
	// hardening (core/155, /156) and the enterprise ojk_* + Indonesia PII
	// tables. The remainder is applied below.
	env := approletest.Setup(t, repoPath("migrations/core"))

	open := func(dsn, label string) *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s DSN: %v", label, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	master := open(env.MasterDSN, "master")
	// Single connection so the session GUCs the later migrations need cannot
	// land on a connection the next statement does not use.
	master.SetMaxOpenConns(1)
	seedMigrationSessionVars(t, master)

	applyMigrationRange(t, master, repoPath("migrations/core"), 112, 999)
	applyMigrationRange(t, master, repoPath("migrations/enterprise"), 1, 999)

	// Prove the schema this package is about actually landed. Without this the
	// tests below would report the ABSENCE of a table as "no rows" and pass.
	for _, table := range []string{
		"audit_logs", "hitl_approval_queue", "static_policies",
		"ojk_breach_notifications", "indonesia_pii_detection_events",
	} {
		var n int
		if err := master.QueryRow(
			`SELECT COUNT(*) FROM pg_class WHERE relname = $1 AND relkind = 'r'`, table,
		).Scan(&n); err != nil {
			t.Fatalf("probe %s: %v", table, err)
		}
		if n != 1 {
			t.Fatalf("table %s is absent after the migration chain; every assertion in this file would be vacuous", table)
		}
	}

	appRole := open(env.AppRoleDSN, "app_role")
	appRole.SetMaxOpenConns(1)

	e := &ojkPGEnv{master: master, appRole: appRole}
	e.svc = &ojkAuditExportServiceImpl{db: master}
	t.Cleanup(func() { e.cleanup() })
	return e
}

// repoPath resolves a repo-root-relative path from this package's directory.
// platform/ is the module root and migrations/ is its sibling.
func repoPath(rel string) string { return "../../../" + rel }

// seedMigrationSessionVars mirrors platform/agent/run.go::setMigrationSessionVars.
// Migration 094 REFUSES to run without app.deployment_org_id, and 028 reads
// app.db_password, so a bare connection cannot apply the chain.
func seedMigrationSessionVars(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, kv := range [][2]string{
		{"app.db_password", "testpass"},
		{"app.deployment_org_id", "local-dev-org"},
		{"app.deployment_kind", "dev"},
		{"app.current_org_id", "local-dev-org"},
	} {
		if _, err := db.Exec("SELECT set_config($1, $2, false)", kv[0], kv[1]); err != nil {
			t.Fatalf("set_config %s: %v", kv[0], err)
		}
	}
}

// applyMigrationRange applies every non-down .sql in dir whose numeric prefix is
// in [lo, hi], in (version, name) order -- the same ordering the production
// runner uses, which matters because two files can share a version prefix
// (core/025_decision_chain.sql and core/025_hitl_oversight_queue.sql).
func applyMigrationRange(t *testing.T, db *sql.DB, dir string, lo, hi int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migration dir %s: %v", dir, err)
	}
	type mig struct {
		version int
		name    string
	}
	var migs []mig
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, "_down.sql") {
			continue
		}
		parts := strings.SplitN(name, "_", 2)
		if len(parts) < 2 {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(parts[0], "%d", &v); err != nil {
			continue
		}
		if v < lo || v > hi {
			continue
		}
		migs = append(migs, mig{version: v, name: name})
	}
	sort.Slice(migs, func(i, j int) bool {
		if migs[i].version != migs[j].version {
			return migs[i].version < migs[j].version
		}
		return migs[i].name < migs[j].name
	})
	for _, m := range migs {
		body, err := os.ReadFile(dir + "/" + m.name)
		if err != nil {
			t.Fatalf("read %s: %v", m.name, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s/%s: %v", dir, m.name, err)
		}
	}
}

// cleanup deletes only rows this package created.
func (e *ojkPGEnv) cleanup() {
	_, _ = e.master.Exec(`DELETE FROM audit_logs WHERE id LIKE $1`, fxPrefix+"%")
	_, _ = e.master.Exec(`DELETE FROM hitl_approval_queue WHERE org_id LIKE $1`, fxPrefix+"%")
	_, _ = e.master.Exec(`DELETE FROM indonesia_pii_detection_events WHERE id LIKE $1`, fxPrefix+"%")
	_, _ = e.master.Exec(`DELETE FROM ojk_breach_notifications WHERE id LIKE $1`, fxPrefix+"%")
	_, _ = e.master.Exec(`DELETE FROM static_policies WHERE policy_id LIKE $1`, fxPrefix+"%")
}

// exec is a fatal-on-error helper for fixture writes.
func (e *ojkPGEnv) exec(t *testing.T, q string, args ...interface{}) {
	t.Helper()
	if _, err := e.master.Exec(q, args...); err != nil {
		t.Fatalf("fixture %.70s: %v", strings.Join(strings.Fields(q), " "), err)
	}
}

const fxInsertAudit = `
	INSERT INTO audit_logs (
		id, request_id, timestamp, user_id, user_email, user_role,
		client_id, tenant_id, org_id, request_type, query, query_hash,
		policy_decision, policy_details, decision_id, plane, correlation_id,
		provider, model, tokens_used, cost, response_time_ms,
		transfer_basis, data_residency
	) VALUES ($1,$2,$3,0,'u@example.test','service','client-1',$4,$5,$6,'(redacted)','h',
	          $7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`

const fxInsertHITL = `
	INSERT INTO hitl_approval_queue (
		request_id, org_id, tenant_id, client_id, original_query, request_type,
		triggered_policy_id, triggered_policy_name, trigger_reason, severity,
		status, reviewer_id, reviewer_role, reviewed_at, expires_at, created_at
	) VALUES (gen_random_uuid(),$1,$2,'client-1','(redacted)','llm_chat',
	          'pol-hitl','Payment Approval',$3,'high',$4,$5,$6,$7,$8,$9)`

const fxInsertPII = `
	INSERT INTO indonesia_pii_detection_events (
		id, org_id, tenant_id, decision_id, correlation_id, plane,
		pii_type, ojk_category, severity, masked_value, confidence, action, detected_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

const fxInsertBreach = `
	INSERT INTO ojk_breach_notifications (
		id, org_id, tenant_id, incident_timestamp, discovery_time, notification_deadline,
		data_subjects_affected, data_types_involved, description, remediation_steps,
		notified_authority, status, submitted_at, created_at, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'MOCDA',$11,$12,$5,$5)`

// seedExportFixture writes the cross-org corpus every export assertion reads.
//
// The two rows that carry the whole point:
//
//   - ojk3242-al-b1 / -b2 belong to org B but carry ORG A's identifier as their
//     TENANT. Any predicate that ORs the two tenancy columns returns them to
//     org A. audit_logs has no RLS, so nothing downstream would catch it.
//   - ojk3242-al-orphan has a BLANK org_id and a tenant_id of fxOrgOrphan --
//     the single-identifier deployment shape. A predicate on org_id ALONE
//     silently drops it and the section reports a confident enabled_empty.
func (e *ojkPGEnv) seedExportFixture(t *testing.T) {
	t.Helper()

	// org A: a blocked Indonesia-PII decision.
	e.exec(t, fxInsertAudit, fxPrefix+"al-a1", "req-a1", fxTS, fxTenantA, fxOrgA, "decision_llm",
		"blocked", `{"decision_id":"dec-a1","stage":"llm","policy_ids":["indonesia_pii_protection"],"reason":"Critical Indonesia PII detected (NIK or NPWP)"}`,
		"dec-a1", "decision", "corr-a1", nil, nil, 0, 0, 12, nil, nil)

	// org A: an allowed LLM forward with a declared cross-border basis.
	e.exec(t, fxInsertAudit, fxPrefix+"al-a2", "req-a2", fxTS.Add(time.Minute), fxTenantA, fxOrgA, "llm_chat",
		"allowed", `{"decision_id":"dec-a2","plane":"llm"}`,
		"dec-a2", "llm", "corr-a2", "anthropic", "claude-haiku-4-5", 1200, 0.004, 950, "pasal_56b_dpa", "US")

	// org B, TENANT = org A's identifier. THE CONFLATION BAIT.
	e.exec(t, fxInsertAudit, fxPrefix+"al-b1", "req-b1", fxTS, fxOrgA, fxOrgB, "decision_llm",
		"blocked", `{"decision_id":"dec-b1","stage":"llm","policy_ids":["indonesia_pii_protection"],"reason":"org B secret"}`,
		"dec-b1", "decision", "corr-b1", nil, nil, 0, 0, 5, nil, nil)
	e.exec(t, fxInsertAudit, fxPrefix+"al-b2", "req-b2", fxTS, fxOrgA, fxOrgB, "llm_chat",
		"allowed", `{"decision_id":"dec-b2","plane":"llm"}`,
		"dec-b2", "llm", "corr-b2", "openai", "gpt-4o", 10, 0.01, 5, "adequacy", "SG")

	// BLANK org_id, tenant_id = fxOrgOrphan. The single-identifier shape.
	e.exec(t, fxInsertAudit, fxPrefix+"al-orphan", "req-orphan", fxTS, fxOrgOrphan, "", "llm_chat",
		"blocked", `{"decision_id":"dec-orphan","plane":"llm","reason":"orphan-org refusal"}`,
		"dec-orphan", "llm", "corr-orphan", "anthropic", "claude-haiku-4-5", 5, 0.001, 3, "consent", "US")

	// HITL: reviewed (exported), pending (not exported), org B (must not leak).
	e.exec(t, fxInsertHITL, fxOrgA, fxTenantA, "payment above threshold", "approved",
		"reviewer-a", "compliance_officer", fxTS.Add(90*time.Second), fxTS.Add(time.Hour), fxTS)
	e.exec(t, fxInsertHITL, fxOrgA, fxTenantA, "still pending", "pending",
		nil, nil, nil, fxTS.Add(time.Hour), fxTS)
	e.exec(t, fxInsertHITL, fxOrgB, fxOrgA, "org B secret", "approved",
		"reviewer-b", "compliance_officer", fxTS.Add(time.Minute), fxTS.Add(time.Hour), fxTS)

	e.exec(t, fxInsertPII, fxPrefix+"pii-a1", fxOrgA, fxTenantA, "dec-a1", "corr-a1", "decision",
		"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", fxTS)
	e.exec(t, fxInsertPII, fxPrefix+"pii-a2", fxOrgA, fxTenantA, nil, nil, "mcp",
		"bank_bca", "financial_account", "high", "***********7890", 0.7, "detected", fxTS)
	e.exec(t, fxInsertPII, fxPrefix+"pii-b1", fxOrgB, fxOrgA, nil, nil, "gateway",
		"npwp_new", "tax_identifier", "critical", "****************", 0.7, "blocked", fxTS)

	e.exec(t, fxInsertBreach, fxPrefix+"br-a1", fxOrgA, fxTenantA, fxTS.Add(-time.Hour), fxTS,
		fxTS.Add(72*time.Hour), 10, "nik", "test breach", "rotate", "submitted", fxTS.Add(time.Hour))
	e.exec(t, fxInsertBreach, fxPrefix+"br-b1", fxOrgB, fxOrgA, fxTS.Add(-time.Hour), fxTS,
		fxTS.Add(72*time.Hour), 99, "nik", "org B secret", "rotate", "submitted", fxTS.Add(time.Hour))
}

// recentTS is inside every readiness window, so a seeded row is measurable
// rather than aged out.
func recentTS() time.Time { return time.Now().UTC().Add(-24 * time.Hour) }
