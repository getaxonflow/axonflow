// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"

	"axonflow/platform/agent/approletest"
)

// Cross-organization IDOR regression suite for the EU AI Act module (#3241,
// epic #2892).
//
// # What was broken
//
// Every by-id path in this module resolved NO organization at all:
//
//	export_repository.go  GetByID  -> `WHERE id = $1`
//	export_handlers.go    getExport / downloadExport -> no org resolution
//	conformity_service.go GetAssessment / Update / Submit / Approve / Reject
//	                      -> no orgID parameter anywhere in the signature
//
// So an authenticated caller of organization B could read, download and MUTATE
// organization A's conformity assessments and export records by naming the id.
// RBI and MAS FEAT were hardened for exactly this class in #3103 / #3141;
// euaiact was missed.
//
// # Why this test drives HTTP and seeds with raw SQL
//
// Deliberately: it must compile and run against BOTH the pre-fix and the
// post-fix tree so the failure can be reproduced before the fix lands
// (`[[feedback_reproduce_the_exploit_on_the_prefix_stack_first]]`). Calling the
// repository or the service directly would bind the test to signatures the fix
// changes, and it would test the post-parse shape rather than the path
// (`[[feedback_test_the_path_not_the_post_parse_shape]]`).
//
// # Why the master (owner) connection
//
// migration 116 ENABLEs RLS on these tables but does not FORCE it, and the
// repository issues bare statements with no rls.WithOrgScope wrap. Under the
// table OWNER - which is the posture of every docker-compose and most
// self-hosted deployments - RLS does not apply, so the cross-org row is fully
// visible to the query and the application layer is the only boundary. That is
// the deployment in which this is exploitable, so that is the deployment the
// test reproduces. (Under axonflow_app_role the same bare statements read zero
// rows instead - a different defect, the #3039 blind-read class, which the same
// fix also closes by adding the WithOrgScope wrap.)

const (
	idorOrgVictim   = "idor-org-victim"
	idorOrgAttacker = "idor-org-attacker"
)

// euaiactIDOREnv is the shared fixture: a real Postgres with core migrations
// plus enterprise/116, two organizations, and one export + one conformity
// assessment owned by the victim.
type euaiactIDOREnv struct {
	db       *sql.DB
	router   *mux.Router
	exportID string
	assessID string
}

func setupEUAIActIDOREnv(t *testing.T) *euaiactIDOREnv {
	t.Helper()
	approletest.SkipUnlessEnabled(t)

	env := approletest.Setup(t, "../../../migrations/core")
	db, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	applySQLFile(t, db, "../../../migrations/enterprise/116_euaiact_orchestrator_tables.sql")
	// The export repository SELECTs download_url / storage_type / storage_key,
	// which 116 does not create. Without them every export read fails with
	// `column "download_url" does not exist`, which would make this suite pass
	// for the wrong reason.
	//
	// This used to apply migrations/industry/travel/201, and that was the #3245
	// defect written into a test fixture: the columns existed here because the
	// TRAVEL pack was applied by hand, while three real deployment postures
	// (in-vpc-enterprise, banking, healthcare) never run that pack and 500 on
	// the same read. enterprise/138 is where they belong, and applying 138 here
	// means this suite now runs against the schema those deployments actually
	// get. See TestEUAIActExportReadsWorkOnTheEnterpriseMigrationSetAlone.
	applySQLFile(t, db, "../../../migrations/enterprise/138_euaiact_export_cloud_storage.sql")

	for _, org := range []string{idorOrgVictim, idorOrgAttacker} {
		if _, err := db.Exec(`
			INSERT INTO organizations (org_id, name, tier, license_key, created_at, updated_at)
			VALUES ($1, $2, 'enterprise', 'test-license-key', NOW(), NOW())
			ON CONFLICT (org_id) DO NOTHING`, org, "org-"+org); err != nil {
			t.Fatalf("seed org %s: %v", org, err)
		}
	}

	exportID := "export-victim-1"
	// `error` is written as '' rather than left NULL for the same reason as the
	// assessment below: that is what the module's own Create writes, and the
	// NULL case is a separate defect with its own test.
	if _, err := db.Exec(`
		INSERT INTO euaiact_exports
			(id, org_id, export_type, format, status, progress, file_path, file_size,
			 record_count, error, requested_by, created_at, completed_at)
		VALUES ($1, $2, 'full_audit', 'json', 'completed', 100, '/tmp/victim-secret-export.json',
		        4242, 17, '', 'victim-compliance-officer@victim.example', NOW(), NOW())`,
		exportID, idorOrgVictim); err != nil {
		t.Fatalf("seed victim export: %v", err)
	}

	assessID := "assess-victim-1"
	// submitted_by / approved_by / rejected_by / rejection_reason are written
	// as '' rather than left NULL, because that is what the module's own
	// Create writes. Seeding NULL here would exercise a different defect (the
	// reader scans those nullable columns into plain strings) and mask the
	// cross-org one this suite is about; the NULL case has its own test below.
	if _, err := db.Exec(`
		INSERT INTO euaiact_conformity_assessments
			(id, org_id, system_id, system_name, risk_category, status, version,
			 assessment_date, requirements, created_by, created_at, updated_at,
			 submitted_by, approved_by, rejected_by, rejection_reason)
		VALUES ($1, $2, 'sys-victim-underwriting', 'Victim Credit Underwriting Model',
		        'high-risk', 'draft', 1, NOW(), '[{"id":"r1","status":"met"}]',
		        'victim-compliance-officer@victim.example', NOW(), NOW(),
		        '', '', '', '')`,
		assessID, idorOrgVictim); err != nil {
		t.Fatalf("seed victim assessment: %v", err)
	}

	module, err := NewModule(ModuleConfig{DB: db})
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	router := mux.NewRouter()
	module.RegisterRoutesWithMux(router)

	return &euaiactIDOREnv{db: db, router: router, exportID: exportID, assessID: assessID}
}

func applySQLFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, err := db.Exec(string(b)); err != nil {
		t.Fatalf("apply %s: %v", path, err)
	}
}

// do issues a request through the real router with the given org header.
// An empty org means the header is omitted entirely.
func (e *euaiactIDOREnv) do(t *testing.T, method, path, org, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *strings.Reader
	if body == "" {
		rdr = strings.NewReader("")
	} else {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if org != "" {
		req.Header.Set("X-Org-ID", org)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// assertRefused requires a refusal that leaks nothing about the victim.
//
// 404 (not 403) is the required shape: a distinguishable refusal is a
// cross-organization existence oracle - it tells the attacker the id is real.
// tenantscope.ErrNotOwned carries the same instruction. 400/401 is accepted
// only for the missing-header case, which is checked separately.
func assertRefused(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusNotFound {
		t.Errorf("%s: got status %d, want 404 (a distinguishable refusal is a cross-org existence oracle). body=%s",
			what, rec.Code, truncateBody(rec.Body.String()))
	}
	assertNoVictimData(t, rec, what)
}

// assertNoVictimData fails if any victim-identifying string reached the wire.
// Checking the STATUS alone would miss a refusal that still echoed the row.
func assertNoVictimData(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	body := rec.Body.String()
	for _, needle := range []string{
		idorOrgVictim,
		"victim-secret-export.json",
		"victim-compliance-officer@victim.example",
		"Victim Credit Underwriting Model",
		"sys-victim-underwriting",
	} {
		if strings.Contains(body, needle) {
			t.Errorf("%s: response leaked victim data %q. body=%s", what, needle, truncateBody(body))
		}
	}
}

func truncateBody(s string) string {
	if len(s) > 600 {
		return s[:600] + "...[truncated]"
	}
	return s
}

// TestEUAIAct_CrossOrgExportReadIsRefused is the primary exploit reproduction:
// organization B naming organization A's export id.
func TestEUAIAct_CrossOrgExportReadIsRefused(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/export/"+env.exportID, idorOrgAttacker, "")
	t.Logf("cross-org GET /export/%s as %s -> %d %s", env.exportID, idorOrgAttacker, rec.Code, truncateBody(rec.Body.String()))
	assertRefused(t, rec, "cross-org export read")
}

// TestEUAIAct_CrossOrgExportDownloadIsRefused covers the download variant,
// which resolved no organization at all pre-fix.
func TestEUAIAct_CrossOrgExportDownloadIsRefused(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/export/"+env.exportID+"/download", idorOrgAttacker, "")
	t.Logf("cross-org GET /export/%s/download as %s -> %d %s", env.exportID, idorOrgAttacker, rec.Code, truncateBody(rec.Body.String()))
	assertRefused(t, rec, "cross-org export download")
}

// TestEUAIAct_CrossOrgConformityReadIsRefused covers the conformity by-id read.
func TestEUAIAct_CrossOrgConformityReadIsRefused(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/conformity/"+env.assessID, idorOrgAttacker, "")
	t.Logf("cross-org GET /conformity/%s as %s -> %d %s", env.assessID, idorOrgAttacker, rec.Code, truncateBody(rec.Body.String()))
	assertRefused(t, rec, "cross-org conformity read")
}

// TestEUAIAct_CrossOrgConformityMutationsAreRefused is the one that matters
// most: pre-fix a foreign organization could not merely READ the assessment, it
// could rewrite it, submit it, approve it or reject it. An Article 43 record
// another company can approve is not evidence of anything.
//
// Each mutation is checked for BOTH a refusal and the absence of a persisted
// effect - a handler that 404s after having already written is still a
// mutation.
func TestEUAIAct_CrossOrgConformityMutationsAreRefused(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	before := env.assessmentSnapshot(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"update", http.MethodPut, "/api/v1/euaiact/conformity/" + env.assessID,
			`{"system_name":"ATTACKER OVERWROTE THIS"}`},
		{"submit", http.MethodPost, "/api/v1/euaiact/conformity/" + env.assessID + "/submit", `{}`},
		{"approve", http.MethodPost, "/api/v1/euaiact/conformity/" + env.assessID + "/approve",
			`{"validity_years":5}`},
		{"reject", http.MethodPost, "/api/v1/euaiact/conformity/" + env.assessID + "/reject",
			`{"reason":"attacker rejection"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, tc.method, tc.path, idorOrgAttacker, tc.body)
			t.Logf("cross-org %s %s as %s -> %d %s", tc.method, tc.path, idorOrgAttacker, rec.Code, truncateBody(rec.Body.String()))
			assertRefused(t, rec, "cross-org conformity "+tc.name)
		})
	}

	after := env.assessmentSnapshot(t)
	if before != after {
		t.Errorf("victim assessment was MUTATED by the attacker organization.\n before: %s\n after:  %s", before, after)
	}
}

// TestEUAIAct_ByIDPathsRequireAnOrgHeader pins the fail-closed posture: a
// request with no authenticated scope is refused, never served.
//
// The accepted refusals are 400/401/404 - the module's existing vocabulary for
// "missing header" is 400. What is NOT accepted is a 200: a by-id path that
// answers without an authenticated organization is the un-scoped read this fix
// removes.
func TestEUAIAct_ByIDPathsRequireAnOrgHeader(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/euaiact/export/" + env.exportID},
		{http.MethodGet, "/api/v1/euaiact/export/" + env.exportID + "/download"},
		{http.MethodGet, "/api/v1/euaiact/conformity/" + env.assessID},
	}
	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			rec := env.do(t, p.method, p.path, "", "")
			t.Logf("no-org-header %s %s -> %d %s", p.method, p.path, rec.Code, truncateBody(rec.Body.String()))
			switch rec.Code {
			case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound:
				// refused, as required
			default:
				t.Errorf("got status %d, want a refusal (400/401/404) for a request carrying no authenticated organization. body=%s",
					rec.Code, truncateBody(rec.Body.String()))
			}
			assertNoVictimData(t, rec, "no-org-header "+p.path)
		})
	}
}

// TestEUAIAct_SameOrgAccessStillWorks is the vacuity control.
//
// Without it, a fix that simply 404s EVERYTHING would pass every test above.
// This asserts the victim can still read its own export and its own assessment,
// and that the payload really is the victim's row.
func TestEUAIAct_SameOrgAccessStillWorks(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/export/"+env.exportID, idorOrgVictim, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner read of own export: got %d, want 200. body=%s", rec.Code, truncateBody(rec.Body.String()))
	}
	var export map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &export); err != nil {
		t.Fatalf("owner export response is not JSON: %v (body=%s)", err, truncateBody(rec.Body.String()))
	}
	if export["id"] != env.exportID {
		t.Errorf("owner export read returned id %v, want %s", export["id"], env.exportID)
	}

	rec = env.do(t, http.MethodGet, "/api/v1/euaiact/conformity/"+env.assessID, idorOrgVictim, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner read of own assessment: got %d, want 200. body=%s", rec.Code, truncateBody(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "Victim Credit Underwriting Model") {
		t.Errorf("owner assessment read did not return the victim's own row. body=%s", truncateBody(rec.Body.String()))
	}
}

// TestEUAIAct_WhitespaceOnlyOrgHeaderIsRefused pins the trimming rule from
// rbi/org_scope.go: an untrimmed " " header is non-empty, so it passes an
// `orgID == ""` check and then matches no row - a silent zero-rows failure
// (#3039) that reads to a customer as "our data is gone". It must be treated as
// absent instead.
func TestEUAIAct_WhitespaceOnlyOrgHeaderIsRefused(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/export/"+env.exportID, "   ", "")
	t.Logf("whitespace-org-header GET /export/%s -> %d %s", env.exportID, rec.Code, truncateBody(rec.Body.String()))
	switch rec.Code {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound:
		// refused, as required
	default:
		t.Errorf("got status %d, want a refusal for a whitespace-only organization header. body=%s",
			rec.Code, truncateBody(rec.Body.String()))
	}
	assertNoVictimData(t, rec, "whitespace-org-header")
}

// TestEUAIAct_ReadsTolerateNullableColumns pins a robustness gap found while
// building this suite.
//
// Several columns are NULLABLE in migration 116 with no default -
// euaiact_exports.error / file_path / file_size / record_count, and
// euaiact_conformity_assessments.submitted_by / approved_by / rejected_by /
// rejection_reason - and both readers scanned them into plain Go strings and
// ints. Any row whose optional columns are NULL (a manual insert, a backfill, a
// future migration that adds a column without a default) made the by-id read
// 500 with `converting NULL to string is unsupported`: the record became
// permanently unreadable through the API. The module's own Create writes ”/0,
// so this never fired in normal use, which is exactly why it went unnoticed.
func TestEUAIAct_ReadsTolerateNullableColumns(t *testing.T) {
	env := setupEUAIActIDOREnv(t)

	const nullAssessID = "assess-victim-nullcols"
	if _, err := env.db.Exec(`
		INSERT INTO euaiact_conformity_assessments
			(id, org_id, system_id, system_name, risk_category, status, version,
			 assessment_date, requirements, created_by, created_at, updated_at)
		VALUES ($1, $2, 'sys-victim-nullcols', 'Victim Null Columns Model',
		        'high-risk', 'draft', 1, NOW(), '[]',
		        'victim-compliance-officer@victim.example', NOW(), NOW())`,
		nullAssessID, idorOrgVictim); err != nil {
		t.Fatalf("seed NULL-column assessment: %v", err)
	}

	const nullExportID = "export-victim-nullcols"
	if _, err := env.db.Exec(`
		INSERT INTO euaiact_exports
			(id, org_id, export_type, format, status, progress, requested_by, created_at)
		VALUES ($1, $2, 'full_audit', 'json', 'pending', 0,
		        'victim-compliance-officer@victim.example', NOW())`,
		nullExportID, idorOrgVictim); err != nil {
		t.Fatalf("seed NULL-column export: %v", err)
	}

	rec := env.do(t, http.MethodGet, "/api/v1/euaiact/conformity/"+nullAssessID, idorOrgVictim, "")
	if rec.Code != http.StatusOK {
		t.Errorf("owner read of an assessment with NULL workflow columns: got %d, want 200. body=%s",
			rec.Code, truncateBody(rec.Body.String()))
	} else if !strings.Contains(rec.Body.String(), "Victim Null Columns Model") {
		t.Errorf("owner assessment read did not return the row. body=%s", truncateBody(rec.Body.String()))
	}

	rec = env.do(t, http.MethodGet, "/api/v1/euaiact/export/"+nullExportID, idorOrgVictim, "")
	if rec.Code != http.StatusOK {
		t.Errorf("owner read of an export with NULL optional columns: got %d, want 200. body=%s",
			rec.Code, truncateBody(rec.Body.String()))
	} else if !strings.Contains(rec.Body.String(), nullExportID) {
		t.Errorf("owner export read did not return the row. body=%s", truncateBody(rec.Body.String()))
	}
}

// assessmentSnapshot returns a stable string of the victim assessment's mutable
// fields, read on the master connection so RLS cannot hide a mutation from the
// assertion.
func (e *euaiactIDOREnv) assessmentSnapshot(t *testing.T) string {
	t.Helper()
	var (
		systemName, status string
		version            int
		submittedBy        sql.NullString
		approvedBy         sql.NullString
		rejectedBy         sql.NullString
		rejectionReason    sql.NullString
		updatedAt          time.Time
	)
	err := e.db.QueryRow(`
		SELECT system_name, status, version, submitted_by, approved_by, rejected_by, rejection_reason, updated_at
		FROM euaiact_conformity_assessments WHERE id = $1`, e.assessID).
		Scan(&systemName, &status, &version, &submittedBy, &approvedBy, &rejectedBy, &rejectionReason, &updatedAt)
	if err != nil {
		t.Fatalf("snapshot victim assessment: %v", err)
	}
	return fmt.Sprintf("name=%q status=%s version=%d submitted_by=%q approved_by=%q rejected_by=%q reason=%q updated_at=%s",
		systemName, status, version, submittedBy.String, approvedBy.String, rejectedBy.String,
		rejectionReason.String, updatedAt.UTC().Format(time.RFC3339Nano))
}
