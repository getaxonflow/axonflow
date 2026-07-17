// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

var errTestDB = errors.New("db boom")

// auditDetailColumns is the exact column set GetAuditLogByID selects, in order.
var auditDetailColumns = []string{
	"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
	"client_id", "tenant_id", "org_id", "request_type", "query",
	"policy_decision", "policy_details", "provider", "model", "response_time_ms",
	"tokens_used", "cost", "redacted_fields", "error_message", "response_sample",
	"compliance_flags", "correlation_id", "decision_id", "plane", "session_id",
}

func newMockAuditLogger(t *testing.T) (*AuditLogger, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return &AuditLogger{db: db}, mock, func() { _ = db.Close() }
}

// withGlobalAuditLogger swaps the package global for the duration of a handler
// test and restores it afterward.
func withGlobalAuditLogger(l *AuditLogger, fn func()) {
	prev := auditLogger
	auditLogger = l
	defer func() { auditLogger = prev }()
	fn()
}

// --- GetAuditLogByID -------------------------------------------------------

func TestGetAuditLogByID_Success_ReturnsFullRedactedRecord(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	ts := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	// query + response_sample are already-redacted values as stored; the detail
	// path must return them verbatim (never re-derive raw PII).
	row := sqlmock.NewRows(auditDetailColumns).AddRow(
		"aud-1", "req-1", ts, 7, "dev@acme.com", "agent",
		"acme", "acme", "org-acme", "tool_call", "Tool: bash",
		"blocked", []byte(`{"policy_name":"sys_dangerous","tool_name":"bash","reasons":["rm -rf"],"latency_ms":3}`),
		"openai", "gpt-4o", int64(12), 0, 0.0,
		[]byte(`["$.ssn"]`), "", "email [REDACTED:email]",
		[]byte(`[]`), "corr-1", "dec-1", "mcp", "sess-1",
	)
	// The tenant id MUST be an argument — this is the cross-tenant leak guard.
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("aud-1", "acme").
		WillReturnRows(row)

	entry, err := al.GetAuditLogByID("aud-1", "acme")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if entry.ID != "aud-1" || entry.TenantID != "acme" {
		t.Fatalf("wrong entry: %+v", entry)
	}
	if entry.Query != "Tool: bash" || entry.ResponseSample != "email [REDACTED:email]" {
		t.Fatalf("stored (redacted) content not returned verbatim: %q / %q", entry.Query, entry.ResponseSample)
	}
	if entry.CorrelationID != "corr-1" || entry.DecisionID != "dec-1" || entry.Plane != "mcp" {
		t.Fatalf("canonical decision columns missing: %+v", entry)
	}
	if entry.SessionID != "sess-1" {
		t.Fatalf("session_id (WS-1 core/129) not surfaced in detail: %q", entry.SessionID)
	}
	if entry.PolicyDetails["tool_name"] != "bash" {
		t.Fatalf("policy_details not surfaced: %+v", entry.PolicyDetails)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetAuditLogByID_NotFound(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("missing", "acme").
		WillReturnError(sql.ErrNoRows)

	_, err := al.GetAuditLogByID("missing", "acme")
	if err != ErrAuditLogNotFound {
		t.Fatalf("want ErrAuditLogNotFound, got %v", err)
	}
}

func TestGetAuditLogByID_NilDB(t *testing.T) {
	al := &AuditLogger{db: nil}
	if _, err := al.GetAuditLogByID("x", "acme"); err != ErrAuditLogNotFound {
		t.Fatalf("want ErrAuditLogNotFound on nil db, got %v", err)
	}
}

// --- auditGetByIDHandler ---------------------------------------------------

func TestAuditGetByIDHandler_MissingTenant_401(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/aud-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "aud-1"})
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})
}

func TestAuditGetByIDHandler_NotFound_404(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("nope", "acme").WillReturnError(sql.ErrNoRows)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/nope", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "nope"})
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("want 404, got %d", rr.Code)
		}
	})
}

// --- ExportAuditLogs -------------------------------------------------------

var auditExportColumns = []string{
	"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
	"client_id", "tenant_id", "org_id", "request_type", "query",
	"policy_decision", "policy_details", "provider", "model", "response_time_ms",
	"tokens_used", "cost", "redacted_fields", "error_message", "response_sample",
	"correlation_id", "session_id",
}

func TestExportAuditLogs_RequiresTenantScope(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	if _, _, err := al.ExportAuditLogs(auditSearchCriteria{TenantID: ""}); err == nil {
		t.Fatalf("expected error when tenant scope missing")
	}
}

func TestExportAuditLogs_TruncationDetected(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	ts := time.Now().UTC()
	rows := sqlmock.NewRows(auditExportColumns)
	// cap+1 rows returned => truncated true, and only cap returned.
	crit := auditSearchCriteria{TenantID: "acme", Limit: 2}
	for i := 0; i < 3; i++ { // Limit(2)+1
		rows.AddRow("id", "req", ts, 1, "u@a.com", "agent", "acme", "acme",
			"org", "llm_call", "q", "allowed", []byte(`{}`), "", "", int64(0), 0, 0.0,
			[]byte(`[]`), "", "", "", "")
	}
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("acme").
		WillReturnRows(rows)

	got, truncated, err := al.ExportAuditLogs(crit)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncated=true when cap+1 rows returned")
	}
	if len(got) != 2 {
		t.Fatalf("want cap(2) rows returned, got %d", len(got))
	}
}

// --- auditExportHandler ----------------------------------------------------

func TestAuditExportHandler_MissingTenant_401(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=csv", strings.NewReader(`{}`))
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})
}

func TestAuditExportHandler_BadFormat_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=xml", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditExportHandler_CSV_HeaderAndDisposition(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-9", "req-9", ts, 1, "dev@acme.com", "agent", "acme", "acme",
		"org", "tool_call", "Tool: bash", "blocked", []byte(`{}`), "", "",
		int64(5), 0, 0.0, []byte(`[]`), "", "resp [REDACTED:ssn]", "corr-9", "sess-9")
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("acme").WillReturnRows(rows)

	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=csv", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
			t.Fatalf("want text/csv, got %q", ct)
		}
		if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
			t.Fatalf("bad content-disposition: %q", cd)
		}
		recs, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("csv parse: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("want header+1 row, got %d", len(recs))
		}
		if strings.Join(recs[0], ",") != strings.Join(auditExportCSVHeader, ",") {
			t.Fatalf("csv header mismatch: %v", recs[0])
		}
		// redacted content preserved verbatim in the export
		if recs[1][8] != "resp [REDACTED:ssn]" {
			t.Fatalf("response_sample not preserved: %q", recs[1][8])
		}
	})
}

func TestAuditExportHandler_JSON_Body(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-j", "req-j", ts, 1, "dev@acme.com", "agent", "acme", "acme",
		"org", "llm_call", "hi", "allowed", []byte(`{}`), "", "", int64(1), 0, 0.0,
		[]byte(`[]`), "", "", "", "")
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("acme").WillReturnRows(rows)

	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		var payload struct {
			Entries   []AuditEntry `json:"entries"`
			Count     int          `json:"count"`
			Truncated bool         `json:"truncated"`
			RowCap    int          `json:"row_cap"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json: %v (%s)", err, rr.Body.String())
		}
		if payload.Count != 1 || payload.RowCap != auditExportMaxRows {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	})
}

// TestAuditExportHandler_SessionIDFilter pins the HTTP→SQL wiring of the
// session_id export filter, mirroring TestAuditSearchHandler_SessionIDFilter
// (#2857): the search handler gained the field in v9.6.1 but the export
// handler's body-decode struct never carried it, so a session-filtered export
// silently returned the whole tenant window with a 200. WithArgs is the real
// assertion — it fails unless the handler forwarded session_id into the query.
// This bug class is invisible to ExportAuditLogs-level tests (the criteria
// struct already had the field), so it is pinned at the handler.
func TestAuditExportHandler_SessionIDFilter(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-s", "req-s", ts, 1, "dev@acme.com", "agent", "acme", "acme",
		"org", "llm_call", "session query", "allowed", []byte(`{}`), "", "",
		int64(3), 0, 0.0, []byte(`[]`), "", "", "corr-s", "sess-42")
	// Tenant from the trusted header ($1), session filter from the body ($2).
	mock.ExpectQuery("SELECT id, request_id, timestamp(.+)session_id = ").
		WithArgs("acme", "sess-42").
		WillReturnRows(rows)

	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json",
			strings.NewReader(`{"session_id":"sess-42"}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		var payload struct {
			Entries []AuditEntry `json:"entries"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
			t.Fatalf("json: %v", err)
		}
		if len(payload.Entries) != 1 || payload.Entries[0].SessionID != "sess-42" {
			t.Fatalf("want exactly the sess-42 entry back, got %+v", payload.Entries)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet: %v", err)
		}
	})
}

// TestAuditExportHandler_PluginBatch1Filters pins the HTTP->SQL wiring of the
// decision_id / policy_name / override_id filters on the export path. Regression
// it guards: SearchAuditLogs honors these three, but the export handler's
// body-decode struct dropped them, so a filtered export silently returned the
// whole tenant window (the same silent-dropped-filter bug class #2857 fixed for
// session_id). WithArgs is the real assertion — it fails unless the handler
// actually forwards the value into the query.
func TestAuditExportHandler_PluginBatch1Filters(t *testing.T) {
	ts := time.Now().UTC()
	cases := []struct {
		name    string
		body    string
		sqlFrag string
		argVal  string
	}{
		{"decision_id", `{"decision_id":"dec-1"}`, "policy_details->>'decision_id' = ", "dec-1"},
		{"override_id", `{"override_id":"ovr-1"}`, "policy_details->>'override_id' = ", "ovr-1"},
		{"policy_name", `{"policy_name":"pii-block"}`, "jsonb_array_elements", "pii-block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			al, mock, done := newMockAuditLogger(t)
			defer done()
			rows := sqlmock.NewRows(auditExportColumns).AddRow(
				"aud-b", "req-b", ts, 1, "dev@acme.com", "agent", "acme", "acme",
				"org", "llm_call", "q", "blocked", []byte(`{}`), "", "",
				int64(3), 0, 0.0, []byte(`[]`), "", "", "corr-b", "sess-b")
			// Tenant from the trusted header ($1), the filter value from the body ($2).
			mock.ExpectQuery("SELECT id, request_id, timestamp(.+)" + tc.sqlFrag).
				WithArgs("acme", tc.argVal).
				WillReturnRows(rows)
			withGlobalAuditLogger(al, func() {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json",
					strings.NewReader(tc.body))
				req.Header.Set("X-Tenant-ID", "acme")
				rr := httptest.NewRecorder()
				auditExportHandler(rr, req)
				if rr.Code != http.StatusOK {
					t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatalf("filter %q not forwarded into the export query (silently dropped): %v", tc.name, err)
				}
			})
		})
	}
}

// TestAuditExportHandler_CSV_SessionColumn pins session_id as the last CSV
// column so a session-filtered export identifies its rows' session membership.
func TestAuditExportHandler_CSV_SessionColumn(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-c", "req-c", ts, 1, "dev@acme.com", "agent", "acme", "acme",
		"org", "llm_call", "q", "allowed", []byte(`{}`), "", "",
		int64(0), 0, 0.0, []byte(`[]`), "", "", "corr-c", "sess-c1")
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("acme").WillReturnRows(rows)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=csv", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		recs, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("csv parse: %v", err)
		}
		if recs[0][len(recs[0])-1] != "session_id" {
			t.Fatalf("want session_id as last CSV column, got header %v", recs[0])
		}
		if recs[1][len(recs[1])-1] != "sess-c1" {
			t.Fatalf("want sess-c1 in session_id cell, got %v", recs[1])
		}
	})
}

// --- ReportByAction --------------------------------------------------------

func TestReportByAction_SeedsFullVerdictSetAndFolds(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()

	// count query: legacy spelling "denied" must fold into canonical "blocked".
	countRows := sqlmock.NewRows([]string{"policy_decision", "count", "sum"}).
		AddRow("allowed", 8, int64(80)).
		AddRow("denied", 2, int64(40)) // legacy spelling of blocked
	mock.ExpectQuery("GROUP BY policy_decision").
		WillReturnRows(countRows)
	topRows := sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}).
		AddRow("sys_dangerous", 2, 2)
	mock.ExpectQuery("GROUP BY policy_details").
		WillReturnRows(topRows)

	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	rep, err := al.ReportByAction("acme", "", "", "", start, end)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rep.Total != 10 {
		t.Fatalf("want total 10, got %d", rep.Total)
	}
	if rep.ByAction["blocked"] != 2 {
		t.Fatalf("legacy 'denied' did not fold into 'blocked': %+v", rep.ByAction)
	}
	if rep.ByAction["allowed"] != 8 {
		t.Fatalf("allowed count wrong: %+v", rep.ByAction)
	}
	// full canonical set seeded even with zero rows
	for _, v := range []string{"allowed", "blocked", "redacted", "needs_approval", "error"} {
		if _, ok := rep.ByAction[v]; !ok {
			t.Fatalf("verdict %q missing from ByAction (should be seeded to 0)", v)
		}
	}
	if rep.AvgLatencyMs != 12.0 { // (80+40)/10
		t.Fatalf("avg latency wrong: %v", rep.AvgLatencyMs)
	}
	if len(rep.TopPolicies) != 1 || rep.TopPolicies[0].PolicyName != "sys_dangerous" {
		t.Fatalf("top policies wrong: %+v", rep.TopPolicies)
	}
}

func TestReportByAction_NilDB_ReturnsSeededEmpty(t *testing.T) {
	al := &AuditLogger{db: nil}
	rep, err := al.ReportByAction("acme", "", "", "", time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(rep.ByAction) != 5 || rep.Total != 0 {
		t.Fatalf("want seeded-empty report, got %+v", rep)
	}
}

// --- auditReportHandler ----------------------------------------------------

func TestAuditReportHandler_MissingTenant_401(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		body := `{"start_time":"2026-06-01T00:00:00Z","end_time":"2026-07-01T00:00:00Z"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report", strings.NewReader(body))
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_BadDateRange_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		// end before start
		body := `{"start_time":"2026-07-01T00:00:00Z","end_time":"2026-06-01T00:00:00Z"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_Success_200(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("GROUP BY policy_decision").
		WillReturnRows(sqlmock.NewRows([]string{"policy_decision", "count", "sum"}).AddRow("allowed", 3, int64(30)))
	mock.ExpectQuery("GROUP BY policy_details").
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))
	withGlobalAuditLogger(al, func() {
		body := `{"start_time":"2026-06-01T00:00:00Z","end_time":"2026-07-01T00:00:00Z","user_email":"dev@acme.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		var rep ActionReport
		if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
			t.Fatalf("json: %v", err)
		}
		if rep.ByAction["allowed"] != 3 {
			t.Fatalf("wrong report: %+v", rep)
		}
	})
}

// --- additional coverage: handler success + validation + filter branches ----

func TestAuditGetByIDHandler_Success_200(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	row := sqlmock.NewRows(auditDetailColumns).AddRow(
		"aud-ok", "req", ts, 1, "dev@acme.com", "agent", "acme", "acme",
		"org", "llm_call", "hi", "allowed", []byte(`{}`), "", "", int64(1), 0, 0.0,
		[]byte(`[]`), "", "", []byte(`[]`), "", "", "", "")
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("aud-ok", "acme").WillReturnRows(row)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/aud-ok", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "aud-ok"})
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
		}
		var e AuditEntry
		if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || e.ID != "aud-ok" {
			t.Fatalf("bad body: %v %s", err, rr.Body.String())
		}
	})
}

func TestAuditGetByIDHandler_EmptyID_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/", nil)
		req = mux.SetURLVars(req, map[string]string{"id": ""})
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditGetByIDHandler_NilLogger_503(t *testing.T) {
	withGlobalAuditLogger(nil, func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/x", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "x"})
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})
}

func TestExportAuditLogs_NilDB_Empty(t *testing.T) {
	al := &AuditLogger{db: nil}
	got, tr, err := al.ExportAuditLogs(auditSearchCriteria{TenantID: "acme"})
	if err != nil || tr || len(got) != 0 {
		t.Fatalf("want empty untruncated, got %v %v %d", err, tr, len(got))
	}
}

func TestExportAuditLogs_AllFilterBranches(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	rows := sqlmock.NewRows(auditExportColumns)
	// tenant, userEmail, clientID, start, end, action-array
	mock.ExpectQuery("SELECT id, request_id, timestamp").
		WithArgs("acme", "dev@acme.com", "cli", start, end, sqlmock.AnyArg()).
		WillReturnRows(rows)
	_, _, err := al.ExportAuditLogs(auditSearchCriteria{
		TenantID: "acme", UserEmail: "dev@acme.com", ClientID: "cli",
		Action: "blocked", StartTime: start, EndTime: end,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet: %v", err)
	}
}

func TestAuditExportHandler_NilLogger_503(t *testing.T) {
	withGlobalAuditLogger(nil, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})
}

func TestAuditExportHandler_MalformedBody_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json", strings.NewReader(`{bad json`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestReportByAction_WithUserAndActionFilters(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("GROUP BY policy_decision").
		WillReturnRows(sqlmock.NewRows([]string{"policy_decision", "count", "sum"}).AddRow("blocked", 4, int64(40)))
	mock.ExpectQuery("GROUP BY policy_details").
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now()
	rep, err := al.ReportByAction("acme", "", "dev@acme.com", "blocked", start, end)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rep.ByAction["blocked"] != 4 || rep.Total != 4 {
		t.Fatalf("bad report: %+v", rep)
	}
}

func TestAuditReportHandler_OptionsPreflight(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/report", nil)
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200 for OPTIONS, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_InvalidBody_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report", strings.NewReader(`{bad`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_InvalidStartTime_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report",
			strings.NewReader(`{"start_time":"nope","end_time":"2026-07-01T00:00:00Z"}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_RangeExceedsYear_400(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report",
			strings.NewReader(`{"start_time":"2024-01-01T00:00:00Z","end_time":"2026-01-01T00:00:00Z"}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d", rr.Code)
		}
	})
}

func TestAuditReportHandler_NilLogger_503(t *testing.T) {
	withGlobalAuditLogger(nil, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/report",
			strings.NewReader(`{"start_time":"2026-06-01T00:00:00Z","end_time":"2026-07-01T00:00:00Z"}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503, got %d", rr.Code)
		}
	})
}

func TestAuditExportHandler_NoTruncationHeaderOnSmallResult(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	// Small result (below the cap) must NOT carry the truncation header. The
	// cap-hit path itself is unit-tested at the method level in
	// TestExportAuditLogs_TruncationDetected (forcing 50k+ rows through the
	// handler is impractical for a unit test).
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"id", "req", ts, 1, "u@a.com", "agent", "acme", "acme", "org",
		"llm_call", "q", "allowed", []byte(`{}`), "", "", int64(0), 0, 0.0, []byte(`[]`), "", "", "", "")
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("acme").WillReturnRows(rows)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		if rr.Header().Get("X-Audit-Export-Truncated") != "" {
			t.Fatalf("did not expect truncation header on small result")
		}
	})
}

func TestAuditExportHandler_DBError_500(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("acme").
		WillReturnError(errTestDB)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("want 500, got %d", rr.Code)
		}
	})
}

func TestAuditExportHandler_OptionsPreflight(t *testing.T) {
	al, _, done := newMockAuditLogger(t)
	defer done()
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit/export", nil)
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200 for OPTIONS, got %d", rr.Code)
		}
	})
}

func TestCSVFormulaSafe(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"normal text":      "normal text",
		"=cmd|'/c calc'!A": "'=cmd|'/c calc'!A",
		"+1234567":         "'+1234567",
		"-5":               "'-5",
		"@SUM(A1)":         "'@SUM(A1)",
		"SELECT * FROM t":  "SELECT * FROM t",
	}
	for in, want := range cases {
		if got := csvFormulaSafe(in); got != want {
			t.Fatalf("csvFormulaSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditExportHandler_CSV_NeutralizesFormula(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	// A malicious query text that got audited (leading '=').
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-x", "req", ts, 1, "dev@acme.com", "agent", "acme", "acme", "org",
		"tool_call", "=cmd|'/c calc'!A1", "blocked", []byte(`{}`), "", "",
		int64(0), 0, 0.0, []byte(`[]`), "", "", "", "")
	mock.ExpectQuery("SELECT id, request_id, timestamp").WithArgs("acme").WillReturnRows(rows)
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/export?format=csv", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		recs, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("csv parse: %v", err)
		}
		// query column index 7 in auditExportCSVHeader
		if recs[1][7] != "'=cmd|'/c calc'!A1" {
			t.Fatalf("formula not neutralized: %q", recs[1][7])
		}
	})
}

// override_lifecycle rows (written by LogOverrideEvent) are NOT one of the five
// canonical verdicts; the report must exclude them so Total keeps summing to the
// per-verdict cards and AvgLatencyMs isn't diluted by their zero latency.
func TestReportByAction_ExcludesOverrideLifecycle(t *testing.T) {
	al, mock, done := newMockAuditLogger(t)
	defer done()
	mock.ExpectQuery("GROUP BY policy_decision").
		WillReturnRows(sqlmock.NewRows([]string{"policy_decision", "count", "sum"}).
			AddRow("blocked", 2, int64(40)).
			AddRow("override_lifecycle", 5, int64(0))) // non-verdict: must be skipped
	mock.ExpectQuery("GROUP BY policy_details").
		WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))
	rep, err := al.ReportByAction("acme", "", "", "", time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if rep.Total != 2 {
		t.Fatalf("override_lifecycle inflated Total: want 2, got %d", rep.Total)
	}
	if _, ok := rep.ByAction["override_lifecycle"]; ok {
		t.Fatalf("phantom by_action key 'override_lifecycle' present: %+v", rep.ByAction)
	}
	if len(rep.ByAction) != 5 {
		t.Fatalf("by_action must have exactly the 5 canonical verdicts, got %d: %+v", len(rep.ByAction), rep.ByAction)
	}
	if rep.AvgLatencyMs != 20.0 { // 40/2, NOT 40/7
		t.Fatalf("AvgLatencyMs diluted by lifecycle rows: want 20, got %v", rep.AvgLatencyMs)
	}
}
