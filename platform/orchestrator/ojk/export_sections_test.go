//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Unit coverage for the OJK export section dispatcher, the section queries, and
// the framework-driven composition (#3242).
//
// These use sqlmock so the REAL SQL text and the REAL bound arguments are
// exercised. That matters here more than usual: the whole class of defect this
// workstream removes is "the section returned nothing", which a hand-built
// fixture of already-parsed records cannot distinguish from "the query was never
// issued". Every populated case asserts on the bound org argument too, so a
// query that silently dropped its tenancy predicate fails.

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

var (
	secStart = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	// secEnd is the END-OF-DAY form of 2026-07-31, matching what ExportAuditData
	// binds after extending the request's end_date.
	secEnd   = time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC).Add(24*time.Hour - time.Nanosecond)
	secRowTS = time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
)

// -----------------------------------------------------------------------------
// Exhaustiveness
// -----------------------------------------------------------------------------

// TestEveryDeclaredDataTypeHasASectionHandler is the standing guard against the
// defect this workstream removed.
//
// OJKDataTypeHITLOversight and OJKDataTypePIIRedactions were DECLARED constants,
// accepted by the request validator, documented in the export contract -- and
// had no case in the dispatcher's switch, so requesting either returned a
// successful, empty section. Nothing in the codebase could notice, because a
// switch with a `default: continue` is exhaustive as far as the compiler is
// concerned.
//
// This test parses types.go for the DECLARED OJKAuditDataType constants (rather
// than reading a hand-maintained list, which would drift the same way) and
// requires each one to be either the "all" alias or to have a section handler.
func TestEveryDeclaredDataTypeHasASectionHandler(t *testing.T) {
	declared := declaredOJKDataTypes(t)
	if len(declared) < 7 {
		t.Fatalf("parsed only %d OJKAuditDataType constants from the package (%v); the parser is not finding the declarations it exists to police", len(declared), declared)
	}

	handlers := ojkSectionHandlers()
	all := make(map[OJKAuditDataType]bool, len(ojkAllDataTypes()))
	for _, dt := range ojkAllDataTypes() {
		all[dt] = true
	}

	for _, dt := range declared {
		if dt == OJKDataTypeAll {
			continue
		}
		if !all[dt] {
			t.Errorf("data type %q is declared but is not in ojkAllDataTypes(); it can never be selected by a framework", dt)
		}
		if _, ok := handlers[dt]; !ok {
			t.Errorf("data type %q is declared but has NO section handler; requesting it would produce an empty section", dt)
		}
	}

	// And the converse: no handler for a type that is not declared.
	for dt := range handlers {
		found := false
		for _, d := range declared {
			if d == dt {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("handler registered for %q, which is not a declared OJKAuditDataType constant", dt)
		}
	}
}

// declaredOJKDataTypes returns every constant of type OJKAuditDataType declared
// anywhere in this PACKAGE.
//
// It parses the whole directory rather than types.go alone, and accepts both
// declaration forms -- `X OJKAuditDataType = "x"` and `X = OJKAuditDataType("x")`
// -- because this is the sole standing defence against re-creating the
// hitl_oversight / pii_redactions defect, and a constant it cannot see is a
// constant that can silently ship without a handler. The magnitude floor in the
// caller catches parser breakage; these two widenings catch omission.
func declaredOJKDataTypes(t *testing.T) []OJKAuditDataType {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	seen := make(map[OJKAuditDataType]bool)
	var out []OJKAuditDataType
	add := func(v string) {
		dt := OJKAuditDataType(strings.Trim(v, `"`))
		if dt == "" || seen[dt] {
			return
		}
		seen[dt] = true
		out = append(out, dt)
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				decl, ok := n.(*ast.GenDecl)
				if !ok || decl.Tok != token.CONST {
					return true
				}
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					// Form 1: an explicitly typed const block.
					typed := false
					if ident, ok := vs.Type.(*ast.Ident); ok && ident.Name == "OJKAuditDataType" {
						typed = true
					}
					for _, v := range vs.Values {
						if lit, ok := v.(*ast.BasicLit); ok && lit.Kind == token.STRING && typed {
							add(lit.Value)
							continue
						}
						// Form 2: an explicit conversion, OJKAuditDataType("x").
						call, ok := v.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							continue
						}
						fn, ok := call.Fun.(*ast.Ident)
						if !ok || fn.Name != "OJKAuditDataType" {
							continue
						}
						if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							add(lit.Value)
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// TestExportAuditData_UnknownDataTypeYieldsExplicitError is written to FAIL on
// the pre-fix implementation: the old dispatcher's `default: continue` swallowed
// an unrecognised type and produced a 200 with no mention of it anywhere.
//
// The assertion is deliberately on the SECTION STATUS, not just on an error
// string somewhere in the body: a regulator consumer must be able to see, per
// requested section, that the platform did not serve it.
func TestExportAuditData_UnknownDataTypeYieldsExplicitError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	// NOTE on what this does and does not observe. ExportAuditData always
	// computes a compliance score, which issues readiness queries the mock
	// rejects (they degrade to "unknown"), so this is NOT a "no statement was
	// issued" test -- and sqlmock's ExpectationsWereMet only verifies that
	// EXPECTED calls were consumed, it does not fail on unexpected ones. The
	// assertion below is on the SECTION STATUS, which is what a regulator
	// consumer actually reads.

	svc := &ojkAuditExportServiceImpl{db: db}
	resp, err := svc.ExportAuditData(context.Background(), "org-a", &OJKAuditExportRequest{
		StartDate: "2026-07-01",
		EndDate:   "2026-07-31",
		DataTypes: []OJKAuditDataType{"quantum_entanglement_log"},
	})
	if err != nil {
		t.Fatalf("ExportAuditData must not fail the whole export on one bad section: %v", err)
	}
	if len(resp.Summary.Sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(resp.Summary.Sections))
	}
	sec := resp.Summary.Sections[0]
	if sec.DataType != "quantum_entanglement_log" {
		t.Errorf("section data_type = %q, want the requested value echoed back", sec.DataType)
	}
	if sec.ReportState != OJKReportStateNotAvailable {
		t.Errorf("report_state = %q, want %q", sec.ReportState, OJKReportStateNotAvailable)
	}
	if sec.Error == "" {
		t.Fatal("an unknown data type produced NO error: this is the silent-empty-section defect")
	}
	if !strings.Contains(sec.Error, "quantum_entanglement_log") {
		t.Errorf("error %q does not name the offending data type", sec.Error)
	}
	if !strings.Contains(sec.Error, "policy_violations") {
		t.Errorf("error %q does not list the supported data types", sec.Error)
	}
	if resp.Summary.ReportState != OJKReportStateNotAvailable {
		t.Errorf("summary report_state = %q, want %q when every section is unavailable", resp.Summary.ReportState, OJKReportStateNotAvailable)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestExportAuditData_OneBadSectionDoesNotKillTheGoodOnes: an unknown type
// alongside a real one must leave the real section populated.
func TestExportAuditData_OneBadSectionDoesNotKillTheGoodOnes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}).
			AddRow("a-1", secRowTS, "SG", "pasal_56b_dpa"))

	svc := &ojkAuditExportServiceImpl{db: db}
	resp, err := svc.ExportAuditData(context.Background(), "org-a", &OJKAuditExportRequest{
		StartDate: "2026-07-01",
		EndDate:   "2026-07-31",
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder, "not_a_type"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byType := sectionsByType(resp)
	if byType[OJKDataTypeCrossBorder].ReportState != OJKReportStatePopulated {
		t.Errorf("cross_border report_state = %q, want populated", byType[OJKDataTypeCrossBorder].ReportState)
	}
	if byType["not_a_type"].Error == "" {
		t.Error("the unknown type must still carry an explicit error")
	}
	if resp.Summary.ReportState != OJKReportStatePopulated {
		t.Errorf("summary report_state = %q, want populated (one bad section must not mask real evidence)", resp.Summary.ReportState)
	}
	if resp.Summary.TotalRecords != 1 {
		t.Errorf("total_records = %d, want 1", resp.Summary.TotalRecords)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func sectionsByType(resp *OJKAuditExportResponse) map[OJKAuditDataType]OJKSectionStatus {
	out := make(map[OJKAuditDataType]OJKSectionStatus, len(resp.Summary.Sections))
	for _, s := range resp.Summary.Sections {
		out[s.DataType] = s
	}
	return out
}

// -----------------------------------------------------------------------------
// Report state
// -----------------------------------------------------------------------------

func TestRollUpReportState(t *testing.T) {
	pop := OJKSectionStatus{ReportState: OJKReportStatePopulated}
	empty := OJKSectionStatus{ReportState: OJKReportStateEnabledEmpty}
	gone := OJKSectionStatus{ReportState: OJKReportStateNotAvailable}

	cases := []struct {
		name string
		in   []OJKSectionStatus
		want OJKReportState
	}{
		{"no sections", nil, OJKReportStateNotAvailable},
		{"all populated", []OJKSectionStatus{pop, pop}, OJKReportStatePopulated},
		{"all empty", []OJKSectionStatus{empty, empty}, OJKReportStateEnabledEmpty},
		{"all unavailable", []OJKSectionStatus{gone, gone}, OJKReportStateNotAvailable},
		{"one populated among unavailable", []OJKSectionStatus{gone, pop}, OJKReportStatePopulated},
		{"empty beside unavailable is not 'not_available'", []OJKSectionStatus{gone, empty}, OJKReportStateEnabledEmpty},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rollUpReportState(c.in); got != c.want {
				t.Errorf("rollUpReportState = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEmptySectionIsEnabledEmptyNotNotAvailable is the honest-empty contract:
// a served section with zero rows must NOT read as "module not enabled".
func TestEmptySectionIsEnabledEmptyNotNotAvailable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-quiet", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}))

	svc := &ojkAuditExportServiceImpl{db: db}
	resp, err := svc.ExportAuditData(context.Background(), "org-quiet", &OJKAuditExportRequest{
		StartDate: "2026-07-01", EndDate: "2026-07-31",
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sec := resp.Summary.Sections[0]
	if sec.ReportState != OJKReportStateEnabledEmpty {
		t.Errorf("report_state = %q, want %q for a served section with no rows", sec.ReportState, OJKReportStateEnabledEmpty)
	}
	if sec.Error != "" {
		t.Errorf("an honest empty section must carry no error, got %q", sec.Error)
	}
}

// TestMissingTableIsNotAvailableNotEmpty: the enterprise/137 migration not being
// applied must NOT render as "no PII was detected".
func TestMissingTableIsNotAvailableNotEmpty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// withOrgScope opens a transaction first.
	mock.ExpectBegin()
	mock.ExpectExec(`set_config`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM indonesia_pii_detection_events`).
		WillReturnError(&pq.Error{Code: "42P01", Message: `relation "indonesia_pii_detection_events" does not exist`})
	mock.ExpectRollback()

	svc := &ojkAuditExportServiceImpl{db: db}
	records, res := svc.queryPIIRedactions(context.Background(), "org-a", secStart, secEnd)
	if !res.unavailable {
		t.Fatalf("a missing table must be classified unavailable, got %+v", res)
	}
	if res.err == nil || !strings.Contains(res.err.Error(), "migration 137") {
		t.Errorf("error %v does not tell the operator which migration is missing", res.err)
	}
	if records == nil {
		t.Error("records must be a non-nil empty slice")
	}
}

// TestIsUndefinedTableErr_DoesNotMisclassifyPermissionDenied is the fail-open
// guard. The sibling SEBI helper substring-matches the word "relation", which
// "permission denied for relation X" also contains -- so a PRIVILEGE failure is
// reported as "table absent" and the section renders as a confident empty. That
// is the same shape as probing information_schema under a role that cannot see
// the table.
func TestIsUndefinedTableErr_DoesNotMisclassifyPermissionDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sqlstate 42P01", &pq.Error{Code: "42P01", Message: `relation "x" does not exist`}, true},
		{"sqlstate 42501 permission denied", &pq.Error{Code: "42501", Message: `permission denied for relation indonesia_pii_detection_events`}, false},
		{"plain permission denied text", errors.New("pq: permission denied for relation audit_logs"), false},
		{"connection reset", errors.New("connection reset by peer"), false},
		{"driver bad conn", driver.ErrBadConn, false},
		{"sqlite-shaped text", errors.New("no such table: hitl_approval_queue"), true},
		{"wrapped 42P01", fmt.Errorf("querying: %w", &pq.Error{Code: "42P01"}), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUndefinedTableErr(c.err); got != c.want {
				t.Errorf("isUndefinedTableErr(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Section queries: tenancy predicate + shape
// -----------------------------------------------------------------------------

// TestSectionQueriesBindTheOrgAndOnlyTheOrg drives every audit_logs-backed
// section and asserts the org is the FIRST bound argument. sqlmock's WithArgs
// fails the query if the bound value differs, so a query that dropped its
// tenancy predicate -- or reintroduced the `(tenant_id = $1 OR org_id = $1)`
// conflation with a second binding -- fails here.
func TestSectionQueriesBindTheOrgAndOnlyTheOrg(t *testing.T) {
	type queryCase struct {
		name    string
		columns []string
		row     []driver.Value
		run     func(svc *ojkAuditExportServiceImpl) (int, sectionResult)
	}

	cases := []queryCase{
		{
			name:    "policy_violations",
			columns: []string{"id", "timestamp", "policy_id", "policy_decision", "reason", "plane", "tenant_id"},
			row:     []driver.Value{"al-1", secRowTS, "indonesia_pii_protection", "blocked", "Critical Indonesia PII detected (NIK or NPWP)", "gateway", "tenant-x"},
			run: func(svc *ojkAuditExportServiceImpl) (int, sectionResult) {
				recs, res := svc.queryPolicyViolations(context.Background(), "org-a", secStart, secEnd)
				return len(recs), res
			},
		},
		{
			name:    "llm_calls",
			columns: []string{"id", "timestamp", "model_id", "provider", "tokens_used", "cost", "response_time_ms", "policy_decision", "transfer_basis", "data_residency", "tenant_id"},
			row:     []driver.Value{"al-2", secRowTS, "claude-haiku-4-5", "anthropic", 1200, 0.004, int64(950), "allowed", "pasal_56b_dpa", "US", "tenant-x"},
			run: func(svc *ojkAuditExportServiceImpl) (int, sectionResult) {
				recs, res := svc.queryLLMCalls(context.Background(), "org-a", secStart, secEnd)
				return len(recs), res
			},
		},
		{
			name:    "decision_chain",
			columns: []string{"id", "timestamp", "decision_id", "correlation_id", "stage", "plane", "policy_decision", "model_id", "tenant_id"},
			row:     []driver.Value{"al-3", secRowTS, "dec-1", "corr-1", "llm", "decision", "blocked", "", "tenant-x"},
			run: func(svc *ojkAuditExportServiceImpl) (int, sectionResult) {
				recs, res := svc.queryDecisionChains(context.Background(), "org-a", secStart, secEnd)
				return len(recs), res
			},
		},
		{
			name:    "cross_border",
			columns: []string{"id", "timestamp", "data_residency", "transfer_basis"},
			row:     []driver.Value{"al-4", secRowTS, "SG", "safeguards"},
			run: func(svc *ojkAuditExportServiceImpl) (int, sectionResult) {
				recs, res := svc.queryCrossBorderTransfers(context.Background(), "org-a", secStart, secEnd)
				return len(recs), res
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()

			mock.ExpectQuery(`FROM audit_logs`).
				WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
				WillReturnRows(sqlmock.NewRows(c.columns).AddRow(c.row...))

			svc := &ojkAuditExportServiceImpl{db: db}
			n, res := c.run(svc)
			if res.err != nil {
				t.Fatalf("unexpected error: %v", res.err)
			}
			if n != 1 || res.count != 1 {
				t.Fatalf("len=%d count=%d, want 1/1", n, res.count)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations (the org predicate or its binding changed): %v", err)
			}
		})
	}
}

// TestSectionQueriesRefuseABlankOrg proves every section refuses BEFORE issuing
// a statement. sqlmock with no expectations fails on any query, so a section
// that let a blank scope through would be caught.
func TestSectionQueriesRefuseABlankOrg(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	svc := &ojkAuditExportServiceImpl{db: db}
	blanks := []string{"", "   ", "\t\n"}

	type namedQuery struct {
		name string
		run  func(org string) sectionResult
	}
	queries := []namedQuery{
		{"policy_violations", func(o string) sectionResult {
			_, r := svc.queryPolicyViolations(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"llm_calls", func(o string) sectionResult {
			_, r := svc.queryLLMCalls(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"decision_chain", func(o string) sectionResult {
			_, r := svc.queryDecisionChains(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"hitl_oversight", func(o string) sectionResult {
			_, r := svc.queryHITLOversight(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"pii_redactions", func(o string) sectionResult {
			_, r := svc.queryPIIRedactions(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"cross_border", func(o string) sectionResult {
			_, r := svc.queryCrossBorderTransfers(context.Background(), o, secStart, secEnd)
			return r
		}},
		{"breach_notifications", func(o string) sectionResult {
			_, r := svc.queryBreachNotifications(context.Background(), o, secStart, secEnd)
			return r
		}},
	}

	for _, q := range queries {
		for _, blank := range blanks {
			res := q.run(blank)
			if !errors.Is(res.err, errOrgScopeRequired) {
				t.Errorf("%s with org %q: err = %v, want errOrgScopeRequired", q.name, blank, res.err)
			}
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a blank scope reached the database: %v", err)
	}
}

// TestQueryPIIRedactions_ExportsOnlyMaskedValues drives the real query and
// asserts the record carries the masked form, the OJK category and the action.
func TestQueryPIIRedactions_ExportsOnlyMaskedValues(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`set_config`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM indonesia_pii_detection_events`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "detected_at", "pii_type", "ojk_category", "severity",
			"masked_value", "confidence", "action", "plane", "decision_id", "correlation_id", "tenant_id",
		}).AddRow("ev-1", secRowTS, "nik", "national_identity", "critical",
			"31**********0001", 0.7, "blocked", "gateway", "dec-9", "corr-9", "tenant-x"))
	mock.ExpectCommit()

	svc := &ojkAuditExportServiceImpl{db: db}
	records, res := svc.queryPIIRedactions(context.Background(), "org-a", secStart, secEnd)
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	r := records[0]
	if r.MaskedValue != "31**********0001" {
		t.Errorf("masked_value = %q", r.MaskedValue)
	}
	if strings.Contains(r.MaskedValue, "3174042506780001") {
		t.Error("a raw NIK reached the export")
	}
	if r.OJKCategory != "national_identity" {
		t.Errorf("ojk_category = %q, want national_identity", r.OJKCategory)
	}
	if r.Action != "blocked" {
		t.Errorf("action = %q, want blocked", r.Action)
	}
	if r.RedactionMethod == "" {
		t.Error("redaction_method must be populated so the column means something to an auditor")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestQueryHITLOversight_OnlyReviewedRows asserts the query is org-scoped inside
// a withOrgScope transaction (hitl_approval_queue is ENABLE RLS: an unwrapped
// read returns zero rows under axonflow_app_role) and computes review latency.
func TestQueryHITLOversight_OnlyReviewedRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	created := secRowTS
	reviewed := secRowTS.Add(90 * time.Second)

	mock.ExpectBegin()
	mock.ExpectExec(`set_config`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`FROM hitl_approval_queue`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason", "triggered_policy_id",
			"triggered_policy_name", "severity", "reviewer_id", "reviewer_role",
			"status", "reviewed_at", "tenant_id",
		}).AddRow(int64(42), "11111111-2222-3333-4444-555555555555", created,
			"payment above threshold", "pol-hitl", "Payment Approval", "high",
			"reviewer-1", "compliance_officer", "approved", reviewed, "tenant-x"))
	mock.ExpectCommit()

	svc := &ojkAuditExportServiceImpl{db: db}
	records, res := svc.queryHITLOversight(context.Background(), "org-a", secStart, secEnd)
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if records[0].ReviewTimeMS != 90000 {
		t.Errorf("review_time_ms = %d, want 90000", records[0].ReviewTimeMS)
	}
	if records[0].Decision != "approved" {
		t.Errorf("decision = %q, want approved", records[0].Decision)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestQueryHITLOversight_ExcludesUnreviewedByQuery proves the "reviewed only"
// rule is enforced in SQL, not by a post-fetch filter that a future refactor
// could drop. It inspects the query text the service issues.
func TestQueryHITLOversight_ExcludesUnreviewedByQuery(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`set_config`).WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`reviewed_at IS NOT NULL`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "created_at", "trigger_reason", "triggered_policy_id",
			"triggered_policy_name", "severity", "reviewer_id", "reviewer_role",
			"status", "reviewed_at", "tenant_id",
		}))
	mock.ExpectCommit()

	svc := &ojkAuditExportServiceImpl{db: db}
	_, res := svc.queryHITLOversight(context.Background(), "org-a", secStart, secEnd)
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the reviewed_at predicate is not in the SQL: %v", err)
	}
}

// TestQueryLLMCalls_FiltersToTheLLMPlane pins the plane predicate: without it,
// the section would sweep in every decision row and report gateway pre-checks as
// model invocations.
func TestQueryLLMCalls_FiltersToTheLLMPlane(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`= 'llm'`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "timestamp", "model_id", "provider", "tokens_used", "cost",
			"response_time_ms", "policy_decision", "transfer_basis", "data_residency", "tenant_id",
		}))
	svc := &ojkAuditExportServiceImpl{db: db}
	_, res := svc.queryLLMCalls(context.Background(), "org-a", secStart, secEnd)
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the llm-plane predicate is not in the SQL: %v", err)
	}
}

// TestQueryPolicyViolations_FiltersToActingVerdicts pins the verdict predicate.
func TestQueryPolicyViolations_FiltersToActingVerdicts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`policy_decision IN \('blocked', 'redacted', 'needs_approval'\)`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "policy_id", "policy_decision", "reason", "plane", "tenant_id"}))
	svc := &ojkAuditExportServiceImpl{db: db}
	_, res := svc.queryPolicyViolations(context.Background(), "org-a", secStart, secEnd)
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the acting-verdict predicate is not in the SQL: %v", err)
	}
}

// TestPolicyDisplayNameNeverInvents: an unrecognised policy id must be surfaced
// verbatim, not given a made-up friendly name.
func TestPolicyDisplayNameNeverInvents(t *testing.T) {
	if got := ojkPolicyDisplayName("indonesia_pii_protection"); !strings.Contains(got, "Indonesia PII") {
		t.Errorf("known id rendered as %q", got)
	}
	if got := ojkPolicyDisplayName("tenant_custom_policy_7"); got != "tenant_custom_policy_7" {
		t.Errorf("unknown id = %q, want it echoed verbatim", got)
	}
	if got := ojkPolicyDisplayName(""); got != "" {
		t.Errorf("empty id = %q, want empty", got)
	}
}

// -----------------------------------------------------------------------------
// Decision chain grouping
// -----------------------------------------------------------------------------

func TestGroupOJKDecisionChains(t *testing.T) {
	t0 := secRowTS
	records := []OJKDecisionChainRecord{
		{ID: "1", CorrelationID: "c1", Timestamp: t0},
		{ID: "2", CorrelationID: "", Timestamp: t0.Add(time.Second)},
		{ID: "3", CorrelationID: "c1", Timestamp: t0.Add(2 * time.Second)},
		{ID: "4", CorrelationID: "c2", Timestamp: t0.Add(3 * time.Second)},
	}
	groups := groupOJKDecisionChains(records)
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3 (c1, singleton, c2)", len(groups))
	}
	if groups[0].CorrelationID != "c1" || groups[0].StepCount != 2 {
		t.Errorf("group[0] = %+v, want c1 with 2 steps", groups[0])
	}
	if !groups[0].EndedAt.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("group[0].ended_at = %v, want the LAST step's timestamp", groups[0].EndedAt)
	}
	if groups[1].CorrelationID != "" || groups[1].StepCount != 1 {
		t.Errorf("group[1] = %+v, want a singleton with no correlation id", groups[1])
	}
	if groups[2].CorrelationID != "c2" {
		t.Errorf("group[2].correlation_id = %q, want c2", groups[2].CorrelationID)
	}
	if groupOJKDecisionChains(nil) != nil {
		t.Error("grouping nothing must yield nil, not an empty group")
	}
}

// -----------------------------------------------------------------------------
// Framework composition
// -----------------------------------------------------------------------------

// TestFourFrameworkLabelsProduceFourDifferentSectionSets is the anti-phantom
// guard: before #3242, framework was a validation whitelist only and all four
// labels produced byte-identical reports.
func TestFourFrameworkLabelsProduceFourDifferentSectionSets(t *testing.T) {
	labels := []OJKComplianceFramework{
		OJKFrameworkAIGovernance,
		OJKFrameworkUUPDP,
		OJKFrameworkBIPJP,
		OJKFrameworkCombined,
	}
	seen := make(map[string]OJKComplianceFramework, len(labels))
	for _, fw := range labels {
		p := resolveFrameworkProfile(fw)
		sections, fromFramework := resolveRequestedDataTypes(nil, p)
		if !fromFramework {
			t.Errorf("%s: an absent data_types request must be answered by the framework", fw)
		}
		if len(sections) == 0 {
			t.Errorf("%s: framework selected no sections", fw)
		}
		key := fmt.Sprint(sections)
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s select an IDENTICAL section list %v; the framework label changes nothing", fw, other, sections)
		}
		seen[key] = fw
	}
}

// TestBIPJPvsAIGovernanceSectionLists documents the concrete difference the DoD
// asks for, as an assertion rather than a claim in a PR body.
func TestBIPJPvsAIGovernanceSectionLists(t *testing.T) {
	bi, _ := resolveRequestedDataTypes(nil, resolveFrameworkProfile(OJKFrameworkBIPJP))
	gov, _ := resolveRequestedDataTypes(nil, resolveFrameworkProfile(OJKFrameworkAIGovernance))

	wantBI := []OJKAuditDataType{
		OJKDataTypeDecisionChain, OJKDataTypeHITLOversight,
		OJKDataTypePIIRedactions, OJKDataTypeCrossBorder, OJKDataTypeBreachNotify,
	}
	wantGov := []OJKAuditDataType{
		OJKDataTypePolicyViolations, OJKDataTypeLLMCalls,
		OJKDataTypeDecisionChain, OJKDataTypeHITLOversight,
	}
	if fmt.Sprint(bi) != fmt.Sprint(wantBI) {
		t.Errorf("BI_PJP sections = %v, want %v", bi, wantBI)
	}
	if fmt.Sprint(gov) != fmt.Sprint(wantGov) {
		t.Errorf("OJK_AI_GOVERNANCE sections = %v, want %v", gov, wantGov)
	}
	// The payment framework must not carry the model-activity register, and the
	// governance framework must not carry the personal-data sections.
	for _, dt := range bi {
		if dt == OJKDataTypeLLMCalls {
			t.Error("BI_PJP must not include llm_calls (not a PBI 23/6 requirement)")
		}
	}
	for _, dt := range gov {
		if dt == OJKDataTypePIIRedactions || dt == OJKDataTypeCrossBorder {
			t.Errorf("OJK_AI_GOVERNANCE must not include %q (that is the UU PDP scope)", dt)
		}
	}
}

// TestCombinedFrameworkCoversEverySection: OJK_BI_COMBINED is the union, so a
// new data type added without being placed in a framework still reaches at
// least one report.
func TestCombinedFrameworkCoversEverySection(t *testing.T) {
	combined := resolveFrameworkProfile(OJKFrameworkCombined)
	for _, dt := range ojkAllDataTypes() {
		if !combined.inScope(dt) {
			t.Errorf("data type %q is in no combined report; it would be unreachable by any framework-driven export", dt)
		}
		if combined.relevance[dt] == "" {
			t.Errorf("data type %q has no framework relevance note in the combined profile", dt)
		}
	}
}

// TestEveryFrameworkRelevanceCoversItsOwnSections: a section a framework claims
// must carry an explanation, otherwise the pack tells a regulator nothing about
// why the section is there.
func TestEveryFrameworkRelevanceCoversItsOwnSections(t *testing.T) {
	for fw, p := range ojkFrameworkProfiles() {
		if p.title == "" || p.citation == "" {
			t.Errorf("%s: profile is missing a title or citation", fw)
		}
		if len(p.pillars) == 0 {
			t.Errorf("%s: profile declares no pillars", fw)
		}
		for _, dt := range p.sections {
			if p.relevance[dt] == "" {
				t.Errorf("%s: section %q has no relevance note", fw, dt)
			}
		}
		for _, pillar := range p.pillars {
			for _, dt := range pillar.Sections {
				if !p.inScope(dt) {
					t.Errorf("%s: pillar %q maps to section %q which the framework does not select", fw, pillar.Name, dt)
				}
			}
		}
	}
}

// TestExplicitDataTypesAreHonouredAndFlaggedOutOfScope: an explicit request
// always wins, but a section the framework does not claim is labelled rather
// than silently promoted to in-scope.
func TestExplicitDataTypesAreHonouredAndFlaggedOutOfScope(t *testing.T) {
	p := resolveFrameworkProfile(OJKFrameworkAIGovernance)
	sections, fromFramework := resolveRequestedDataTypes(
		[]OJKAuditDataType{OJKDataTypeCrossBorder}, p)
	if fromFramework {
		t.Error("an explicit data_types request must not be reported as framework-selected")
	}
	if len(sections) != 1 || sections[0] != OJKDataTypeCrossBorder {
		t.Fatalf("sections = %v, want [cross_border_transfers]", sections)
	}
	if p.inScope(OJKDataTypeCrossBorder) {
		t.Error("cross_border_transfers is not in the AI-governance scope; the fixture is wrong")
	}
}

func TestResolveRequestedDataTypes_Dedup(t *testing.T) {
	p := resolveFrameworkProfile(OJKFrameworkCombined)

	got, _ := resolveRequestedDataTypes([]OJKAuditDataType{
		OJKDataTypeCrossBorder, OJKDataTypeCrossBorder, OJKDataTypeLLMCalls,
	}, p)
	if fmt.Sprint(got) != fmt.Sprint([]OJKAuditDataType{OJKDataTypeCrossBorder, OJKDataTypeLLMCalls}) {
		t.Errorf("dedup = %v", got)
	}

	// "all" mixed with explicit types expands to every concrete type, once each.
	got, fromFramework := resolveRequestedDataTypes([]OJKAuditDataType{
		OJKDataTypeBreachNotify, OJKDataTypeAll,
	}, p)
	if fromFramework {
		t.Error("a mixed explicit+all request is not framework-selected")
	}
	if len(got) != len(ojkAllDataTypes()) {
		t.Errorf("all-expansion produced %d sections, want %d", len(got), len(ojkAllDataTypes()))
	}
	if got[0] != OJKDataTypeBreachNotify {
		t.Errorf("request order not preserved: %v", got)
	}

	// Empty strings are ignored, and an all-empty request falls back to the
	// framework rather than producing an empty report.
	got, fromFramework = resolveRequestedDataTypes([]OJKAuditDataType{"", ""}, p)
	if !fromFramework || len(got) != len(p.sections) {
		t.Errorf("all-blank request = %v (fromFramework=%v), want the framework's sections", got, fromFramework)
	}

	// "all" alone means the FRAMEWORK's full scope, not every section.
	gov := resolveFrameworkProfile(OJKFrameworkAIGovernance)
	got, fromFramework = resolveRequestedDataTypes([]OJKAuditDataType{OJKDataTypeAll}, gov)
	if !fromFramework {
		t.Error(`"all" alone must be treated as a framework selection`)
	}
	if len(got) != len(gov.sections) {
		t.Errorf(`"all" under OJK_AI_GOVERNANCE = %v, want the framework's %v`, got, gov.sections)
	}
}

// TestUnknownFrameworkFallsBackToTheWidestProfile: a mislabelled request must
// over-report rather than silently omit sections.
func TestUnknownFrameworkFallsBackToTheWidestProfile(t *testing.T) {
	p := resolveFrameworkProfile(OJKComplianceFramework("MADE_UP"))
	if len(p.sections) != len(ojkAllDataTypes()) {
		t.Errorf("fallback profile has %d sections, want every section (%d)", len(p.sections), len(ojkAllDataTypes()))
	}
}

// TestFrameworkSummaryIsEmittedOnEveryExport
func TestFrameworkSummaryIsEmittedOnEveryExport(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}))

	svc := &ojkAuditExportServiceImpl{db: db}
	resp, err := svc.ExportAuditData(context.Background(), "org-a", &OJKAuditExportRequest{
		StartDate: "2026-07-01", EndDate: "2026-07-31",
		Framework: OJKFrameworkBIPJP,
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fs := resp.Summary.FrameworkSummary
	if fs == nil {
		t.Fatal("framework_summary is absent")
	}
	if fs.Framework != OJKFrameworkBIPJP {
		t.Errorf("framework = %q", fs.Framework)
	}
	if !strings.Contains(fs.Citation, "23/6/PBI/2021") {
		t.Errorf("BI PJP summary does not cite PBI 23/6/PBI/2021: %q", fs.Citation)
	}
	if len(fs.Pillars) != 3 {
		t.Errorf("BI PJP pillars = %d, want 3 (transaction integrity, data protection, incident handling)", len(fs.Pillars))
	}
	if !strings.Contains(fs.Notes, "explicit data_types") {
		t.Errorf("an explicit data_types request must be noted in the summary: %q", fs.Notes)
	}
}

// TestExportMetadataVersionIsBumped: consumers keying on export_version must be
// able to tell the new per-section contract from the old one.
func TestExportMetadataVersionIsBumped(t *testing.T) {
	if ojkExportVersion == "1.0.0" {
		t.Error("export_version must change when the section contract changes")
	}
}

// capturingArg is a sqlmock argument matcher that RECORDS the value it was
// given. Without it the end-of-day assertion below would compare two constants
// in the test file and never observe what the service actually binds.
type capturingArg struct{ got *driver.Value }

func (c capturingArg) Match(v driver.Value) bool {
	*c.got = v
	return true
}

// TestEndDateCoversTheWholeFinalDay is the off-by-a-day guard. end_date is a
// DATE; parsed as midnight it excluded every row recorded after 00:00:00 on the
// final day of the requested window -- a whole day of evidence missing from a
// regulator pack, silently.
//
// It asserts on the value the service BINDS, captured from the driver, not on a
// constant restated in the test.
func TestEndDateCoversTheWholeFinalDay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	var boundEnd driver.Value
	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-a", secStart, capturingArg{got: &boundEnd}, ojkSectionLimit).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}))

	svc := &ojkAuditExportServiceImpl{db: db}
	if _, err := svc.ExportAuditData(context.Background(), "org-a", &OJKAuditExportRequest{
		StartDate: "2026-07-01", EndDate: "2026-07-31",
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	end, ok := boundEnd.(time.Time)
	if !ok {
		t.Fatalf("bound end argument is %T, not a time.Time", boundEnd)
	}
	lateOnFinalDay := time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC)
	if end.Before(lateOnFinalDay) {
		t.Errorf("bound window end %v excludes %v, which is inside the requested final day 2026-07-31", end, lateOnFinalDay)
	}
	nextDay := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if !end.Before(nextDay) {
		t.Errorf("bound window end %v reaches into 2026-08-01, outside the requested window", end)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Tenancy-predicate structure
// -----------------------------------------------------------------------------

// conflationFindings is THE predicate. Both the standing guard and its
// mutant-detector call it.
//
// R3 round 1 caught the earlier shape by mutation: the detector re-implemented
// the four boolean conditions inline, so weakening the REAL guard left both
// tests green. A mutant-detector that tests a COPY of the guard proves nothing
// about the guard that ships.
func conflationFindings(where string) []string {
	var out []string

	// ojkOrgPredicate is the ONE legitimate shape that mentions tenant_id: it
	// matches rows owned by this organisation PLUS rows with no organisation
	// attribution at all whose tenant is this identifier. It can never return a
	// row owned by a DIFFERENT organisation, because the second arm requires the
	// row's own org to be blank. Remove it whole and judge what is left.
	remainder := strings.Replace(where, ojkOrgPredicate, "", 1)
	usedShared := remainder != where

	if !usedShared && !strings.Contains(where, "org_id = $1") {
		out = append(out, "does not scope on org_id = $1")
	}
	if strings.Contains(remainder, "tenant_id = $") {
		out = append(out, "predicates on tenant_id outside the shared org predicate, conflating the two v9 identifiers")
	}
	if strings.Contains(remainder, "OR org_id") || strings.Contains(remainder, "org_id = $1 OR") {
		out = append(out, "ORs its organisation predicate")
	}
	return out
}

// TestNoAuditLogsQueryConflatesTenantAndOrg is the standing guard for the
// tenant/org conflation class.
//
// It exists because a mutation test proved the argument-binding assertions
// elsewhere in this file cannot catch it: re-introducing
// `WHERE (org_id = $1 OR tenant_id = $1)` still binds exactly one argument in
// position 1, so sqlmock's WithArgs matches and every section test stays green
// while the query returns rows belonging to a DIFFERENT organisation whose
// tenant identifier happens to equal the caller's org. audit_logs has no RLS, so
// there is no database backstop either -- the predicate IS the boundary, and
// only its STRUCTURE can be asserted.
func TestNoAuditLogsQueryConflatesTenantAndOrg(t *testing.T) {
	files := auditLogsSourceFiles(t)
	checked := 0
	for _, f := range files {
		for _, lit := range sqlLiteralsIn(t, f) {
			if !strings.Contains(lit, "FROM audit_logs") {
				continue
			}
			checked++
			where := whereClauseOf(lit)
			if where == "" {
				t.Errorf("%s: an audit_logs query has no WHERE clause at all:\n%s", f, lit)
				continue
			}
			for _, finding := range conflationFindings(where) {
				t.Errorf("%s: an audit_logs query %s:\n%s", f, finding, where)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no audit_logs queries were resolved at all; the extractor is not finding what it exists to police")
	}
	// The guard above can only judge statements it can RESOLVE. This is what
	// stops a statement being hidden from it.
	assertEverySQLStatementIsResolvable(t, files)
}

// assertEverySQLStatementIsResolvable is what makes the tenancy guards
// un-hideable.
//
// The guards work by resolving SQL string expressions at parse time. A query
// that the resolver CANNOT resolve is simply absent from their input -- so the
// way to smuggle a conflated predicate past them is not to write one, it is to
// make the statement unresolvable. Round 2 demonstrated exactly that: moving the
// table name behind `const auditLogsTbl = "audit_logs"` left no fragment
// containing "FROM audit_logs", the query vanished from every guard, and the
// package stayed green with a live cross-tenant conflation in it.
//
// A count-based floor cannot catch this, and neither can counting `FROM
// audit_logs` in the raw text -- the mutation removes that string too. The only
// signal that does not fall with the mutation is the STATEMENT ITSELF: this
// walks every database call in the package and requires its SQL argument to
// resolve. An unresolvable statement is the finding, whatever it contains.
func assertEverySQLStatementIsResolvable(t *testing.T, files []string) {
	t.Helper()
	dbCalls := map[string]bool{
		"QueryContext": true, "QueryRowContext": true, "ExecContext": true,
		"Query": true, "QueryRow": true, "Exec": true,
	}

	checked := 0
	for _, f := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		// Walk per FUNCTION so a local `const q = ...` / `q := ...` binding can
		// be resolved from the same scope the call site sees.
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if dynamicSQLExemptions[fn.Name.Name] != "" {
				continue
			}
			locals := localStringBindings(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !dbCalls[sel.Sel.Name] {
					return true
				}
				// The SQL is the first argument for Query/Exec and the second
				// for the *Context variants.
				idx := 0
				if strings.HasSuffix(sel.Sel.Name, "Context") {
					idx = 1
				}
				if len(call.Args) <= idx {
					return true
				}
				checked++
				if _, ok := resolveSQLExprWith(call.Args[idx], locals); !ok {
					t.Errorf("%s:%d (%s): the SQL argument to %s does not resolve to a constant string, so it is INVISIBLE to the tenancy guards in this file. Build it from string literals, local string constants and the ojkOrgPredicate constant -- or, if it is genuinely dynamic, add it to dynamicSQLExemptions with the test that covers it instead.",
						f, fset.Position(call.Args[idx].Pos()).Line, fn.Name.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no database calls found in the package; the walker is not finding what it exists to police")
	}
}

// dynamicSQLExemptions names the functions whose SQL is genuinely assembled at
// run time, mapped to the test that covers them INSTEAD.
//
// An exemption is only acceptable with a named replacement: the point of the
// walker is that a statement is never simultaneously dynamic and unexamined.
var dynamicSQLExemptions = map[string]string{
	// retentionWindowFor composes its statement from the retentionSource table
	// and column names. It is covered by
	// TestRetentionAuditLogsPredicateIsTheSharedOne, which DRIVES it through a
	// recording driver and applies conflationFindings to the SQL Postgres
	// actually received -- a stronger check than parsing, not a weaker one.
	"retentionWindowFor": "TestRetentionAuditLogsPredicateIsTheSharedOne",
}

// localStringBindings collects `const x = "..."` and `x := "..."` string
// bindings in a function body, so a query written as a named local resolves.
func localStringBindings(fn *ast.FuncDecl) map[string]string {
	out := map[string]string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.GenDecl:
			if v.Tok != token.CONST && v.Tok != token.VAR {
				return true
			}
			for _, spec := range v.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if got, ok := resolveSQLExprWith(vs.Values[i], out); ok {
							out[name.Name] = got
						}
					}
				}
			}
		case *ast.AssignStmt:
			if v.Tok != token.DEFINE && v.Tok != token.ASSIGN {
				return true
			}
			for i, lhs := range v.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || i >= len(v.Rhs) {
					continue
				}
				if got, ok := resolveSQLExprWith(v.Rhs[i], out); ok {
					out[ident.Name] = got
				}
			}
		}
		return true
	})
	return out
}

// auditLogsSourceFiles enumerates every non-test .go file in this PACKAGE.
//
// A hardcoded file list is the other way a query goes invisible: round 1 widened
// the data-type parser to scan the whole directory and left these two guards on
// three- and four-file lists, so a new file in the package was invisible to
// both. The directory IS the boundary; anything in it that reads audit_logs is
// in scope by construction.
func auditLogsSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		t.Fatal("no non-test .go files found in the package directory")
	}
	return out
}

// resolveSQLExpr returns the constant string an expression evaluates to, and
// whether it could be resolved at all. It understands string literals, `+`
// concatenation, parentheses, and the ojkOrgPredicate constant -- the shapes the
// package's SQL is actually written in. Anything else is UNRESOLVABLE, which
// assertEverySQLStatementIsResolvable treats as a finding rather than a silent
// omission.
func resolveSQLExpr(e ast.Expr) (string, bool) { return resolveSQLExprWith(e, nil) }

// resolveSQLExprWith is resolveSQLExpr with an additional scope of local string
// bindings (see localStringBindings).
func resolveSQLExprWith(e ast.Expr, locals map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		return strings.Trim(v.Value, "`\""), true
	case *ast.Ident:
		if v.Name == "ojkOrgPredicate" {
			return ojkOrgPredicate, true
		}
		if got, ok := locals[v.Name]; ok {
			return got, true
		}
		return "", false
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, okL := resolveSQLExprWith(v.X, locals)
		r, okR := resolveSQLExprWith(v.Y, locals)
		if !okL || !okR {
			return "", false
		}
		return l + r, true
	case *ast.ParenExpr:
		return resolveSQLExprWith(v.X, locals)
	}
	return "", false
}

// recordingQueryMatcher captures the SQL the driver actually receives and
// matches unconditionally. It is how a test can judge a statement that is
// ASSEMBLED IN GO rather than written as a literal -- which the literal-scanning
// guard above cannot see at all.
type recordingQueryMatcher struct{ got *string }

func (m recordingQueryMatcher) Match(expectedSQL, actualSQL string) error {
	*m.got = strings.Join(strings.Fields(actualSQL), " ")
	return nil
}

// TestRetentionAuditLogsPredicateIsTheSharedOne closes the gap round 1 found:
// the retention view builds its WHERE in Go, so the literal-scanning guard
// cannot see it.
//
// Round 1's version of this test RE-IMPLEMENTED that construction in the test
// body -- the exact sin round 1 fixed one test earlier -- and round 2 proved it
// by deleting the audit_logs branch from retention.go and watching the package
// stay green. This drives the REAL retentionWindowFor and judges the SQL the
// driver received.
func TestRetentionAuditLogsPredicateIsTheSharedOne(t *testing.T) {
	inspected := 0
	for dt, src := range ojkRetentionSources() {
		dt, src := dt, src
		t.Run(string(dt), func(t *testing.T) {
			var seen string
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(recordingQueryMatcher{got: &seen}))
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()

			rows := sqlmock.NewRows([]string{"count", "min", "max"}).AddRow(0, nil, nil)
			if src.rlsWrapped {
				// The RLS-gated sources run inside withOrgScope, so the driver
				// sees BEGIN + set_config first. The recording matcher captures
				// the LAST statement, which is the one under test.
				mock.ExpectBegin()
				mock.ExpectExec(".*").WithArgs("org-a").WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectQuery(".*").WillReturnRows(rows)
				mock.ExpectCommit()
			} else {
				mock.ExpectQuery(".*").WillReturnRows(rows)
			}

			svc := &ojkAuditExportServiceImpl{db: db}
			if _, _, _, err := svc.retentionWindowFor(context.Background(), "org-a", src); err != nil {
				t.Fatalf("retentionWindowFor: %v", err)
			}
			if seen == "" {
				t.Fatalf("no statement was captured; this test cannot judge what it claims to")
			}
			inspected++

			where := whereClauseOf(seen)
			if where == "" {
				t.Fatalf("no WHERE clause in:\n%s", seen)
			}
			for _, finding := range conflationFindings(where) {
				t.Errorf("retention query for %q %s:\n%s", dt, finding, where)
			}
			if src.table == "audit_logs" && !strings.Contains(where, ojkOrgPredicate) {
				t.Errorf("retention query for %q reads audit_logs WITHOUT the shared org predicate; the blank-org corpus would be visible to the export section and invisible here:\n%s", dt, where)
			}
			if src.table != "audit_logs" && !strings.Contains(where, "org_id = $1") {
				t.Errorf("retention query for %q does not scope on org_id:\n%s", dt, where)
			}
		})
	}
	if inspected != len(ojkAllDataTypes()) {
		t.Fatalf("inspected %d retention sources, want %d", inspected, len(ojkAllDataTypes()))
	}
}

// sqlLiteralsIn returns the RESOLVED SQL of every database call in a source
// file, whitespace-normalised so a multi-line query reads as one line.
//
// It walks per FUNCTION with that function's local string bindings in scope, so
// a query written as `const q = ...` or assembled from
// `"..." + ojkOrgPredicate + "..."` or `"..." + someLocal + "..."` resolves to
// the statement the database receives.
//
// The per-function scope is not an optimisation. Round 2 hid a conflated
// predicate by moving the table name behind a local constant; a resolver that
// only understood literals and one package constant could not see the statement
// at all, and neither could the guard built on it. Resolving locals closes that,
// and assertEverySQLStatementIsResolvable fails on anything that STILL does not
// resolve -- so the two are complementary: this one judges what it can read, and
// that one guarantees there is nothing it cannot read.
func sqlLiteralsIn(t *testing.T, filename string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	dbCalls := map[string]bool{
		"QueryContext": true, "QueryRowContext": true, "ExecContext": true,
		"Query": true, "QueryRow": true, "Exec": true,
	}

	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		locals := localStringBindings(fn)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !dbCalls[sel.Sel.Name] {
				return true
			}
			idx := 0
			if strings.HasSuffix(sel.Sel.Name, "Context") {
				idx = 1
			}
			if len(call.Args) <= idx {
				return true
			}
			if got, ok := resolveSQLExprWith(call.Args[idx], locals); ok {
				out = append(out, strings.Join(strings.Fields(got), " "))
			}
			return true
		})
	}
	return out
}

// whereClauseOf extracts the WHERE clause of a whitespace-normalised statement,
// stopping at ORDER BY / GROUP BY / LIMIT so a trailing clause cannot smuggle
// text past the checks.
func whereClauseOf(sql string) string {
	upper := strings.ToUpper(sql)
	i := strings.Index(upper, " WHERE ")
	if i < 0 {
		return ""
	}
	rest := sql[i+len(" WHERE "):]
	restUpper := strings.ToUpper(rest)
	for _, stop := range []string{" ORDER BY ", " GROUP BY ", " LIMIT "} {
		if j := strings.Index(restUpper, stop); j >= 0 {
			rest = rest[:j]
			restUpper = restUpper[:j]
		}
	}
	return rest
}

// -----------------------------------------------------------------------------
// Response encoding must not be mislabelled
// -----------------------------------------------------------------------------

// TestResponseNeverMislabelsItsOwnEncoding is the content-mislabel guard.
//
// The handler writes Content-Type: application/json and marshals Data inline,
// unconditionally. The response used to echo req.Format, so a request for csv
// came back labelled `"format": "csv"` carrying a JSON body -- the same class
// the epic #2892 design record calls out for SEBI (D5). A regulator artifact
// that misstates its own encoding is worse than one that refuses outright.
func TestResponseNeverMislabelsItsOwnEncoding(t *testing.T) {
	for _, requested := range []OJKExportFormat{"", OJKFormatJSON, OJKFormatCSV, OJKFormatXML} {
		requested := requested
		t.Run("requested="+string(requested), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()
			mock.ExpectQuery(`FROM audit_logs`).
				WithArgs("org-a", secStart, secEnd, ojkSectionLimit).
				WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}))

			svc := &ojkAuditExportServiceImpl{db: db}
			resp, err := svc.ExportAuditData(context.Background(), "org-a", &OJKAuditExportRequest{
				StartDate: "2026-07-01", EndDate: "2026-07-31",
				Format:    requested,
				DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
			})
			if err != nil {
				t.Fatalf("ExportAuditData: %v", err)
			}

			// The body IS json, so the label must be json, whatever was asked.
			if resp.Format != OJKFormatJSON {
				t.Errorf("format = %q for a JSON body; the response is mislabelling its own encoding", resp.Format)
			}

			wantsSomethingElse := requested != "" && requested != OJKFormatJSON
			if wantsSomethingElse {
				if resp.RequestedFormat != requested {
					t.Errorf("requested_format = %q, want %q: the discrepancy must be visible", resp.RequestedFormat, requested)
				}
				if resp.FormatNote == "" {
					t.Error("format_note is empty; a consumer should not have to infer the discrepancy from two fields disagreeing")
				}
				if !strings.Contains(resp.FormatNote, string(requested)) {
					t.Errorf("format_note %q does not name the requested format", resp.FormatNote)
				}
			} else {
				if resp.RequestedFormat != "" || resp.FormatNote != "" {
					t.Errorf("requested_format=%q note=%q on a plain JSON request; the discrepancy fields must stay absent when there is no discrepancy",
						resp.RequestedFormat, resp.FormatNote)
				}
			}
		})
	}
}
