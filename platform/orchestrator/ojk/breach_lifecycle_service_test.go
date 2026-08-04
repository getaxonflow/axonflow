//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestAcknowledgeBreachNotification_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	if _, err := svc.AcknowledgeBreachNotification(context.Background(), "t", "some-id"); err == nil {
		t.Error("expected error for nil DB")
	}
}

func TestEvaluateBreachDeadlines_NilDB(t *testing.T) {
	svc := NewOJKAuditExportService(nil, nil)
	if _, err := svc.EvaluateBreachDeadlines(context.Background(), "t"); err == nil {
		t.Error("expected error for nil DB")
	}
}

// TestGetDashboard_NilDBReportsUnavailableNotZero pins the INVERTED contract
// (#3242). This test used to assert that a dashboard built with NO database
// returned breach counts of 0/0 -- i.e. it PINNED the behaviour of answering a
// regulator-facing question with a confident zero derived from nothing.
//
// A count of 0 and "we could not measure" are different answers. Every count is
// now OJKCountUnavailable (-1) and names itself in Unavailable.
func TestGetDashboard_NilDBReportsUnavailableNotZero(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.GetDashboard(context.Background(), "t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.BreachNotifications != OJKCountUnavailable || resp.OverdueBreachNotifications != OJKCountUnavailable {
		t.Errorf("nil-db dashboard breach counts = %d/%d, want %d/%d (unavailable, not a fabricated zero)",
			resp.BreachNotifications, resp.OverdueBreachNotifications,
			OJKCountUnavailable, OJKCountUnavailable)
	}
	if resp.TotalAuditRecords != OJKCountUnavailable {
		t.Errorf("total_audit_records = %d, want %d", resp.TotalAuditRecords, OJKCountUnavailable)
	}
	if resp.ActivePolicies != OJKCountUnavailable {
		t.Errorf("active_policies = %d, want %d (the old code returned a literal 8)", resp.ActivePolicies, OJKCountUnavailable)
	}
	if resp.RecentViolations != OJKCountUnavailable {
		t.Errorf("recent_violations = %d, want %d", resp.RecentViolations, OJKCountUnavailable)
	}
	for _, want := range []string{"total_audit_records", "active_policies", "recent_violations", "breach_notifications", "indonesia_pii_events"} {
		found := false
		for _, got := range resp.Unavailable {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unavailable list %v is missing %q; an unmeasurable count must NAME itself", resp.Unavailable, want)
		}
	}
}

// TestGetDashboard_BlankOrgIsRefused proves a blank scope never reaches a query.
func TestGetDashboard_BlankOrgIsRefused(t *testing.T) {
	svc := &ojkAuditExportServiceImpl{}
	if _, err := svc.GetDashboard(context.Background(), "   "); err == nil {
		t.Fatal("expected a blank org scope to be refused")
	}
}

// TestValidateComplianceReadiness_NilDBIsUnknownNotPass is the core anti-
// regression for the literal-"pass" class: with NO database, four of the five
// checks cannot be measured at all, so they must read unknown and the report
// must NOT be ready. The old implementation returned score 100, Ready=true on
// exactly this input.
func TestValidateComplianceReadiness_NilDBIsUnknownNotPass(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	svc := &ojkAuditExportServiceImpl{}
	resp, err := svc.ValidateComplianceReadiness(context.Background(), "org-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Ready {
		t.Error("Ready must be false when no dimension beyond retention could be measured")
	}
	if resp.UnknownChecks != 4 {
		t.Errorf("unknown checks = %d, want 4 (PII, oversight, audit, breach are all DB-derived)", resp.UnknownChecks)
	}
	if resp.MeasuredChecks != 1 {
		t.Errorf("measured checks = %d, want 1 (retention is config-derived)", resp.MeasuredChecks)
	}
	// The score is over EVERY check, not just the measurable ones. R3 round 1
	// proved by execution that scoring over the measurable set made a
	// no-database deployment score 100 -- strictly worse than the literal-pass
	// code it replaced. One passing dimension out of five is 20.
	if resp.Score != 20 {
		t.Errorf("score = %d, want 20 (1 of 5 dimensions passing); an unobservable dimension must drag the score DOWN", resp.Score)
	}
	for _, c := range resp.Checks {
		if c.Name == "Data Retention" {
			continue
		}
		if c.Status != OJKCheckUnknown {
			t.Errorf("check %q status = %q, want %q; a DB-derived check with no DB must never claim pass",
				c.Name, c.Status, OJKCheckUnknown)
		}
	}
}

// TestNoUnconditionalStatusLiteralsRemain is the structural guard for the
// class this workstream removed: an OJKComplianceCheck whose Status is a
// hard-coded string in the composite literal, so it can never depend on a
// measurement.
//
// It PARSES readiness.go rather than grepping it. A grep would have matched the
// prose in this file's own header comment (it did, on the first attempt) --
// a guard that fires on its own documentation is a guard nobody keeps.
//
// Assignments like `c.Status = OJKCheckPass` on a measured branch are fine and
// are not flagged: the defect is a status baked into the initialiser.
func TestNoUnconditionalStatusLiteralsRemain(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "readiness.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse readiness.go: %v", err)
	}

	var findings []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "OJKComplianceCheck" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Status" {
				continue
			}
			if _, isLiteral := kv.Value.(*ast.BasicLit); isLiteral {
				findings = append(findings, fmt.Sprintf("%s: OJKComplianceCheck literal sets Status to a constant string",
					fset.Position(kv.Pos())))
			}
		}
		return true
	})

	if len(findings) > 0 {
		t.Errorf("readiness checks must derive Status from a measurement, not a literal:\n%s",
			strings.Join(findings, "\n"))
	}
}

// TestNoUnconditionalStatusLiteralsRemain_DetectsTheDefect proves the guard
// above can actually FAIL. Without this, a parser change that stopped matching
// OJKComplianceCheck would leave the guard green forever.
func TestNoUnconditionalStatusLiteralsRemain_DetectsTheDefect(t *testing.T) {
	const mutant = `package ojk

func bad() OJKComplianceCheck {
	return OJKComplianceCheck{
		Name:   "Human Oversight",
		Status: "pass",
	}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mutant.go", mutant, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse mutant: %v", err)
	}
	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		ident, ok := lit.Type.(*ast.Ident)
		if !ok || ident.Name != "OJKComplianceCheck" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "Status" {
				continue
			}
			if _, isLiteral := kv.Value.(*ast.BasicLit); isLiteral {
				found++
			}
		}
		return true
	})
	if found != 1 {
		t.Fatalf("the guard found %d literal-status checks in the mutant, want 1; it cannot detect the defect it exists for", found)
	}
}

func TestSplitDataTypes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"   ", []string{}},
		{"nik", []string{"nik"}},
		{"nik,npwp", []string{"nik", "npwp"}},
		{"nik, npwp ,", []string{"nik", "npwp"}},
		{",,", []string{}},
	}
	for _, c := range cases {
		got := splitDataTypes(c.in)
		if got == nil {
			t.Errorf("splitDataTypes(%q) = nil, want non-nil slice", c.in)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("splitDataTypes(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("splitDataTypes(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
