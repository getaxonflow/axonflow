// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Tests for the Indonesia PII detection-event seam (#3242).
//
// These run in BOTH editions. The community assertions are the ones that keep
// the seam honest: with the hook nil, nothing may be attempted at all.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"axonflow/platform/agent/indonesia"
)

func sampleDetections() []indonesia.IndonesiaPIIDetectionResult {
	return []indonesia.IndonesiaPIIDetectionResult{
		{
			Type:        indonesia.IndonesiaPIITypeNIK,
			Value:       "3174042506780001",
			MaskedValue: "31**********0001",
			Severity:    indonesia.IndonesiaPIISeverityCritical,
			Confidence:  0.7,
			OJKCategory: "national_identity",
			Context:     "Customer NIK is 3174042506780001 for account opening",
		},
		{
			Type:        indonesia.IndonesiaPIITypeBCA,
			Value:       "BCA: 1234567890",
			MaskedValue: "***********7890",
			Severity:    indonesia.IndonesiaPIISeverityHigh,
			Confidence:  0.7,
			OJKCategory: "financial_account",
			Context:     "Transfer to BCA: 1234567890 now",
		},
	}
}

// TestIndonesiaPIIEventsFrom_CarriesNoRawValue is the core privacy contract:
// the projection must carry the MASKED value and neither the raw match nor the
// detector's context window (which is free text lifted from the caller's query
// and would re-introduce exactly what masking removes).
func TestIndonesiaPIIEventsFrom_CarriesNoRawValue(t *testing.T) {
	events := indonesiaPIIEventsFrom(sampleDetections())
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}

	for i, ev := range events {
		raw := sampleDetections()[i]
		if ev.MaskedValue != raw.MaskedValue {
			t.Errorf("event[%d].MaskedValue = %q, want %q", i, ev.MaskedValue, raw.MaskedValue)
		}
		// Every string field of the event must be free of the raw value AND of
		// the context window. Checking field-by-field rather than only
		// MaskedValue means a future field that quietly carries the raw text
		// fails here.
		for name, field := range map[string]string{
			"PIIType":     ev.PIIType,
			"OJKCategory": ev.OJKCategory,
			"Severity":    ev.Severity,
			"MaskedValue": ev.MaskedValue,
		} {
			if strings.Contains(field, raw.Value) {
				t.Errorf("event[%d].%s = %q contains the RAW detected value", i, name, field)
			}
			if raw.Context != "" && strings.Contains(field, raw.Context) {
				t.Errorf("event[%d].%s = %q contains the detector context window", i, name, field)
			}
		}
	}
	if events[0].OJKCategory != "national_identity" {
		t.Errorf("OJKCategory = %q, want national_identity", events[0].OJKCategory)
	}
	if events[1].OJKCategory != "financial_account" {
		t.Errorf("OJKCategory = %q, want financial_account", events[1].OJKCategory)
	}
}

// TestIndonesiaPIIEventsFrom_DropsUnwritableDetections: a detection with no
// masked value or no category would be refused by the enterprise/137 CHECK
// constraints and would take the whole batch down with it.
func TestIndonesiaPIIEventsFrom_DropsUnwritableDetections(t *testing.T) {
	in := []indonesia.IndonesiaPIIDetectionResult{
		{Type: "nik", MaskedValue: "", OJKCategory: "national_identity"},
		{Type: "nik", MaskedValue: "31**", OJKCategory: ""},
		{Type: "nik", MaskedValue: "31**", OJKCategory: "national_identity"},
	}
	got := indonesiaPIIEventsFrom(in)
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (only the fully-populated detection is writable)", len(got))
	}
}

// TestIndonesiaPIIActionVocabularyIsPlaneSpecific pins the distinction R3 found:
// a POLICY DECISION POINT (the gateway pre-check, /api/v1/decide) never masks
// anything -- it sets RequiresRedaction or emits a redact_pii obligation and the
// calling SDK acts. Recording those as "redacted" told a regulator the platform
// had masked a value it had only asked someone else to mask, including on paths
// where the obligation was subsequently dropped by a later deny.
func TestIndonesiaPIIActionVocabularyIsPlaneSpecific(t *testing.T) {
	t.Run("enforced plane (MCP) may claim a mask", func(t *testing.T) {
		cases := []struct {
			blocked, masked bool
			want            string
		}{
			{true, false, indonesiaPIIActionBlocked},
			{true, true, indonesiaPIIActionBlocked}, // a block outranks a mask
			{false, true, indonesiaPIIActionRedacted},
			{false, false, indonesiaPIIActionDetected},
		}
		for _, c := range cases {
			if got := indonesiaPIIActionForEnforcedPlane(c.blocked, c.masked); got != c.want {
				t.Errorf("indonesiaPIIActionForEnforcedPlane(%v,%v) = %q, want %q", c.blocked, c.masked, got, c.want)
			}
		}
	})

	t.Run("decision plane may NEVER claim a mask", func(t *testing.T) {
		cases := []struct {
			blocked, redactionRequired bool
			want                       string
		}{
			{true, false, indonesiaPIIActionBlocked},
			{true, true, indonesiaPIIActionBlocked},
			{false, true, indonesiaPIIActionRedactionRequired},
			{false, false, indonesiaPIIActionDetected},
		}
		for _, c := range cases {
			got := indonesiaPIIActionForDecisionPlane(c.blocked, c.redactionRequired)
			if got != c.want {
				t.Errorf("indonesiaPIIActionForDecisionPlane(%v,%v) = %q, want %q", c.blocked, c.redactionRequired, got, c.want)
			}
			if got == indonesiaPIIActionRedacted {
				t.Errorf("a policy decision point claimed action %q; it masks nothing itself", got)
			}
		}
	})
}

// TestDecisionPlanesNeverRecordRedacted is the structural half: no call site on
// a PDP plane may reach the enforced-plane mapper, which is the only function
// that can return "redacted".
func TestDecisionPlanesNeverRecordRedacted(t *testing.T) {
	for _, f := range []string{"gateway_handlers.go", "decision_handler.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if strings.Contains(string(src), "indonesiaPIIActionForEnforcedPlane") {
			t.Errorf("%s uses indonesiaPIIActionForEnforcedPlane; that plane never masks content and must not be able to record \"redacted\"", f)
		}
		if strings.Contains(string(src), "indonesiaPIIActionRedacted") {
			t.Errorf("%s references indonesiaPIIActionRedacted directly", f)
		}
	}
	// Negative control: the MCP plane DOES mask, so it must use the enforced
	// mapper -- otherwise this guard would pass on a file that records nothing.
	src, err := os.ReadFile("mcp_handler.go")
	if err != nil {
		t.Fatalf("read mcp_handler.go: %v", err)
	}
	if !strings.Contains(string(src), "indonesiaPIIActionForEnforcedPlane") {
		t.Error("mcp_handler.go no longer uses the enforced-plane mapper; the guard above would then be vacuous")
	}
}

// TestRecordIndonesiaPIIEvents_NoOpCases pins that the seam attempts NOTHING in
// the cases that must stay free: a nil hook (community build), a nil result, no
// detections, and detections that all project away.
func TestRecordIndonesiaPIIEvents_NoOpCases(t *testing.T) {
	original := persistIndonesiaPIIEvents
	t.Cleanup(func() { persistIndonesiaPIIEvents = original })

	calls := 0
	persistIndonesiaPIIEvents = func(ctx context.Context, batch indonesiaPIIEventBatch) { calls++ }

	recordIndonesiaPIIEvents(context.Background(), "org", "tenant", "", "", PlaneGateway,
		indonesiaPIIActionBlocked, nil)
	recordIndonesiaPIIEvents(context.Background(), "org", "tenant", "", "", PlaneGateway,
		indonesiaPIIActionBlocked, &indonesia.IndonesiaPIICheckResult{HasPII: true})
	recordIndonesiaPIIEvents(context.Background(), "org", "tenant", "", "", PlaneGateway,
		indonesiaPIIActionBlocked, &indonesia.IndonesiaPIICheckResult{
			HasPII:     true,
			Detections: []indonesia.IndonesiaPIIDetectionResult{{Type: "nik"}}, // no masked value
		})
	if calls != 0 {
		t.Errorf("hook called %d times for no-op inputs, want 0", calls)
	}

	// Nil hook (the community posture): must not panic and must not attempt
	// anything.
	persistIndonesiaPIIEvents = nil
	recordIndonesiaPIIEvents(context.Background(), "org", "tenant", "d", "c", PlaneGateway,
		indonesiaPIIActionBlocked, &indonesia.IndonesiaPIICheckResult{
			HasPII: true, Detections: sampleDetections(),
		})
}

// TestRecordIndonesiaPIIEvents_PassesThroughIdentityAndAction
func TestRecordIndonesiaPIIEvents_PassesThroughIdentityAndAction(t *testing.T) {
	original := persistIndonesiaPIIEvents
	t.Cleanup(func() { persistIndonesiaPIIEvents = original })

	var got indonesiaPIIEventBatch
	persistIndonesiaPIIEvents = func(ctx context.Context, batch indonesiaPIIEventBatch) { got = batch }

	recordIndonesiaPIIEvents(context.Background(), "org-a", "tenant-b", "dec-1", "corr-1",
		PlaneDecision, indonesiaPIIActionDetected, &indonesia.IndonesiaPIICheckResult{
			HasPII: true, Detections: sampleDetections(),
		})

	if got.OrgID != "org-a" || got.TenantID != "tenant-b" {
		t.Errorf("identity = %q/%q, want org-a/tenant-b", got.OrgID, got.TenantID)
	}
	if got.DecisionID != "dec-1" || got.CorrelationID != "corr-1" {
		t.Errorf("join keys = %q/%q", got.DecisionID, got.CorrelationID)
	}
	if got.Plane != PlaneDecision {
		t.Errorf("plane = %q, want %q", got.Plane, PlaneDecision)
	}
	if got.Action != indonesiaPIIActionDetected {
		t.Errorf("action = %q, want %q", got.Action, indonesiaPIIActionDetected)
	}
	if len(got.Events) != 2 {
		t.Errorf("events = %d, want 2", len(got.Events))
	}
}

// TestPlaneVocabularyMatchesTheMigrationCheck: enterprise/137 constrains plane
// to (gateway, decision, mcp). A plane constant used at a call site that is not
// in that set would make every write on that plane fail the CHECK -- silently,
// because the writer is best-effort.
func TestPlaneVocabularyMatchesTheMigrationCheck(t *testing.T) {
	allowed := map[string]bool{"gateway": true, "decision": true, "mcp": true}
	for _, p := range []string{PlaneGateway, PlaneDecision, PlaneMCP} {
		if !allowed[p] {
			t.Errorf("plane constant %q is not in the enterprise/137 CHECK vocabulary (gateway, decision, mcp)", p)
		}
	}
}

// TestActionVocabularyMatchesTheMigrationCheck mirrors the above for action.
func TestActionVocabularyMatchesTheMigrationCheck(t *testing.T) {
	allowed := map[string]bool{"blocked": true, "redacted": true, "redaction_required": true, "detected": true}
	for _, a := range []string{indonesiaPIIActionBlocked, indonesiaPIIActionRedacted, indonesiaPIIActionRedactionRequired, indonesiaPIIActionDetected} {
		if !allowed[a] {
			t.Errorf("action constant %q is not in the enterprise/137 CHECK vocabulary", a)
		}
	}
}

// TestNoRawDetectionFieldIsReferencedInTheSeam is the structural guard: the seam
// source must never mention the detector's raw-bearing fields at all.
//
// A value-level test can only prove the raw value is absent from the fixtures it
// happens to use. This proves the CODE cannot carry it: `.Value` and `.Context`
// on an IndonesiaPIIDetectionResult are the two raw-bearing fields, and the
// projection copies named fields precisely so their absence is checkable.
//
// This runs in BOTH editions, so it scans only the always-present seam file.
// indonesia_pii_events_enterprise.go is //go:build enterprise and is stripped
// from the community mirror, so parsing it here would fail the test only in
// community. The enterprise seam file is guarded by
// TestNoRawDetectionFieldIsReferencedInTheEnterpriseSeam in the enterprise-only
// test file, which sees it in the builds where it exists.
func TestNoRawDetectionFieldIsReferencedInTheSeam(t *testing.T) {
	files := []string{"indonesia_pii_events.go"}
	inspected := 0
	for _, f := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		inspected++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !isRawDetectionFieldRef(sel) {
				return true
			}
			t.Errorf("%s:%d references .%s on a detection; the raw match and the context window must never reach the database",
				f, fset.Position(sel.Pos()).Line, sel.Sel.Name)
			return true
		})
	}
	if inspected != 1 {
		t.Fatalf("inspected %d seam files, want 1", inspected)
	}
}

// isRawDetectionFieldRef reports whether sel reads a raw-bearing field off a
// detection.
//
// `context.Context` in a signature is a SelectorExpr whose Sel is literally
// named "Context" -- the first version of this guard flagged every function in
// both seam files. Excluding the `context` package qualifier is the whole
// difference between a guard that runs and one that gets deleted; a detection
// variable is never named `context`.
func isRawDetectionFieldRef(sel *ast.SelectorExpr) bool {
	if sel.Sel.Name != "Value" && sel.Sel.Name != "Context" {
		return false
	}
	if x, ok := sel.X.(*ast.Ident); ok && x.Name == "context" {
		return false
	}
	return true
}

// TestNoRawDetectionFieldIsReferencedInTheSeam_DetectsTheDefect proves the guard
// can fail on the real defect AND does not fire on the shape that made its first
// version unusable.
func TestNoRawDetectionFieldIsReferencedInTheSeam_DetectsTheDefect(t *testing.T) {
	const mutant = `package agent

import "context"

func leaky(ctx context.Context, d detection) (string, string) {
	return d.Value, d.Context
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "mutant.go", mutant, 0)
	if err != nil {
		t.Fatalf("parse mutant: %v", err)
	}
	hits := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && isRawDetectionFieldRef(sel) {
			hits++
		}
		return true
	})
	if hits != 2 {
		t.Fatalf("the guard found %d raw-field references in the mutant, want 2 (d.Value and d.Context); it cannot detect the defect it exists for", hits)
	}

	// Negative control: a file that ONLY uses context.Context must produce zero
	// findings, or the guard is a blanket reject nobody can keep green.
	const clean = `package agent

import "context"

func fine(ctx context.Context) context.Context { return ctx }
`
	cleanFile, err := parser.ParseFile(fset, "clean.go", clean, 0)
	if err != nil {
		t.Fatalf("parse clean: %v", err)
	}
	falsePositives := 0
	ast.Inspect(cleanFile, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && isRawDetectionFieldRef(sel) {
			falsePositives++
		}
		return true
	})
	if falsePositives != 0 {
		t.Fatalf("the guard fired %d times on context.Context alone; that false positive is what made its first version unusable", falsePositives)
	}
}

// TestEventCapIsBounded documents the cap as a real number, so a change to it is
// a deliberate edit rather than a silent uncapping.
func TestEventCapIsBounded(t *testing.T) {
	if maxIndonesiaPIIEventsPerRequest <= 0 || maxIndonesiaPIIEventsPerRequest > 1000 {
		t.Errorf("maxIndonesiaPIIEventsPerRequest = %d; a single request must write a bounded, modest number of rows",
			maxIndonesiaPIIEventsPerRequest)
	}
}
