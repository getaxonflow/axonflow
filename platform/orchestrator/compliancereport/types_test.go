// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func aPeriod() (time.Time, time.Time) {
	return fixedNow.AddDate(0, -1, 0), fixedNow
}

func TestReportRequest_Validate_Accepts(t *testing.T) {
	start, end := aPeriod()
	for _, reg := range AllRegulators() {
		for _, format := range FormatsFor(reg) {
			for _, fw := range FrameworksFor(reg) {
				req := ReportRequest{Regulator: reg, Framework: fw, Format: format, PeriodStart: start, PeriodEnd: end}
				if err := req.Validate(); err != nil {
					t.Errorf("%s/%s/%s: %v", reg, fw, format, err)
				}
			}
		}
	}
}

func TestReportRequest_Validate_Rejects(t *testing.T) {
	start, end := aPeriod()
	base := func() ReportRequest {
		return ReportRequest{Regulator: RegulatorSEBI, Framework: FrameworkSEBIAIML, Format: FormatJSON, PeriodStart: start, PeriodEnd: end}
	}

	cases := []struct {
		name string
		code string
		mut  func(*ReportRequest)
	}{
		{"unknown regulator", ErrCodeUnknownRegulator, func(r *ReportRequest) { r.Regulator = "fca" }},
		{"empty regulator", ErrCodeUnknownRegulator, func(r *ReportRequest) { r.Regulator = "" }},
		{"framework from another regulator", ErrCodeUnknownFramework, func(r *ReportRequest) { r.Framework = FrameworkUUPDP }},
		{"unknown format", ErrCodeUnsupportedFormat, func(r *ReportRequest) { r.Format = "docx" }},
		{"empty format", ErrCodeUnsupportedFormat, func(r *ReportRequest) { r.Format = "" }},
		{"format not offered for this regulator", ErrCodeUnsupportedFormat, func(r *ReportRequest) {
			r.Regulator, r.Framework, r.Format = RegulatorOJK, FrameworkUUPDP, FormatXLSX
		}},
		{"zero period start", ErrCodeInvalidPeriod, func(r *ReportRequest) { r.PeriodStart = time.Time{} }},
		{"zero period end", ErrCodeInvalidPeriod, func(r *ReportRequest) { r.PeriodEnd = time.Time{} }},
		{"inverted period", ErrCodeInvalidPeriod, func(r *ReportRequest) { r.PeriodStart, r.PeriodEnd = end, start }},
		{"zero-length period", ErrCodeInvalidPeriod, func(r *ReportRequest) { r.PeriodEnd = r.PeriodStart }},
		{"period beyond the cap", ErrCodeInvalidPeriod, func(r *ReportRequest) {
			r.PeriodStart = r.PeriodEnd.AddDate(0, 0, -(maxPeriodDays + 1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := base()
			tc.mut(&req)
			err := req.Validate()
			var reqErr *RequestError
			if !errors.As(err, &reqErr) {
				t.Fatalf("err = %v, want a *RequestError", err)
			}
			if reqErr.Code != tc.code {
				t.Errorf("code = %s, want %s (message: %s)", reqErr.Code, tc.code, reqErr.Message)
			}
		})
	}
}

// TestReportRequest_OJKRequiresAnExplicitFramework pins the one regulator with
// no default. Picking one of OJK's four silently would file a report under the
// wrong Indonesian instrument.
func TestReportRequest_OJKRequiresAnExplicitFramework(t *testing.T) {
	start, end := aPeriod()
	req := ReportRequest{Regulator: RegulatorOJK, Format: FormatPDF, PeriodStart: start, PeriodEnd: end}

	err := req.Validate()
	var reqErr *RequestError
	if !errors.As(err, &reqErr) || reqErr.Code != ErrCodeUnknownFramework {
		t.Fatalf("err = %v, want %s", err, ErrCodeUnknownFramework)
	}
	// The refusal must enumerate the four so the caller can act on it.
	for _, want := range []string{"OJK_AI_GOVERNANCE", "UU_PDP", "BI_PJP", "OJK_BI_COMBINED"} {
		if !strings.Contains(reqErr.Message, want) {
			t.Errorf("the refusal does not name %s: %s", want, reqErr.Message)
		}
	}
}

// TestReportRequest_SingleFrameworkRegulatorsDefault pins the counterpart: the
// four regulators with exactly one framework do not force the caller to name it.
func TestReportRequest_SingleFrameworkRegulatorsDefault(t *testing.T) {
	start, end := aPeriod()
	for _, reg := range []Regulator{RegulatorEUAIAct, RegulatorSEBI, RegulatorRBI, RegulatorMASFEAT} {
		req := ReportRequest{Regulator: reg, Format: FormatJSON, PeriodStart: start, PeriodEnd: end}
		if err := req.Validate(); err != nil {
			t.Errorf("%s: %v", reg, err)
			continue
		}
		want := FrameworksFor(reg)[0]
		if req.Framework != want {
			t.Errorf("%s: framework defaulted to %q, want %q", reg, req.Framework, want)
		}
	}
}

// TestFormatMatrixMatchesDesignRecord pins the per-regulator format matrix
// against the table in epic #2892's design record, which is also what the docs
// page publishes. XLSX is offered ONLY where the regulator's submission
// practice is spreadsheet-shaped; widening it silently would mean shipping a
// layout nobody designed for that regulator.
func TestFormatMatrixMatchesDesignRecord(t *testing.T) {
	want := map[Regulator][]Format{
		RegulatorOJK:     {FormatPDF, FormatCSV, FormatJSON},
		RegulatorEUAIAct: {FormatPDF, FormatCSV, FormatJSON},
		RegulatorSEBI:    {FormatPDF, FormatCSV, FormatXLSX, FormatJSON},
		RegulatorRBI:     {FormatPDF, FormatCSV, FormatXLSX, FormatJSON},
		RegulatorMASFEAT: {FormatPDF, FormatCSV, FormatJSON},
	}
	if len(want) != len(AllRegulators()) {
		t.Fatalf("the matrix covers %d regulators, AllRegulators has %d", len(want), len(AllRegulators()))
	}
	for reg, wantFormats := range want {
		got := FormatsFor(reg)
		if len(got) != len(wantFormats) {
			t.Errorf("%s: formats = %v, want %v", reg, got, wantFormats)
			continue
		}
		for i := range got {
			if got[i] != wantFormats[i] {
				t.Errorf("%s: formats = %v, want %v", reg, got, wantFormats)
				break
			}
		}
		// Every offered format must have a renderer, or the job fails after
		// the caller has already been told 202.
		for _, f := range got {
			if _, err := RendererFor(f); err != nil {
				t.Errorf("%s offers %s but there is no renderer: %v", reg, f, err)
			}
		}
	}
}

// TestEveryRegulatorHasARetentionNote pins that no artifact goes out with a
// blank retention line. Retention is a regulator-specific claim on the face of
// the document; an empty one reads as "we do not retain this".
func TestEveryRegulatorHasARetentionNote(t *testing.T) {
	for _, reg := range AllRegulators() {
		if strings.TrimSpace(RetentionNoteFor(reg)) == "" {
			t.Errorf("%s has no retention note", reg)
		}
		if strings.TrimSpace(reg.DisplayName()) == "" {
			t.Errorf("%s has no display name", reg)
		}
	}
}

// TestDocsPublishTheSameFormatMatrix guards the docs page against the code.
//
// The matrix is a customer-facing promise; a docs page claiming XLSX for a
// regulator the code refuses produces a support ticket, and the two live in
// different repositories so nothing else keeps them together. The docs file is
// read from the sibling checkout when present and the check is skipped when it
// is not, so this never fails a build that has no docs clone.
func TestDocsPublishTheSameFormatMatrix(t *testing.T) {
	const docsPath = "../../../../axonflow-docs/docs/enterprise/compliance-reports.md"
	b, err := os.ReadFile(docsPath)
	if err != nil {
		t.Skipf("docs checkout not present at %s - skipping the cross-repo matrix check", docsPath)
	}
	doc := string(b)
	for _, reg := range AllRegulators() {
		for _, f := range FormatsFor(reg) {
			// The docs table row is `| <regulator> | ... | pdf, csv, json |`.
			if !strings.Contains(doc, string(f)) {
				t.Errorf("the docs page never mentions the %s format", f)
			}
		}
		if !strings.Contains(doc, string(reg)) {
			t.Errorf("the docs page never mentions regulator %s", reg)
		}
	}
}

func TestStatusAndReportStateVocabulary(t *testing.T) {
	for _, s := range []Status{StatusPending, StatusProcessing, StatusCompleted, StatusFailed} {
		if !s.Valid() {
			t.Errorf("%s is not Valid()", s)
		}
	}
	if Status("cancelled").Valid() {
		t.Error("an unknown status is Valid()")
	}
	if !StatusCompleted.Terminal() || !StatusFailed.Terminal() {
		t.Error("completed/failed must be terminal")
	}
	if StatusPending.Terminal() || StatusProcessing.Terminal() {
		t.Error("pending/processing must not be terminal")
	}
	// The undetermined value is deliberately NOT Valid(): Valid() guards the
	// state a FINISHED report carries.
	if ReportStateUndetermined.Valid() {
		t.Error("the undetermined report state must not pass Valid()")
	}
	for _, rs := range []ReportState{ReportStateNotAvailable, ReportStateEnabledEmpty, ReportStatePopulated} {
		if !rs.Valid() {
			t.Errorf("%s is not Valid()", rs)
		}
	}
}

// TestSortedKVIsStable pins the helper every provider funnels a map through.
// Ranging a Go map directly is the single easiest way to make a renderer
// nondeterministic, and it fails intermittently rather than always.
func TestSortedKVIsStable(t *testing.T) {
	m := map[string]int{"critical": 3, "high": 2, "low": 9, "medium": 1, "info": 4}
	first := SortedKV(m)
	for i := 0; i < 50; i++ {
		got := SortedKV(m)
		if len(got) != len(first) {
			t.Fatalf("length changed between calls")
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("SortedKV is not stable: %v vs %v", got, first)
			}
		}
	}
	if first[0].Key != "critical" || first[len(first)-1].Key != "medium" {
		t.Errorf("SortedKV is not sorted by key: %v", first)
	}
}

// TestCapRowsAnnouncesWhatItDropped pins that truncation is never silent. A
// regulatory artifact that shows a subset without saying so is asserting that
// the subset is everything.
func TestCapRowsAnnouncesWhatItDropped(t *testing.T) {
	rows := make([][]string, maxSectionRows+7)
	for i := range rows {
		rows[i] = []string{"r"}
	}
	got, note := capRows(rows)
	if len(got) != maxSectionRows {
		t.Errorf("kept %d rows, want %d", len(got), maxSectionRows)
	}
	if !strings.Contains(note, "TRUNCATED") || !strings.Contains(note, "7 not shown") {
		t.Errorf("truncation note does not state what was dropped: %q", note)
	}

	small := [][]string{{"a"}}
	if _, note := capRows(small); note != "" {
		t.Errorf("an untruncated section produced a truncation note: %q", note)
	}
}

// TestFinishSectionEmitsAnEmptyStateSentence pins that an empty section is
// still emitted, carrying WHY it is empty.
func TestFinishSectionEmitsAnEmptyStateSentence(t *testing.T) {
	s := finishSection(Section{Key: "k", Title: "T", Columns: []string{"A"}}, "nothing in range")
	if len(s.Rows) != 0 {
		t.Errorf("rows = %v, want none", s.Rows)
	}
	if len(s.Notes) != 1 || s.Notes[0] != "nothing in range" {
		t.Errorf("notes = %v, want the empty-state sentence", s.Notes)
	}
}

func TestStateFromCount(t *testing.T) {
	if stateFromCount(0) != ReportStateEnabledEmpty {
		t.Error("zero rows must be enabled_empty")
	}
	if stateFromCount(1) != ReportStatePopulated {
		t.Error("one row must be populated")
	}
}

func TestStorageKeyFor(t *testing.T) {
	job := &ReportJob{ID: "creport-1", OrgID: "acme", Regulator: RegulatorRBI}
	if got, want := StorageKeyFor(job, "pdf"), "compliance-reports/acme/rbi/creport-1.pdf"; got != want {
		t.Errorf("StorageKeyFor = %q, want %q", got, want)
	}
}

func TestCloneIsADeepCopyOfTheTimePointers(t *testing.T) {
	started := fixedNow
	job := &ReportJob{ID: "j", StartedAt: &started}
	clone := job.Clone()
	*clone.StartedAt = fixedNow.Add(time.Hour)
	if job.StartedAt.Equal(*clone.StartedAt) {
		t.Error("Clone shares the StartedAt pointer - a mutation on one side is visible on the other")
	}
	if Clone := (*ReportJob)(nil).Clone(); Clone != nil {
		t.Error("Clone of nil must be nil")
	}
}
