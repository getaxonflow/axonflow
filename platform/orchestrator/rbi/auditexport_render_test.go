// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xuri/excelize/v2"
)

// Tests for the real PDF / XLSX artifacts (#3241, epic #2892).
//
// The behaviour these pin is not "a file was produced" - the broken versions
// produced files too. It is that the BYTES are the format the extension claims:
// generatePDFFile wrote plain text renamed to .pdf, and generateXLSXFile wrote
// CSV named .xlsx. Both then flowed through the service's SHA-256, so the
// export verified perfectly as the wrong thing.

func sampleExportData(t *testing.T) *ExportData {
	t.Helper()
	generated := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	created := time.Date(2026, 2, 2, 2, 2, 2, 0, time.UTC)
	return &ExportData{
		Systems: []*AISystem{{
			ID: "sys-1", SystemName: "Retail Credit Scorer", Description: "Scores retail loan applications",
			RiskCategory: RiskCategory("high"), DeploymentStatus: DeploymentStatus("production"), CreatedAt: created,
		}},
		Validations: []*ModelValidation{{
			ID: "val-1", SystemID: "sys-1", ValidatorName: "Independent Model Risk",
			ValidationType: ValidationType("bias"), Recommendation: ValidationRecommendation("approve"), CreatedAt: created,
		}},
		Incidents: []*AIIncident{{
			ID: "inc-1", SystemID: "sys-1", Title: "Score drift beyond tolerance",
			Severity: IncidentSeverity("high"), Status: IncidentStatus("resolved"), CreatedAt: created,
		}},
		KillSwitches: []*KillSwitch{{
			ID: "ks-1", SystemID: "sys-1", ActivationReason: "drift", IsActive: false, CreatedAt: created,
		}},
		Reports: []*BoardReport{{
			ID: "rpt-1", ReportType: ReportType("quarterly"),
			ReportPeriodStart: &start, ReportPeriodEnd: &end,
			ApprovalStatus: ReportApprovalStatus("approved"), CreatedAt: created,
		}},
		TotalRecords: 5,
		Summary: &AuditExportSummary{
			TotalSystems: 1, TotalValidations: 1, TotalIncidents: 1,
			TotalKillSwitches: 1, TotalReports: 1,
		},
		ExportMeta: &ExportMetadata{
			ExportID: "exp-1", OrgID: "bank-org", ExportType: "full",
			Format: "pdf", StartDate: &start, EndDate: &end,
			GeneratedAt: generated, GeneratedBy: "compliance@bank.example", Purpose: "RBI FREE-AI submission",
		},
	}
}

// TestGeneratePDFFile_IsARealPDF is the direct inversion of the old behaviour:
// the artifact must begin with the PDF magic bytes, and no sibling .txt may be
// left behind by a rename that no longer happens.
func TestGeneratePDFFile_IsARealPDF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rbi-audit.pdf")
	svc := &AuditExportService{}

	if err := svc.generatePDFFile(path, sampleExportData(t)); err != nil {
		t.Fatalf("generatePDFFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if !bytes.HasPrefix(b, []byte("%PDF-")) {
		head := b
		if len(head) > 80 {
			head = head[:80]
		}
		t.Fatalf("artifact is not a PDF; it begins with %q", string(head))
	}
	// A PDF ends with the EOF marker. Checking both ends catches a truncated
	// write that a prefix check alone would pass.
	if !bytes.Contains(b[max0(len(b)-64):], []byte("%%EOF")) {
		t.Errorf("PDF is missing its %%%%EOF trailer; tail=%q", string(b[max0(len(b)-64):]))
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected exactly one artifact in the export directory, got %v (the old code wrote a .txt and renamed it)", names)
	}
}

// TestGenerateXLSXFile_IsARealWorkbook opens the artifact with excelize. A CSV
// named .xlsx - the old behaviour - fails to open at all.
func TestGenerateXLSXFile_IsARealWorkbook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rbi-audit.xlsx")
	svc := &AuditExportService{}

	if err := svc.generateXLSXFile(path, sampleExportData(t)); err != nil {
		t.Fatalf("generateXLSXFile: %v", err)
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		b, _ := os.ReadFile(path)
		head := b
		if len(head) > 80 {
			head = head[:80]
		}
		t.Fatalf("artifact does not open as a workbook: %v; it begins with %q", err, string(head))
	}
	defer func() { _ = f.Close() }()

	sheets := f.GetSheetList()
	if len(sheets) < 2 {
		t.Fatalf("expected a cover sheet plus per-section sheets, got %v", sheets)
	}
	// The data must actually be IN the workbook, not merely a valid empty one.
	found := false
	for _, sheet := range sheets {
		rows, err := f.GetRows(sheet)
		if err != nil {
			t.Fatalf("GetRows(%s): %v", sheet, err)
		}
		for _, row := range rows {
			if strings.Contains(strings.Join(row, "|"), "Retail Credit Scorer") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("workbook does not contain the seeded AI system name; sheets=%v", sheets)
	}
}

// TestGenerateCSVFile_StillParsesAsCSV is the control for the two above: the
// CSV path was never broken and must stay unbroken by this change.
func TestGenerateCSVFile_StillParsesAsCSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rbi-audit.csv")
	svc := &AuditExportService{}

	if err := svc.generateCSVFile(path, sampleExportData(t)); err != nil {
		t.Fatalf("generateCSVFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	rd := csv.NewReader(bytes.NewReader(b))
	// The legacy RBI CSV is sectioned and therefore ragged; -1 accepts a
	// variable field count. This is the pre-existing shape of that endpoint and
	// is NOT the shape of the new facade's CSV, which pads every record.
	rd.FieldsPerRecord = -1
	if _, err := rd.ReadAll(); err != nil {
		t.Fatalf("CSV artifact does not parse: %v", err)
	}
}

// determinismRenders is how many times each artifact is rendered.
//
// TWO IS NOT ENOUGH, measured. The nondeterminism this guards against is Go map
// iteration order in fpdf's /Font resource dictionary, and this report uses
// three font entries - so with only two renders a broken renderer produces
// identical bytes by chance roughly a third of the time and the test passes.
// Verified by mutation: with `pdf.SetCatalogSort(true)` removed, a 2-render
// version passed on the first attempt and only failed once run with -count=8;
// this 6-render version fails on essentially every attempt.
const determinismRenders = 6

// TestRenderedArtifactsAreDeterministic pins the checksum contract: the export
// service SHA-256s the artifact and stores the digest, and GetExportFile later
// refuses a mismatch. If rendering were nondeterministic, re-rendering the same
// export would produce a "corrupt" verdict on an uncorrupted file.
func TestRenderedArtifactsAreDeterministic(t *testing.T) {
	svc := &AuditExportService{}
	for _, tc := range []struct {
		name string
		ext  string
		gen  func(string, *ExportData) error
	}{
		{"pdf", "pdf", svc.generatePDFFile},
		{"xlsx", "xlsx", svc.generateXLSXFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var want [32]byte
			var wantLen int
			for i := 0; i < determinismRenders; i++ {
				path := filepath.Join(dir, "render-"+string(rune('a'+i))+"."+tc.ext)
				if err := tc.gen(path, sampleExportData(t)); err != nil {
					t.Fatalf("render %d: %v", i, err)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read render %d: %v", i, err)
				}
				got := sha256.Sum256(b)
				if i == 0 {
					want, wantLen = got, len(b)
					// A wall-clock gap after the first render only: a renderer
					// that reads time.Now() anywhere fails here, and one second
					// is enough for any timestamp with second resolution to
					// move. Sleeping between every pair would just make the
					// test slow.
					time.Sleep(1100 * time.Millisecond)
					continue
				}
				if got != want {
					t.Fatalf("render %d differs from render 0 (%d vs %d bytes) - the stored checksum would not verify on re-render",
						i, len(b), wantLen)
				}
			}
		})
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
