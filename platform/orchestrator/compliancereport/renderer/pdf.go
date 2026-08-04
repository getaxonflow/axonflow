// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package renderer

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/go-pdf/fpdf"
)

// PDFRenderer emits a real PDF via github.com/go-pdf/fpdf.
//
// # Library choice (epic #2892 D2)
//
// Candidates were go-pdf/fpdf and maroto v2.
//
//   - go-pdf/fpdf: MIT. The maintained community fork of the archived
//     jung-kurt/gofpdf. Zero transitive dependencies beyond the stdlib. Ships
//     the PDF standard-14 CORE fonts by metric table, so nothing is embedded
//     and there is NO font file to license, vendor or ship - which matters
//     because an in-VPC deployment builds and runs with no internet.
//   - maroto v2: MIT, but it is a layout DSL built ON TOP of go-pdf/fpdf, so it
//     adds a dependency layer and its own transitive set without removing the
//     one below it, and it does not expose the two knobs this file needs
//     (SetCatalogSort and SetCreationDate) as first-class API.
//
// go-pdf/fpdf was selected: fewer moving parts, the same license, and direct
// control of the determinism knobs.
//
// # Determinism
//
// Three things in a PDF are clocks or hash maps by default:
//
//   - /CreationDate and /ModDate: set from Report.GeneratedAt (the persisted job
//     record), never time.Now().
//   - /ID: many PDF writers put a random or time-derived document identifier in
//     the trailer. fpdf writes an /ID only for an ENCRYPTED document, and then
//     a fixed `[()()]` (fpdf.go puttrailer). These reports are not encrypted,
//     so no identifier is written at all and nothing random reaches the
//     trailer. Asserted by TestPDFRenderer_StructuralAssertions.
//   - The /Font resource dictionary: fpdf builds it by ranging a Go map.
//     SetCatalogSort(true) makes it sort instead. WITHOUT that call two renders
//     of the same document differ - measured, not assumed.
//
// # Glyph coverage
//
// Core fonts are cp1252-encoded. Any rune outside cp1252 (Devanagari, Han, an
// emoji) has no glyph and would be emitted as garbage, so text is transcoded
// through fpdf's cp1252 translator and any remaining unencodable rune is
// replaced with '?'. That is a VISIBLE, honest lossy marker. Callers that need
// full Unicode should request the JSON or CSV artifact, which is stated in the
// docs page's format matrix.
type PDFRenderer struct{}

// NewPDF returns a PDF renderer.
func NewPDF() *PDFRenderer { return &PDFRenderer{} }

// ContentType implements Renderer.
func (PDFRenderer) ContentType() string { return "application/pdf" }

// Extension implements Renderer.
func (PDFRenderer) Extension() string { return "pdf" }

// Page geometry, in mm on A4.
const (
	pdfMarginLeft   = 12.0
	pdfMarginTop    = 14.0
	pdfMarginRight  = 12.0
	pdfBottomMargin = 16.0
	pdfPageWidth    = 210.0
	pdfPageHeight   = 297.0
	pdfContentWidth = pdfPageWidth - pdfMarginLeft - pdfMarginRight
	pdfLineHeight   = 4.6
)

// Render implements Renderer.
func (r PDFRenderer) Render(rep *Report) ([]byte, error) {
	if err := validateReport(rep); err != nil {
		return nil, err
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	// See the package doc: without this the /Font dictionary order is a Go map
	// range and two renders of the same report differ.
	pdf.SetCatalogSort(true)
	pdf.SetCreationDate(rep.GeneratedAt.UTC())
	pdf.SetModificationDate(rep.GeneratedAt.UTC())
	pdf.SetTitle(documentTitle(rep), true)
	pdf.SetAuthor(brandName, true)
	pdf.SetCreator(brandName+" Orchestrator", true)
	pdf.SetSubject(fmt.Sprintf("%s compliance report for %s", rep.RegulatorName, rep.OrgID), true)
	pdf.SetMargins(pdfMarginLeft, pdfMarginTop, pdfMarginRight)
	pdf.SetAutoPageBreak(true, pdfBottomMargin)
	pdf.AliasNbPages("{nb}")

	tr := pdf.UnicodeTranslatorFromDescriptor("") // "" => cp1252
	enc := func(s string) string { return tr(sanitizeForCore(s)) }

	title := enc(documentTitle(rep))
	footer := enc(fmt.Sprintf("%s | report %s | generated %s", brandName, rep.JobID, fmtStamp(rep.GeneratedAt)))

	pdf.SetHeaderFunc(func() {
		pdf.SetY(6)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(pdfContentWidth, 5, title, "", 1, "L", false, 0, "")
		pdf.SetDrawColor(180, 180, 180)
		pdf.Line(pdfMarginLeft, 12, pdfPageWidth-pdfMarginRight, 12)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetY(pdfMarginTop)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(pdfContentWidth-30, 5, footer, "", 0, "L", false, 0, "")
		pdf.CellFormat(30, 5, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	})

	pdf.AddPage()

	// Identity block.
	pdf.SetFont("Helvetica", "B", 15)
	pdf.MultiCell(pdfContentWidth, 7, title, "", "L", false)
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "", 9)
	for _, kv := range headerLines(rep) {
		if kv.Value == "" {
			continue
		}
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(38, pdfLineHeight, enc(kv.Key), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(pdfContentWidth-38, pdfLineHeight, enc(kv.Value), "", "L", false)
	}
	pdf.Ln(3)

	for i := range rep.Sections {
		renderPDFSection(pdf, enc, &rep.Sections[i])
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("renderer: pdf output: %w", err)
	}
	return buf.Bytes(), nil
}

func renderPDFSection(pdf *fpdf.Fpdf, enc func(string) string, s *Section) {
	// Keep a section heading with at least a couple of lines of its content.
	ensureSpace(pdf, 22)

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetFillColor(238, 240, 244)
	pdf.CellFormat(pdfContentWidth, 6.5, " "+enc(s.Title), "", 1, "L", true, 0, "")
	pdf.Ln(1.5)

	if s.Description != "" {
		pdf.SetFont("Helvetica", "I", 8.5)
		pdf.MultiCell(pdfContentWidth, pdfLineHeight, enc(s.Description), "", "L", false)
		pdf.Ln(1)
	}
	for _, n := range s.Notes {
		pdf.SetFont("Helvetica", "", 8.5)
		pdf.MultiCell(pdfContentWidth, pdfLineHeight, enc("Note: "+n), "", "L", false)
	}
	if len(s.Summary) > 0 {
		pdf.Ln(1)
		pdf.SetFont("Helvetica", "", 9)
		for _, kv := range s.Summary {
			pdf.SetFont("Helvetica", "B", 9)
			pdf.CellFormat(60, pdfLineHeight, enc(kv.Key), "", 0, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 9)
			pdf.MultiCell(pdfContentWidth-60, pdfLineHeight, enc(kv.Value), "", "L", false)
		}
	}

	if len(s.Columns) > 0 && len(s.Rows) > 0 {
		pdf.Ln(2)
		renderPDFTable(pdf, enc, s.Columns, s.Rows)
	}
	pdf.Ln(4)
}

// renderPDFTable draws a wrapping table.
//
// fpdf has no table primitive. The standard approach - and the one used here -
// is to measure each cell with SplitLines, take the tallest cell as the row
// height, then draw every cell with MultiCell at an explicit (x, y). Without
// the measure pass a long cell silently overlaps the row beneath it, which on a
// regulatory artifact reads as corrupted data.
func renderPDFTable(pdf *fpdf.Fpdf, enc func(string) string, columns []string, rows [][]string) {
	widths := columnWidths(len(columns))
	const fontSize = 7.5
	const lineH = 3.6

	drawHeader := func() {
		pdf.SetFont("Helvetica", "B", fontSize)
		pdf.SetFillColor(222, 226, 233)
		x := pdfMarginLeft
		y := pdf.GetY()
		h := lineH + 1.6
		for i, c := range columns {
			pdf.SetXY(x, y)
			pdf.CellFormat(widths[i], h, enc(c), "1", 0, "L", true, 0, "")
			x += widths[i]
		}
		pdf.SetXY(pdfMarginLeft, y+h)
	}

	ensureSpace(pdf, 16)
	drawHeader()

	pdf.SetFont("Helvetica", "", fontSize)
	pdf.SetFillColor(255, 255, 255)
	for _, row := range rows {
		cells := make([]string, len(columns))
		maxLines := 1
		for i := range columns {
			v := ""
			if i < len(row) {
				v = enc(row[i])
			}
			cells[i] = v
			// SplitLines must be given the width MultiCell will actually have
			// for text, i.e. minus the cell margin fpdf applies on both sides.
			// Measuring against the full column width under-counts the lines on
			// a cell that only just overflows, and the row then draws one line
			// short - the overlap this measure pass exists to prevent.
			if n := len(pdf.SplitLines([]byte(v), widths[i]-2*pdf.GetCellMargin())); n > maxLines {
				maxLines = n
			}
		}
		rowH := float64(maxLines)*lineH + 1.4
		if !hasSpace(pdf, rowH) {
			pdf.AddPage()
			drawHeader()
			pdf.SetFont("Helvetica", "", fontSize)
		}
		x := pdfMarginLeft
		y := pdf.GetY()
		for i := range columns {
			pdf.SetXY(x, y)
			// Border on the wrapper cell, then the text on top: MultiCell's own
			// border would be drawn per WRAPPED LINE, giving a ragged grid.
			pdf.CellFormat(widths[i], rowH, "", "1", 0, "L", false, 0, "")
			pdf.SetXY(x, y+0.7)
			pdf.MultiCell(widths[i], lineH, cells[i], "", "L", false)
			x += widths[i]
		}
		pdf.SetXY(pdfMarginLeft, y+rowH)
	}
}

// columnWidths splits the content width evenly. Even, not content-derived:
// a width computed from the widest observed value would make the layout depend
// on the DATA, so two reports of the same shape would not be visually
// comparable side by side - and an auditor comparing two quarters is the whole
// use case.
func columnWidths(n int) []float64 {
	if n <= 0 {
		return nil
	}
	w := pdfContentWidth / float64(n)
	out := make([]float64, n)
	for i := range out {
		out[i] = w
	}
	return out
}

// hasSpace reports whether h mm remain above the bottom margin.
func hasSpace(pdf *fpdf.Fpdf, h float64) bool {
	return pdf.GetY()+h <= pdfPageHeight-pdfBottomMargin
}

// ensureSpace starts a new page when less than h mm remain.
func ensureSpace(pdf *fpdf.Fpdf, h float64) {
	if !hasSpace(pdf, h) {
		pdf.AddPage()
	}
}

// sanitizeForCore replaces every rune the cp1252 core-font encoding cannot
// represent with '?', and normalizes the whitespace a PDF cell cannot show.
//
// Doing this BEFORE fpdf's translator is deliberate: the translator drops
// unmappable runes silently, so "Ravi Kumar" written in Devanagari would render
// as an empty cell that looks like missing data. A row of '?' is unmistakably
// "we could not draw this text", which is the honest signal.
func sanitizeForCore(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r < 0x20:
			// Other control characters carry no glyph at all.
			continue
		case r <= 0xFF:
			b.WriteRune(r)
		case isCP1252Extra(r):
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

// cp1252Extras are the printable characters cp1252 places in 0x80-0x9F, which
// in Unicode live outside Latin-1. Listing them keeps typographic quotes and
// dashes - which arrive constantly in copy-pasted policy descriptions - from
// being flattened to '?'.
var cp1252Extras = []rune{
	0x20AC, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030,
	0x0160, 0x2039, 0x0152, 0x017D, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
	0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x017E, 0x0178,
}

func isCP1252Extra(r rune) bool {
	for _, e := range cp1252Extras {
		if e == r {
			return true
		}
	}
	return false
}
