// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package renderer

import (
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"
)

// XLSXRenderer emits a real .xlsx workbook via excelize (BSD-3-Clause).
//
// Layout: one "Report" cover sheet carrying the identity block, then one sheet
// per section. Sheet names are derived from section titles and sanitized to the
// Excel rules (<=31 chars, none of : \ / ? * [ ]) with a numeric prefix so two
// sections whose titles collide after sanitizing still get distinct sheets.
//
// Determinism: excelize writes a zip whose entry headers carry a FIXED
// timestamp, and this renderer sets no document properties from a clock, so two
// renders of the same report are byte-identical. Measured, not assumed - see
// TestXLSXRendererIsDeterministic.
type XLSXRenderer struct{}

// NewXLSX returns an XLSX renderer.
func NewXLSX() *XLSXRenderer { return &XLSXRenderer{} }

// ContentType implements Renderer.
func (XLSXRenderer) ContentType() string {
	return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

// Extension implements Renderer.
func (XLSXRenderer) Extension() string { return "xlsx" }

const xlsxCoverSheet = "Report"

// Render implements Renderer.
func (r XLSXRenderer) Render(rep *Report) (out []byte, err error) {
	if err := validateReport(rep); err != nil {
		return nil, err
	}
	f := excelize.NewFile()
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("renderer: xlsx close: %w", cerr)
		}
	}()

	// excelize's new file starts with a sheet called "Sheet1"; rename it rather
	// than adding a cover sheet and leaving an empty "Sheet1" in the workbook.
	if err = f.SetSheetName("Sheet1", xlsxCoverSheet); err != nil {
		return nil, fmt.Errorf("renderer: xlsx rename cover sheet: %w", err)
	}

	if err = setCell(f, xlsxCoverSheet, 1, 1, documentTitle(rep)); err != nil {
		return nil, err
	}
	row := 3
	for _, kv := range headerLines(rep) {
		if err = setCell(f, xlsxCoverSheet, row, 1, kv.Key); err != nil {
			return nil, err
		}
		if err = setCell(f, xlsxCoverSheet, row, 2, kv.Value); err != nil {
			return nil, err
		}
		row++
	}

	used := map[string]bool{strings.ToLower(xlsxCoverSheet): true}
	for i := range rep.Sections {
		s := &rep.Sections[i]
		name := uniqueSheetName(sanitizeSheetName(s.Title, i+1), used)
		if _, err = f.NewSheet(name); err != nil {
			return nil, fmt.Errorf("renderer: xlsx new sheet %q: %w", name, err)
		}
		if err = writeSectionSheet(f, name, s); err != nil {
			return nil, err
		}
	}

	// The cover sheet is the one a reader should land on.
	idx, err := f.GetSheetIndex(xlsxCoverSheet)
	if err != nil {
		return nil, fmt.Errorf("renderer: xlsx cover sheet index: %w", err)
	}
	f.SetActiveSheet(idx)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, fmt.Errorf("renderer: xlsx write: %w", err)
	}
	return buf.Bytes(), nil
}

func writeSectionSheet(f *excelize.File, sheet string, s *Section) error {
	row := 1
	if err := setCell(f, sheet, row, 1, s.Title); err != nil {
		return err
	}
	row += 2
	if s.Description != "" {
		if err := setCell(f, sheet, row, 1, s.Description); err != nil {
			return err
		}
		row++
	}
	for _, n := range s.Notes {
		if err := setCell(f, sheet, row, 1, "NOTE"); err != nil {
			return err
		}
		if err := setCell(f, sheet, row, 2, n); err != nil {
			return err
		}
		row++
	}
	for _, kv := range s.Summary {
		if err := setCell(f, sheet, row, 1, kv.Key); err != nil {
			return err
		}
		if err := setCell(f, sheet, row, 2, kv.Value); err != nil {
			return err
		}
		row++
	}
	if len(s.Columns) == 0 || len(s.Rows) == 0 {
		return nil
	}
	row++
	for c, col := range s.Columns {
		if err := setCell(f, sheet, row, c+1, col); err != nil {
			return err
		}
	}
	row++
	for _, dataRow := range s.Rows {
		for c, cell := range dataRow {
			if err := setCell(f, sheet, row, c+1, cell); err != nil {
				return err
			}
		}
		row++
	}
	return nil
}

// setCell writes a STRING cell. SetCellStr, not SetCellValue: SetCellValue
// type-switches and would coerce a value that merely looks numeric ("007", a
// long request id, a leading-+ phone number) into a float, destroying leading
// zeros and rendering long ids in scientific notation. Every value in a report
// row is already a formatted string; it must land in the sheet unchanged.
func setCell(f *excelize.File, sheet string, row, col int, value string) error {
	axis, err := excelize.CoordinatesToCellName(col, row)
	if err != nil {
		return fmt.Errorf("renderer: xlsx cell (%d,%d): %w", col, row, err)
	}
	// NO FORMULA NEUTRALIZATION HERE, DELIBERATELY - and this is not an
	// oversight, so please do not "fix" it (#3241 round 2, R3).
	//
	// XLSX is not CSV. SetCellStr writes a STRING cell; measured on the
	// generated workbook, `=HYPERLINK("http://x","c")` is stored as
	//
	//   xl/worksheets/sheet1.xml : <c r="A1" t="s"><v>0</v></c>
	//   xl/sharedStrings.xml     : <si><t>=HYPERLINK(&#34;http://x&#34;,...)</t></si>
	//
	// A formula in XLSX lives in an <f> element, which nothing here emits, so a
	// spreadsheet application never evaluates this cell - the value round-trips
	// as text. Prefixing it with an apostrophe would NOT produce the
	// quote-prefix flag either (that is a cell STYLE, `quotePrefix="1"`, which
	// excelize does not set here); it would simply put a visible apostrophe in
	// front of an auditor's data.
	//
	// So the choice is between corrupting the artifact and defending against
	// nothing. The CSV renderer neutralizes because there the risk is real -
	// see neutralizeFormula in csv.go.
	if err := f.SetCellStr(sheet, axis, value); err != nil {
		return fmt.Errorf("renderer: xlsx set %s!%s: %w", sheet, axis, err)
	}
	return nil
}

// invalidSheetRunes are the characters Excel refuses in a sheet name.
const invalidSheetRunes = `:\/?*[]`

// sanitizeSheetName produces a legal, non-empty Excel sheet name.
// ordinal keeps names unique-ish and stable when a title sanitizes to nothing.
func sanitizeSheetName(title string, ordinal int) string {
	var b strings.Builder
	for _, r := range title {
		if strings.ContainsRune(invalidSheetRunes, r) {
			b.WriteRune('-')
			continue
		}
		if r < 0x20 {
			continue
		}
		b.WriteRune(r)
	}
	name := strings.TrimSpace(b.String())
	// A sheet name may not start or end with an apostrophe.
	name = strings.Trim(name, "'")
	if name == "" {
		name = fmt.Sprintf("Section %d", ordinal)
	}
	return truncateRunes(name, 31)
}

// uniqueSheetName disambiguates a name against the ones already used. Excel
// sheet names are case-INSENSITIVE for uniqueness, so the comparison is folded.
func uniqueSheetName(name string, used map[string]bool) string {
	key := strings.ToLower(name)
	if !used[key] {
		used[key] = true
		return name
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf(" (%d)", i)
		candidate := truncateRunes(name, 31-len([]rune(suffix))) + suffix
		k := strings.ToLower(candidate)
		if !used[k] {
			used[k] = true
			return candidate
		}
	}
}

// truncateRunes cuts a string to at most n runes (not bytes: cutting a UTF-8
// sequence mid-way produces an invalid name Excel rejects).
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
