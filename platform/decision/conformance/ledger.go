package conformance

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

// LedgerFile is the committed disposition ledger, embedded so the guard reads
// the artifact that ships rather than a copy on the runner's disk.
//
//go:embed disposition_ledger.tsv
var LedgerFile string

// LedgerHeader is the exact expected header row, tab separated. It is a
// constant rather than a derived value because two workstreams append to this
// file from different repositories and a column reorder would silently
// reinterpret every row.
var LedgerHeader = []string{
	"source_case_id", "source_title", "source_family", "source_result",
	"disposition", "adr065_result", "semantic_reason",
	"replacement_case_ids", "coverage_case_ids", "approving_reviewer",
}

// SourceCaseCount is the number of cases in the source proposal. The ledger has
// exactly this many data rows, one per source case, forever: ADR-065 Phase 0
// requires every source case to carry exactly one disposition, so a
// forty-eighth row would break the gate rather than extend it.
const SourceCaseCount = 47

// Disposition is what happened to a source case under ADR-065.
type Disposition string

const (
	// DispositionKept means ADR-065 produces the same operational outcome by
	// the same rule and the case transcribes directly.
	DispositionKept Disposition = "kept"
	// DispositionChanged means the case remains meaningful but ADR-065
	// produces a different outcome, a different determining rule, or both.
	DispositionChanged Disposition = "changed"
	// DispositionReplaced means the source case's mechanism does not exist in
	// ADR-065 and other cases cover the property it protected.
	DispositionReplaced Disposition = "replaced"
	// DispositionDropped means the case tests a construct ADR-065 removes.
	// It still requires named replacement coverage: ADR-065 gate 14 asks for
	// executable replacement coverage for changed, replaced AND dropped cases,
	// so a drop is never a way to stop covering a property.
	DispositionDropped Disposition = "dropped"
)

// AllDispositions returns every declared disposition.
func AllDispositions() []Disposition {
	return []Disposition{DispositionKept, DispositionChanged, DispositionReplaced, DispositionDropped}
}

// declaredResults are the values allowed in source_result and adr065_result.
// A compound outcome is written explicitly with a semicolon, for example
// "ERROR;DENY", so that a case with two arms names both rather than being
// summarised into an aggregate category the source case cannot be read out of.
var declaredResults = map[string]bool{
	"Permit": true, "Deny": true, "Escalate": true, "Indeterminate": true, "Rejected": true,
	"ALLOW": true, "DENY": true, "CHALLENGE": true, "ERROR": true, "REJECTED": true,
}

// LedgerRow is one source case disposition.
type LedgerRow struct {
	SourceCaseID      string
	SourceTitle       string
	SourceFamily      string
	SourceResult      string
	Disposition       Disposition
	ADR065Result      string
	SemanticReason    string
	ReplacementCases  []string
	CoverageCases     []string
	ApprovingReviewer string
	// Line is the one-based line number in the file, for error messages.
	Line int
}

// ParseLedger parses the tab separated ledger.
//
// It is strict about shape on purpose. Every cell is present, no cell is blank,
// and an empty list is the literal "-" rather than an empty string, so a column
// count check is meaningful and a shifted column is a parse error rather than a
// value quietly landing in the wrong field.
func ParseLedger(content string) ([]LedgerRow, error) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("ledger: file is empty")
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != len(LedgerHeader) {
		return nil, fmt.Errorf("ledger: header has %d columns, expected %d", len(header), len(LedgerHeader))
	}
	for i, want := range LedgerHeader {
		if header[i] != want {
			return nil, fmt.Errorf("ledger: header column %d is %q, expected %q", i+1, header[i], want)
		}
	}
	var rows []LedgerRow
	for n, line := range lines[1:] {
		lineNo := n + 2
		cells := strings.Split(line, "\t")
		if len(cells) != len(LedgerHeader) {
			return nil, fmt.Errorf("ledger: line %d has %d columns, expected %d", lineNo, len(cells), len(LedgerHeader))
		}
		for i, c := range cells {
			if c == "" {
				return nil, fmt.Errorf("ledger: line %d column %q is empty; an empty list is written as \"-\"", lineNo, LedgerHeader[i])
			}
			if strings.TrimSpace(c) != c {
				return nil, fmt.Errorf("ledger: line %d column %q has surrounding whitespace", lineNo, LedgerHeader[i])
			}
		}
		rows = append(rows, LedgerRow{
			SourceCaseID: cells[0], SourceTitle: cells[1], SourceFamily: cells[2],
			SourceResult: cells[3], Disposition: Disposition(cells[4]), ADR065Result: cells[5],
			SemanticReason:   cells[6],
			ReplacementCases: splitCaseList(cells[7]), CoverageCases: splitCaseList(cells[8]),
			ApprovingReviewer: cells[9], Line: lineNo,
		})
	}
	return rows, nil
}

func splitCaseList(cell string) []string {
	if cell == "-" {
		return nil
	}
	parts := strings.Split(cell, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// LedgerCoverage indexes rows by source case identifier.
func LedgerCoverage(rows []LedgerRow) map[string]LedgerRow {
	out := make(map[string]LedgerRow, len(rows))
	for _, r := range rows {
		out[r.SourceCaseID] = r
	}
	return out
}
