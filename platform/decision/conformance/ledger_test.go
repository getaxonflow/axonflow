package conformance

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	sourceCaseIDPattern = regexp.MustCompile(`^EX-\d{2}$`)
	anyCaseIDPattern    = regexp.MustCompile(`^(EX-\d{2}|AXC-\d{3})$`)
)

// ledgerWorld is everything the gate compares the ledger against: which case
// identifiers execute here, and what each transcribed case declares it
// produces.
type ledgerWorld struct {
	local    map[string]struct{}
	declared map[string][]string
}

func currentLedgerWorld() ledgerWorld {
	w := ledgerWorld{local: map[string]struct{}{}, declared: map[string][]string{}}
	for _, c := range AllCases() {
		w.local[c.ID] = struct{}{}
		if len(c.Produces) > 0 {
			w.declared[c.ID] = c.Produces
		}
	}
	return w
}

// gateViolations is THE gate. It is one function so that the self-test below
// and the acceptance test above cannot be two implementations of one rule set:
// an earlier version had the gate reimplement the semantic rules inline while
// the self-test exercised a separate copy, and five rules could then be
// disabled with the suite green.
func gateViolations(rows []LedgerRow, w ledgerWorld) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if len(rows) != SourceCaseCount {
		add("the ledger has %d data rows; the source proposal has %d cases and each needs exactly one",
			len(rows), SourceCaseCount)
	}

	seen := map[string]int{}
	for _, r := range rows {
		if !sourceCaseIDPattern.MatchString(r.SourceCaseID) {
			add("line %d: source case id %q is not of the form EX-NN", r.Line, r.SourceCaseID)
		}
		if prev, dup := seen[r.SourceCaseID]; dup {
			add("line %d: source case %q already has a disposition on line %d", r.Line, r.SourceCaseID, prev)
		}
		seen[r.SourceCaseID] = r.Line

		for _, problem := range checkRowSemantics(r, w.local) {
			add("line %d (%s): %s", r.Line, r.SourceCaseID, problem)
		}

		for _, id := range r.CoverageCases {
			if !anyCaseIDPattern.MatchString(id) {
				add("line %d (%s): coverage id %q is not of the form EX-NN or AXC-NNN", r.Line, r.SourceCaseID, id)
			}
		}
		for _, id := range r.ReplacementCases {
			if !contains(r.CoverageCases, id) {
				add("line %d (%s): replacement %q is not listed in coverage", r.Line, r.SourceCaseID, id)
			}
		}

		// The result column is checked against what the transcribed case
		// DECLARES it produces, and the runner separately checks that
		// declaration against what the case observed. Without both halves the
		// column is unverified prose and gate 14 is satisfied by a cell nothing
		// executes.
		want, ok := w.declared[r.SourceCaseID]
		if !ok {
			add("line %d (%s): the transcribed case declares no produced outcome, so its adr065_result %q is unverifiable",
				r.Line, r.SourceCaseID, r.ADR065Result)
			continue
		}
		if !sameSet(strings.Split(r.ADR065Result, ";"), want) {
			add("line %d (%s): the row records adr065_result %q, the case produces %v",
				r.Line, r.SourceCaseID, r.ADR065Result, want)
		}
	}

	for i := 1; i <= SourceCaseCount; i++ {
		id := fmt.Sprintf("EX-%02d", i)
		if _, ok := seen[id]; !ok {
			add("source case %s has no disposition row", id)
		}
	}
	sort.Strings(out)
	return out
}

// checkRowSemantics is the per-row rule set.
func checkRowSemantics(r LedgerRow, local map[string]struct{}) []string {
	var problems []string
	if !validDisposition(r.Disposition) {
		problems = append(problems, fmt.Sprintf("disposition %q is not declared", r.Disposition))
	}
	for _, cell := range []struct{ label, value string }{
		{"source_result", r.SourceResult}, {"adr065_result", r.ADR065Result},
	} {
		for _, part := range strings.Split(cell.value, ";") {
			if !declaredResults[part] {
				problems = append(problems, fmt.Sprintf("%s %q is not a declared result value", cell.label, part))
			}
		}
	}
	// A reason is the whole point of the row. A one-word reason is not a
	// reason, and a row for a case ADR-065 changed has to say what changed and
	// why rather than that something did.
	if len(r.SemanticReason) < 40 {
		problems = append(problems, "the semantic reason is not reviewable at this length")
	}
	if r.Disposition == DispositionKept && r.ApprovingReviewer != "architecture" {
		problems = append(problems, "a kept row is approved by architecture")
	}
	if r.Disposition != DispositionKept && r.ApprovingReviewer != "architecture+security" {
		problems = append(problems, "a row that is not kept changes a fail-closed boundary and needs security review")
	}
	// A replaced or dropped case has no transcription left, so it MUST name
	// what covers its property instead.
	if (r.Disposition == DispositionReplaced || r.Disposition == DispositionDropped) && len(r.ReplacementCases) == 0 {
		problems = append(problems, "a replaced or dropped row must name its replacement coverage")
	}
	if r.Disposition == DispositionKept && len(r.ReplacementCases) > 0 {
		problems = append(problems, "a kept row has no replacement")
	}
	// Coverage is what makes this a gate rather than a spreadsheet. At least
	// one identifier must resolve to a case that actually executes here, so a
	// row whose only coverage is a placeholder is refused; identifiers that do
	// not resolve are permitted, because another workstream's corpus cites its
	// own into these rows.
	resolved := 0
	for _, id := range r.CoverageCases {
		if _, ok := local[id]; ok {
			resolved++
		}
	}
	if resolved == 0 {
		problems = append(problems, "the row is not covered by any case that runs here")
	}
	return problems
}

// TestDispositionLedgerIsComplete is ADR-065 acceptance gate 14.
func TestDispositionLedgerIsComplete(t *testing.T) {
	rows, err := ParseLedger(LedgerFile)
	if err != nil {
		t.Fatalf("parsing the ledger: %v", err)
	}
	for _, v := range gateViolations(rows, currentLedgerWorld()) {
		t.Error(v)
	}
}

// TestEveryTranscribedCaseHasALedgerRow closes the loop in the other
// direction: a case named after a source case must be the case that source
// case's row points at.
func TestEveryTranscribedCaseHasALedgerRow(t *testing.T) {
	rows, err := ParseLedger(LedgerFile)
	if err != nil {
		t.Fatalf("parsing the ledger: %v", err)
	}
	index := LedgerCoverage(rows)
	for _, c := range AllCases() {
		if !sourceCaseIDPattern.MatchString(c.ID) {
			continue
		}
		row, ok := index[c.ID]
		if !ok {
			t.Errorf("case %s has no ledger row", c.ID)
			continue
		}
		if !contains(row.CoverageCases, c.ID) {
			t.Errorf("case %s exists but its ledger row does not list it as coverage: %v", c.ID, row.CoverageCases)
		}
	}
}

// TestLedgerGuardSelfTest shows the gate going red on every defect it claims to
// catch, on this commit.
//
// A guard written to catch a blind spot is written by the same process that
// produced the blind spot, and the default failure mode of a hand-written check
// is to fail OPEN: a rule stops matching and the gate goes green over a file it
// never really read. Several of these defect classes do not occur in the
// committed ledger at all, so without this test the rules that catch them would
// never execute. Every case below drives the SAME gateViolations the acceptance
// test drives, so there is no second implementation to drift.
func TestLedgerGuardSelfTest(t *testing.T) {
	clean := LedgerFile
	rows, err := ParseLedger(clean)
	if err != nil {
		t.Fatalf("the committed ledger does not parse: %v", err)
	}
	world := currentLedgerWorld()
	if got := gateViolations(rows, world); len(got) > 0 {
		t.Fatalf("the committed ledger does not pass its own gate, so the mutations below prove nothing: %s",
			strings.Join(got, "; "))
	}

	// Parse-level rejections.
	for name, tc := range map[string]struct {
		mutate  func(string) string
		wantErr string
	}{
		"a reordered header": {
			mutate: func(s string) string {
				lines := strings.Split(s, "\n")
				cells := strings.Split(lines[0], "\t")
				cells[0], cells[1] = cells[1], cells[0]
				lines[0] = strings.Join(cells, "\t")
				return strings.Join(lines, "\n")
			},
			wantErr: "header column 1",
		},
		"a dropped column": {
			mutate: func(s string) string {
				lines := strings.Split(s, "\n")
				cells := strings.Split(lines[1], "\t")
				lines[1] = strings.Join(cells[:len(cells)-1], "\t")
				return strings.Join(lines, "\n")
			},
			wantErr: "columns, expected",
		},
		"a blank cell": {
			mutate:  func(s string) string { return replaceCell(s, 1, 7, "") },
			wantErr: "is empty",
		},
		"a padded cell": {
			mutate:  func(s string) string { return replaceCell(s, 1, 4, " kept") },
			wantErr: "surrounding whitespace",
		},
	} {
		t.Run("parsing refuses "+name, func(t *testing.T) {
			_, err := ParseLedger(tc.mutate(clean))
			if err == nil {
				t.Fatalf("the parser accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("the parser rejected %s with the wrong message: %v", name, err)
			}
		})
	}

	// Gate-level rejections, each applied to the real row set and each run
	// through the real gate.
	for name, tc := range map[string]struct {
		mutate func([]LedgerRow, *ledgerWorld) []LedgerRow
		want   string
	}{
		"a missing row": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow { return in[1:] },
			want:   "each needs exactly one",
		},
		"a duplicated row": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				return append(append([]LedgerRow(nil), in...), in[0])
			},
			want: "already has a disposition",
		},
		"a row whose only coverage does not run here": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].CoverageCases = []string{"AXC-999"}
				return out
			},
			want: "not covered by any case that runs here",
		},
		"a replaced row with no replacement": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = DispositionReplaced
				out[0].ReplacementCases = nil
				out[0].ApprovingReviewer = "architecture+security"
				return out
			},
			want: "must name its replacement coverage",
		},
		"a dropped row with no replacement": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = DispositionDropped
				out[0].ReplacementCases = nil
				out[0].ApprovingReviewer = "architecture+security"
				return out
			},
			want: "must name its replacement coverage",
		},
		"a kept row carrying a replacement": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = DispositionKept
				out[0].ApprovingReviewer = "architecture"
				out[0].ReplacementCases = []string{"EX-01"}
				return out
			},
			want: "a kept row has no replacement",
		},
		"a replacement not listed in coverage": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = DispositionChanged
				out[0].ApprovingReviewer = "architecture+security"
				out[0].ReplacementCases = []string{"AXC-005"}
				return out
			},
			want: "is not listed in coverage",
		},
		"a one-word reason": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].SemanticReason = "unchanged"
				return out
			},
			want: "not reviewable",
		},
		"a changed row approved by architecture alone": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = DispositionChanged
				out[0].ApprovingReviewer = "architecture"
				return out
			},
			want: "needs security review",
		},
		"an undeclared disposition": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].Disposition = Disposition("mostly kept")
				return out
			},
			want: "is not declared",
		},
		"an undeclared result value": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].ADR065Result = "MAYBE"
				return out
			},
			want: "is not a declared result value",
		},
		"a result the transcribed case does not produce": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].ADR065Result = "CHALLENGE"
				return out
			},
			want: "the case produces",
		},
		"a case that declares no produced outcome": {
			mutate: func(in []LedgerRow, w *ledgerWorld) []LedgerRow {
				delete(w.declared, in[0].SourceCaseID)
				return cloneRows(in)
			},
			want: "declares no produced outcome",
		},
		"a malformed coverage identifier": {
			mutate: func(in []LedgerRow, _ *ledgerWorld) []LedgerRow {
				out := cloneRows(in)
				out[0].CoverageCases = []string{out[0].CoverageCases[0], "EX-1"}
				return out
			},
			want: "is not of the form",
		},
	} {
		t.Run("the gate refuses "+name, func(t *testing.T) {
			w := ledgerWorld{local: map[string]struct{}{}, declared: map[string][]string{}}
			for k, v := range world.local {
				w.local[k] = v
			}
			for k, v := range world.declared {
				w.declared[k] = v
			}
			got := gateViolations(tc.mutate(rows, &w), w)
			if len(got) == 0 {
				t.Fatalf("the gate accepted %s", name)
			}
			if !strings.Contains(strings.Join(got, "; "), tc.want) {
				t.Fatalf("the gate refused %s with the wrong message: %s", name, strings.Join(got, "; "))
			}
		})
	}
}

func cloneRows(in []LedgerRow) []LedgerRow {
	out := make([]LedgerRow, len(in))
	copy(out, in)
	return out
}

// replaceCell rewrites one cell of one line, preserving the tab structure.
func replaceCell(content string, line, col int, value string) string {
	lines := strings.Split(content, "\n")
	cells := strings.Split(lines[line], "\t")
	cells[col] = value
	lines[line] = strings.Join(cells, "\t")
	return strings.Join(lines, "\n")
}

func sameSet(a, b []string) bool {
	sa, sb := map[string]struct{}{}, map[string]struct{}{}
	for _, v := range a {
		sa[v] = struct{}{}
	}
	for _, v := range b {
		sb[v] = struct{}{}
	}
	if len(sa) != len(sb) {
		return false
	}
	for v := range sa {
		if _, ok := sb[v]; !ok {
			return false
		}
	}
	return true
}

func validDisposition(d Disposition) bool {
	for _, k := range AllDispositions() {
		if k == d {
			return true
		}
	}
	return false
}
