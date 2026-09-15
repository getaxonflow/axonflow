// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

// THE SUPERSESSION LEDGER AS A RECORDED DECISION (#3323, under #3884)
//
// `detectors_census_superseded.tsv` names the twelve pre-canonical shipped
// rows: seeded before migration 031's structured pass and, for five of them,
// replaced in PATTERN by one or more `sys_*` rows. #3323 asked for those five
// to be deleted on the ground that "nothing is dropped by removing them". The
// census measured the opposite: migration 067 relaxed the canonical rows to
// `warn` by category and by an explicit id list, the pre-canonical spellings
// escaped both clauses, and every one of the five still enforces more than the
// row that replaced it.
//
// Until this file the ledger DESCRIBED that and decided nothing. A reader of
// the note could see that deleting the rows lowers DROP TABLE handling; the
// importer's --collapse-superseded could not, and dropped whichever generation
// lost a strength comparison - which on these pairs is the case-insensitive
// canonical row, leaving the lowercase-only `drop\s+table` as the only DROP
// TABLE detector in the imported document. So each row now carries a DECISION,
// and the decision is what consumers read.
//
// # THE DECISION IS RECORDED, AND ITS PRECONDITION IS DERIVED
//
// A hand-written "keep" is a claim. What makes it checkable is that each
// decision has a precondition over facts the census holds to a migrated
// database, and nothing may carry a decision whose precondition is false:
//
//	keep_first_class  the row names no superseder
//	keep_both         the row names a superseder, and it enforces MORE than at
//	                  least one of them (checked where a legacy action can be
//	                  ranked: legacycompile.CheckSupersessionDecisions)
//	drop_superseded   the row names a superseder, and it enforces more than
//	                  NONE of them
//
// THE drop_superseded PRECONDITION IS NECESSARY AND NOT SUFFICIENT. It rules
// out lowering an ACTION on the inputs both generations match. It says nothing
// about inputs only the pre-canonical PATTERN matches, and nothing here can
// derive that: on the live pairs neither pattern contains the other as
// stored (`\bdrop\s+table\b`, core/185, matches "please drop table users
// now" and not "DROP TABLE users"; sys_sqli_drop_table's shipped pattern
// does the reverse). Since #4131 the agent's loader compiles this family
// case-insensitively (shared/policy.EffectivePattern), so there the
// pre-canonical row matches both, and a coverage note must say which
// compile it means. So a
// drop_superseded row is a human decision whose strength ground is checked and
// whose coverage ground its note must state.
//
// `drop_superseded` has no instance today. It is declared because it is the
// state a cleanup reaches once it carries the stronger action forward onto the
// superseders, and without a spelling for it the importer's collapse would have
// nothing it is ever permitted to remove.
//
// # WHAT THIS FILE CHECKS AND WHAT IT LEAVES TO legacycompile
//
// This package has no ranking of legacy actions, and deliberately gains none:
// ADR-065 states there is no action ranking, and the one place a ranking is
// needed - collapsing a migration - owns it in legacycompile. So the structural
// half lives here (shape, vocabulary, the census cross-check, and which rows
// must be ledgered at all), and the strength half lives beside that ranking.

// SupersessionLedgerFile is the checked-in ledger, embedded for the reason
// DetectorCensusFile is: a consumer reads the artifact that ships rather than a
// copy on the runner's disk.
//
//go:embed detectors_census_superseded.tsv
var SupersessionLedgerFile string

// supersessionLedgerHeader is the exact expected header, in order.
var supersessionLedgerHeader = []string{
	"policy_id", "seeded_by", "superseded_by", "still_live", "tracking", "decision", "note",
}

// SupersessionDecision is what the platform decided to do with one
// pre-canonical row.
type SupersessionDecision string

const (
	// SupersessionKeepFirstClass is a pre-canonical row nothing supersedes. It
	// is a control in its own right, and "seeded before 031" is not a reason
	// to remove it.
	SupersessionKeepFirstClass SupersessionDecision = "keep_first_class"
	// SupersessionKeepBoth keeps the row AND every superseder. Removing either
	// generation, or collapsing the pair in an import, lowers enforcement on
	// some input.
	SupersessionKeepBoth SupersessionDecision = "keep_both"
	// SupersessionDropSuperseded permits removing the pre-canonical row. Only
	// the pre-canonical generation may go; its superseders stay.
	SupersessionDropSuperseded SupersessionDecision = "drop_superseded"
)

// AllSupersessionDecisions returns every declared decision in a stable order.
func AllSupersessionDecisions() []SupersessionDecision {
	return []SupersessionDecision{SupersessionDropSuperseded, SupersessionKeepBoth, SupersessionKeepFirstClass}
}

// IsValid reports whether the decision is a declared member.
func (d SupersessionDecision) IsValid() bool {
	for _, k := range AllSupersessionDecisions() {
		if k == d {
			return true
		}
	}
	return false
}

// RemovesAGeneration reports whether the decision permits any generation of
// the row to be removed. It is the one question a consumer that deletes or
// collapses must ask, so it is asked here rather than by comparing strings.
func (d SupersessionDecision) RemovesAGeneration() bool { return d == SupersessionDropSuperseded }

// SupersessionRow is one parsed ledger row.
type SupersessionRow struct {
	PolicyID string
	SeededBy string
	// SupersededBy is empty for a first-class row. The ledger spells that "-",
	// which is not a superseder named "-".
	SupersededBy []string
	StillLive    bool
	Tracking     string
	Decision     SupersessionDecision
	Note         string
	Line         int
}

// ParseSupersessionLedger parses the ledger.
//
// Strict for the reason ParseDetectorCensus is: every cell is a string, so a
// reordered header parses cleanly and produces a ledger whose superseders are
// its notes. And every rule that needs only the file itself is applied here,
// so no consumer can hold a ledger in which a row both keeps and drops, or one
// superseder replaces two generations.
func ParseSupersessionLedger(content string) ([]SupersessionRow, error) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, fmt.Errorf("registry: the supersession ledger is empty")
	}
	header := strings.Split(strings.TrimRight(lines[0], "\r"), "\t")
	if strings.Join(header, "\t") != strings.Join(supersessionLedgerHeader, "\t") {
		return nil, fmt.Errorf("registry: the supersession ledger header is %q, expected %q",
			strings.Join(header, "\t"), strings.Join(supersessionLedgerHeader, "\t"))
	}
	var out []SupersessionRow
	seen := map[string]int{}
	supersededBy := map[string]string{}
	for n, raw := range lines[1:] {
		lineNo := n + 2
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		cells := strings.Split(line, "\t")
		if len(cells) != len(supersessionLedgerHeader) {
			return nil, fmt.Errorf("registry: supersession ledger line %d has %d fields, expected %d",
				lineNo, len(cells), len(supersessionLedgerHeader))
		}
		for i, c := range cells {
			if c == "" {
				return nil, fmt.Errorf("registry: supersession ledger line %d column %q is empty; the ledger writes an absent value as \"-\"",
					lineNo, supersessionLedgerHeader[i])
			}
			if strings.TrimSpace(c) != c {
				return nil, fmt.Errorf("registry: supersession ledger line %d column %q has surrounding whitespace",
					lineNo, supersessionLedgerHeader[i])
			}
		}
		row, err := supersessionRowFrom(cells, lineNo)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[row.PolicyID]; dup {
			return nil, fmt.Errorf("registry: supersession ledger line %d names %q twice (first on line %d)", lineNo, row.PolicyID, prev)
		}
		seen[row.PolicyID] = lineNo
		for _, s := range row.SupersededBy {
			if prior, dup := supersededBy[s]; dup {
				return nil, fmt.Errorf("registry: supersession ledger names %q as the superseder of both %q and %q; one row cannot replace two generations without saying which",
					s, prior, row.PolicyID)
			}
			supersededBy[s] = row.PolicyID
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		// A ledger with a header and no rows makes every consumer report "no
		// superseded pairs" and look clean, which is the shape of a silent
		// enforcement downgrade.
		return nil, fmt.Errorf("registry: the supersession ledger has a header and no rows; refusing rather than reporting zero pairs")
	}
	// A superseder that is itself a ledgered row would be a chain of
	// generations, which no consumer models: collapsing the middle of one
	// decides the outer pair by accident.
	for _, r := range out {
		if replaced, ok := supersededBy[r.PolicyID]; ok {
			return nil, fmt.Errorf("registry: supersession ledger line %d: %q is ledgered as pre-canonical and is also the superseder of %q; a chain of generations is not a pair",
				r.Line, r.PolicyID, replaced)
		}
	}
	return out, nil
}

func supersessionRowFrom(cells []string, lineNo int) (SupersessionRow, error) {
	row := SupersessionRow{
		PolicyID: cells[0], SeededBy: cells[1], Tracking: cells[4],
		Decision: SupersessionDecision(cells[5]), Note: cells[6], Line: lineNo,
	}
	if cells[2] != "-" {
		for _, s := range strings.Split(cells[2], ",") {
			if s == "" || strings.TrimSpace(s) != s {
				return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: superseded_by %q has an empty or padded member; a spelling that differs is a different policy id",
					lineNo, cells[2])
			}
			if s == row.PolicyID {
				return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: %q names itself as its own superseder", lineNo, s)
			}
			row.SupersededBy = append(row.SupersededBy, s)
		}
	}
	switch cells[3] {
	case "yes":
		row.StillLive = true
	case "no":
	default:
		return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: still_live is %q, expected \"yes\" or \"no\"", lineNo, cells[3])
	}
	if row.Tracking != "-" && !strings.HasPrefix(row.Tracking, "#") {
		return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: tracking %q is neither \"-\" nor an issue reference", lineNo, row.Tracking)
	}
	if !row.Decision.IsValid() {
		return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: decision %q is not one of %v", lineNo, cells[5], AllSupersessionDecisions())
	}
	// THE PRECONDITION THIS FILE CAN CHECK ALONE. A first-class row has no
	// superseder by definition, and a keep-or-drop decision about a pair is
	// meaningless without one.
	switch {
	case row.Decision == SupersessionKeepFirstClass && len(row.SupersededBy) > 0:
		return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: %q is decided keep_first_class and names superseder(s) %v; a first-class row is one nothing supersedes",
			lineNo, row.PolicyID, row.SupersededBy)
	case row.Decision != SupersessionKeepFirstClass && len(row.SupersededBy) == 0:
		return SupersessionRow{}, fmt.Errorf("registry: supersession ledger line %d: %q is decided %s and names no superseder; that decision is about a pair",
			lineNo, row.PolicyID, row.Decision)
	}
	return row, nil
}

// ShippedSupersessionLedger parses the embedded ledger.
func ShippedSupersessionLedger() ([]SupersessionRow, error) {
	return ParseSupersessionLedger(SupersessionLedgerFile)
}

// CheckSupersessionLedgerAgainstCensus holds the ledger to the census.
//
// The census is held to a migrated database; this holds the ledger to the
// census, so the ledger's population is derived rather than listed:
//
//   - every ledgered row and every superseder is a census row, and the ledger's
//     seeded_by is the census's seed_migration;
//   - WHICH rows are pre-canonical is derived, not listed: the canonical pass
//     is the earliest migration that seeds a system-tier row, and every census
//     row seeded before it must be ledgered while every ledgered row must be.
//     A superseder, by the same rule, is never pre-canonical itself;
//   - a row a decision KEEPS, and every superseder of a keep_both row, is
//     enabled - a kept generation that evaluates nowhere keeps nothing.
//
// It returns every disagreement rather than the first.
func CheckSupersessionLedgerAgainstCensus(ledger []SupersessionRow, census []CensusRow) error {
	if len(ledger) == 0 || len(census) == 0 {
		return fmt.Errorf("registry: the supersession cross-check was handed %d ledger row(s) and %d census row(s); a comparison with an empty side proves nothing",
			len(ledger), len(census))
	}
	byID := map[string]CensusRow{}
	canonical := -1
	for _, r := range census {
		byID[r.PolicyID] = r
		if !r.SystemTier() {
			continue
		}
		n, err := migrationNumber(r.SeedMigration)
		if err != nil {
			return err
		}
		if canonical < 0 || n < canonical {
			canonical = n
		}
	}
	if canonical < 0 {
		return fmt.Errorf("registry: the census holds no system-tier row, so the canonical pass cannot be derived and no row can be classed pre-canonical")
	}
	preCanonical := func(r CensusRow) (bool, error) {
		n, err := migrationNumber(r.SeedMigration)
		if err != nil {
			return false, err
		}
		return n < canonical, nil
	}

	var problems []string
	ledgered := map[string]bool{}
	for _, l := range ledger {
		ledgered[l.PolicyID] = true
		c, ok := byID[l.PolicyID]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is ledgered and is not a census row", l.PolicyID))
			continue
		}
		if c.SeedMigration != l.SeededBy {
			problems = append(problems, fmt.Sprintf("%s: the ledger says seeded_by %q and the census says seed_migration %q", l.PolicyID, l.SeededBy, c.SeedMigration))
		}
		if pre, err := preCanonical(c); err != nil {
			return err
		} else if !pre {
			problems = append(problems, fmt.Sprintf("%s is ledgered as pre-canonical and is seeded by %s, which is not before the canonical pass (migration %03d)", l.PolicyID, c.SeedMigration, canonical))
		}
		if !l.Decision.RemovesAGeneration() && !c.Enabled {
			problems = append(problems, fmt.Sprintf("%s is decided %s and is disabled in the census; a kept generation that evaluates nowhere keeps nothing", l.PolicyID, l.Decision))
		}
		for _, s := range l.SupersededBy {
			sc, ok := byID[s]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s names superseder %q, which is not a census row", l.PolicyID, s))
				continue
			}
			if pre, err := preCanonical(sc); err != nil {
				return err
			} else if pre {
				problems = append(problems, fmt.Sprintf("%s names superseder %q, which is itself seeded before the canonical pass", l.PolicyID, s))
			}
			if !sc.Enabled {
				problems = append(problems, fmt.Sprintf("%s names superseder %q, which is disabled in the census; a disabled row supersedes nothing", l.PolicyID, s))
			}
		}
	}
	for _, c := range census {
		if ledgered[c.PolicyID] {
			continue
		}
		pre, err := preCanonical(c)
		if err != nil {
			return err
		}
		if pre {
			problems = append(problems, fmt.Sprintf("%s is seeded by %s, before the canonical pass (migration %03d), and is not ledgered; a pre-canonical row with no recorded decision is one a cleanup would treat as superseded by default",
				c.PolicyID, c.SeedMigration, canonical))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("registry: the supersession ledger disagrees with the census in %d way(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

// migrationNumber reads the ordinal a migration file name starts with.
func migrationNumber(file string) (int, error) {
	digits := file
	if i := strings.IndexFunc(file, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = file[:i]
	}
	n, err := strconv.Atoi(digits)
	if err != nil || digits == "" {
		return 0, fmt.Errorf("registry: seed migration %q does not start with a migration number", file)
	}
	return n, nil
}
