// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"strings"
	"testing"
)

// TestTheShippedSupersessionLedgerParsesAndAgreesWithTheCensus is the ledger's
// runtime consumer check, on the tier with no database.
//
// The census is held to a migrated database by the policy package's census
// test; this holds the ledger to the census. So a row deleted from the ledger,
// a decision recorded on a row the census does not hold, or a pre-canonical row
// nobody decided about, is red here rather than only where Postgres runs.
func TestTheShippedSupersessionLedgerParsesAndAgreesWithTheCensus(t *testing.T) {
	ledger, err := ShippedSupersessionLedger()
	if err != nil {
		t.Fatalf("ShippedSupersessionLedger: %v", err)
	}
	census, err := ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	if err := CheckSupersessionLedgerAgainstCensus(ledger, census); err != nil {
		t.Fatal(err)
	}

	// The five rows #3323 would delete, named, each with its decision. A
	// check that the ledger merely parses would pass on one that decided to
	// drop them.
	kept := map[string]SupersessionDecision{}
	pairs := 0
	for _, r := range ledger {
		kept[r.PolicyID] = r.Decision
		pairs += len(r.SupersededBy)
	}
	for _, id := range []string{"drop_table_prevention", "truncate_prevention", "sql_injection_or", "sql_injection_union", "pii_ssn_detection"} {
		if kept[id] != SupersessionKeepBoth {
			t.Errorf("%s is decided %q; it is one of the five rows that enforce more than their superseders, and #3323's deletion was ruled do-not-apply for exactly that reason", id, kept[id])
		}
	}
	if pairs != 9 {
		t.Errorf("the ledger declares %d superseded/superseder pairs; the census found nine, and a parser that took only the first superseder of a multi-superseder row produces fewer", pairs)
	}
	t.Logf("ledger rows %d, pairs %d", len(ledger), pairs)
}

// TestTheSupersessionLedgerParseRefusesAShapeItCannotTrust is the parse's
// negative half, with a good fixture that must parse first.
func TestTheSupersessionLedgerParseRefusesAShapeItCannotTrust(t *testing.T) {
	header := strings.Join(supersessionLedgerHeader, "\t")
	good := header + "\n" +
		"old\t010_x.sql\tnew_a,new_b\tyes\t#3323\tkeep_both\tstronger\n" +
		"lone\t014_x.sql\t-\tyes\t-\tkeep_first_class\tnothing replaces it\n"
	rows, err := ParseSupersessionLedger(good)
	if err != nil {
		t.Fatalf("the good fixture does not parse, so every negative case below proves nothing: %v", err)
	}
	if len(rows) != 2 || len(rows[0].SupersededBy) != 2 || rows[1].SupersededBy != nil {
		t.Fatalf("the good fixture parsed to the wrong shape: %+v", rows)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"an empty file", "", "is empty"},
		// A reordered header is the dangerous one: every cell is a string.
		{"a reordered header", strings.Replace(good, "seeded_by\tsuperseded_by", "superseded_by\tseeded_by", 1), "header"},
		{"only a header", header + "\n", "no rows"},
		{"a short row", header + "\nold\t010_x.sql\n", "expected 7"},
		{"an empty cell", strings.Replace(good, "\tstronger\n", "\t\n", 1), "is empty"},
		{"a padded superseder", strings.Replace(good, "new_a,new_b", "new_a, new_b", 1), "padded"},
		{"a duplicate row", good + "lone\t014_x.sql\t-\tyes\t-\tkeep_first_class\tagain\n", "twice"},
		{"one superseder for two generations", good + "other\t010_x.sql\tnew_a\tyes\t-\tkeep_both\tn\n", "superseder of both"},
		{"a self-superseding row", strings.Replace(good, "new_a,new_b", "old", 1), "its own superseder"},
		{"a chain of generations", good + "new_a\t010_x.sql\tnewer\tyes\t-\tkeep_both\tn\n", "chain"},
		{"an undeclared decision", strings.Replace(good, "\tkeep_both\t", "\tdelete\t", 1), "decision"},
		{"an unreadable still_live", strings.Replace(good, "\tyes\t#3323", "\tmaybe\t#3323", 1), "still_live"},
		{"a tracking cell that is no issue", strings.Replace(good, "#3323", "3323", 1), "tracking"},
		// The two preconditions that need only the file.
		{"a first-class row naming a superseder", strings.Replace(good, "\t-\tyes\t-\tkeep_first_class", "\tnew_c\tyes\t-\tkeep_first_class", 1), "nothing supersedes"},
		{"a pair decision with no superseder", strings.Replace(good, "\t-\tyes\t-\tkeep_first_class", "\t-\tyes\t-\tkeep_both", 1), "names no superseder"},
		{"a drop with no superseder", strings.Replace(good, "\t-\tyes\t-\tkeep_first_class", "\t-\tyes\t-\tdrop_superseded", 1), "names no superseder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSupersessionLedger(tc.in)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: want a message containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestTheLedgerCensusCrossCheckRefusesEachDisagreementByName drives every arm
// of CheckSupersessionLedgerAgainstCensus from the REAL pair, so each refusal
// is known to be reachable from data a migration could produce.
func TestTheLedgerCensusCrossCheckRefusesEachDisagreementByName(t *testing.T) {
	census, err := ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	ledger, err := ShippedSupersessionLedger()
	if err != nil {
		t.Fatalf("ShippedSupersessionLedger: %v", err)
	}

	withoutLedgerRow := func(id string) []SupersessionRow {
		var out []SupersessionRow
		for _, r := range ledger {
			if r.PolicyID != id {
				out = append(out, r)
			}
		}
		return out
	}
	editedLedger := func(id string, edit func(*SupersessionRow)) []SupersessionRow {
		out := append([]SupersessionRow(nil), ledger...)
		for i := range out {
			if out[i].PolicyID == id {
				out[i].SupersededBy = append([]string(nil), out[i].SupersededBy...)
				edit(&out[i])
			}
		}
		return out
	}
	editedCensus := func(id string, edit func(*CensusRow)) []CensusRow {
		out := append([]CensusRow(nil), census...)
		for i := range out {
			if out[i].PolicyID == id {
				edit(&out[i])
			}
		}
		return out
	}

	cases := []struct {
		name   string
		ledger []SupersessionRow
		census []CensusRow
		want   string
	}{
		{
			// THE DROP OF A STRONGER ROW FROM THE LEDGER ITSELF. The row is still
			// seeded by 010 and still in the census, so the derived pre-canonical
			// population names it.
			name: "a pre-canonical row removed from the ledger", ledger: withoutLedgerRow("truncate_prevention"), census: census,
			want: "truncate_prevention is seeded by 010_policy_tables.sql, before the canonical pass (migration 031), and is not ledgered",
		},
		{
			name: "a ledgered row the census does not hold", census: census,
			ledger: editedLedger("truncate_prevention", func(r *SupersessionRow) { r.PolicyID = "no_such_row" }),
			want:   "no_such_row is ledgered and is not a census row",
		},
		{
			name: "a seeded_by that disagrees with the census", census: census,
			ledger: editedLedger("truncate_prevention", func(r *SupersessionRow) { r.SeededBy = "011_elsewhere.sql" }),
			want:   `truncate_prevention: the ledger says seeded_by "011_elsewhere.sql"`,
		},
		{
			name: "a canonical row ledgered as pre-canonical", census: census,
			ledger: append(append([]SupersessionRow(nil), ledger...), SupersessionRow{
				PolicyID: "sys_sqli_or_true", SeededBy: "031_seed_system_policies.sql", Decision: SupersessionKeepFirstClass,
			}),
			want: "sys_sqli_or_true is ledgered as pre-canonical",
		},
		{
			name: "a superseder the census does not hold", census: census,
			ledger: editedLedger("truncate_prevention", func(r *SupersessionRow) { r.SupersededBy = []string{"sys_gone"} }),
			want:   `names superseder "sys_gone", which is not a census row`,
		},
		{
			name: "a superseder that is itself pre-canonical", census: census,
			ledger: editedLedger("truncate_prevention", func(r *SupersessionRow) { r.SupersededBy = []string{"eu_gdpr_cross_border_pii"} }),
			want:   `names superseder "eu_gdpr_cross_border_pii", which is itself seeded before the canonical pass`,
		},
		{
			name: "a kept row that is disabled", ledger: ledger,
			census: editedCensus("truncate_prevention", func(r *CensusRow) { r.Enabled = false }),
			want:   "truncate_prevention is decided keep_both and is disabled in the census",
		},
		{
			name: "a disabled superseder", ledger: ledger,
			census: editedCensus("sys_sqli_truncate", func(r *CensusRow) { r.Enabled = false }),
			want:   `names superseder "sys_sqli_truncate", which is disabled`,
		},
		{"an empty ledger", nil, census, "empty side"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSupersessionLedgerAgainstCensus(tc.ledger, tc.census)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: want a message containing %q, got %v", tc.want, err)
			}
		})
	}
}
