// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestCensusObligationsSpeakTheCanonicalVocabulary asserts, rather than reads,
// that every term in the shipped census's `obligations` column is a type the
// ONE obligation vocabulary declares (#3891). The parser already refuses an
// undeclared term at load, so the first half is a positive statement over the
// shipped rows and the second half is the planted negative that proves the
// parser is what makes the first half true.
func TestCensusObligationsSpeakTheCanonicalVocabulary(t *testing.T) {
	rows, err := ShippedCensus()
	if err != nil {
		t.Fatalf("shipped census: %v", err)
	}
	declared := map[contract.ObligationType]bool{}
	for _, typ := range contract.AllObligationTypes() {
		declared[typ] = true
	}
	seen := map[contract.ObligationType]int{}
	for _, r := range rows {
		for _, ob := range r.Obligations {
			if !declared[ob] {
				t.Errorf("census row %s names obligation %q, which the canonical vocabulary does not declare", r.PolicyID, ob)
			}
			seen[ob]++
		}
	}
	// The denominator: the census carries obligations at all, in the three
	// types the shipped policy tables actually produce. A vocabulary check
	// over an empty column would be vacuous.
	for _, want := range []contract.ObligationType{contract.ObFieldRedact, contract.ObImmutableAudit, contract.ObNotification} {
		if seen[want] == 0 {
			t.Errorf("no census row names %s; the column this test reads may have moved", want)
		}
	}

	// The planted negative: the losing spelling is refused by the parser, so
	// a census row could not carry it even if someone typed it.
	for _, losing := range []string{"field_redaction", "response_filtering", "schema_constrained_transform"} {
		if _, err := parseObligationSet(losing, 0); err == nil || !strings.Contains(err.Error(), losing) {
			t.Errorf("parseObligationSet(%q) = %v; the losing spelling must be refused by name", losing, err)
		}
	}
	if got, err := parseObligationSet("field_redact,notification", 0); err != nil || len(got) != 2 {
		t.Fatalf("the parser refuses the canonical spelling: %v %v", got, err)
	}
}
