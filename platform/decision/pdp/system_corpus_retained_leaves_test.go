// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"strings"
	"testing"
)

// #4254: the retained leaves are the union of every divergence's fields, sorted
// and deduplicated; a divergence that records none contributes none, and an
// artifact that does not parse is refused.
func TestTheRetainedPayloadLeavesAreTheDivergencesFields(t *testing.T) {
	src := []byte(`{"divergences":[
		{"policy_id":"a","kind":"dynamic_redaction_ships_as_warn","fields":["ssn","email"]},
		{"policy_id":"b","kind":"plane_action_collapsed"},
		{"policy_id":"c","kind":"dynamic_redaction_ships_as_warn","fields":["email","phone"]}]}`)
	got, err := parseRetainedPayloadLeaves(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "email,phone,ssn" {
		t.Fatalf("retained leaves %v; want email, phone and ssn, sorted and once each", got)
	}
	none, err := parseRetainedPayloadLeaves([]byte(`{"divergences":[{"policy_id":"b","kind":"plane_action_collapsed"}]}`))
	if err != nil || len(none) != 0 {
		t.Fatalf("a corpus whose divergences retain no field answered %v, %v; want none", none, err)
	}
	if _, err := parseRetainedPayloadLeaves([]byte(`{"divergences":`)); err == nil {
		t.Fatal("an artifact that does not parse answered no error")
	}
}

// A blank or padded retained field is refused: it would declare a payload leaf
// no response carries, and an author could aim a redaction at it.
func TestABlankRetainedPayloadLeafIsRefused(t *testing.T) {
	for _, bad := range []string{`""`, `" ssn"`, `"ssn "`} {
		src := []byte(`{"divergences":[{"policy_id":"a","fields":[` + bad + `]}]}`)
		if _, err := parseRetainedPayloadLeaves(src); err == nil || !strings.Contains(err.Error(), "blank or padded") {
			t.Errorf("retained field %s answered %v; want the refusal naming a blank or padded field", bad, err)
		}
	}
}

// The shipped accessor returns a copy: a caller writing to it changes nothing
// the next caller reads.
func TestTheShippedRetainedPayloadLeavesAreACopy(t *testing.T) {
	first, err := SystemCorpusRetainedPayloadLeaves()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("PREMISE: the shipped corpus retains no payload field, so a copy check proves nothing")
	}
	first[0] = "mutated"
	second, err := SystemCorpusRetainedPayloadLeaves()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range second {
		if f == "mutated" {
			t.Fatalf("a caller's write to the returned slice reached the next caller: %v", second)
		}
	}
}
