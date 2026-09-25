// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package queue

import (
	"testing"

	"github.com/google/uuid"
)

// classifyGrant must refuse every row ConsumeBindingGrantSQL refuses, for the
// same reason, and may call "consumed" only a row every clause of that
// statement admits (a concurrent retry locked and spent it). An approved row
// with no review time is not spendable (the SQL requires reviewed_at), so it
// reads as an approval no person is recorded as giving - never as "consumed",
// which feeds the breaker and tells the caller a spend happened.
func TestClassifyAgreesWithTheConsumeOnAnApprovalWithNoReviewTime(t *testing.T) {
	row := grantRow{
		requestID: BindingHoldID("d", 1), hold: "1",
		requestType: RequestTypePolicyStepUp, status: "approved", binding: "d", live: true,
		reviewerRole: "user", reviewerID: "ops@corp.example", reviewerEmail: "ops@corp.example",
	}
	if got := classifyGrant(row, "d", []string{"caller"}); got != GrantReviewerUnattributed {
		t.Fatalf("an approved row with no review time classified %s; want %s", got, GrantReviewerUnattributed)
	}
	row.reviewed = true
	if got := classifyGrant(row, "d", []string{"caller"}); got != GrantConsumed {
		t.Fatalf("CONTROL: a fully spendable row the consume declined (a lock loser) classified %s; want %s", got, GrantConsumed)
	}
}

// A row whose id is not the hold id its own binding and hold number derive was
// not written by Enqueue (#4375 R3 round 1: a caller's policy_step_up row that
// copied a digest). It is not found, however spendable its other columns read,
// and a CONTROL shows the same row under its derived id is.
func TestClassifyRefusesARowWhoseIDIsNotItsDerivedHoldID(t *testing.T) {
	spendable := grantRow{
		requestID: BindingHoldID("d", 2), hold: "2",
		requestType: RequestTypePolicyStepUp, status: "approved", binding: "d", live: true, reviewed: true,
		reviewerRole: "user", reviewerID: "ops@corp.example", reviewerEmail: "ops@corp.example",
	}
	if got := classifyGrant(spendable, "d", []string{"caller"}); got != GrantConsumed {
		t.Fatalf("CONTROL: a derived, spendable row classified %s; want %s", got, GrantConsumed)
	}
	for name, mutate := range map[string]func(*grantRow){
		"a random id":                  func(r *grantRow) { r.requestID = uuid.New() },
		"no hold number":               func(r *grantRow) { r.hold = "" },
		"another hold's number":        func(r *grantRow) { r.hold = "1" },
		"a non-canonical number":       func(r *grantRow) { r.hold = "02" },
		"a zero number":                func(r *grantRow) { r.requestID, r.hold = BindingHoldID("d", 0), "0" },
		"another binding's hold id":    func(r *grantRow) { r.requestID = BindingHoldID("e", 2) },
		"a number that is not a count": func(r *grantRow) { r.hold = "two" },
	} {
		r := spendable
		mutate(&r)
		if got := classifyGrant(r, "d", []string{"caller"}); got != GrantNotFound {
			t.Errorf("%s: classified %s; want %s", name, got, GrantNotFound)
		}
	}
}
