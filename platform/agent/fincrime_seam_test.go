// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/agent/fincrime"
)

func TestFinCrimeParametersFromContext(t *testing.T) {
	if got := finCrimeParametersFromContext(nil); got != nil {
		t.Fatalf("nil context: %v", got)
	}
	if got := finCrimeParametersFromContext(map[string]interface{}{"x-session-id": "s"}); got != nil {
		t.Fatalf("no fincrime keys must yield nil (bit-identical legacy call): %v", got)
	}
	txn := map[string]interface{}{"amount": 9300.0}
	cohort := map[string]interface{}{"txn_frequency_1h": 12.0}
	got := finCrimeParametersFromContext(map[string]interface{}{
		fincrime.TransactionContextKey: txn,
		fincrime.CohortContextKey:      cohort,
		"x-session-id":                 "s",
		"unrelated":                    map[string]interface{}{"a": 1},
	})
	if len(got) != 2 {
		t.Fatalf("exactly the two documented keys must lift: %v", got)
	}
	if _, ok := got[fincrime.TransactionContextKey]; !ok {
		t.Fatal("transaction key missing")
	}
	if _, ok := got[fincrime.CohortContextKey]; !ok {
		t.Fatal("cohort key missing")
	}
	// Cohort-only requests lift too.
	got = finCrimeParametersFromContext(map[string]interface{}{fincrime.CohortContextKey: cohort})
	if len(got) != 1 {
		t.Fatalf("cohort-only lift: %v", got)
	}
}
