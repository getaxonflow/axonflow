//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import "testing"

// TestTransferBasisValid covers the UU PDP Pasal 56 transfer-basis validator.
// pasal_56b_dpa is the explicit Pasal 56(b) tag; safeguards is its accepted
// semantic equivalent; both must validate alongside adequacy and consent.
// Matching is case-sensitive and rejects malformed / empty values.
func TestTransferBasisValid(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"adequacy", "adequacy", true},
		{"safeguards", "safeguards", true},
		{"pasal_56b_dpa", "pasal_56b_dpa", true},
		{"consent", "consent", true},
		{"wrong format pasal_56_b", "pasal_56_b", false},
		{"empty", "", false},
		{"uppercase is case-sensitive", "PASAL_56B_DPA", false},
		{"unknown value", "binding_clauses", false},
		{"leading space", " safeguards", false},
		{"trailing space", "consent ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TransferBasisValid(tt.value); got != tt.want {
				t.Errorf("TransferBasisValid(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestTransferBasisCanonicalForms pins the accepted set and its stable order.
func TestTransferBasisCanonicalForms(t *testing.T) {
	want := []string{"adequacy", "safeguards", "pasal_56b_dpa", "consent"}
	got := TransferBasisCanonicalForms()

	if len(got) != len(want) {
		t.Fatalf("TransferBasisCanonicalForms() returned %d values, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("TransferBasisCanonicalForms()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestTransferBasisCanonicalFormsAllValid guards the invariant that every
// canonical form is accepted by the validator — they must never drift apart.
func TestTransferBasisCanonicalFormsAllValid(t *testing.T) {
	for _, form := range TransferBasisCanonicalForms() {
		if !TransferBasisValid(form) {
			t.Errorf("canonical form %q is not accepted by TransferBasisValid", form)
		}
	}
}

// TestTransferBasisConstants ensures the exported constants match the
// canonical string forms an auditor and external callers depend on.
func TestTransferBasisConstants(t *testing.T) {
	cases := map[string]string{
		TransferBasisAdequacy:    "adequacy",
		TransferBasisSafeguards:  "safeguards",
		TransferBasisPasal56bDPA: "pasal_56b_dpa",
		TransferBasisConsent:     "consent",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("transfer-basis constant = %q, want %q", got, want)
		}
	}
}
