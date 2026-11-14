// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package fincrime

import "testing"

// TestFinCrimeSharedProtocolSemanticsAreCommunityBuilt exercises the public
// transaction/cohort vocabulary and typed fact semantics without importing or
// activating either Enterprise artifact. This file deliberately has no build
// constraint: the Community lane compiles and runs the shared protocol.
func TestFinCrimeSharedProtocolSemanticsAreCommunityBuilt(t *testing.T) {
	if TransactionContextKey != "fincrime_transaction" || CohortContextKey != "fincrime_cohort" {
		t.Fatalf("shared context keys changed: transaction=%q cohort=%q", TransactionContextKey, CohortContextKey)
	}

	raw := []byte(`{"version":3,"organizations":{"org":{"actions":[{"client_id":"client","plane":"mcp","server":"payments","tool":"transfer","operation":"execute","class":"execute"}],"currencies":{"USD":{"cap":"10000","structuring_floor":"3000","cnp":"5000"}}}}}`)
	registry, err := ParseRegistry(raw)
	if err != nil {
		t.Fatalf("ParseRegistry: %v", err)
	}
	result := registry.Evaluate(
		Target{OrgID: "org", ClientID: "client", Plane: "mcp", Server: "payments", Tool: "transfer", Operation: "execute"},
		map[string]interface{}{
			TransactionContextKey: map[string]interface{}{
				"version": float64(2), "transaction_id": "tx-community", "amount": "100",
				"amount_unit": "major", "currency": "USD", "beneficiary_id": "beneficiary",
				"payment_type": "transfer", "sender_location": "US", "receiver_location": "GB",
				"timestamp": "2026-11-06T00:00:00Z",
			},
			CohortContextKey: map[string]interface{}{
				"currency": "USD", "historical_mean_amount": "50", "txn_frequency_1h": float64(1),
			},
		},
	)
	if !result.Covered || result.Reason != "" || result.Facts["fincrime_invalid_context_block"] ||
		!result.Facts["fincrime_payment_execution_stepup"] {
		t.Fatalf("Community shared semantics did not produce the expected typed facts: %+v", result)
	}
}
