// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import "testing"

// sys_pii_singapore_nric (`[STFGM]\d{7}[A-Z]`) and sys_pii_singapore_fin
// (`[FG]\d{7}[A-Z]`) are CategoryPIISingapore → nil category default (accept-all),
// and EvaluateAll has no confidence threshold, so before this fix every
// letter+7digit+letter id (asset tags, SKUs, order refs) fired and — under
// PII_ACTION=redact — was masked. These tests pin the adjacent-label gates.

func TestValidatorForPolicyID_SingaporeIC(t *testing.T) {
	if v := ValidatorForPolicyID("sys_pii_singapore_nric"); v == nil {
		t.Error("sys_pii_singapore_nric must resolve to ValidateSingaporeNRIC (was accept-all)")
	}
	if v := ValidatorForPolicyID("sys_pii_singapore_fin"); v == nil {
		t.Error("sys_pii_singapore_fin must resolve to ValidateSingaporeFIN (was accept-all)")
	}
	// The exact sweep false positive: a benign asset tag must NOT validate as NRIC.
	if ok, _ := ValidatorForPolicyID("sys_pii_singapore_nric")("S1234567Z", "asset tag S1234567Z warehouse"); ok {
		t.Error("resolved NRIC validator governed a benign asset tag — false positive not closed")
	}
}

func TestValidateSingaporeNRIC_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"S1234567Z", "NRIC S1234567Z on file", true},                  // labelled
		{"T7654321A", "nric: T7654321A", true},                         // label + separator
		{"S1234567Z", "national registration S1234567Z", true},         // spelled-out label
		{"S1234567Z", "asset tag S1234567Z warehouse", false},          // the sweep FP
		{"T7654321A", "order T7654321A shipped", false},                // benign id
		{"M0000000B", "bin M0000000B is full", false},                  // benign id
		{"S1234567Z", "the NRIC field; sku S1234567Z here", false},     // label not adjacent
		{"S1234567Z", "replace the fin S1234567Z on the shark", false}, // "fin" word, no separator (R3 medium)
	} {
		got, _ := ValidateSingaporeNRIC(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidateSingaporeNRIC(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}

func TestValidateSingaporeFIN_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"F1234567X", "FIN: F1234567X recorded", true},                 // labelled (separator)
		{"F1234567X", "FIN no. F1234567X", true},                       // labelled (qualifier)
		{"G7654321A", "foreign identification number G7654321A", true}, // spelled-out
		{"F1234567X", "asset tag F1234567X in bin", false},             // benign id
		{"G7654321A", "order G7654321A on shelf", false},               // benign id
		{"F1234567X", "replace the fin F1234567X on the shark", false}, // "fin" word, no separator (R3 medium)
		{"F1234567X", "FIN F1234567X recorded", false},                 // bare-space FIN now out of scope (documented)
	} {
		got, _ := ValidateSingaporeFIN(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidateSingaporeFIN(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}
