// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import "testing"

// sys_pii_singapore_postal / sys_pii_singapore_uen are CategoryPIISingapore, whose
// category default validator is nil (accept-all). Before this fix they fired on
// every regex match: a bare 6-digit number ("369318") matched the postal pattern
// and an 8-9-digit+letter id ("12345678X") matched the UEN pattern, so under
// PII_ACTION=redact the engine masked benign financial/order figures. Worse, when
// the masked value was a bare JSON number the redacted document became invalid
// JSON and a re-validating PEP (the Claude Desktop proxy) fail-closed an otherwise
// benign response. These tests pin the proximity gates that close that class.

// Regression: both IDs must now resolve to their context-gated validators (not the
// nil Singapore-category default that accepted everything).
func TestValidatorForPolicyID_SingaporeBroad(t *testing.T) {
	if v := ValidatorForPolicyID("sys_pii_singapore_postal"); v == nil {
		t.Error("sys_pii_singapore_postal must resolve to ValidateSingaporePostal (was accept-all)")
	}
	if v := ValidatorForPolicyID("sys_pii_singapore_uen"); v == nil {
		t.Error("sys_pii_singapore_uen must resolve to ValidateSingaporeUEN (was accept-all)")
	}
	// The exact id=102 datum: a benign avg-order figure must NOT validate as postal.
	if ok, _ := ValidatorForPolicyID("sys_pii_singapore_postal")("369318", "avg order value 369318 rupiah"); ok {
		t.Error("resolved postal validator governed a benign 6-digit figure — false positive not closed")
	}
}

func TestValidateSingaporePostal_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"408600", "Singapore 408600 office", true},        // labelled address
		{"408600", "postal code 408600", true},             // explicit label
		{"408600", "postcode: 408600", true},               // label + separator
		{"369318", "avg order value 369318 rupiah", false}, // the id=102 false positive
		{"123456", "transaction count 123456 this quarter", false},
		{"408600", "invoice 408600 paid", false},                   // a 6-digit id, no postal context
		{"408600", "shipped to Singapore last week 408600", false}, // label not adjacent (proximity)
	} {
		got, _ := ValidateSingaporePostal(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidateSingaporePostal(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}

func TestValidateSingaporeUEN_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"T09LL0001B", "registered as T09LL0001B", true}, // structured UEN — self-anchoring
		{"S98LL1234C", "S98LL1234C", true},               // structured UEN, no context needed
		{"12345678X", "UEN 12345678X", true},             // broad form WITH label
		{"123456789A", "unique entity number 123456789A", true},
		{"12345678X", "invoice number 12345678X total 42", false},          // benign invoice id
		{"201912345A", "see order 201912345A for details", false},          // benign order ref
		{"12345678X", "the UEN registry lists 12345678X somewhere", false}, // label not adjacent
	} {
		got, _ := ValidateSingaporeUEN(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidateSingaporeUEN(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}
