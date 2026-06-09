// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import "testing"

// #2567: sys_pii_passport / sys_pii_dob must resolve to ValidatePassport /
// ValidateDOB (not the credit-card category default that left them inert).
func TestValidatorForPolicyID_PassportDOB(t *testing.T) {
	if v := ValidatorForPolicyID("sys_pii_passport"); v == nil {
		t.Error("sys_pii_passport must resolve to a validator (was credit-card-default inert)")
	}
	if v := ValidatorForPolicyID("sys_pii_dob"); v == nil {
		t.Error("sys_pii_dob must resolve to a validator (was credit-card-default inert)")
	}
	// Regression: the credit-card default rejects a passport string, so pre-#2567
	// passport detection was inert. Confirm the resolved validator accepts it.
	if ok, _ := ValidatorForPolicyID("sys_pii_passport")("A1234567", "passport number A1234567"); !ok {
		t.Error("resolved passport validator rejected a contextual passport — still inert")
	}
}

// ValidatePassport is context-gated: the broad 1-2-letter+6-9-digit pattern only
// validates WITH a passport/travel context, so generic uppercase-alphanumeric IDs
// are not blocked (the policy action is block, and EvaluateAll has no confidence
// threshold).
func TestValidatePassport_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"A1234567", "passport number A1234567 issued in 2020", true},
		{"GB1234567", "travel document GB1234567", true},
		{"X1234567", "order X1234567 shipped today", false},               // generic ID, no context
		{"A1234567", "reference A1234567 for the case", false},            // no passport context
		{"ABC1234567", "passport ABC1234567", false},                      // 3 letters → bad format
		{"A12345", "passport A12345", false},                              // 5 digits → too short
		{"1A234567", "passport copy 1A234567", false},                     // digit-first → bad format (R3 #2)
		{"A1234567", "passporting goods A1234567", false},                 // "passporting" != passport (word boundary)
		{"A1234567", "the passport office returned form A1234567", false}, // proximity: label not adjacent (R3 r2)
	} {
		got, _ := ValidatePassport(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidatePassport(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}

// ValidateDOB is context-gated: only a date with a birth-date indicator validates,
// so timestamps / due dates are not redacted as DOB.
func TestValidateDOB_ContextGated(t *testing.T) {
	for _, c := range []struct {
		match, context string
		want           bool
	}{
		{"01/15/1990", "date of birth 01/15/1990", true},
		{"01/15/1990", "DOB: 01/15/1990", true},
		{"12/25/2023", "born on 12/25/2023", true},
		{"01/15/1990", "invoice due 01/15/1990 net30", false},     // no birth context
		{"12/25/2023", "meeting on 12/25/2023", false},            // generic date
		{"01/02/2025", "Adobe Acrobat license 01/02/2025", false}, // "aDOBe" substring — must NOT match (R3 #1)
		{"03/04/2020", "Division airborne 03/04/2020", false},     // "airBORNe" substring — must NOT match (R3 #1)
		{"05/06/2021", "Project Reborn ships 05/06/2021", false},  // "reBORN" substring — must NOT match (R3 #1)
		// Proximity over-block (R3 round-2): a birth word elsewhere in the window
		// must NOT govern an unrelated date — only an ADJACENT label does.
		{"03/04/2025", "the company was born in 2018, invoice 03/04/2025", false},
		{"03/04/1990", "born on 03/04/1990", true}, // adjacent label still works
		{"03/04/1990", "date of birth is 03/04/1990", true},
		{"01/01/1990", "d.o.b. 01/01/1990", true}, // full abbreviation w/ trailing period
	} {
		got, _ := ValidateDOB(c.match, c.context)
		if got != c.want {
			t.Errorf("ValidateDOB(%q, ctx=%q) = %v, want %v", c.match, c.context, got, c.want)
		}
	}
}
