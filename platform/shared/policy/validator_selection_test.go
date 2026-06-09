// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package policy

import "testing"

// ValidatorForPolicyID must select a validator by PII-type token within the
// policy ID — the behavior the exact-match ValidatorRegistry[policyID] lookup
// never delivered (every "sys_pii_*" ID missed the bare type keys and fell back
// to the category default, so pii-global policies all got the credit-card
// validator and email/phone/dob/ip/passport detection was inert).
func TestValidatorForPolicyID(t *testing.T) {
	// Same function instance => compare via behavior on a probe string.
	cases := []struct {
		policyID string
		// probe that the CORRECT validator accepts and the wrong (credit-card)
		// category default rejects, proving the right validator was chosen.
		probe   string
		wantNil bool
	}{
		{"sys_pii_email", "alice@example.com", false},
		{"sys_pii_phone", "415-555-1234", false},
		{"sys_pii_ssn", "529-21-1234", false},
		{"sys_pii_ip_address", "8.8.8.8", false},
		{"sys_pii_bank_account", "021000021123456789", false},
		{"sys_pii_credit_card", "4111111111111111", false},
		{"sys_pii_booking_ref", "ABC123", true}, // no token, no registry validator → nil (caller uses category)
		// sys_pii_passport / sys_pii_dob resolution + context-gating is covered by
		// TestValidatorForPolicyID_PassportDOB and the dedicated *_ContextGated tests
		// (their validators are context-gated, so a policyID-as-context probe here
		// would not exercise them meaningfully).
	}
	for _, c := range cases {
		v := ValidatorForPolicyID(c.policyID)
		if c.wantNil {
			if v != nil {
				t.Errorf("%s: expected nil validator (caller falls back to category), got non-nil", c.policyID)
			}
			continue
		}
		if v == nil {
			t.Errorf("%s: expected a validator, got nil", c.policyID)
			continue
		}
		if ok, _ := v(c.probe, c.policyID); !ok {
			t.Errorf("%s: selected validator rejected its own valid probe %q — wrong validator chosen", c.policyID, c.probe)
		}
	}

	// Regression lock for the exact bug: sys_pii_email must NOT resolve to the
	// credit-card validator (which rejects every email).
	emailV := ValidatorForPolicyID("sys_pii_email")
	if ok, _ := emailV("alice@example.com", "email"); !ok {
		t.Fatal("sys_pii_email resolved to a validator that rejects a valid email (the credit-card-default bug)")
	}
	// And the credit-card validator DOES reject an email (proving the probe is meaningful).
	if ok, _ := ValidateCreditCard("alice@example.com", "email"); ok {
		t.Fatal("ValidateCreditCard unexpectedly accepted an email — probe is not discriminating")
	}
}

// The validator fix changes sys_pii_indonesia_phone / sys_pii_singapore_phone
// from their category default (nil = accept every pattern match) to ValidatePhone
// — a slight narrowing on those locales' request AND response paths. This locks
// in that real local numbers are STILL governed (not dropped) after the change.
func TestValidatorForPolicyID_LocalePhones(t *testing.T) {
	for _, c := range []struct {
		policyID string
		number   string
		context  string
	}{
		{"sys_pii_indonesia_phone", "081234567890", "call the customer"}, // 12 digits
		{"sys_pii_indonesia_phone", "6281234567890", "contact"},          // +62 form, 13 digits
		{"sys_pii_singapore_phone", "91234567", "mobile"},                // 8 digits
		{"sys_pii_singapore_phone", "6591234567", "phone"},               // +65 form, 10 digits
	} {
		v := ValidatorForPolicyID(c.policyID)
		if v == nil {
			t.Errorf("%s: expected ValidatePhone, got nil (would fall back to category default)", c.policyID)
			continue
		}
		if ok, _ := v(c.number, c.context); !ok {
			t.Errorf("%s: ValidatePhone rejected a real local number %q — narrowing dropped a legitimate match", c.policyID, c.number)
		}
	}
}

// The loader must stamp the email policy with the email validator (not the
// pii-global category default), so DB-loaded email policies actually match.
func TestLoaderGetValidatorForPolicy_EmailNotCreditCard(t *testing.T) {
	l := &PolicyLoader{}
	v := l.getValidatorForPolicy("sys_pii_email", CategoryPIIGlobal)
	if v == nil {
		t.Fatal("loader returned nil validator for sys_pii_email")
	}
	if ok, _ := v("alice@example.com", "email"); !ok {
		t.Fatal("loader assigned a non-email validator to sys_pii_email (the credit-card-default regression)")
	}
}
