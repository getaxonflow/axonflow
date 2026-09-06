// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import "testing"

// The entitlement PARTITION - which modes are entitled, by name - used to live
// here as its own hand-written table. It has moved into
// TestDeploymentModePartitions in deploymode_test.go, which since #3738 states
// every axis for every recognised spelling in ONE table. Two hand-written
// tables over the same mode list is precisely the drift this package exists to
// end, and it would have been a second one.
//
// Only that one mechanism was removed. TestTheEntitlementAndSchemaAxesAgreeToday
// below is NOT redundant with the combined table and stays: the table accepts
// any pair of values somebody types, so a row set to entitled-without-the-schema
// passes there. The agreement assertion makes such a divergence take a SECOND
// deliberate act - deleting this test - instead of riding along in a table edit.

// TestEveryCanonicalModeHasAnEntitlement is the totality requirement that lets
// the declared table stand in for a derivation.
//
// enterpriseEntitledModes is a SECOND table keyed on mode names, and a second
// table is exactly the drift this package was created to end - so it is only
// defensible while it is provably complete over the first one. A mode added to
// canonicalModes and not here would resolve to false and be silently denied
// Enterprise limits; a key here that is not a canonical mode is dead and
// answers for nothing.
func TestEveryCanonicalModeHasAnEntitlement(t *testing.T) {
	for mode := range canonicalModes {
		if _, ok := enterpriseEntitledModes[mode]; !ok {
			t.Errorf("canonical mode %q has no entitlement classification; "+
				"it currently resolves to false (no Enterprise limits). Add it to "+
				"enterpriseEntitledModes and to TestEnterpriseEntitlementPartition.", mode)
		}
	}
	for mode := range enterpriseEntitledModes {
		if _, ok := canonicalModes[mode]; !ok {
			t.Errorf("enterpriseEntitledModes has %q, which is not a canonical mode; "+
				"an alias belongs in aliases, and anything else answers for nothing", mode)
		}
	}
}

// TestUnrecognisedIsNotEnterpriseEntitled pins the direction that was the
// security half of #3713, and pins it AGAINST its neighbour.
//
// AppliesCategory answers YES for an unrecognised value on purpose. If this
// axis had been derived from that one - the free, always-total derivation this
// package deliberately did not take - a typo in DEPLOYMENT_MODE would still be
// granting unlimited Enterprise limits after the fix. The assertion on
// AppliesCategory below is not decoration: it is the proof that the two answers
// genuinely differ here, so this test fails if someone replaces the declared
// table with the derivation.
func TestUnrecognisedIsNotEnterpriseEntitled(t *testing.T) {
	for _, raw := range []string{
		"comunity",   // a typo
		"Community",  // wrong case; Resolve is deliberately exact
		" community", // leading space; likewise
		"ENTERPRISE",
		"in-vpc-", // a prefix of the namespace, not a mode
		"saas-eu", // plausible, undeclared
		"free",    // aspirational
	} {
		if _, recognised := Resolve(raw); recognised {
			t.Fatalf("test bug: %q is recognised, so it cannot exercise the unrecognised path", raw)
		}
		if IsEnterpriseEntitled(raw) {
			t.Errorf("IsEnterpriseEntitled(%q) = true; an unvalidated string must not "+
				"be worth a purchased licence (#3713)", raw)
		}
		if !AppliesCategory(raw, CategoryEnterprise) {
			t.Fatalf("AppliesCategory(%q, enterprise) = false, but its contract says an "+
				"unrecognised value answers YES. Either that changed - in which case the "+
				"argument in enterpriseEntitledModes' comment needs rewriting - or this "+
				"test no longer proves the two axes differ on the input that matters.", raw)
		}
	}
}

// TestTheEntitlementAndSchemaAxesAgreeToday records that the two tables
// coincide on every RECOGNISED mode, and is the place a future divergence gets
// stated.
//
// They are separate tables because they answer separate questions, not because
// they disagree - today they do not. Pinning the coincidence means the two
// cannot drift apart by accident: an edit to either table that separates them
// fails here, and whoever made it either did not mean to, or writes down which
// mode has Enterprise TABLES without Enterprise LIMITS (or the reverse) and
// why.
//
// Note the scope: RECOGNISED modes only. The two axes deliberately DISAGREE on
// unrecognised values, which is TestUnrecognisedIsNotEnterpriseEntitled's
// subject, and folding that input in here would make this test unsatisfiable.
func TestTheEntitlementAndSchemaAxesAgreeToday(t *testing.T) {
	for _, mode := range RecognisedModes() {
		entitled := IsEnterpriseEntitled(mode)
		schema := AppliesCategory(mode, CategoryEnterprise)
		if entitled != schema {
			t.Errorf("mode %q: entitled=%v but applies the enterprise schema=%v.\n"+
				"If this is deliberate, say here which it is and why: a mode with the "+
				"tables but not the limits, or the limits but not the tables.",
				mode, entitled, schema)
		}
	}
}

// TestCurrentIsEnterpriseEntitledReadsTheEnvironment covers the env-reading
// wrapper, on the two inputs that decide the live fleet.
func TestCurrentIsEnterpriseEntitledReadsTheEnvironment(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	if CurrentIsEnterpriseEntitled() {
		t.Fatal("CurrentIsEnterpriseEntitled() = true under DEPLOYMENT_MODE=community-saas; " +
			"that is #3713 - the free shared fleet drawing unlimited custom-policy connectors")
	}
	t.Setenv("DEPLOYMENT_MODE", "saas")
	if !CurrentIsEnterpriseEntitled() {
		t.Fatal("CurrentIsEnterpriseEntitled() = false under DEPLOYMENT_MODE=saas; " +
			"production-us would be held to the Community connector limit")
	}
}

// TestUnsetIsNotEnterpriseEntitledDirectly pins the empty-string answer on the
// ENTITLEMENT axis itself.
//
// R3 round 1: the unset answer was reachable only through Resolve's `Unset`
// constant, whose own doc scopes it to SCHEMA selection and notes that the
// divergence from the runtime posture is open issue #3128 - and #3128's likely
// resolution runs the other way, with unset meaning the enterprise posture.
// Mutating `Unset` to a paid mode makes IsEnterpriseEntitled("") true, and that
// was caught only by a SCHEMA test and by the policy package's rows. Borrowing
// another axis's constant for this answer is the coupling this file argues
// against elsewhere, so the answer is pinned here directly.
func TestUnsetIsNotEnterpriseEntitledDirectly(t *testing.T) {
	if IsEnterpriseEntitled("") {
		t.Fatal("IsEnterpriseEntitled(\"\") = true: an operator who never configured " +
			"DEPLOYMENT_MODE at all would draw unlimited paid limits. Whatever Unset " +
			"means for SCHEMA selection (#3128), the entitlement answer for a value " +
			"nobody set is no.")
	}
}
