// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capabilityresolution

import "testing"

func TestReasonVocabularyIsStableAndClosed(t *testing.T) {
	want := []Reason{
		"edition_required",
		"capability_not_granted",
		"quota_exhausted",
		"dependency_unreachable",
	}
	got := Reasons()
	if len(got) != len(want) {
		t.Fatalf("Reasons() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] || !Valid(got[i]) {
			t.Errorf("Reasons()[%d] = %q (valid=%t), want %q", i, got[i], Valid(got[i]), want[i])
		}
	}
	got[0] = "mutated"
	if Reasons()[0] != ReasonEditionRequired {
		t.Fatal("Reasons returned its mutable backing slice")
	}
	if Valid("") || Valid("unknown") || Valid("grant_missing") {
		t.Fatal("an unknown refusal reason was accepted")
	}
}

func TestFinCrimeIdentitiesAreStableAndSeparate(t *testing.T) {
	want := map[string]string{
		"module":         "fincrime",
		"protocol":       "fincrime.protocol",
		"policy pack":    "fincrime.policy_pack",
		"risk scoring":   "fincrime.risk_scoring",
		"score requests": "fincrime.score_requests",
	}
	got := map[string]string{
		"module":         FinCrimeModuleID,
		"protocol":       FinCrimeProtocolCapabilityID,
		"policy pack":    FinCrimePolicyPackCapabilityID,
		"risk scoring":   FinCrimeRiskScoringCapabilityID,
		"score requests": FinCrimeScoreRequestsLimitID,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Errorf("%s identity = %q, want %q", name, got[name], expected)
		}
	}
	if FinCrimeModuleID == FinCrimePolicyPackCapabilityID ||
		FinCrimeModuleID == FinCrimeRiskScoringCapabilityID ||
		FinCrimePolicyPackCapabilityID == FinCrimeRiskScoringCapabilityID {
		t.Fatal("commercial module, pack and scorer identities were collapsed")
	}
}
