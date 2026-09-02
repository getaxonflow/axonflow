// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

// TestParseDecisionShadowModeRefusesEnforceByName pins the NAMED refusal.
//
// A generic "not a recognized mode" would be safe and would still be wrong:
// an operator who typed enforce has a specific incorrect belief about what
// this release does, and sending them to check their spelling is sending them
// to the wrong investigation. The message has to say the plane becomes an
// authority at v11.
func TestParseDecisionShadowModeRefusesEnforceByName(t *testing.T) {
	_, err := ParseDecisionShadowMode("enforce")
	if err == nil {
		t.Fatal("enforce was accepted on the decision shadow axis; the PDP has no authority before v11")
	}
	if !strings.Contains(err.Error(), "v11") {
		t.Fatalf("the refusal does not name the release that changes the answer, so it reads as a typo: %v", err)
	}
	// THE CANONICAL PHRASE, not merely the token "v11".
	//
	// This refusal is what an operator reads off a crash-looping container and
	// what runtime-e2e 3564 Phase D greps the container log for. A reword that
	// still contained "v11" would leave that suite red for a reason no unit
	// test named, which is how the phrase drifted from the one
	// Observer.effectiveMode uses in the first place.
	const canonical = "the decision plane has no authority before v11"
	if !strings.Contains(err.Error(), canonical) {
		t.Fatalf("the refusal does not carry the canonical phrase %q; every refusal on this axis uses it and the runtime suite reads for it: %v", canonical, err)
	}
	for _, spelling := range []string{"ENFORCE", "  Enforce  "} {
		if _, err := ParseDecisionShadowMode(spelling); err == nil {
			t.Fatalf("%q was accepted; the parser normalizes case and space before deciding, so every spelling of enforce must be refused", spelling)
		}
	}
}

// TestParseDecisionShadowModeAcceptsOnlyTheClosedSet covers both directions:
// what it must accept, and that an unrecognized value is an ERROR rather than
// a silent off.
func TestParseDecisionShadowModeAcceptsOnlyTheClosedSet(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want CompatMode
	}{
		{"", CompatModeOff},
		{"off", CompatModeOff},
		{"false", CompatModeOff},
		{"0", CompatModeOff},
		{"disabled", CompatModeOff},
		{"  OFF\t", CompatModeOff},
		{"shadow", CompatModeShadow},
		{" Shadow ", CompatModeShadow},
	} {
		got, err := ParseDecisionShadowMode(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("ParseDecisionShadowMode(%q) = %v, %v; want %v", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"shadwo", "on", "true", "1", "record", "unspecified"} {
		got, err := ParseDecisionShadowMode(raw)
		if err == nil {
			t.Fatalf("ParseDecisionShadowMode(%q) = %v with no error; a silent off leaves an operator believing the planes are measured when nothing measures them", raw, got)
		}
		if got != CompatModeUnspecified {
			t.Fatalf("ParseDecisionShadowMode(%q) returned %v alongside its error; a refusing parser must not also hand back a usable mode", raw, got)
		}
	}
}

// TestDecisionShadowModeIsStorableIsPositiveMembership is the tri-state
// lesson, asserted rather than assumed: the predicate must refuse the zero
// value and an out-of-range value, which `m != CompatModeEnforce` would both
// admit.
func TestDecisionShadowModeIsStorableIsPositiveMembership(t *testing.T) {
	for _, m := range []CompatMode{CompatModeOff, CompatModeShadow} {
		if !DecisionShadowModeIsStorable(m) {
			t.Fatalf("%v must be storable on the decision axis", m)
		}
	}
	for _, m := range []CompatMode{CompatModeUnspecified, CompatModeEnforce, CompatMode(99), CompatMode(-1)} {
		if DecisionShadowModeIsStorable(m) {
			t.Fatalf("%v was reported storable; an inequality against enforce would admit exactly these", m)
		}
	}
}

// TestEffectiveModeIsTheOneCompositionRule pins the rule both per-organization
// axes now share, at the level of the exported function, in BOTH directions.
//
// The two directions are not symmetric decoration: raising (process off, record
// shadow) is the release plan's case, and lowering (process enforce, record
// off) is the incident case. A composition that only handled one of them would
// pass a test that only checked the other.
func TestEffectiveModeIsTheOneCompositionRule(t *testing.T) {
	t.Run("no record means the process flag", func(t *testing.T) {
		for _, process := range []CompatMode{CompatModeOff, CompatModeShadow, CompatModeEnforce} {
			got, err := EffectiveMode(process, CompatModeShadow, false)
			if err != nil {
				t.Fatalf("an absent record is not an error: %v", err)
			}
			if got != process {
				t.Fatalf("an organization with no record ran in %v on a %v deployment; the record argument must be ignored entirely when found is false", got, process)
			}
		}
	})

	t.Run("raising: the record wins above the process flag", func(t *testing.T) {
		got, err := EffectiveMode(CompatModeOff, CompatModeShadow, true)
		if err != nil || got != CompatModeShadow {
			t.Fatalf("got %v, %v; a recorded shadow on an off deployment is the release plan's whole per-org case", got, err)
		}
	})

	t.Run("lowering: the record wins below the process flag", func(t *testing.T) {
		got, err := EffectiveMode(CompatModeEnforce, CompatModeOff, true)
		if err != nil || got != CompatModeOff {
			t.Fatalf("got %v, %v; an organization exempted by its record must not inherit the deployment's enforcement", got, err)
		}
	})

	t.Run("an undeclared record is an error and the process flag", func(t *testing.T) {
		for _, bad := range []CompatMode{CompatModeUnspecified, CompatMode(99)} {
			got, err := EffectiveMode(CompatModeShadow, bad, true)
			if err == nil {
				t.Fatalf("record %v composed silently; the caller must be told so it can count the fall-back", bad)
			}
			if got != CompatModeShadow {
				t.Fatalf("an unreadable record fell back to %v; the direction of the fall-back is towards the DEPLOYMENT'S declaration, never towards a guess", got)
			}
		}
	})
}
