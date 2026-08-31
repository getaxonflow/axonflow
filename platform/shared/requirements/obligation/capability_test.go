// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"strings"
	"testing"
)

// TestCapabilityNegotiationHasNoWildcardAndNoVersionRange. Every relaxation a
// reader might expect is checked here as an absence, because each of them is a
// way for a PEP to be handed an obligation it discharges under the wrong
// meaning.
func TestCapabilityNegotiationHasNoWildcardAndNoVersionRange(t *testing.T) {
	c := PEPCapabilities{
		PEPID:     "wcp",
		Supported: []Capability{{Type: TypeFieldRedaction, Version: 2}},
	}.Normalize()

	if c.Supports(Capability{Type: TypeFieldRedaction, Version: 1}) {
		t.Error("v2 support implied v1 support; there is no backward range")
	}
	if c.Supports(Capability{Type: TypeFieldRedaction, Version: 3}) {
		t.Error("v2 support implied v3 support; there is no forward range")
	}
	if c.Supports(Capability{Type: TypeFieldRedaction, Version: 0}) {
		t.Error("version 0 matched; 0 is not a wildcard")
	}
	if c.Supports(Capability{Type: "*", Version: 2}) {
		t.Error("a wildcard type matched")
	}
	if !c.Supports(Capability{Type: TypeFieldRedaction, Version: 2}) {
		t.Error("the exact advertised capability did not match")
	}
}

// TestSupportsWorksBeforeNormalize: Normalize builds an index, and a caller
// that forgets it must still get the right ANSWER (just slower). A nil index
// silently answering "false" would deny every mandatory obligation on a
// correctly configured PEP.
func TestSupportsWorksBeforeNormalize(t *testing.T) {
	c := PEPCapabilities{PEPID: "wcp", Supported: []Capability{{Type: TypeFieldRedaction, Version: 1}}}
	if !c.Supports(Capability{Type: TypeFieldRedaction, Version: 1}) {
		t.Fatal("Supports on an un-normalized value returned false for an advertised capability")
	}
	if c.Supports(Capability{Type: TypeFieldRedaction, Version: 2}) {
		t.Fatal("Supports on an un-normalized value matched a version that is not advertised")
	}
}

// TestCapabilityDigestIsOrderIndependentAndDeduplicated: two PEPs advertising
// the same set must bind the same digest into a decision proof whatever order
// they listed it in, or an identical deployment would produce non-comparable
// proofs.
func TestCapabilityDigestIsOrderIndependentAndDeduplicated(t *testing.T) {
	a := PEPCapabilities{PEPID: "p", ProfileVersion: "v1", Supported: []Capability{
		{Type: TypeFieldRedaction, Version: 1}, {Type: TypeApprovalChallenge, Version: 1},
	}}
	b := PEPCapabilities{PEPID: "p", ProfileVersion: "v1", Supported: []Capability{
		{Type: TypeApprovalChallenge, Version: 1}, {Type: TypeFieldRedaction, Version: 1},
		{Type: TypeFieldRedaction, Version: 1}, // duplicate
	}}
	if a.Digest() != b.Digest() {
		t.Fatalf("digests differ:\n a=%s\n b=%s", a.Digest(), b.Digest())
	}
}

// TestCapabilityDigestSeparatesDifferentPEPsAndProfiles. Two PEPs with the
// same capability set are not interchangeable: the proof is audience-bound to
// one of them.
func TestCapabilityDigestSeparatesDifferentPEPsAndProfiles(t *testing.T) {
	base := PEPCapabilities{PEPID: "p", ProfileVersion: "v1", Supported: []Capability{{Type: TypeFieldRedaction, Version: 1}}}
	other := base
	other.PEPID = "q"
	if base.Digest() == other.Digest() {
		t.Error("two different PEPs produced the same digest")
	}
	profile := base
	profile.ProfileVersion = "v2"
	if base.Digest() == profile.Digest() {
		t.Error("two different profile versions produced the same digest")
	}
}

// TestCheckAgainstRegistryFindsVersionSkew. Not a decision gate - an advertised
// capability nobody asks for is harmless - but it is the tell for a skewed
// deployment, and an operator wants it at startup rather than when a mandatory
// obligation denies in production.
func TestCheckAgainstRegistryFindsVersionSkew(t *testing.T) {
	reg := testRegistry(t)
	c := PEPCapabilities{PEPID: "p", Supported: []Capability{
		{Type: TypeFieldRedaction, Version: 1}, // known
		{Type: TypeFieldRedaction, Version: 7}, // skew
		{Type: "invented_type", Version: 1},    // skew
	}}
	unknown := c.CheckAgainstRegistry(reg)
	if len(unknown) != 2 {
		t.Fatalf("unknown = %v, want the two skewed capabilities", unknown)
	}
}

func TestPEPValidateRefusesAnUnidentifiedPEPAndVersionZero(t *testing.T) {
	if err := (PEPCapabilities{}).Validate(); err == nil {
		t.Error("an unidentified PEP must be refused: it cannot be bound into a decision proof")
	}
	err := PEPCapabilities{PEPID: "p", Supported: []Capability{{Type: TypeFieldRedaction, Version: 0}}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not mean 'any'") {
		t.Errorf("err = %v, want a refusal of version 0", err)
	}
	err = PEPCapabilities{PEPID: "p", Supported: []Capability{{Version: 1}}}.Validate()
	if err == nil {
		t.Error("a capability with an empty type must be refused")
	}
}

func TestCapabilityStringIsStable(t *testing.T) {
	if got := (Capability{Type: TypeFieldRedaction, Version: 3}).String(); got != "field_redaction@v3" {
		t.Fatalf("String() = %q", got)
	}
}
