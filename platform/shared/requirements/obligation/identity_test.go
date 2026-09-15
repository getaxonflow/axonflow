// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package obligation

import (
	"encoding/base64"
	"reflect"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestCapabilityDiscoveryWireAndExecutionShareOneIdentity is the type/version
// identity proof #3891 asks for: the identity a PEP DISCOVERS itself with (the
// handshake), the identity the WIRE carries on an obligation (type +
// schema_version), and the identity EXECUTION keys on (the registry and the
// evidence map) are one value, contract.Capability, spelled one way.
//
// It is driven through the shipped encoder and decoder rather than by
// constructing a profile by hand, because the seam between "what the PEP
// said" and "what the planner judged against" is exactly where a second
// spelling would hide.
func TestCapabilityDiscoveryWireAndExecutionShareOneIdentity(t *testing.T) {
	reg := testRegistry(t)

	// 1. DISCOVERY: a PEP advertises the registry's capabilities through the
	//    handshake the agent decodes. Round-trip through the wire form.
	declared := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1,
		PEPID:          "identity-pep",
		Audience:       "axonflow-decision-proof",
		Capabilities:   reg.Capabilities(),
	}
	encoded, refusal := declared.Encode()
	if refusal != nil {
		t.Fatalf("encode: %v", refusal)
	}
	decoded, refusal := contract.DecodePEPHandshake(encoded)
	if refusal != nil {
		t.Fatalf("decode: %v", refusal)
	}
	profile := decoded.Profile()
	if !reflect.DeepEqual(contract.SortCapabilities(profile.Capabilities), reg.Capabilities()) {
		t.Fatalf("the decoded handshake advertises %v; the registry keys on %v", profile.Capabilities, reg.Capabilities())
	}

	// 2. WIRE: an obligation as the PDP emits it names (type, schema_version).
	wire := redact("p1", "user.ssn")
	if wire.Capability() != (contract.Capability{Type: contract.ObFieldRedact, Version: 1}) {
		t.Fatalf("wire identity = %v", wire.Capability())
	}

	// 3. EXECUTION: the planner judges the wire obligation against the decoded
	//    profile, and the evidence it waits for is keyed by the same value.
	res := Plan(PlanInput{
		Registry: reg, Payload: contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{wire}, PEP: profile, Evidence: map[contract.Capability]EvidenceState{},
	})
	if res.Outcome != OutcomeChallenge {
		t.Fatalf("outcome=%q reasons=%v, want CHALLENGE (advertised, composed, awaiting its receipt)", res.Outcome, res.Reasons)
	}
	if !reflect.DeepEqual(res.AwaitingEvidence, []contract.Capability{wire.Capability()}) {
		t.Fatalf("awaiting %v, want exactly the wire identity", res.AwaitingEvidence)
	}
	// Supplying the receipt UNDER THAT IDENTITY discharges it.
	res = Plan(PlanInput{
		Registry: reg, Payload: contract.KnownPayloadLeaves("user.ssn"),
		Obligations: []Obligation{wire}, PEP: profile,
		Evidence: map[contract.Capability]EvidenceState{res.AwaitingEvidence[0]: EvidenceSatisfied},
	})
	if res.Outcome != OutcomeAllow {
		t.Fatalf("outcome=%q reasons=%v, want ALLOW once the receipt is filed under the discovered identity", res.Outcome, res.Reasons)
	}
	for _, o := range res.Plan.Obligations {
		if s, ok := reg.Lookup(o.Type, o.SchemaVersion); !ok || s.Owner == "" {
			t.Errorf("composed %s has no executor under the identity it was composed with", o.CapabilityOf())
		}
	}

	// 4. And the losing spelling is refused at every one of the three seams,
	//    which is what "one vocabulary" means operationally.
	if _, refusal := contract.DecodePEPHandshake(mustEncodeRaw(t, `{"profile_version":1,"pep_id":"x","audience":"a","capabilities":[{"type":"field_redaction","version":1}]}`)); refusal == nil {
		t.Error("discovery accepted field_redaction")
	}
	if err := (contract.Obligation{Type: "field_redaction", Target: "x", Mandatory: true, SourcePolicy: "p", SchemaVersion: 1}).Validate(); err == nil {
		t.Error("the wire validator accepted field_redaction")
	}
	if _, err := NewRegistryBuilder("v").Add(Schema{Type: "field_redaction", Version: 1, Owner: "o", Phases: []Phase{PhaseRequest}, CompletionEvidence: "e", OnFailure: FailClosed}).Build(); err == nil {
		t.Error("execution registration accepted field_redaction")
	}
}

// mustEncodeRaw renders a raw JSON document as the handshake header value,
// with the same alphabet the shipped encoder uses (raw URL-safe base64, no
// padding), so a document the shipped encoder would refuse to produce can
// still be presented to the decoder.
func mustEncodeRaw(t *testing.T, doc string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(doc))
}
