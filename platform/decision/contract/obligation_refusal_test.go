// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The capability refusal carries the obligation it could not discharge as a
// typed cause, so an adapter names the gap without parsing Detail, and Detail
// is what it was.
func TestTheCapabilityRefusalCarriesTheObligationItCouldNotDischarge(t *testing.T) {
	known := KnownPayloadLeaves("user.name", "user.ssn")
	redactSSN := gob(ObFieldRedact, "user.ssn", true, "p1", nil)
	out := ComposeObligations(ComposeInput{Obligations: []Obligation{redactSSN}, Payload: known,
		PEP: &PEPProfile{ID: "narrow", Capabilities: []Capability{{Type: ObImmutableAudit, Version: 1}}}})
	if !out.Denied || out.Reason != ReasonUnsupportedObligation {
		t.Fatalf("PREMISE: denied=%v reason=%q; want the capability refusal", out.Denied, out.Reason)
	}
	var cause *UndischargedObligationError
	if !errors.As(out.Err, &cause) {
		t.Fatalf("the refusal carries no typed cause: Err=%v", out.Err)
	}
	if o := cause.Obligation; o.Type != ObFieldRedact || o.Target != "user.ssn" || o.SourcePolicy != "p1" || !o.Mandatory || o.SchemaVersion != 1 {
		t.Fatalf("the typed cause names %+v; want the mandatory field_redact@1 on user.ssn from p1", o)
	}
	if cause.Error() != out.Detail || !strings.Contains(out.Detail, `enforcement point "narrow" advertises no field_redact at schema version 1`) {
		t.Fatalf("Error()=%q Detail=%q; want the same operator detail", cause.Error(), out.Detail)
	}

	ok := ComposeObligations(ComposeInput{Obligations: []Obligation{redactSSN}, Payload: known,
		PEP: &PEPProfile{ID: "capable", Capabilities: []Capability{{Type: ObFieldRedact, Version: 1}}}})
	if ok.Denied || ok.Err != nil {
		t.Fatalf("CONTROL: a profile that supports it: denied=%v err=%v; want composed with no cause", ok.Denied, ok.Err)
	}
}

// Trace.Undischarged is internal: no audience's projection carries it, no
// encoding carries it, and a decision's digest is the same with it as without.
func TestTheUndischargedObligationReachesNoAudienceNoEncodingAndNoDigest(t *testing.T) {
	const marker = "undischarged-marker-policy"
	full := &Trace{
		State: StateDeny, Category: CategoryFor(ReasonUnsupportedObligation), Reason: ReasonUnsupportedObligation,
		Undischarged: []Obligation{gob(ObFieldRedact, "user.ssn", true, marker, nil)},
	}
	if raw, err := json.Marshal(full); err != nil || strings.Contains(string(raw), marker) {
		t.Fatalf("the trace's encoding carries the undischarged obligation (err=%v): %s", err, raw)
	}
	for _, aud := range AllAudiences() {
		p, err := full.Project(aud)
		if err != nil {
			t.Fatalf("projecting for %s: %v", aud, err)
		}
		if len(p.Undischarged) != 0 {
			t.Errorf("audience %s receives the undischarged obligation", aud)
		}
		if raw, err := json.Marshal(p); err != nil || strings.Contains(string(raw), marker) {
			t.Errorf("audience %s's encoding carries the undischarged obligation (err=%v): %s", aud, err, raw)
		}
	}

	dec := &Decision{DecisionID: "d1", RequestID: "r1", Authorization: AuthzDeny, State: StateDeny, Reason: ReasonUnsupportedObligation}
	without, err := Digest(dec)
	if err != nil {
		t.Fatalf("digest without a trace: %v", err)
	}
	dec.Trace = full
	with, err := Digest(dec)
	if err != nil {
		t.Fatalf("digest with the trace: %v", err)
	}
	if with != without {
		t.Fatalf("the decision's digest moved with the undischarged obligation: %s -> %s", without, with)
	}
	if raw, err := json.Marshal(dec); err != nil || strings.Contains(string(raw), marker) {
		t.Fatalf("the decision's encoding carries the undischarged obligation (err=%v): %s", err, raw)
	}
}
