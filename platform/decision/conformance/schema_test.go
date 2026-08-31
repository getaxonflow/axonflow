package conformance

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestEveryDecisionSatisfiesItsSchema is the contract-guard for the
// declared-but-never-emitted class: the JSON Schemas are what a non-Go plane
// reads, so a shape that passes the Go validators and fails the schema is a
// real defect rather than a documentation lag. Every request the corpus builds
// and every decision it produces is checked, so the schemas cannot drift from
// the types without this failing.
func TestEveryDecisionSatisfiesItsSchema(t *testing.T) {
	w := defaultWorld(t)
	checked := 0
	for _, s := range propertyRequests() {
		req, err := w.Request(s)
		if err != nil {
			t.Fatalf("building %+v: %v", s, err)
		}
		if err := contract.ValidateAgainstSchema(contract.SchemaRequest, req); err != nil {
			t.Fatalf("request for %s on %s: %v", s.Principal, s.Action, err)
		}
		d := decide(t, w, s)
		if err := contract.ValidateAgainstSchema(contract.SchemaDecision, d); err != nil {
			t.Fatalf("decision for %s on %s: %v", s.Principal, s.Action, err)
		}
		for _, o := range d.Obligations {
			if err := contract.ValidateAgainstSchema(contract.SchemaObligation, o); err != nil {
				t.Fatalf("obligation from %s: %v", o.SourcePolicy, err)
			}
		}
		if d.Approval != nil {
			if err := contract.ValidateAgainstSchema(contract.SchemaApproval, d.Approval); err != nil {
				t.Fatalf("approval requirement for %s on %s: %v", s.Principal, s.Action, err)
			}
		}
		for _, aud := range contract.AllAudiences() {
			projected, err := d.Trace.Project(aud)
			if err != nil {
				t.Fatalf("projecting %s: %v", aud, err)
			}
			if err := contract.ValidateAgainstSchema(contract.SchemaTrace, projected); err != nil {
				t.Fatalf("trace for audience %s on %s: %v", aud, s.Action, err)
			}
		}
		checked++
	}
	if checked != len(propertyRequests()) {
		t.Fatalf("validated %d of %d requests", checked, len(propertyRequests()))
	}
}
