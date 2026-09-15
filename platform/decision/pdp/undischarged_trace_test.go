// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"testing"

	"axonflow/platform/decision/contract"
)

// A capability refusal leaves the obligation it could not discharge on the
// decision's internal trace, where the agent names the enforcement point's gap
// from it; a permit leaves nothing there.
func TestACapabilityRefusalLeavesItsObligationOnTheInternalTrace(t *testing.T) {
	ctx := context.Background()
	e := engineWithProfiles(t, obligationDoc(), auditCapableProfile("engine-pep"), nil)

	dec, err := e.DecideWith(ctx, testRequest(baseAttrs()), DecideOptions{PEP: &contract.PEPProfile{ID: "deaf-pep"}})
	if err != nil {
		t.Fatalf("DecideWith: %v", err)
	}
	if dec.Reason != contract.ReasonUnsupportedObligation {
		t.Fatalf("PREMISE: reason %q; want the capability refusal", dec.Reason)
	}
	if dec.Trace == nil || len(dec.Trace.Undischarged) != 1 {
		t.Fatalf("the trace carries %d undischarged obligation(s); want 1", len(dec.Trace.Undischarged))
	}
	if o := dec.Trace.Undischarged[0]; o.Type != contract.ObImmutableAudit || o.SourcePolicy != auditObligationSource || !o.Mandatory {
		t.Fatalf("the trace names %+v; want %s's mandatory immutable_audit", o, auditObligationSource)
	}

	ok, err := e.DecideWith(ctx, testRequest(baseAttrs()), DecideOptions{PEP: auditCapableProfile("capable-caller")})
	if err != nil {
		t.Fatalf("control DecideWith: %v", err)
	}
	if ok.Authorization != contract.AuthzPermit || len(ok.Trace.Undischarged) != 0 {
		t.Fatalf("CONTROL: authorization %q with %d undischarged; want a permit with none", ok.Authorization, len(ok.Trace.Undischarged))
	}
}
