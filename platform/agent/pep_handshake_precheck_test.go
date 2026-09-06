package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestPreCheckRedactionObligationMatchesTheOtherPlanes is the anti-drift pin.
//
// A client's declaration is ONE document presented on every governed call. If
// this plane asked about a different type or schema version from the decide
// plane's projection, a client that correctly declares what /decide requires
// would be DENIED here for a version it could not have known to declare - and
// the failure would look like a client bug on a client that did exactly what
// the contract said.
//
// Driven THROUGH mapObligations rather than against a copied literal, because a
// literal would be a second declaration of the same fact and would go on
// agreeing with itself after the projection changed.
func TestPreCheckRedactionObligationMatchesTheOtherPlanes(t *testing.T) {
	projected, err := mapObligations([]DecisionObligation{{
		Type: ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{
			Endpoint: "/api/v1/mcp/check-input",
			Method:   "POST",
			Phase:    "request",
		},
	}})
	if err != nil {
		t.Fatalf("the decide plane's projection refused its own obligation: %v", err)
	}
	decide := projected[0]

	pre := preCheckRedactionObligation()
	if pre.Type != decide.Type {
		t.Fatalf("the pre-check plane asks about %q while the decide plane stamps %q; "+
			"one client declaration must satisfy every plane", pre.Type, decide.Type)
	}
	if pre.SchemaVersion != decide.SchemaVersion {
		t.Fatalf("the pre-check plane asks about %s@%d while the decide plane stamps %s@%d",
			pre.Type, pre.SchemaVersion, decide.Type, decide.SchemaVersion)
	}
	// And equal to the MCP plane's, so all three agree rather than two of three.
	mcp := mcpRedactionObligation()
	if pre.Type != mcp.Type || pre.SchemaVersion != mcp.SchemaVersion {
		t.Fatalf("the pre-check plane (%s@%d) and the MCP plane (%s@%d) disagree",
			pre.Type, pre.SchemaVersion, mcp.Type, mcp.SchemaVersion)
	}
}

// TestPreCheckRedactionObligationIsMandatory pins the member the gate turns on.
//
// firstUnsupportedMandatory SKIPS an advisory obligation, deliberately, so an
// advisory one here would make every pre-check refusal silently stop firing.
func TestPreCheckRedactionObligationIsMandatory(t *testing.T) {
	if !preCheckRedactionObligation().Mandatory {
		t.Fatal("the pre-check plane's redaction instruction is not Mandatory; " +
			"firstUnsupportedMandatory skips advisory obligations, so the capability gate " +
			"on this plane would silently stop enforcing")
	}
}

// TestPreCheckRedactionObligationIsValidUnderTheContract checks a hand-built
// value against the contract's own validator, since that is exactly the kind
// that drifts out of validity silently.
func TestPreCheckRedactionObligationIsValidUnderTheContract(t *testing.T) {
	if err := preCheckRedactionObligation().Validate(); err != nil {
		t.Fatalf("the obligation this plane asks its capability question about is not valid "+
			"under the contract: %v", err)
	}
}

// TestPreCheckRedactionObligationTypeIsInTheDeclaredVocabulary keeps the
// obligation metric label bounded.
func TestPreCheckRedactionObligationTypeIsInTheDeclaredVocabulary(t *testing.T) {
	want := preCheckRedactionObligation().Type
	for _, declared := range contract.AllObligationTypes() {
		if declared == want {
			return
		}
	}
	t.Fatalf("the pre-check plane asks about obligation type %q, which is not in "+
		"contract.AllObligationTypes(); it would appear as an undeclared metric label", want)
}
