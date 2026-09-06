package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestMCPRedactionObligationMatchesTheDecidePlaneProjection is the anti-drift
// pin, and it is the sharpest claim this lane makes.
//
// # WHAT WOULD BREAK WITHOUT IT
//
// A client's capability declaration is ONE document presented on every governed
// call. If the MCP plane asked about field_redact@2 while the decide plane
// stamped field_redact@1, a client that correctly declares what /decide
// requires would be DENIED on the MCP plane for a version it could not have
// known to declare - and the failure would look like a client bug on a plugin
// that did exactly what the contract told it to.
//
// So the type and the schema version are not independently chosen here. They
// are asserted equal to what mapObligations - the decide plane's own closed
// projection table - stamps on its projection of `redact_pii`. If either side
// moves, this fails rather than a plugin failing in the field.
//
// It is driven THROUGH mapObligations rather than against a copied literal,
// because a literal would be a second declaration of the same fact and would go
// on agreeing with itself after the projection changed.
func TestMCPRedactionObligationMatchesTheDecidePlaneProjection(t *testing.T) {
	// The decide plane's projection of the only obligation it can emit. The
	// fulfillment block is required by mapObligations and is what the MCP plane
	// correctly does NOT have - the caller is already at the fulfillment
	// endpoint - so this fixture supplies one purely to reach the projection.
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
	if len(projected) != 1 {
		t.Fatalf("projection produced %d obligations, want exactly 1", len(projected))
	}

	decide := projected[0]
	mcp := mcpRedactionObligation()

	if mcp.Type != decide.Type {
		t.Fatalf("the MCP plane asks about obligation type %q while the decide plane stamps %q; "+
			"one client declaration must satisfy both planes", mcp.Type, decide.Type)
	}
	if mcp.SchemaVersion != decide.SchemaVersion {
		t.Fatalf("the MCP plane asks about %s@%d while the decide plane stamps %s@%d; "+
			"a client declaring what /decide requires would be denied on the MCP plane",
			mcp.Type, mcp.SchemaVersion, decide.Type, decide.SchemaVersion)
	}
}

// TestMCPRedactionObligationIsMandatory pins the member the whole gate turns
// on.
//
// firstUnsupportedMandatory SKIPS an advisory obligation - deliberately, because
// an advisory control that can deny is an enforcement control nobody declared.
// So if this obligation were ever built as advisory, every MCP-plane refusal
// would silently stop firing and every test above that asserts a deny would
// fail loudly - except that a future edit could "fix" those by weakening them.
// This asserts the member directly, where the reason is written down.
func TestMCPRedactionObligationIsMandatory(t *testing.T) {
	if !mcpRedactionObligation().Mandatory {
		t.Fatal("the MCP plane's inline redaction is not marked Mandatory; " +
			"firstUnsupportedMandatory skips advisory obligations, so the entire " +
			"capability gate on this plane would silently stop enforcing")
	}
}

// TestMCPRedactionObligationIsValidUnderTheContract checks the obligation this
// plane constructs by hand against the contract's own validator.
//
// It is built here rather than projected through mapObligations (see that
// function's doc for why a synthetic fulfillment block would be a fiction), and
// a hand-built value is exactly the kind that drifts out of validity silently.
func TestMCPRedactionObligationIsValidUnderTheContract(t *testing.T) {
	if err := mcpRedactionObligation().Validate(); err != nil {
		t.Fatalf("the obligation the MCP plane asks its capability question about is not valid "+
			"under the contract: %v", err)
	}
}

// TestMCPRedactionObligationTypeIsInTheDeclaredVocabulary keeps the obligation
// label bounded.
//
// The refusal counter carries gap.Type as a label, and the metric label domain
// declares that label's domain as obligationTypeNames(). A type outside it
// would mint an undeclared series.
func TestMCPRedactionObligationTypeIsInTheDeclaredVocabulary(t *testing.T) {
	want := mcpRedactionObligation().Type
	for _, declared := range contract.AllObligationTypes() {
		if declared == want {
			return
		}
	}
	t.Fatalf("the MCP plane asks about obligation type %q, which is not in "+
		"contract.AllObligationTypes(); it would appear as an undeclared metric label", want)
}
