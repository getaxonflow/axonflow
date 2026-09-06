//go:build !enterprise

package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// TestMCPRedactionRefusalIsAbsentFromTheCommunityBuild pins the edition split
// on the MCP plane.
//
// It asserts the community arm never denies EVEN FOR THE INPUT THE ENTERPRISE
// ARM DENIES ON - an admitted enforcement point that declared it discharges
// nothing, on a request that actually redacted. A test that only checked the
// absent-handshake case would pass on a build where the split had collapsed and
// the enterprise deny had leaked into the community binary.
//
// The build tag is the mechanism (ADR-066 Decision 5, "prefer physical
// absence"), so this file and the enterprise one can never both compile.
func TestMCPRedactionRefusalIsAbsentFromTheCommunityBuild(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	// The exact shape the enterprise arm refuses: a declaration of NO
	// capabilities, on a request where a redaction occurred.
	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "mcp-none")), "acme")
	if res.refused {
		t.Fatalf("fixture handshake was refused: %s", res.detail)
	}
	if !res.pep.Admitted() {
		t.Fatal("fixture handshake admitted no enforcement point, so the assertion below would be vacuous")
	}

	if reason, denied := applyMCPRedactionRefusal(res, true); denied {
		t.Fatalf("the community build DENIED on a capability gap (%q); the deny is "+
			"enterprise_implementation and must be physically absent from this build", reason)
	}
}

// TestMCPRedactionObligationShipsInTheCommunityBuild is the other half of the
// split, and it is the one a reader is likely to get backwards.
//
// The wire contract is enterprise_protocol and ships in BOTH editions: a
// Community deployment must be able to read, validate and bind a declaration,
// because a client is correct against ONE contract, not one per edition. Only
// the code that DECIDES on the strength of a declaration is Enterprise. So the
// obligation this plane asks its question about must be constructible here.
func TestMCPRedactionObligationShipsInTheCommunityBuild(t *testing.T) {
	ob := mcpRedactionObligation()
	if ob.Type != contract.ObFieldRedact {
		t.Fatalf("obligation type = %q, want %q", ob.Type, contract.ObFieldRedact)
	}
	if err := ob.Validate(); err != nil {
		t.Fatalf("the obligation is not valid under the contract in a community build: %v", err)
	}
}
