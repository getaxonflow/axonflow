//go:build !enterprise

package agent

import "testing"

// TestPreCheckRefusalIsAbsentFromTheCommunityBuild.
//
// Asserted against the EXACT input the enterprise arm denies on - an admitted
// enforcement point declaring nothing, on a request that requires a redaction.
// A test that only checked the absent case would pass on a build where the
// split had collapsed and the enterprise deny had leaked into this binary.
func TestPreCheckRefusalIsAbsentFromTheCommunityBuild(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "gw-none")), "acme")
	if !res.pep.Admitted() {
		t.Fatal("fixture admitted nothing, so the assertion below would be vacuous")
	}
	if reason, denied := applyPreCheckRedactionRefusal(res, true); denied {
		t.Fatalf("the community build DENIED on a capability gap (%q); the deny is "+
			"enterprise_implementation and must be physically absent from this build", reason)
	}
}
