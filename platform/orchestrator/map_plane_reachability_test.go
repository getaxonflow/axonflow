// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// TestTheMAPPlaneIsDeclaredGatedInTheModel is a DRIFT DETECTOR over the model's
// reason string, and it is worth being precise about what it can and cannot
// prove (R3 round 1, F11).
//
// It asserts that the model still declares this plane, and that its reason
// still names the two conditions run.go constructs MAPHITLPolicyChecker under:
// AXONFLOW_HITL_ENABLED and a non-community deployment posture. Those are
// string comparisons against comment-grade prose: they catch a rename or a
// dropped entry, and they CANNOT distinguish a correct declaration from a stale
// one whose wording was left intact.
func TestTheMAPPlaneIsDeclaredGatedInTheModel(t *testing.T) {
	why, gated := legacycompile.PlanesGatedUnderDefaultPosture[legacycompile.PlaneMAP]
	if !gated {
		// SKIP, NOT FAIL, AND THE DIFFERENCE IS THE POINT (R3 round 3). This
		// entry is DESIGNED TO EXPIRE - its REVISIT WHEN names the condition
		// that retires it - so failing here would red the day the work
		// succeeds, which is the class W0-E paid for on #3840 and which two
		// sibling censuses were already moved off. The declaration's own
		// census (TestGatedPlanesMatchTheCallSiteCensus) is what fails if the
		// entry is dropped while the plane is STILL gated; this test only
		// checks the reason's wording, and a retired entry has no wording to
		// check.
		t.Skip("PlanesGatedUnderDefaultPosture no longer declares the map plane. If the plane became " +
			"reachable under the default posture this test has nothing to check and the call-site " +
			"census now owns the question; if the entry was dropped while the plane is still gated, " +
			"that census fails rather than this one.")
	}
	// The reason must name the gate run.go actually constructs the checker
	// under, or the model and the boot code are describing different
	// mechanisms.
	if !strings.Contains(why, "AXONFLOW_HITL_ENABLED") {
		t.Errorf("the model's reason for gating the map plane does not name AXONFLOW_HITL_ENABLED, which "+
			"is the condition run.go constructs MAPHITLPolicyChecker under. Reason: %s", why)
	}
	if !strings.Contains(why, "MAPHITLPolicyChecker") {
		t.Errorf("the model's reason does not name MAPHITLPolicyChecker, the object whose construction "+
			"decides the plane's reachability. Reason: %s", why)
	}

	// THE SECOND GATE, which the first version of this reason left out. The
	// construction has two conditions and clearing only the named one leaves
	// the site unreachable, so a reason naming one gate is a claim a reader can
	// check and still be wrong about.
	if !strings.Contains(why, "DEPLOYMENT_MODE") && !strings.Contains(why, "community") {
		t.Errorf("the model's reason names only one of the two gates. MAPHITLPolicyChecker is built "+
			"under AXONFLOW_HITL_ENABLED=true AND a non-community deployment posture; an operator who "+
			"cleared the first would still find the plane unreachable. Reason: %s", why)
	}
}
