//go:build !enterprise

package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestCommunityBuildValidatesAndCountsButDoesNotDecide.
//
// The ADR-066 split, asserted on the build where the enforcement is ABSENT
// rather than inferred from the enterprise build's behaviour.
//
// It is the same posture a Community deployment has today: an enforcement point
// that declares it discharges nothing is still handed the obligation, and still
// fails closed at its own seam rather than forwarding ungoverned content. What
// the Enterprise build adds is turning that into a deny the platform can see.
func TestCommunityBuildValidatesAndCountsButDoesNotDecide(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	// The PROTOCOL half is present: the declaration is read, validated and bound.
	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-none")), "acme")
	if res.refused {
		t.Fatalf("a valid handshake was refused on the community build: %s", res.detail)
	}
	if !res.pep.Admitted() {
		t.Fatal("the community build must still admit an enforcement point; the wire contract ships in both editions")
	}
	if res.pep.SupportsObligation(contract.Obligation{
		Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true,
	}).Supported() {
		t.Fatal("fixture invalid: this enforcement point declared nothing and must not support the obligation, " +
			"so the no-deny assertion below would be vacuous")
	}

	// The DECISION half is absent: the same input that denies on the Enterprise
	// build leaves the verdict untouched here.
	verdict, reasons, obs, denied := applyPEPCapabilityRefusal(
		PlaneDecision, res, VerdictAllow, []string{"policy"}, redactObligations())
	if denied {
		t.Fatal("the community build denied on the strength of a handshake")
	}
	if verdict != VerdictAllow || len(reasons) != 1 || !hasRedactObligation(obs) {
		t.Fatalf("the triple was rewritten: verdict=%q reasons=%v obligations=%v", verdict, reasons, obs)
	}
}

// TestCommunityBuildStillRefusesAMalformedHandshake.
//
// The split is between PROTOCOL and DECISION, not between "validates" and
// "does not". A community deployment that accepted garbage where an Enterprise
// one refuses it would be a SECOND wire contract, and a client would then be
// correct against one edition and not the other.
func TestCommunityBuildStillRefusesAMalformedHandshake(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide",
		strings.NewReader(`{"stage":"llm","query":"hello"}`))
	r.Header.Set(contract.PEPHandshakeHeader, "!!! not base64 !!!")
	w := httptest.NewRecorder()
	handleDecide(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; a malformed declaration must refuse in BOTH editions or the wire contract is two contracts", w.Code)
	}
	if !strings.Contains(w.Body.String(), contract.PEPHandshakeHeader) {
		t.Errorf("the refusal does not name the header: %s", w.Body.String())
	}
}

// TestCommunityOverAdvertisingIsStillDropped.
//
// The over-advertising rule is enterprise_protocol and fires HERE - a Community
// deployment is the one place it can fire at all, since an Enterprise
// deployment derives EditionEnterprise and the rule never enters that branch.
func TestCommunityOverAdvertisingIsStillDropped(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-x",
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})), "acme")

	if res.refused {
		t.Fatalf("an over-advertising declaration refused the request: %s", res.detail)
	}
	if res.outcome != pepHandshakeOverAdvertised {
		t.Fatalf("outcome = %q, want %q", res.outcome, pepHandshakeOverAdvertised)
	}
	if len(res.dropped) != 1 || res.dropped[0].Type != contract.ObApprovalChallenge {
		t.Fatalf("dropped = %v", res.dropped)
	}
}
