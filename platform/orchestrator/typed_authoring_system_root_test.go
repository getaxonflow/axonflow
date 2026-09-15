// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheRoutesDryRunLeavesItsTrustAloneAndSignsTheSystemRootWithItsOwnKey is
// #4047 at this call site (typed_authoring_route.go), through the route rather
// than at the package boundary.
//
// This route passed its workspace's own signing key to activation as the system
// key, and activation authorized it under the system root in the trust store
// the workspace verifies against. After one activation through the route, that
// store must hold no system-root key, the workspace's activator must sign the
// system root with a key that is not the workspace's, and the workspace's own
// key presented as the system key must be refused by name.
func TestTheRoutesDryRunLeavesItsTrustAloneAndSignsTheSystemRootWithItsOwnKey(t *testing.T) {
	ctx := context.Background()
	h := newRouteHandler(t, authoring.EditionCommunity)
	r := routerFor(h)

	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	if digest == "" {
		t.Fatalf("publication returned no digest: %s", rr.Body.String())
	}
	rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: "first activation"}, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("activate: status=%d body=%s", rr.Code, rr.Body.String())
	}

	h.mu.Lock()
	ws := h.workspaces[testOrg]
	h.mu.Unlock()
	if ws == nil || ws.activationInputs == nil {
		t.Fatal("the activation left no workspace with activator inputs, so nothing below is measured")
	}
	in, err := ws.activationInputs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := in.Trust.PublicKey(pdp.RootSystem, authoring.SystemKeyID); ok {
		t.Fatalf("after an activation through the route, the workspace's trust store authorizes %q under the system root", authoring.SystemKeyID)
	}
	if in.System.PublicKey().Equal(ws.priv.Public()) {
		t.Fatal("the route's activator signs the system root with the workspace's own signing key")
	}
	// THE DRY RUN BUILDS decide AS THE AGENT'S SEAM DOES (#4046): it delivers the
	// Decision API's vocabulary. No activation of the shipped corpus depends on
	// it, so it is asserted as the input it is; the day a control binds a
	// mandatory obligation on decide, a dry run without it would refuse an
	// activation the seam accepts.
	if fmt.Sprint(in.Delivers) != fmt.Sprint(contract.DecisionWireCapabilities()) {
		t.Fatalf("the route's dry run delivers %v; the decide seam delivers %v", in.Delivers, contract.DecisionWireCapabilities())
	}

	// THE REFUSAL IS REACHABLE FROM THIS CALL SITE: the same inputs the
	// activator uses, with the workspace's own key as the system key.
	active, ok, err := ws.api.Store().Active(ctx, pdp.RootOrganization)
	if err != nil || !ok {
		t.Fatalf("nothing is active after the route's activation (ok=%v err=%v)", ok, err)
	}
	misused, err := authoring.NewSystemAuthority(ws.priv)
	if err != nil {
		t.Fatal(err)
	}
	in.Organization, in.System = active, misused
	_, err = activation.Activate(ctx, in)
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) || refusal.Code != activation.RefusalSystemKeyIsOrganizationKey {
		t.Fatalf("the workspace's signing key as the system key returned %v; want %s", err, activation.RefusalSystemKeyIsOrganizationKey)
	}
}
