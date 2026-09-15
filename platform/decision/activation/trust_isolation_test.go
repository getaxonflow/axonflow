// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/pdp"
)

// The system root and the organization root are separate signing authorities
// (#4047). Before this, activation authorized the system key into the CALLER's
// trust store on every activation, and both transports passed their
// organization workspace's own signing key as that system key - so a dry run
// left the organization's key authorized under the system root, in the very
// store the organization's authoring surface verifies against.

// TestActivateWritesNothingIntoTheCallersTrustStore is #4047's first acceptance
// item: a dry run leaves the organization's trust store as it found it.
//
// RED ON main BEFORE THE FIX, with this exact message: "after one activation
// the caller's trust store authorizes "deployment-system-corpus" under the
// system root".
func TestActivateWritesNothingIntoTheCallersTrustStore(t *testing.T) {
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	// THROUGH A REAL PROMOTE, so the activator's dry run is what is measured,
	// and then a direct activation with the organization document beside it -
	// the two call shapes a transport and an enforcing plane use.
	w.promote(t, w.publish(t, pack, 1, ""))
	w.activate(t)

	if _, ok := w.trust.PublicKey(pdp.RootSystem, authoring.SystemKeyID); ok {
		t.Fatalf("after one activation the caller's trust store authorizes %q under the system root; that store is "+
			"the one the organization's authoring surface verifies against", authoring.SystemKeyID)
	}
	// And the organization's own authorization is untouched: isolation that
	// removed the caller's keys would pass the check above and break every
	// later verification.
	if _, ok := w.trust.PublicKey(pdp.RootOrganization, w.orgKeyID); !ok {
		t.Fatalf("activation removed the organization key %q from the caller's trust store", w.orgKeyID)
	}
}

// TestActivateRefusesTheOrganizationKeyAsTheSystemKey is #4047's second
// acceptance item: the organization's signing key passed as the system key is
// refused BY NAME, not accepted. It is the exact shape both transports shipped.
func TestActivateRefusesTheOrganizationKeyAsTheSystemKey(t *testing.T) {
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	w.promote(t, w.publish(t, pack, 1, ""))
	active, ok, err := w.api.Store().Active(context.Background(), pdp.RootOrganization)
	if err != nil || !ok {
		t.Fatalf("the positive control has no active organization document (ok=%v err=%v)", ok, err)
	}

	misused, err := authoring.NewSystemAuthority(w.orgPriv)
	if err != nil {
		t.Fatal(err)
	}
	in := w.inputs()
	in.System = misused
	in.Organization = active
	_, err = activation.Activate(context.Background(), in)
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) || refusal.Code != activation.RefusalSystemKeyIsOrganizationKey {
		t.Fatalf("activating with the organization's signing key as the system key returned %v; want the typed %s refusal",
			err, activation.RefusalSystemKeyIsOrganizationKey)
	}
	if !strings.Contains(refusal.Detail, w.orgKeyID) {
		t.Fatalf("the refusal does not name the key it refused: %s", refusal.Detail)
	}

	// THE POSITIVE CONTROL, same organization document: a separately minted
	// system key activates, so the refusal above is about the key and nothing
	// else.
	in.System = w.system
	if _, err := activation.Activate(context.Background(), in); err != nil {
		t.Fatalf("the control activation with a separate system key failed: %v", err)
	}
}
