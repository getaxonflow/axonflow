// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/pdp"
)

// TestTheOrganizationAuthorityRefusesTheSystemRootWhateverItsTrustHolds drives
// #4047's shape at the library: ONE key authorized under BOTH roots in the trust
// store an API verifies against - exactly what an activation dry run used to
// leave behind - and an organization API that must refuse the system root
// anyway, by name, at every door.
func TestTheOrganizationAuthorityRefusesTheSystemRootWhateverItsTrustHolds(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	pub, priv := testKeys(t)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootSystem, "system-key-1", pub)
	trust.Authorize(pdp.RootOrganization, organizationKeyID, pub)
	api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	activatorCalls := 0
	api.WithActivator(func(context.Context, ActivationKind, *Artifact) error {
		activatorCalls++
		return nil
	})

	refusedByAuthority := func(t *testing.T, operation string, err error) {
		t.Helper()
		var refusal *ErrSystemRootOutsideAuthority
		if !errors.As(err, &refusal) {
			t.Fatalf("%s under the system root returned %v; want the organization authority's refusal", operation, err)
		}
		if refusal.Code() != CodeSystemRootRequiresSystemAuthority || refusal.Operation != operation || refusal.Root != pdp.RootSystem {
			t.Fatalf("%s was refused as %q/%q/%q; want %s for %s under %q",
				operation, refusal.Code(), refusal.Operation, refusal.Root, CodeSystemRootRequiresSystemAuthority, operation, pdp.RootSystem)
		}
	}

	t.Run("publish", func(t *testing.T) {
		_, _, err := api.Publish(ctx, baseDocument(t), publishOptions(t, priv))
		refusedByAuthority(t, "publish", err)
	})
	// THE DOCUMENT'S ROOT IS JUDGED ON ITS OWN, not only the root the options
	// name. A system document offered with organization options and an
	// organization key is refused by the authority, by name - rather than
	// reaching the package-level cross-root refusal, which says something else
	// and would let the two fences stand in for each other unnoticed.
	t.Run("publish of a system document with organization options", func(t *testing.T) {
		opts := publishOptions(t, priv)
		opts.Root = pdp.RootOrganization
		opts.KeyID = organizationKeyID
		_, _, err := api.Publish(ctx, baseDocument(t), opts)
		refusedByAuthority(t, "publish", err)
	})

	// The artifact a leaked authorization would have let through: a genuine
	// system-root artifact, signed by a key this trust store DOES authorize under
	// the system root, produced by the root-agnostic primitive.
	art, _, err := Publish(ctx, baseDocument(t), cat, publishOptions(t, priv))
	if err != nil {
		t.Fatalf("the primitive must sign the system fixture; it is root-agnostic by design: %v", err)
	}
	t.Run("admit", func(t *testing.T) {
		refusedByAuthority(t, "admit", api.Store().Admit(ctx, art))
	})
	t.Run("promote", func(t *testing.T) {
		_, err := api.Promote(ctx, pdp.RootSystem, art.Digest(), pid(t, principalBob), timeFixture(), "rollout")
		refusedByAuthority(t, "promote", err)
		_, err = api.Store().Promote(ctx, pdp.RootSystem, art.Digest(), pid(t, principalBob), timeFixture(), "rollout")
		refusedByAuthority(t, "promote", err)
	})
	t.Run("rollback", func(t *testing.T) {
		_, err := api.Rollback(ctx, pdp.RootSystem, art.Digest(), pid(t, principalBob), timeFixture(), "restore")
		refusedByAuthority(t, "rollback", err)
		_, err = api.Store().Rollback(ctx, pdp.RootSystem, art.Digest(), pid(t, principalBob), timeFixture(), "restore")
		refusedByAuthority(t, "rollback", err)
	})
	if n, err := api.Store().Count(ctx, pdp.RootSystem); err != nil || n != 0 {
		t.Fatalf("the organization authority holds %d system-root artifact(s) (err %v)", n, err)
	}
	if activatorCalls != 0 {
		t.Fatalf("the activator ran %d time(s) for a refused system-root activation; the authority must refuse before it", activatorCalls)
	}

	// POSITIVE CONTROL, on the SAME API and the SAME trust store: the
	// organization-root document publishes, admits and promotes, and the
	// activator runs. The refusals above are about the root and nothing else.
	orgArt, findings, err := api.Publish(ctx, organizationDocument(t), organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("the organization document did not publish on the same surface: %v\n%v", err, findings)
	}
	if _, err := api.Promote(ctx, pdp.RootOrganization, orgArt.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatalf("the organization document did not promote on the same surface: %v", err)
	}
	if activatorCalls != 1 {
		t.Fatalf("the activator ran %d time(s) for one organization promotion", activatorCalls)
	}

	// AND THE PRIMITIVE IS ROOT-AGNOSTIC, stated rather than hidden: a store no
	// authority was bound to admits the same system artifact. No production code
	// constructs one - TestNoProductionCodeReachesTheRootAgnosticPrimitives holds
	// that - which is why the authority lives on the constructor transports use.
	bare, err := NewStore(StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	if err := bare.Admit(ctx, art); err != nil {
		t.Fatalf("the unbound primitive refused the system fixture, so the test above cannot tell the authority from the store: %v", err)
	}
}
