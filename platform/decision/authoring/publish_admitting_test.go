// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheAdmissionHookRunsOnlyForAPublicationThatSUCCEEDS pins the seam #3973
// added, and it is the only test of it: no other test in the tree calls
// PublishAdmitting at all.
//
// # What the hook is for, and the one way it can be wrong
//
// Publish is two halves - a PURE one that validates, applies the edition
// boundary, runs the gauntlet and signs, and a DURABLE one that stores the
// artifact. The hook exists to sit BETWEEN them, so a caller recording
// something against a bounded resource records it only for a publication that
// was actually going to happen. Against an append-only ledger that is the whole
// point: a row spent on a refused publication never comes back.
//
// So the failure that matters is the hook running too EARLY. Hoisted above the
// pure half it would fire for every refusal, which is precisely the defect the
// seam removes - and every other assertion about it would still pass, because
// the successful path looks identical either way. Each refusal case below is
// what makes that mutant die.
//
// # Why two different refusals
//
// They are two different gates inside the pure half, and one passing is not
// evidence about the other: the edition boundary is checkEditionConstructs, the
// two-person rule is the separation-of-duties check, and a change could move
// the hook past one and not the other.
func TestTheAdmissionHookRunsOnlyForAPublicationThatSUCCEEDS(t *testing.T) {
	// ONE organizationTrust call per surface, and the private key travels with
	// the API it belongs to. Calling it twice would sign with a key the store's
	// trust does not hold, and the "success" case would then fail on a signature
	// rather than on anything this test is about.
	//
	// THE ORGANIZATION AUTHORITY, NOT THE SYSTEM ROOT, AND #4052 IS WHY. This
	// test was written against the system-root fixtures, which every other test
	// in the package still uses. Those go through the package-level Publish, a
	// free function with no Store - so Store.refuseOutsideAuthority never sees
	// them. PublishAdmitting is a method on an *API, and NewAPI is the
	// ORGANIZATION authority by construction, so after #4052 gave the system
	// root its own authority every case here was refused at the door with
	// SYSTEM_ROOT_REQUIRES_SYSTEM_AUTHORITY before reaching the gate it was
	// about - the two refusal cases reported an EMPTY findings slice, because
	// the guard fires before findings are populated.
	//
	// The organization root is also what this seam MEANS: the hook's caller
	// charges org_root_policy against the OrgPolicies ceiling. The group scope
	// the Community case needs survives the move - toOrganizationRoot rewrites
	// roots and clears PierceableBy, and leaves Scope.Groups alone.
	newSurface := func(t *testing.T, ed Edition) (*API, ed25519.PrivateKey) {
		t.Helper()
		trust, priv := organizationTrust(t)
		api, err := NewAPI(baseCatalog(t), StaticTrust(trust), mustProfile(t, ed))
		if err != nil {
			t.Fatalf("NewAPI: %v", err)
		}
		return api, priv
	}

	t.Run("an EDITION refusal does not call the hook", func(t *testing.T) {
		// A Community surface. The baseline document uses group scope, which
		// Enterprise carries and Community does not, so this is refused inside
		// the pure half - below where a hoisted hook would have fired.
		api, priv := newSurface(t, EditionCommunity)
		calls := 0
		art, findings, err := api.PublishAdmitting(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv),
			func(context.Context, *Artifact) error { calls++; return nil })
		if err == nil {
			t.Fatal("a Community surface published a group-scoped document")
		}
		if !findings.Has(CodeGroupScopeNotInEdition) {
			t.Fatalf("refused for the wrong reason; codes: %v", findings.Codes())
		}
		if art != nil {
			t.Error("a refused publication returned an artifact")
		}
		if calls != 0 {
			t.Fatalf("the hook ran %d time(s) for a publication refused by the EDITION BOUNDARY. It is hoisted above "+
				"the judgement, so every refusal now spends whatever the hook spends - which is the defect the seam "+
				"exists to remove", calls)
		}
	})

	t.Run("a SEPARATION-OF-DUTIES refusal does not call the hook", func(t *testing.T) {
		api, priv := newSurface(t, EditionEnterprise)
		d := organizationDocument(t)
		author := d.Metadata.Author
		if author.IsZero() {
			t.Fatal("the baseline document names no author, so this test could not fail")
		}
		opts := organizationPublishOptions(t, priv)
		opts.Approvers = []contract.ID{author} // the author approving themselves
		calls := 0
		_, findings, err := api.PublishAdmitting(context.Background(), d, opts,
			func(context.Context, *Artifact) error { calls++; return nil })
		if err == nil {
			t.Fatal("the author approved their own publication")
		}
		if !findings.Has(CodeApproverIsAuthor) {
			t.Fatalf("refused for the wrong reason; codes: %v", findings.Codes())
		}
		if calls != 0 {
			t.Fatalf("the hook ran %d time(s) for a publication refused by the two-person rule", calls)
		}
	})

	t.Run("a SUCCESS calls the hook once, BEFORE the artifact is stored", func(t *testing.T) {
		api, priv := newSurface(t, EditionEnterprise)
		var calls int
		var sawDigest string
		var storedAtHookTime int
		art, findings, err := api.PublishAdmitting(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv),
			func(ctx context.Context, a *Artifact) error {
				calls++
				if a == nil {
					// A hoisted hook has no artifact to hand over, because
					// nothing has been signed yet.
					t.Error("the hook was handed a nil artifact, so it cannot have run after the document was signed")
					return nil
				}
				sawDigest = a.Digest()
				n, cerr := api.Store().Count(ctx, pdp.RootOrganization)
				if cerr != nil {
					t.Errorf("counting the store inside the hook: %v", cerr)
				}
				storedAtHookTime = n
				return nil
			})
		if err != nil {
			t.Fatalf("the baseline must publish: %v\n%v", err, findings)
		}
		if calls != 1 {
			t.Fatalf("the hook ran %d time(s) for one publication, want exactly 1", calls)
		}
		if sawDigest != art.Digest() {
			t.Errorf("the hook saw digest %q and the publication returned %q", sawDigest, art.Digest())
		}
		// THE ORDERING ASSERTION. If the hook ran after the durable write, the
		// store would already hold it.
		if storedAtHookTime != 0 {
			t.Fatalf("the store already held %d artifact(s) when the hook ran, so the hook is running AFTER the "+
				"durable write - a hook that refuses would then be refusing something already stored", storedAtHookTime)
		}
		if n, cerr := api.Store().Count(context.Background(), pdp.RootOrganization); cerr != nil || n != 1 {
			t.Fatalf("after a successful publication the store holds %d artifact(s) (err=%v), want 1; without this "+
				"the zero above is a property of a store that never writes", n, cerr)
		}
	})

	t.Run("a hook that REFUSES stores nothing", func(t *testing.T) {
		api, priv := newSurface(t, EditionEnterprise)
		sentinel := errors.New("the ceiling is full")
		art, _, err := api.PublishAdmitting(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv),
			func(context.Context, *Artifact) error { return sentinel })
		if !errors.Is(err, sentinel) {
			t.Fatalf("the hook's refusal did not reach the caller: %v", err)
		}
		if art != nil {
			t.Error("a publication refused by the hook returned an artifact")
		}
		// This is what makes a ceiling refusal leave nothing behind for anyone
		// to activate later.
		if n, cerr := api.Store().Count(context.Background(), pdp.RootOrganization); cerr != nil || n != 0 {
			t.Fatalf("the store holds %d artifact(s) (err=%v) after the hook refused; a refused publication must "+
				"leave no durable document, or a caller who was told 402 still has something promotable", n, cerr)
		}
	})

	t.Run("a nil hook is the plain Publish", func(t *testing.T) {
		api, priv := newSurface(t, EditionEnterprise)
		if _, findings, err := api.PublishAdmitting(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv), nil); err != nil {
			t.Fatalf("a nil hook must be the existing behaviour, not a refusal: %v\n%v", err, findings)
		}
	})
}
